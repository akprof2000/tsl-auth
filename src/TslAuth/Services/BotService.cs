using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;

namespace TslAuth.Services;

/// <summary>
/// Привязка аккаунта мессенджера к учётной записи. ExternalId сюда не входит: в БД он хранится
/// как blind index (необратимый HMAC) — по нему можно искать, но восстановить исходное значение нельзя.
/// </summary>
public sealed record LinkedIdentityDto(Guid Id, string Provider, string LinkedByClientId, DateTime CreatedAt);

/// <summary>Запрос бота на привязку: пользователь мессенджера + код, полученный им в личном кабинете.</summary>
public sealed record BotLinkInput(string Provider, string ExternalId, string Code);

/// <summary>Идентификация пользователя мессенджера: провайдер (например mattermost) + его внешний Id.</summary>
public sealed record BotUserRef(string Provider, string ExternalId);

/// <summary>Результат сброса пароля через бота.</summary>
/// <param name="Mode">"link" — ResetLink заполнена (отправьте пользователю лично); "temporary" — TemporaryPassword.</param>
public sealed record BotResetResult(string Mode, string UserName, string? ResetLink, string? TemporaryPassword, DateTime ExpiresAt);

/// <summary>
/// Интеграция с ботом мессенджера: привязка аккаунта мессенджера к учётной записи по одноразовому коду
/// и сброс пароля по запросу пользователя в боте. Бот доказывает личность пользователя привязкой,
/// которую пользователь сам подтвердил кодом из личного кабинета.
/// Вызывается из Api/BotApi.cs (бот — клиент с разрешением password_reset) и страницы Account/Messenger.
/// </summary>
public sealed class BotService(
    AuthDbContext db,
    UserService users,
    AccountLinks links,
    SettingsService settings,
    AuditService audit,
    WebhookService webhooks)
{
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);
    private const string ResetAuditType = "bot.password_reset";

    /// <summary>Одноразовый код привязки для личного кабинета (8 символов, 10 минут).</summary>
    public async Task<(string Code, DateTime ExpiresAt)> CreateLinkCodeAsync(Guid userId, CancellationToken ct = default)
    {
        // У пользователя действует только последний код; заодно чистим все просроченные.
        await db.BotLinkCodes.Where(c => c.UserId == userId || c.ExpiresAt < DateTime.UtcNow).ExecuteDeleteAsync(ct);
        // Алфавит без похожих символов (0/O, 1/I/L), чтобы код было легко перепечатать вручную.
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var code = new string(Enumerable.Range(0, 8).Select(_ => alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]).ToArray());
        var expires = DateTime.UtcNow + CodeLifetime;
        // В БД хранится только SHA-256 кода: утечка базы не даёт привязать чужой аккаунт.
        db.BotLinkCodes.Add(new BotLinkCode { CodeHash = Hash(code), UserId = userId, ExpiresAt = expires });
        await db.SaveChangesAsync(ct);
        return (code, expires);
    }

    /// <summary>Привязывает аккаунт мессенджера к владельцу кода; код одноразовый.</summary>
    public async Task<LinkedIdentityDto> LinkAsync(string botClientId, BotLinkInput input, CancellationToken ct = default)
    {
        var provider = Provider(input.Provider);
        var externalId = input.ExternalId?.Trim();
        if (string.IsNullOrEmpty(externalId) || externalId.Length > 200) throw new AdminException("Укажите externalId пользователя мессенджера.");

        var hash = Hash((input.Code ?? "").Trim().ToUpperInvariant());
        var code = await db.BotLinkCodes.FirstOrDefaultAsync(c => c.CodeHash == hash && c.ExpiresAt > DateTime.UtcNow, ct);
        if (code is null)
        {
            // Warning: серия неверных кодов может означать перебор — попадёт в ленту security.alert.
            await audit.WriteAsync("bot.link", false, AuditSeverity.Warning, botClientId, details: new { provider, reason = "bad_code" });
            throw new AdminException("Код привязки неверный или истёк.", StatusCodes.Status400BadRequest);
        }

        // Один аккаунт мессенджера — одна учётная запись: повторная привязка переносит её.
        await db.ExternalIdentities.Where(x => x.Provider == provider && x.ExternalId == externalId).ExecuteDeleteAsync(ct);
        var identity = new ExternalIdentity { UserId = code.UserId, Provider = provider, ExternalId = externalId, LinkedByClientId = botClientId };
        db.ExternalIdentities.Add(identity);
        db.BotLinkCodes.Remove(code);
        await db.SaveChangesAsync(ct);

        await audit.WriteAsync("bot.link", true, AuditSeverity.Info, botClientId, code.UserId, new { provider });
        return new LinkedIdentityDto(identity.Id, provider, botClientId, identity.CreatedAt);
    }

    /// <summary>Отвязка по запросу бота; false — привязки не было.</summary>
    public async Task<bool> UnlinkAsync(string botClientId, BotUserRef user, CancellationToken ct = default)
    {
        var provider = Provider(user.Provider);
        var identity = await db.ExternalIdentities.FirstOrDefaultAsync(x => x.Provider == provider && x.ExternalId == user.ExternalId, ct);
        if (identity is null) return false;
        db.ExternalIdentities.Remove(identity);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("bot.unlink", true, AuditSeverity.Info, botClientId, identity.UserId, new { provider });
        return true;
    }

    /// <summary>Проверка привязки (бот может показать, от чьего имени он будет действовать).</summary>
    public async Task<string?> WhoIsAsync(BotUserRef user, CancellationToken ct = default)
    {
        var provider = Provider(user.Provider);
        var userId = await db.ExternalIdentities.Where(x => x.Provider == provider && x.ExternalId == user.ExternalId)
            .Select(x => (Guid?)x.UserId).FirstOrDefaultAsync(ct);
        return userId is null ? null : (await users.GetAsync(userId.Value, ct))?.UserName;
    }

    /// <summary>
    /// Сброс пароля по запросу пользователя в боте: в зависимости от политики — ссылка на сброс
    /// или временный пароль. Ограничен по частоте и всегда сопровождается алертом безопасности.
    /// </summary>
    public async Task<BotResetResult> ResetPasswordAsync(string botClientId, BotUserRef input, CancellationToken ct = default)
    {
        var policy = (await settings.GetAsync(ct)).BotReset;
        if (!policy.Enabled) throw new AdminException("Сброс пароля через бота отключён администратором.", StatusCodes.Status403Forbidden);

        var provider = Provider(input.Provider);
        var identity = await db.ExternalIdentities.AsNoTracking()
            .FirstOrDefaultAsync(x => x.Provider == provider && x.ExternalId == input.ExternalId, ct);
        if (identity is null)
            throw AdminException.NotFound("Привязка мессенджера (пользователь должен сначала выполнить /link с кодом из личного кабинета)");

        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == identity.UserId, ct) ?? throw AdminException.NotFound("Пользователь");
        if (!user.IsActive) throw new AdminException("Учётная запись отключена.", StatusCodes.Status403Forbidden);

        // Лимит считается по журналу аудита: он общий для всех узлов кластера, отдельный счётчик не нужен.
        // Успешные сбросы пишутся с Warning, т.е. сразу (не через пакетную очередь), поэтому подсчёт точен.
        var since = DateTime.UtcNow.AddHours(-1);
        var recent = await db.AuditEntries.CountAsync(a => a.Type == ResetAuditType && a.SubjectUserId == user.Id && a.Success &&
                                                           a.OccurredAt > since, ct);
        if (recent >= policy.MaxPerUserPerHour)
        {
            await audit.WriteAsync(ResetAuditType, false, AuditSeverity.Warning, botClientId, user.Id, new { provider, reason = "rate_limit" });
            throw new AdminException("Слишком много сбросов за последний час, попробуйте позже.", StatusCodes.Status429TooManyRequests);
        }

        BotResetResult result;
        if (policy.Mode == "temporary")
        {
            var password = await users.SetTemporaryPasswordAsync(user.Id, ct);
            result = new BotResetResult("temporary", user.UserName!, null, password, DateTime.UtcNow.AddHours(24));
        }
        else
        {
            // Снимаем блокировку, иначе пользователь, заблокированный за неверные пароли, не сможет войти по новой ссылке.
            await users.UnlockAsync(user.Id);
            result = new BotResetResult("link", user.UserName!, await links.CreatePasswordResetLinkAsync(user), null, DateTime.UtcNow.AddHours(2));
        }

        await audit.WriteAsync(ResetAuditType, true, AuditSeverity.Warning, botClientId, user.Id, new { provider, mode = result.Mode });
        await webhooks.PublishAsync("security.alert", $"🔑 Сброс пароля {user.UserName} через бота {botClientId} ({provider}, режим {result.Mode}).",
            new { userId = user.Id, userName = user.UserName, bot = botClientId, provider, mode = result.Mode }, ct);
        return result;
    }

    /// <summary>Привязки пользователя (для страницы Account/Messenger).</summary>
    public async Task<List<LinkedIdentityDto>> ListAsync(Guid userId, CancellationToken ct = default) =>
        await db.ExternalIdentities.AsNoTracking().Where(x => x.UserId == userId).OrderBy(x => x.CreatedAt)
            .Select(x => new LinkedIdentityDto(x.Id, x.Provider, x.LinkedByClientId, x.CreatedAt)).ToListAsync(ct);

    /// <summary>Удаление привязки самим пользователем; фильтр по userId не даёт удалить чужую.</summary>
    public async Task RemoveAsync(Guid userId, Guid identityId, CancellationToken ct = default)
    {
        if (await db.ExternalIdentities.Where(x => x.Id == identityId && x.UserId == userId).ExecuteDeleteAsync(ct) == 0)
            throw AdminException.NotFound("Привязка");
        await audit.WriteAsync("bot.unlink", true, AuditSeverity.Info, null, userId, new { identityId, by = "user" });
    }

    // Нормализация имени провайдера: регистр не должен порождать разные привязки.
    private static string Provider(string? provider)
    {
        provider = provider?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(provider) || provider.Length > 50) throw new AdminException("Укажите provider (например mattermost).");
        return provider;
    }

    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
