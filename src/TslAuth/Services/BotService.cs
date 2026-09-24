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

/// <summary>
/// Команда бота над учётной записью: отправитель (provider + externalId) и цель — логин или email.
/// <c>Target</c> пустой — действие над собственной учётной записью отправителя.
/// </summary>
public sealed record BotTargetInput(string Provider, string ExternalId, string? Target = null);

/// <summary>Результат команды блокировки/смены пароля: кто инициировал, над кем выполнено, изменилось ли состояние.</summary>
public sealed record BotActionResult(string Action, string Actor, string UserName, bool Self, bool Changed);

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
    WebhookService webhooks,
    AccessService access)
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
        var externalId = ExternalId(input.ExternalId);

        var hash = Hash((input.Code ?? "").Trim().ToUpperInvariant());
        var code = await db.BotLinkCodes.FirstOrDefaultAsync(c => c.CodeHash == hash && c.ExpiresAt > DateTime.UtcNow, ct);
        if (code is null)
        {
            // Одиночная ошибка (опечатка в коде) — Info, без рассылки. Серия ошибок от бота — признак перебора:
            // на пороге пишется Warning и уходит один security.alert (а не на каждый неверный код).
            var burst = BadCodeBurst(botClientId);
            await audit.WriteAsync("bot.link", false, burst ? AuditSeverity.Warning : AuditSeverity.Info, botClientId,
                details: new { provider, reason = burst ? "bad_code_burst" : "bad_code" });
            throw new AdminException("Код привязки неверный или истёк.", StatusCodes.Status400BadRequest);
        }

        // Один аккаунт мессенджера — одна учётная запись: повторная привязка переносит её. Удаление прежней привязки,
        // новая привязка и погашение кода — одной транзакцией (иначе сбой оставил бы пользователя без привязки).
        var identity = new ExternalIdentity { UserId = code.UserId, Provider = provider, ExternalId = externalId, LinkedByClientId = botClientId };
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            await db.ExternalIdentities.Where(x => x.Provider == provider && x.ExternalId == externalId).ExecuteDeleteAsync(ct);
            db.ExternalIdentities.Add(identity);
            db.BotLinkCodes.Remove(code);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }

        await audit.WriteAsync("bot.link", true, AuditSeverity.Info, botClientId, code.UserId, new { provider });
        return new LinkedIdentityDto(identity.Id, provider, botClientId, identity.CreatedAt);
    }

    /// <summary>Отвязка по запросу бота; false — привязки не было.</summary>
    public async Task<bool> UnlinkAsync(string botClientId, BotUserRef user, CancellationToken ct = default)
    {
        var provider = Provider(user.Provider);
        var identity = await db.ExternalIdentities.FirstOrDefaultAsync(x => x.Provider == provider && x.ExternalId == ExternalId(user.ExternalId), ct);
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
        var userId = await db.ExternalIdentities.Where(x => x.Provider == provider && x.ExternalId == ExternalId(user.ExternalId))
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
            .FirstOrDefaultAsync(x => x.Provider == provider && x.ExternalId == ExternalId(input.ExternalId), ct);
        if (identity is null)
            throw AdminException.NotFound("Привязка мессенджера (пользователь должен сначала выполнить /link с кодом из личного кабинета)");

        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == identity.UserId, ct) ?? throw AdminException.NotFound("Пользователь");
        if (!user.IsActive) throw new AdminException("Учётная запись отключена.", StatusCodes.Status403Forbidden);

        // Лимит считается по журналу аудита: он общий для всех узлов кластера, отдельный счётчик не нужен.
        // Сброс записывается ДО выполнения и обязательно (required): если запись не удалась, сброса нет —
        // иначе сбой записи в журнал снимал бы ограничение.
        var since = DateTime.UtcNow.AddHours(-1);
        var recent = await db.AuditEntries.CountAsync(a => a.Type == ResetAuditType && a.SubjectUserId == user.Id && a.Success &&
                                                           a.OccurredAt > since, ct);
        if (recent >= policy.MaxPerUserPerHour)
        {
            await audit.WriteAsync("bot.password_reset_limited", false, AuditSeverity.Warning, botClientId, user.Id, new { provider, reason = "rate_limit" });
            throw new AdminException("Слишком много сбросов за последний час, попробуйте позже.", StatusCodes.Status429TooManyRequests);
        }

        var mode = policy.Mode == "temporary" ? "temporary" : "link";
        await audit.WriteAsync(ResetAuditType, true, AuditSeverity.Warning, botClientId, user.Id, new { provider, mode },
            required: true, alert: false);

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

        // Один security.alert с подробностями (автоматический алерт аудита для этой записи отключён).
        await webhooks.PublishAsync("security.alert", $"🔑 Сброс пароля {user.UserName} через бота {botClientId} ({provider}, режим {result.Mode}).",
            new { userId = user.Id, userName = user.UserName, bot = botClientId, provider, mode = result.Mode }, ct);
        return result;
    }

    /// <summary>
    /// Блокировка учётной записи по команде в боте. Свою учётку («телефон украли») может заблокировать любой
    /// привязанный пользователь; чужую — только имеющий разрешение user_lock в системном приложении.
    /// </summary>
    public Task<BotActionResult> LockAsync(string botClientId, BotTargetInput input, CancellationToken ct = default) =>
        ExecuteAsync(botClientId, input, "bot.user_lock", SystemApp.UserLockPermission, allowSelf: true,
            (user, c) => users.SetActiveAsync(user.Id, false, c),
            user => $"🔒 Учётная запись {user.UserName} заблокирована через бота", ct);

    /// <summary>Разблокировка (включение) учётной записи: только по разрешению user_lock — себя разблокировать нельзя.</summary>
    public Task<BotActionResult> UnlockAsync(string botClientId, BotTargetInput input, CancellationToken ct = default) =>
        ExecuteAsync(botClientId, input, "bot.user_unlock", SystemApp.UserLockPermission, allowSelf: false,
            (user, c) => users.SetActiveAsync(user.Id, true, c),
            user => $"🔓 Учётная запись {user.UserName} разблокирована через бота", ct);

    /// <summary>
    /// Принудительная смена пароля: сессии отзываются, при следующем входе потребуется новый пароль.
    /// Для себя — любой привязанный пользователь, для других — разрешение password_force.
    /// </summary>
    public Task<BotActionResult> ForcePasswordChangeAsync(string botClientId, BotTargetInput input, CancellationToken ct = default) =>
        ExecuteAsync(botClientId, input, "bot.password_force", SystemApp.PasswordForcePermission, allowSelf: true,
            async (user, c) => { await users.RequirePasswordChangeAsync(user.Id, c); return true; },
            user => $"🔑 Для {user.UserName} через бота потребована смена пароля", ct);

    /// <summary>
    /// Общий сценарий команд над учётной записью: отправитель обязан быть привязан и активен; цель — он сам
    /// (если <paramref name="allowSelf"/>) или другой пользователь при наличии разрешения в tsl-auth-admin.
    /// Каждое действие — запись аудита уровня Warning и событие security.alert для ботов-уведомителей.
    /// </summary>
    private async Task<BotActionResult> ExecuteAsync(string botClientId, BotTargetInput input, string auditType, string permission,
        bool allowSelf, Func<AppUser, CancellationToken, Task<bool>> action, Func<AppUser, string> text, CancellationToken ct)
    {
        var provider = Provider(input.Provider);
        var identity = await db.ExternalIdentities.AsNoTracking()
            .FirstOrDefaultAsync(x => x.Provider == provider && x.ExternalId == ExternalId(input.ExternalId), ct);
        if (identity is null)
            throw AdminException.NotFound("Привязка мессенджера (пользователь должен сначала выполнить /link с кодом из личного кабинета)");
        var actor = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == identity.UserId, ct) ?? throw AdminException.NotFound("Пользователь");
        if (!actor.IsActive) throw new AdminException("Ваша учётная запись отключена.", StatusCodes.Status403Forbidden);

        var target = string.IsNullOrWhiteSpace(input.Target) ? actor : await users.FindByLoginAsync(input.Target.Trim());
        if (target is null) throw AdminException.NotFound("Пользователь");
        var self = target.Id == actor.Id;

        if (self && !allowSelf)
            throw new AdminException("Эту команду нельзя применить к самому себе.", StatusCodes.Status403Forbidden);
        if (!self && !await access.HasPermissionAsync(SubjectType.User, actor.Id.ToString(), SystemApp.ClientId, permission, ct))
        {
            await audit.WriteAsync(auditType, false, AuditSeverity.Warning, botClientId, actor.Id,
                new { provider, target = target.UserName, reason = "forbidden" });
            throw new AdminException("Недостаточно прав для действий над другими пользователями.", StatusCodes.Status403Forbidden);
        }

        var changed = await action(target, ct);
        await audit.WriteAsync(auditType, true, AuditSeverity.Warning, botClientId, target.Id,
            new { provider, actor = actor.UserName, self, changed });
        await webhooks.PublishAsync("security.alert", $"{text(target)} (инициатор {actor.UserName}, бот {botClientId}).",
            new { userId = target.Id, userName = target.UserName, actor = actor.UserName, bot = botClientId, provider, action = auditType }, ct);
        return new BotActionResult(auditType, actor.UserName!, target.UserName!, self, changed);
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

    /// <summary>Идентификатор пользователя мессенджера без пробелов по краям — одинаково во всех операциях бота.</summary>
    private static string ExternalId(string? value)
    {
        var id = value?.Trim();
        if (string.IsNullOrEmpty(id) || id.Length > 100)
            throw new AdminException("Укажите externalId пользователя мессенджера (до 100 символов).");
        return id;
    }

    // Неверные коды привязки по боту: окно 10 минут, порог 5 (на экземпляр — для сигнала о переборе этого достаточно).
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (int Count, DateTime Since)> BadCodes = new();

    /// <summary>true, если неудачная попытка довела серию до порога (тогда серия начинается заново).</summary>
    private static bool BadCodeBurst(string botClientId)
    {
        var now = DateTime.UtcNow;
        var state = BadCodes.AddOrUpdate(botClientId, _ => (1, now),
            (_, s) => now - s.Since > TimeSpan.FromMinutes(10) ? (1, now) : (s.Count + 1, s.Since));
        if (state.Count < 5) return false;
        BadCodes.TryRemove(botClientId, out _);
        return true;
    }
}
