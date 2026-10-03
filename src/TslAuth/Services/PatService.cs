using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using TslAuth.Data;

namespace TslAuth.Services;

/// <summary>
/// PAT для отображения: вместо секрета — только его префикс (чтобы пользователь узнал свой токен).
/// <c>AllApplications</c> — доступ ко всем приложениям владельца (тогда <c>Audiences</c> пуст);
/// <c>ClientId</c> — сервис-робот, которому выписан токен подключения (null — токен для скриптов).
/// </summary>
public sealed record PatDto(Guid Id, string Name, string Prefix, List<string> Audiences, DateTime CreatedAt, DateTime? ExpiresAt,
    DateTime? LastUsedAt, string? LastUsedIp, bool IsActive, bool AllApplications = false, string? ClientId = null);

/// <summary>
/// Параметры нового PAT: название, приложения-аудитории, срок жизни (null — максимальный по политике),
/// «все мои приложения» вместо списка и сервис-робот, которому выписывается токен подключения.
/// </summary>
public sealed record PatInput(string Name, List<string> Audiences, int? ExpiresInDays, bool AllApplications = false, string? ClientId = null);

/// <summary>Сервис-робот, которому пользователь может выписать токен подключения.</summary>
public sealed record PatServiceClient(string ClientId, string DisplayName);

/// <summary>
/// Персональные токены доступа (как в GitHub). Сам токен показывается один раз; в БД — только SHA-256.
/// Токен обменивается на короткоживущий JWT (grant urn:tsl:grant-type:pat), права в котором
/// всегда вычисляются по текущей матрице доступа пользователя — PAT не может дать больше, чем есть у владельца.
/// Два вида: токен для скриптов (обменивает кто угодно через служебный клиент tsl-pat) и токен подключения
/// сервиса-робота (обменивает только этот сервис со своим секретом или ключом; в JWT — claim act с его client_id).
/// Создание/отзыв — страница Account/Tokens, Admin/Users/Edit и Admin API; проверка — AuthorizationController.
/// </summary>
public sealed class PatService(AuthDbContext db, SettingsService settings, AuditService audit, ApplicationService applications)
{
    /// <summary>Узнаваемый префикс: позволяет сканерам секретов находить утёкшие токены и быстро отсекать мусор.</summary>
    public const string TokenPrefix = "tslpat_";

    /// <summary>Служебный клиент OpenIddict, от имени которого выполняется обмен PAT на JWT (создаётся StartupInitializer).</summary>
    public const string PatClientId = "tsl-pat";

    /// <summary>Нестандартный grant_type обмена PAT (и токена подключения робота) на короткоживущий JWT.</summary>
    public const string GrantType = "urn:tsl:grant-type:pat";

    /// <summary>Все токены пользователя, включая отозванные и истёкшие.</summary>
    public async Task<List<PatDto>> ListAsync(Guid userId, CancellationToken ct = default) =>
        (await db.PersonalAccessTokens.AsNoTracking().Where(t => t.UserId == userId).OrderByDescending(t => t.CreatedAt).ToListAsync(ct))
        .Select(ToDto).ToList();

    /// <summary>Приложения, для которых пользователь может выпустить токен (где у него есть роли).</summary>
    public async Task<List<string>> AvailableAudiencesAsync(Guid userId, CancellationToken ct = default) =>
        await db.AccessRoleAssignments.Where(a => a.SubjectType == SubjectType.User && a.SubjectId == userId.ToString())
            .Select(a => a.Role.ClientId).Distinct().OrderBy(c => c).ToListAsync(ct);

    /// <summary>
    /// Сервисы-роботы, которым можно выписать токен подключения: администратор разрешил им grant
    /// <see cref="AppGrantTypes.ConnectionToken"/> (только confidential-клиенты), и они не отключены.
    /// </summary>
    public async Task<List<PatServiceClient>> ServiceClientsAsync(CancellationToken ct = default) =>
        (await applications.ListAsync(ct))
        .Where(a => a.ClientId != PatClientId && !a.Disabled && a.GrantTypes.Contains(AppGrantTypes.ConnectionToken))
        .Select(a => new PatServiceClient(a.ClientId, a.DisplayName ?? a.ClientId))
        .OrderBy(a => a.DisplayName).ToList();

    /// <summary>Приложения, к которым токен даёт доступ сейчас: для «все приложения» — по текущим ролям владельца.</summary>
    public async Task<List<string>> AudiencesAsync(PersonalAccessToken token, CancellationToken ct = default) =>
        token.AllApplications
            ? await AvailableAudiencesAsync(token.UserId, ct)
            : token.Audiences.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();

    /// <summary>Выпускает PAT с учётом политики (включено, лимит числа, макс. срок); секрет возвращается один раз.</summary>
    public async Task<(PatDto Token, string Secret)> CreateAsync(Guid userId, PatInput input, CancellationToken ct = default)
    {
        var policy = (await settings.GetAsync(ct)).Pats;
        if (!policy.Enabled) throw AdminException.Localized("error.tokensDisabled", "Персональные токены отключены администратором.", StatusCodes.Status403Forbidden);

        var name = input.Name?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > 100) throw AdminException.Localized("error.tokenNameRequired", "Укажите название токена (до 100 символов).");

        var active = await db.PersonalAccessTokens.CountAsync(t => t.UserId == userId && t.RevokedAt == null &&
                                                                    (t.ExpiresAt == null || t.ExpiresAt > DateTime.UtcNow), ct);
        if (active >= policy.MaxTokensPerUser) throw AdminException.Localized("error.tokenLimit", $"Не более {policy.MaxTokensPerUser} активных токенов.");

        var days = input.ExpiresInDays ?? policy.MaxLifetimeDays;
        if (days < 1 || days > policy.MaxLifetimeDays)
            throw AdminException.Localized("error.tokenExpiryInvalid", $"Срок действия токена: от 1 до {policy.MaxLifetimeDays} дней.");

        var allowed = await AvailableAudiencesAsync(userId, ct);
        var audiences = input.AllApplications ? [] : (input.Audiences ?? []).Distinct().ToList();
        if (input.AllApplications)
        {
            if (allowed.Count == 0) throw AdminException.Localized("error.tokenAppsRequired", "Выберите хотя бы одно приложение.");
        }
        else
        {
            if (audiences.Count == 0) throw AdminException.Localized("error.tokenAppsRequired", "Выберите хотя бы одно приложение.");
            var forbidden = audiences.Except(allowed).ToList();
            if (forbidden.Count > 0) throw AdminException.Localized("error.tokenAppsRequired", $"Нет ролей в приложениях: {string.Join(", ", forbidden)}.");
        }

        // Токен подключения — только сервису, которому администратор разрешил работать от имени пользователей.
        var clientId = string.IsNullOrWhiteSpace(input.ClientId) ? null : input.ClientId.Trim();
        if (clientId is not null && (await ServiceClientsAsync(ct)).All(c => c.ClientId != clientId))
            throw AdminException.Localized("error.tokenServiceInvalid",
                $"Сервису «{clientId}» нельзя выписать токен подключения: его нет или администратор не разрешил ему работать от имени пользователей.");

        // 256 бит случайности: соль при хэшировании не нужна, перебор невозможен, поэтому достаточно SHA-256
        // (быстрый поиск по индексу TokenHash без медленных KDF вроде PBKDF2).
        var secret = TokenPrefix + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var entity = new PersonalAccessToken
        {
            UserId = userId,
            Name = name,
            TokenHash = Hash(secret),
            Prefix = secret[..(TokenPrefix.Length + 6)],
            Audiences = string.Join(",", audiences),
            AllApplications = input.AllApplications,
            ClientId = clientId,
            ExpiresAt = DateTime.UtcNow.AddDays(days)
        };
        db.PersonalAccessTokens.Add(entity);
        await db.SaveChangesAsync(ct);

        await audit.WriteAsync("pat.created", true, AuditSeverity.Info, clientId, userId,
            new { tokenId = entity.Id, name, audiences, allApplications = input.AllApplications, service = clientId, expiresAt = entity.ExpiresAt });
        return (ToDto(entity), secret);
    }

    /// <summary>Отзывает токен. <paramref name="ownerId"/> = null — отзыв администратором (любой токен).</summary>
    public async Task RevokeAsync(Guid id, Guid? ownerId, CancellationToken ct = default)
    {
        // Мягкий отзыв (RevokedAt), а не удаление: запись остаётся для истории и аудита.
        var token = await db.PersonalAccessTokens.FirstOrDefaultAsync(t => t.Id == id && (ownerId == null || t.UserId == ownerId), ct)
                    ?? throw AdminException.NotFound("Токен");
        token.RevokedAt ??= DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("pat.revoked", true, AuditSeverity.Info, token.ClientId, token.UserId, new { tokenId = id, token.Name, service = token.ClientId });
    }

    /// <summary>Проверяет токен; возвращает запись и владельца, если токен действителен.</summary>
    public async Task<(PersonalAccessToken Token, AppUser User)?> ValidateAsync(string? secret, string? ip, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(secret) || !secret.StartsWith(TokenPrefix, StringComparison.Ordinal)) return null;
        if (!(await settings.GetAsync(ct)).Pats.Enabled) return null;

        var hash = Hash(secret);
        var token = await db.PersonalAccessTokens.FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (token is null || token.RevokedAt is not null || token.ExpiresAt <= DateTime.UtcNow) return null;

        // Отключённый пользователь или пользователь с обязательной сменой пароля не может пользоваться PAT.
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == token.UserId, ct);
        if (user is not { IsActive: true, MustChangePassword: false }) return null;

        token.LastUsedAt = DateTime.UtcNow;
        token.LastUsedIp = ip;
        await db.SaveChangesAsync(ct);
        return (token, user);
    }

    /// <summary>В БД хранится только SHA-256 токена: сам токен показывается пользователю один раз.</summary>
    private static string Hash(string secret) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    /// <summary>DTO токена: вместо секрета — только префикс; активен, если не отозван и не истёк.</summary>
    private static PatDto ToDto(PersonalAccessToken t) => new(t.Id, t.Name, t.Prefix + "…",
        t.Audiences.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(), t.CreatedAt, t.ExpiresAt, t.LastUsedAt, t.LastUsedIp,
        t.RevokedAt is null && (t.ExpiresAt is null || t.ExpiresAt > DateTime.UtcNow), t.AllApplications, t.ClientId);
}
