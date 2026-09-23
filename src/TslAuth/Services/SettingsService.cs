using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;

namespace TslAuth.Services;

/// <summary>Настройки, хранящиеся в БД и изменяемые без перезапуска (админка / Admin API).</summary>
/// <param name="AuditRetentionDays">Срок хранения журнала безопасности.</param>
/// <param name="AuditLogTokenRefresh">Записывать в журнал каждое обновление по refresh-токену.</param>
/// <param name="EventsRetentionDays">Срок хранения ленты событий (long-polling/SSE/вебхуки) и истории доставок.</param>
/// <param name="TokensRetentionHours">Через сколько часов удалять истёкшие/отозванные токены и авторизации.</param>
/// <param name="AuditRetentionByType">
/// Срок хранения по типу события (дней). Ключ — тип или префикс ("auth." — вся группа);
/// применяется самое длинное совпадение, иначе <paramref name="AuditRetentionDays"/>.
/// </param>
public sealed record RuntimeSettings(
    int AuditRetentionDays = 365,
    bool AuditLogTokenRefresh = false,
    int EventsRetentionDays = 30,
    int TokensRetentionHours = 24,
    Dictionary<string, int>? AuditRetentionByType = null,
    PasswordPolicy? PasswordPolicy = null,
    PatPolicy? PatPolicy = null,
    TokenPolicy? TokenPolicy = null,
    BotResetPolicy? BotResetPolicy = null)
{
    // Вложенные политики nullable, чтобы JSON, сохранённый старой версией (без этих секций), читался без ошибок;
    // свойства ниже подставляют значения по умолчанию.
    public BotResetPolicy BotReset => BotResetPolicy ?? new BotResetPolicy();
    public PasswordPolicy Passwords => PasswordPolicy ?? new PasswordPolicy();
    public PatPolicy Pats => PatPolicy ?? new PatPolicy();
    public TokenPolicy Tokens => TokenPolicy ?? new TokenPolicy();

    /// <summary>Разумные значения по умолчанию: частые события храним меньше, изменения и инциденты — дольше.</summary>
    public static readonly Dictionary<string, int> DefaultRetentionByType = new()
    {
        [AuditTypes.TokenIssued] = 30,
        [AuditTypes.LoginSucceeded] = 180,
        [AuditTypes.LoginFailed] = 365,
        [AuditTypes.AdminChange] = 1825,
        [AuditTypes.AppApiChange] = 1825,
        [AuditTypes.LockedOut] = 1825,
        [AuditTypes.AccessDenied] = 730
    };

    /// <summary>Правила хранения по типам: заданные администратором или значения по умолчанию.</summary>
    public Dictionary<string, int> EffectiveRetentionByType => AuditRetentionByType ?? DefaultRetentionByType;

    /// <summary>Срок хранения для конкретного типа события (самый длинный подходящий префикс).</summary>
    public int RetentionFor(string type) =>
        EffectiveRetentionByType.Where(r => type.StartsWith(r.Key, StringComparison.Ordinal))
            .OrderByDescending(r => r.Key.Length).Select(r => (int?)r.Value).FirstOrDefault() ?? AuditRetentionDays;

    /// <summary>Проверяет все значения (включая вложенные политики); при ошибке бросает <see cref="AdminException"/>.</summary>
    public RuntimeSettings Validate()
    {
        if (AuditRetentionDays is < 1 or > 3650) throw new AdminException("Срок хранения журнала: от 1 до 3650 дней.");
        foreach (var (type, days) in AuditRetentionByType ?? [])
        {
            if (string.IsNullOrWhiteSpace(type) || type.Length > 100)
                throw new AdminException("Тип события в правиле хранения не должен быть пустым.");
            if (days is < 1 or > 3650) throw new AdminException($"Срок хранения для «{type}»: от 1 до 3650 дней.");
        }
        if (EventsRetentionDays is < 1 or > 365) throw new AdminException("Срок хранения событий: от 1 до 365 дней.");
        if (TokensRetentionHours is < 1 or > 24 * 90) throw new AdminException("Срок хранения токенов: от 1 часа до 90 дней.");
        Passwords.Validate();
        Pats.Validate();
        Tokens.Validate();
        BotReset.Validate();
        return this;
    }
}

/// <summary>
/// Политика паролей (применяется ко всем способам смены/установки пароля).
/// Проверяется валидаторами из Security/PasswordPolicyServices; MaxFailedAttempts/LockoutMinutes
/// переносятся в опции блокировки Identity (см. <see cref="SettingsService"/>).
/// HistoryCount = 0 — история не проверяется; MaxAgeDays = 0 — пароль бессрочный.
/// </summary>
public sealed record PasswordPolicy(
    int MinLength = 8,
    bool RequireUppercase = true,
    bool RequireLowercase = true,
    bool RequireDigit = true,
    bool RequireSymbol = false,
    int MinUniqueChars = 1,
    int HistoryCount = 0,
    int MaxAgeDays = 0,
    int MaxFailedAttempts = 5,
    int LockoutMinutes = 15)
{
    public void Validate()
    {
        if (MinLength is < 6 or > 128) throw new AdminException("Минимальная длина пароля: от 6 до 128.");
        if (MinUniqueChars < 1 || MinUniqueChars > MinLength) throw new AdminException("Уникальных символов: от 1 до минимальной длины.");
        if (HistoryCount is < 0 or > 24) throw new AdminException("История паролей: от 0 до 24.");
        if (MaxAgeDays is < 0 or > 3650) throw new AdminException("Срок действия пароля: от 0 (бессрочно) до 3650 дней.");
        if (MaxFailedAttempts is < 1 or > 100) throw new AdminException("Попыток до блокировки: от 1 до 100.");
        if (LockoutMinutes is < 1 or > 1440 * 7) throw new AdminException("Длительность блокировки: от 1 минуты до 7 дней.");
    }

    /// <summary>Текст требований для подсказки пользователю.</summary>
    public string Describe()
    {
        var parts = new List<string> { $"не короче {MinLength} символов" };
        if (RequireLowercase) parts.Add("строчные буквы");
        if (RequireUppercase) parts.Add("заглавные буквы");
        if (RequireDigit) parts.Add("цифры");
        if (RequireSymbol) parts.Add("спецсимволы");
        if (MinUniqueChars > 1) parts.Add($"не менее {MinUniqueChars} разных символов");
        if (HistoryCount > 0) parts.Add($"не совпадает с последними {HistoryCount}");
        return string.Join(", ", parts) + ".";
    }
}

/// <summary>
/// Сроки жизни токенов. Применяются к каждому выпускаемому токену (без перезапуска).
/// Итоговый срок вычисляет <see cref="TokenLifetimeService"/> с учётом настроек приложения.
/// </summary>
public sealed record TokenPolicy(
    int AccessTokenMinutes = 15,
    int RefreshTokenDays = 14,
    int ExchangeTokenMinutes = 5,
    int PatAccessTokenMinutes = 15,
    int IdentityTokenMinutes = 15,
    int AuthorizationCodeMinutes = 5)
{
    public void Validate()
    {
        if (AccessTokenMinutes is < 1 or > 1440) throw new AdminException("Access-токен: от 1 до 1440 минут.");
        if (RefreshTokenDays is < 1 or > 365) throw new AdminException("Refresh-токен: от 1 до 365 дней.");
        if (ExchangeTokenMinutes is < 1 or > 1440) throw new AdminException("Токен token exchange: от 1 до 1440 минут.");
        if (PatAccessTokenMinutes is < 1 or > 1440) throw new AdminException("Токен по PAT: от 1 до 1440 минут.");
        if (IdentityTokenMinutes is < 1 or > 1440) throw new AdminException("id_token: от 1 до 1440 минут.");
        if (AuthorizationCodeMinutes is < 1 or > 30) throw new AdminException("Код авторизации: от 1 до 30 минут.");
    }
}

/// <summary>Переопределение сроков жизни токенов для конкретного приложения (null — глобальное значение).</summary>
public sealed record AppTokenLifetimes(int? AccessTokenMinutes = null, int? RefreshTokenDays = null, int? ExchangeTokenMinutes = null)
{
    public void Validate()
    {
        if (AccessTokenMinutes is < 1 or > 1440) throw new AdminException("Access-токен приложения: от 1 до 1440 минут.");
        if (RefreshTokenDays is < 1 or > 365) throw new AdminException("Refresh-токен приложения: от 1 до 365 дней.");
        if (ExchangeTokenMinutes is < 1 or > 1440) throw new AdminException("Exchange-токен приложения: от 1 до 1440 минут.");
    }
}

/// <summary>Сброс пароля через внешнего бота (мессенджер).</summary>
/// <param name="Mode">"link" — одноразовая ссылка сброса (бот не видит пароль); "temporary" — временный пароль со сменой при входе.</param>
public sealed record BotResetPolicy(bool Enabled = true, string Mode = "link", int MaxPerUserPerHour = 3)
{
    public void Validate()
    {
        if (Mode is not ("link" or "temporary")) throw new AdminException("Режим сброса через бота: link или temporary.");
        if (MaxPerUserPerHour is < 1 or > 20) throw new AdminException("Сбросов через бота в час: от 1 до 20.");
    }
}

/// <summary>Политика персональных токенов доступа.</summary>
public sealed record PatPolicy(bool Enabled = true, int MaxLifetimeDays = 365, int MaxTokensPerUser = 20)
{
    public void Validate()
    {
        if (MaxLifetimeDays is < 1 or > 3650) throw new AdminException("Максимальный срок PAT: от 1 до 3650 дней.");
        if (MaxTokensPerUser is < 1 or > 1000) throw new AdminException("Токенов на пользователя: от 1 до 1000.");
    }
}

/// <summary>
/// Кэш на 30 секунд: экземпляры кластера подхватывают изменения, сделанные на любом из них,
/// не обращаясь к БД на каждый запрос.
/// Singleton: БД открывается через собственный scope. Все настройки — одна JSON-строка в SystemSettings (ключ "runtime").
/// Читают AuthorizationController, TokenPruningService, страницы входа/токенов/настроек, валидаторы паролей, Admin API.
/// </summary>
public sealed class SettingsService(IServiceScopeFactory scopes,
    Microsoft.Extensions.Options.IOptions<Microsoft.AspNetCore.Identity.IdentityOptions> identity)
{
    /// <summary>
    /// Блокировку проверяет Identity по своим (singleton) опциям — обновляем их при каждой загрузке настроек,
    /// так все экземпляры кластера применяют новые значения в пределах TTL кэша.
    /// </summary>
    private void ApplyLockout(RuntimeSettings s)
    {
        identity.Value.Lockout.MaxFailedAccessAttempts = s.Passwords.MaxFailedAttempts;
        identity.Value.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(s.Passwords.LockoutMinutes);
    }

    private const string Key = "runtime";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(30);
    private RuntimeSettings? _cached;
    private DateTime _cachedAt;

    /// <summary>Текущие настройки (из кэша, если он моложе 30 секунд).</summary>
    public async Task<RuntimeSettings> GetAsync(CancellationToken ct = default)
    {
        // Блокировки нет намеренно: при гонке несколько потоков лишь перечитают одну и ту же строку из БД,
        // а замена ссылки на неизменяемый record атомарна.
        if (_cached is not null && DateTime.UtcNow - _cachedAt < CacheTtl) return _cached;

        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var row = await db.SystemSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Key == Key, ct);
        _cached = row is null ? new RuntimeSettings() : JsonSerializer.Deserialize<RuntimeSettings>(row.Value) ?? new RuntimeSettings();
        _cachedAt = DateTime.UtcNow;
        ApplyLockout(_cached);
        return _cached;
    }

    /// <summary>
    /// Валидирует и сохраняет настройки. Локальный кэш обновляется сразу,
    /// остальные узлы кластера увидят изменения по истечении TTL.
    /// </summary>
    public async Task<RuntimeSettings> SetAsync(RuntimeSettings settings, string updatedBy, CancellationToken ct = default)
    {
        settings.Validate();
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var row = await db.SystemSettings.FirstOrDefaultAsync(s => s.Key == Key, ct);
        if (row is null) db.SystemSettings.Add(row = new SystemSetting { Key = Key, Value = "" });
        row.Value = JsonSerializer.Serialize(settings);
        row.UpdatedAt = DateTime.UtcNow;
        row.UpdatedBy = updatedBy;
        await db.SaveChangesAsync(ct);

        _cached = settings;
        _cachedAt = DateTime.UtcNow;
        ApplyLockout(settings);
        return settings;
    }

    /// <summary>Кто и когда последний раз менял настройки (без кэша).</summary>
    public async Task<(DateTime? UpdatedAt, string? UpdatedBy)> GetMetadataAsync(CancellationToken ct = default)
    {
        using var scope = scopes.CreateScope();
        var row = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().SystemSettings.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Key == Key, ct);
        return (row?.UpdatedAt, row?.UpdatedBy);
    }
}
