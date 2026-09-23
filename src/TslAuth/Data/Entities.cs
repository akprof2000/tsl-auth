using Microsoft.AspNetCore.Identity;

namespace TslAuth.Data;

/// <summary>
/// Пользователь (ASP.NET Core Identity) — единый для всех приложений. UserName, Email, PhoneNumber и
/// DisplayName хранятся в БД зашифрованными, а NormalizedUserName/NormalizedEmail — в виде blind index
/// (HMAC) для поиска на равенство; см. конвертеры в <see cref="AuthDbContext"/>.
/// Права в приложениях задаются не здесь, а через <see cref="AccessRoleAssignment"/>.
/// </summary>
public sealed class AppUser : IdentityUser<Guid>
{
    [PersonalData]
    public string? DisplayName { get; set; }

    /// <summary>false — учётная запись отключена администратором: вход и выдача/обновление токенов запрещены.</summary>
    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastLoginAt { get; set; }

    /// <summary>Выдан временный (одноразовый) пароль — при входе требуется сменить.</summary>
    public bool MustChangePassword { get; set; }

    /// <summary>client_id приложения, создавшего пользователя через App API (null — создан администратором).</summary>
    public string? CreatedByClientId { get; set; }

    /// <summary>Когда пароль менялся последний раз (для политики срока действия пароля).</summary>
    public DateTime? PasswordChangedAt { get; set; }
}

/// <summary>История паролей (хеши) — запрет повторного использования последних N паролей.</summary>
public sealed class PasswordHistoryEntry
{
    public long Id { get; set; }
    public Guid UserId { get; set; }

    /// <summary>Хеш прежнего пароля в формате Identity PasswordHasher (сравнивается через VerifyHashedPassword).</summary>
    public required string PasswordHash { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Персональный токен доступа (PAT), как в GitHub: для скриптов и автоматических сервисов.
/// Сам токен показывается пользователю один раз при создании; далее он обменивается на короткоживущий
/// JWT через грант urn:tsl:grant-type:pat, поэтому права всегда соответствуют текущим ролям владельца.
/// </summary>
public sealed class PersonalAccessToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public required string Name { get; set; }

    /// <summary>
    /// SHA-256 от токена (сам токен не хранится). Медленный хеш не нужен: токен случайный и
    /// высокоэнтропийный, перебор невозможен, а быстрый хеш позволяет искать по уникальному индексу.
    /// </summary>
    public required string TokenHash { get; set; }

    /// <summary>Первые символы токена — чтобы пользователь узнал его в списке.</summary>
    public required string Prefix { get; set; }

    /// <summary>client_id приложений (через запятую), к которым токен даёт доступ.</summary>
    public required string Audiences { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public string? LastUsedIp { get; set; }

    /// <summary>Время отзыва; запись не удаляется, чтобы сохранилась история в списке токенов.</summary>
    public DateTime? RevokedAt { get; set; }
}

/// <summary>
/// Разрешение (действие) внутри приложения, например "orders.read". Столбец матрицы доступа;
/// уникально в пределах ClientId. Попадает в токен как claim разрешения, если есть у роли пользователя.
/// </summary>
public sealed class AccessPermission
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string ClientId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }

    public List<AccessRolePermission> Roles { get; set; } = [];
}

/// <summary>Роль приложения — набор разрешений (строка матрицы доступа).</summary>
public sealed class AccessRole
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string ClientId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }

    /// <summary>Роль можно запросить при самостоятельной регистрации / через «Запросить доступ».</summary>
    public bool IsRequestable { get; set; }

    public List<AccessRolePermission> Permissions { get; set; } = [];
    public List<AccessRoleAssignment> Assignments { get; set; } = [];
}

/// <summary>Ячейка матрицы доступа "роль × разрешение".</summary>
public sealed class AccessRolePermission
{
    public Guid RoleId { get; set; }
    public AccessRole Role { get; set; } = null!;

    public Guid PermissionId { get; set; }
    public AccessPermission Permission { get; set; } = null!;
}

/// <summary>Тип субъекта, которому назначается роль.</summary>
public enum SubjectType
{
    User = 0,

    /// <summary>Сервисная учётная запись клиента (client_credentials).</summary>
    Client = 1
}

/// <summary>Назначение роли пользователю или сервисному клиенту.</summary>
public sealed class AccessRoleAssignment
{
    public Guid RoleId { get; set; }
    public AccessRole Role { get; set; } = null!;

    public SubjectType SubjectType { get; set; }

    /// <summary>Id пользователя (Guid строкой) или client_id сервисного клиента — в зависимости от SubjectType.</summary>
    public required string SubjectId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public enum AccessRequestStatus
{
    Pending = 0,
    Approved = 1,
    Rejected = 2
}

/// <summary>Заявка пользователя на роль приложения; роль назначается только после одобрения.</summary>
public sealed class AccessRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }

    public Guid RoleId { get; set; }
    public AccessRole Role { get; set; } = null!;

    public AccessRequestStatus Status { get; set; }

    /// <summary>Комментарий заявителя (зашифрован; как и DecisionComment).</summary>
    public string? Comment { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? DecidedAt { get; set; }

    /// <summary>Кто принял решение: "user:{id}" или "client:{client_id}".</summary>
    public string? DecidedBy { get; set; }
    public string? DecisionComment { get; set; }
}

/// <summary>Журнал событий (для вебхуков и pull-ленты /api/admin/events). Id — монотонный курсор.</summary>
public sealed class WebhookEvent
{
    public long Id { get; set; }
    public required string Type { get; set; }
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    /// <summary>Готовый текст уведомления (зашифрован: может содержать персональные данные).</summary>
    public required string Text { get; set; }

    /// <summary>JSON с деталями события (зашифрован).</summary>
    public required string Data { get; set; }
}

/// <summary>Подписка внешней системы (бота) на события.</summary>
public sealed class WebhookSubscription
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public required string Url { get; set; }

    /// <summary>Секрет для подписи HMAC-SHA256 (зашифрован).</summary>
    public string? Secret { get; set; }

    /// <summary>Типы событий через запятую; "*" — все.</summary>
    public string Events { get; set; } = "*";
    public bool IsEnabled { get; set; } = true;

    /// <summary>Кто создал подписку ("user:admin", "client:bot").</summary>
    public string? CreatedBy { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public enum WebhookDeliveryStatus
{
    Pending = 0,
    Succeeded = 1,
    Failed = 2
}

/// <summary>Outbox доставки: переживает перезапуск, в кластере отправляется ровно одним экземпляром.</summary>
public sealed class WebhookDelivery
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SubscriptionId { get; set; }
    public WebhookSubscription Subscription { get; set; } = null!;
    public long EventId { get; set; }
    public WebhookEvent Event { get; set; } = null!;

    public WebhookDeliveryStatus Status { get; set; }
    public int Attempts { get; set; }

    /// <summary>Когда пробовать снова (растёт с каждой неудачной попыткой).</summary>
    public DateTime NextAttemptAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Аренда записи экземпляром-отправителем: пока не истекла, другие экземпляры её не берут;
    /// если экземпляр упал, по истечении аренды доставку подхватит другой.
    /// </summary>
    public DateTime? LockedUntil { get; set; }

    /// <summary>Идентификатор экземпляра, взявшего доставку в работу.</summary>
    public string? LockedBy { get; set; }
    public int? LastStatusCode { get; set; }
    public string? LastError { get; set; }
    public DateTime? DeliveredAt { get; set; }
}

public enum AuditSeverity
{
    Info = 0,
    Warning = 1,
    Critical = 2
}

/// <summary>Журнал безопасности (аудит). Запись неизменяема; удаляется только по сроку хранения.</summary>
public sealed class AuditEntry
{
    public long Id { get; set; }
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    /// <summary>Тип события, например "auth.login.failed", "admin.change", "token.issued".</summary>
    public required string Type { get; set; }
    public AuditSeverity Severity { get; set; }
    public bool Success { get; set; }

    /// <summary>Кто выполнил действие: "user:{id}", "client:{client_id}", "anonymous".</summary>
    public string? Actor { get; set; }

    /// <summary>Читаемое имя актора на момент события (зашифровано — это персональные данные).</summary>
    public string? ActorName { get; set; }

    /// <summary>Пользователь, которого касается событие.</summary>
    public Guid? SubjectUserId { get; set; }

    /// <summary>Приложение, к которому относится событие (для выборки «своих» событий через App API).</summary>
    public string? ClientId { get; set; }

    public string? Ip { get; set; }
    public string? UserAgent { get; set; }

    /// <summary>Имя экземпляра сервиса, записавшего событие (для разбора инцидентов в кластере).</summary>
    public string? Instance { get; set; }

    /// <summary>Детали в JSON (зашифрованы: могут содержать персональные данные).</summary>
    public string? Details { get; set; }
}

/// <summary>Привязка учётной записи к пользователю внешней системы (мессенджер-бот).</summary>
public sealed class ExternalIdentity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }

    /// <summary>Провайдер (например "mattermost", "telegram").</summary>
    public required string Provider { get; set; }

    /// <summary>ID пользователя во внешней системе (хранится как HMAC-индекс — не раскрывает исходный ID).</summary>
    public required string ExternalId { get; set; }

    /// <summary>Какой клиент-бот выполнил привязку.</summary>
    public required string LinkedByClientId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Одноразовый код привязки мессенджера (хранится хеш). Пользователь получает код в личном кабинете
/// и отправляет боту; бот через /api/bot/link обменивает его на запись <see cref="ExternalIdentity"/>.
/// </summary>
public sealed class BotLinkCode
{
    public required string CodeHash { get; set; }
    public Guid UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
}

/// <summary>Языковой пакет (JSON «ключ → текст»): новый язык или переопределение строк встроенного.</summary>
public sealed class LanguagePack
{
    /// <summary>Код языка: ru, en, kk, uz-Latn …</summary>
    public required string Culture { get; set; }
    public required string Name { get; set; }
    public required string Json { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? UpdatedBy { get; set; }
}

/// <summary>Настройки, изменяемые во время работы (общие для всех экземпляров).</summary>
public sealed class SystemSetting
{
    public required string Key { get; set; }

    /// <summary>Значение в JSON (секция RuntimeSettings).</summary>
    public required string Value { get; set; }
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? UpdatedBy { get; set; }
}

/// <summary>
/// Общие для всех экземпляров криптографические ключи сервера (хранятся зашифрованными).
/// Хранение в БД гарантирует, что все экземпляры кластера подписывают/шифруют токены одними ключами.
/// </summary>
public sealed class KeyMaterial
{
    public required string Id { get; set; }
    public required string Value { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
