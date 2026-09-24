using System.Text.RegularExpressions;

namespace TslAuth.Services;

/// <summary>
/// Встроенное приложение самого сервиса: его матрица доступа управляет правами администрирования.
/// Создаётся StartupInitializer; роли/разрешения этого приложения проверяет AdminAuthorization
/// для админки, Admin API, ленты событий и Bot API.
/// </summary>
public static class SystemApp
{
    public const string ClientId = "tsl-auth-admin";
    public const string AdministratorRole = "administrator";
    public const string AuditorRole = "auditor";
    public const string ViewPermission = "view";
    public const string ManagePermission = "manage";

    /// <summary>Чтение ленты событий и управление своими подписками (для ботов-уведомителей).</summary>
    public const string EventsPermission = "events";
    public const string NotifierRole = "notifier";

    /// <summary>Привязка мессенджера и сброс пароля через бота.</summary>
    public const string PasswordResetPermission = "password_reset";
    public const string ResetBotRole = "reset-bot";

    /// <summary>Блокировка/разблокировка учётной записи по команде в боте (для клиента бота и для пользователя-инициатора).</summary>
    public const string UserLockPermission = "user_lock";

    /// <summary>Принудительная смена пароля по команде в боте (для клиента бота и для пользователя-инициатора).</summary>
    public const string PasswordForcePermission = "password_force";

    /// <summary>Клиент бота безопасности: сброс, блокировка, принудительная смена пароля.</summary>
    public const string SecurityBotRole = "security-bot";

    /// <summary>Пользователь, которому разрешено через бота блокировать чужие учётки и требовать смену пароля.</summary>
    public const string SecurityOfficerRole = "security-officer";

    /// <summary>Scope/audience App API — самоуправление приложений своими пользователями и ролями.</summary>
    public const string AppApiScope = "tsl-auth-app";
}

/// <summary>Нестандартные claims, которые TslAuth добавляет в токены (см. <see cref="TokenPrincipalFactory"/>).</summary>
public static class CustomClaims
{
    /// <summary>"user" или "client" — кто является субъектом токена.</summary>
    public const string SubjectType = "subject_type";

    /// <summary>Плоский список разрешений вида "client_id:permission".</summary>
    public const string Permissions = "permissions";

    /// <summary>Роли/разрешения по приложениям в формате, совместимом с Keycloak.</summary>
    public const string ResourceAccess = "resource_access";

    /// <summary>RFC 8693: кто получил токен обменом (цепочка вызовов сервисов).</summary>
    public const string Actor = "act";
}

/// <summary>
/// Ошибка бизнес-логики администрирования, транслируется в HTTP-статус.
/// Сервисы бросают её, а API-эндпоинты и Razor-страницы превращают в ответ с кодом/сообщение в форме.
/// </summary>
public sealed class AdminException(string message, int statusCode = StatusCodes.Status400BadRequest) : Exception(message)
{
    public int StatusCode { get; } = statusCode;

    /// <summary>
    /// Ключ языкового пакета (например <c>error.emailTaken</c>) для ошибок, которые видит пользователь на страницах
    /// входа/регистрации: страница показывает <c>L[Key]</c> на языке пользователя, API — русский <see cref="Exception.Message"/>.
    /// </summary>
    public string? Key { get; init; }

    public static AdminException NotFound(string what) => new($"{what} не найден(о).", StatusCodes.Status404NotFound);
    public static AdminException Conflict(string message) => new(message, StatusCodes.Status409Conflict);

    /// <summary>Ошибка с ключом локализации для пользовательских страниц.</summary>
    public static AdminException Localized(string key, string message, int statusCode = StatusCodes.Status400BadRequest) =>
        new(message, statusCode) { Key = key };
}

/// <summary>
/// Валидация технических имён (client_id, роли, разрешения): они попадают в claims вида "client:role"
/// и в URL API, поэтому набор символов ограничен.
/// </summary>
public static partial class Names
{
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")]
    private static partial Regex Pattern();

    public static string Validate(string? value, string what)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value) || !Pattern().IsMatch(value))
            throw new AdminException($"{what}: допустимы латинские буквы, цифры и символы . _ : - (до 100 символов).");
        return value;
    }

    // Техническое имя роли: без пробелов и заглавных букв, начинается с буквы. Без «:» — это разделитель
    // приложения и роли в claims ("app:role") и в ссылках на роль.
    [GeneratedRegex("^[a-z][a-z0-9._-]{0,99}$")]
    private static partial Regex RolePattern();

    /// <summary>Проверяет техническое имя роли (уникальность в приложении проверяет вызывающий код).</summary>
    public static string ValidateRole(string? value)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value) || !RolePattern().IsMatch(value))
            throw new AdminException("Техническое имя роли: строчные латинские буквы, цифры и символы . _ - без пробелов, " +
                                     "начинается с буквы (до 100 символов), например orders-manager. " +
                                     "Название для пользователей задаётся отдельно (displayName).");
        return value;
    }

    /// <summary>Отображаемое название: любой текст до 200 символов; пустое — null (показывается техническое имя).</summary>
    public static string? DisplayName(string? value)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value)) return null;
        if (value.Length > 200) throw new AdminException("Название роли: не более 200 символов.");
        return value;
    }
}

/// <summary>Роль для выбора в админке: ссылка на роль и её название для пользователей (если задано).</summary>
public sealed record RoleOption(string ClientId, string Role, string? DisplayName)
{
    public RoleRef Ref => new(ClientId, Role);
}

/// <summary>Ссылка на роль конкретного приложения; строковая форма — "client_id:role".</summary>
public sealed record RoleRef(string ClientId, string Role)
{
    public override string ToString() => $"{ClientId}:{Role}";
}
