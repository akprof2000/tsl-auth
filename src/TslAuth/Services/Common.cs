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

    public static AdminException NotFound(string what) => new($"{what} не найден(о).", StatusCodes.Status404NotFound);
    public static AdminException Conflict(string message) => new(message, StatusCodes.Status409Conflict);
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
}

/// <summary>Ссылка на роль конкретного приложения; строковая форма — "client_id:role".</summary>
public sealed record RoleRef(string ClientId, string Role)
{
    public override string ToString() => $"{ClientId}:{Role}";
}
