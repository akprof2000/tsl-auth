using System.Security.Claims;
using OpenIddict.Abstractions;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.Services;

namespace TslAuth.Api;

// DTO входных данных REST API (используются также в AppApi).
public sealed record PermissionInput(string Name, string? Description);
/// <summary>
/// Новая роль: <c>Name</c> — техническое имя (строчные латинские, без пробелов, уникально в приложении; попадает в токены),
/// <c>DisplayName</c> — название для пользователей на языке установки (может содержать пробелы и повторяться).
/// </summary>
public sealed record RoleInput(string Name, string? Description, List<string>? Permissions, bool Requestable = false,
    string? DisplayName = null);

/// <summary>Изменение роли: название для пользователей и описание (техническое имя не меняется).</summary>
public sealed record RoleUpdateInput(string? DisplayName, string? Description);
public sealed record DecisionInput(string? Comment);
public sealed record LanguagePackInput(string? Name, Dictionary<string, string> Strings, bool IsEnabled = true);
public sealed record PasswordInput(string Password, bool MustChangePassword = false);

/// <summary>
/// REST API внешнего администрирования. Авторизация: Bearer-токен с audience "tsl-auth-admin"
/// (scope tsl-auth-admin) и ролью administrator/auditor в матрице системного приложения.
/// Группа /api/admin по умолчанию требует политику ApiView (чтение — хватает роли auditor);
/// все изменяющие эндпоинты дополнительно требуют ApiManage (administrator). Потребители —
/// внешние скрипты/CI и сервисы автоматизации, получающие токен через client_credentials или PAT.
/// Логика живёт в сервисах (Services/*); здесь только маршрутизация, аудит и перевод ошибок в HTTP.
/// </summary>
public static class AdminApi
{
    /// <summary>Регистрирует все маршруты /api/admin/*.</summary>
    public static void MapAdminApi(this IEndpointRouteBuilder endpoints)
    {
        // HandleErrors превращает AdminException (ошибки валидации/404 из сервисов) в ProblemDetails,
        // ApiAuditFilter пишет изменяющие вызовы в журнал безопасности.
        var api = endpoints.MapGroup("/api/admin")
            .RequireAuthorization(AdminPolicies.ApiView)
            .AddEndpointFilter(HandleErrors)
            .AddEndpointFilter(new ApiAuditFilter(AuditTypes.AdminChange))
            .WithTags("Admin");

        // ---------- Журнал безопасности ----------
        api.MapGet("/audit", (DateTime? from, DateTime? to, string? type, AuditSeverity? minSeverity, string? clientId, Guid? userId,
            bool? success, long? beforeId, int? take, AuditService s, CancellationToken ct) =>
            s.QueryAsync(new AuditQuery(from, to, type, minSeverity, clientId, userId, success, beforeId, take ?? 100), ct));
        // CSV с BOM (чтобы Excel распознал UTF-8); выгрузка ограничена 1000 последними записями.
        api.MapGet("/audit.csv", async (DateTime? from, DateTime? to, string? type, AuditSeverity? minSeverity, string? clientId,
            Guid? userId, AuditService s, CancellationToken ct) =>
            Results.File(System.Text.Encoding.UTF8.GetPreamble().Concat(System.Text.Encoding.UTF8.GetBytes(AuditService.ToCsv(
                await s.QueryAsync(new AuditQuery(from, to, type, minSeverity, clientId, userId, Take: 1000), ct)))).ToArray(),
                "text/csv", $"audit-{DateTime.UtcNow:yyyyMMdd-HHmm}.csv"));

        // ---------- Настройки (хранятся в БД) ----------
        api.MapGet("/settings", (SettingsService s, CancellationToken ct) => s.GetAsync(ct));
        api.MapPut("/settings", (RuntimeSettings settings, ClaimsPrincipal me, SettingsService s, CancellationToken ct) =>
            s.SetAsync(settings, Caller(me), ct)).RequireAuthorization(AdminPolicies.ApiManage);
        // Внеочередной запуск очистки просроченных токенов/авторизаций (обычно выполняется фоновой службой).
        api.MapPost("/maintenance/run", async (IServiceScopeFactory scopes, CancellationToken ct) =>
            Results.Ok(await TokenPruningService.RunOnceAsync(scopes, ct))).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Языковые пакеты ----------
        api.MapGet("/languages", (Localization.LocalizationService s) => s.ListAsync(includeDisabled: true));
        api.MapGet("/languages/template", (string? from) => Localization.LocalizationService.Template(from ?? "ru"));
        api.MapGet("/languages/{culture}", async (string culture, Localization.LocalizationService s) =>
            await s.GetPackAsync(culture) is { } p ? Results.Ok(p) : Results.NotFound());
        api.MapPut("/languages/{culture}", async (string culture, LanguagePackInput input, ClaimsPrincipal me,
            Localization.LocalizationService s, CancellationToken ct) =>
        {
            await s.SavePackAsync(culture, input.Name ?? "", System.Text.Json.JsonSerializer.Serialize(input.Strings), input.IsEnabled,
                Caller(me), ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        api.MapDelete("/languages/{culture}", async (string culture, Localization.LocalizationService s, CancellationToken ct) =>
        {
            await s.DeletePackAsync(culture, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Приложения ----------
        var apps = api.MapGroup("/applications");
        apps.MapGet("/", (ApplicationService s, CancellationToken ct) => s.ListAsync(ct));
        apps.MapGet("/{clientId}", async (string clientId, ApplicationService s, CancellationToken ct) =>
            await s.GetAsync(clientId, ct) is { } app ? Results.Ok(app) : Results.NotFound());
        apps.MapPost("/", async (ApplicationInput input, ApplicationService s, CancellationToken ct) =>
        {
            var created = await s.CreateAsync(input, ct: ct);
            return Results.Created($"/api/admin/applications/{created.Application.ClientId}", created);
        }).RequireAuthorization(AdminPolicies.ApiManage);
        apps.MapPut("/{clientId}", (string clientId, ApplicationInput input, ApplicationService s, CancellationToken ct) =>
            s.UpdateAsync(clientId, input, ct)).RequireAuthorization(AdminPolicies.ApiManage);
        apps.MapDelete("/{clientId}", async (string clientId, ApplicationService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(clientId, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        // Новый client_secret возвращается открытым текстом только один раз — в БД хранится лишь его хеш.
        apps.MapPost("/{clientId}/secret", async (string clientId, ApplicationService s, CancellationToken ct) =>
            Results.Ok(new { clientSecret = await s.RegenerateSecretAsync(clientId, ct) })).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Сроки жизни токенов приложения (не больше глобальных) ----------
        apps.MapGet("/{clientId}/token-lifetimes", (string clientId, TokenLifetimeService s) => s.GetForAppAsync(clientId));
        apps.MapPut("/{clientId}/token-lifetimes", async (string clientId, AppTokenLifetimes input, TokenLifetimeService s,
            CancellationToken ct) =>
        {
            await s.SetForAppAsync(clientId, input, ct);
            return await s.GetForAppAsync(clientId);
        }).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Оформление страницы входа ----------
        apps.MapGet("/{clientId}/branding", (string clientId, BrandingService s, CancellationToken ct) => s.GetAsync(clientId, ct));
        apps.MapPut("/{clientId}/branding", (string clientId, LoginBranding branding, BrandingService s, CancellationToken ct) =>
            s.SetAsync(clientId, branding, ct)).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Матрица доступа ----------
        // Матрица: роль → список разрешений. EnsureAppAsync даёт внятный 404 для несуществующего client_id,
        // иначе AccessService молча вернул бы пустую матрицу.
        apps.MapGet("/{clientId}/matrix", async (string clientId, ApplicationService a, AccessService s, CancellationToken ct) =>
        {
            await EnsureAppAsync(a, clientId, ct);
            return await s.GetMatrixAsync(clientId, ct);
        });
        apps.MapPut("/{clientId}/matrix", async (string clientId, Dictionary<string, List<string>> matrix, ApplicationService a,
            AccessService s, CancellationToken ct) =>
        {
            await EnsureAppAsync(a, clientId, ct);
            await s.SetMatrixAsync(clientId, matrix, ct);
            return await s.GetMatrixAsync(clientId, ct);
        }).RequireAuthorization(AdminPolicies.ApiManage);

        apps.MapPost("/{clientId}/permissions", async (string clientId, PermissionInput input, ApplicationService a, AccessService s,
            CancellationToken ct) =>
        {
            await EnsureAppAsync(a, clientId, ct);
            return Results.Ok(await s.AddPermissionAsync(clientId, input.Name, input.Description, ct));
        }).RequireAuthorization(AdminPolicies.ApiManage);
        apps.MapDelete("/{clientId}/permissions/{name}", async (string clientId, string name, AccessService s, CancellationToken ct) =>
        {
            await s.DeletePermissionAsync(clientId, name, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);

        apps.MapPost("/{clientId}/roles", async (string clientId, RoleInput input, ApplicationService a, AccessService s,
            CancellationToken ct) =>
        {
            await EnsureAppAsync(a, clientId, ct);
            return Results.Ok(await s.AddRoleAsync(clientId, input.Name, input.Description, input.Permissions, ct, input.Requestable,
                input.DisplayName));
        }).RequireAuthorization(AdminPolicies.ApiManage);
        apps.MapPut("/{clientId}/roles/{name}", (string clientId, string name, RoleUpdateInput input, AccessService s,
            CancellationToken ct) => s.UpdateRoleAsync(clientId, name, input.DisplayName, input.Description, ct))
            .RequireAuthorization(AdminPolicies.ApiManage);
        apps.MapPut("/{clientId}/roles/{name}/permissions", async (string clientId, string name, List<string> permissions,
            AccessService s, CancellationToken ct) =>
        {
            await s.SetRolePermissionsAsync(clientId, name, permissions, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        apps.MapDelete("/{clientId}/roles/{name}", async (string clientId, string name, AccessService s, CancellationToken ct) =>
        {
            await s.DeleteRoleAsync(clientId, name, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);

        // Роли сервисной учётной записи клиента (client_credentials).
        apps.MapGet("/{clientId}/service-roles", async (string clientId, ApplicationService a, AccessService s, CancellationToken ct) =>
        {
            await EnsureAppAsync(a, clientId, ct);
            return await s.GetAssignmentsAsync(SubjectType.Client, clientId, ct);
        });
        apps.MapPut("/{clientId}/service-roles", async (string clientId, List<RoleRef> roles, ApplicationService a, AccessService s,
            CancellationToken ct) =>
        {
            await EnsureAppAsync(a, clientId, ct);
            await s.SetAssignmentsAsync(SubjectType.Client, clientId, roles, ct);
            return await s.GetAssignmentsAsync(SubjectType.Client, clientId, ct);
        }).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Пользователи ----------
        var users = api.MapGroup("/users");
        users.MapGet("/", (string? search, int? skip, int? take, UserService s, CancellationToken ct) =>
            s.ListAsync(search, skip ?? 0, take ?? 50, ct));
        users.MapGet("/{id:guid}", async (Guid id, UserService s, CancellationToken ct) =>
            await s.GetAsync(id, ct) is { } user ? Results.Ok(user) : Results.NotFound());
        // ?invite=true — создать без пароля и сразу выслать приглашение (ссылка возвращается в ответе).
        users.MapPost("/", async (UserInput input, bool? invite, UserService s, CancellationToken ct) =>
        {
            var user = await s.CreateAsync(input, ct);
            var invitation = invite == true ? await s.InviteAsync(user.Id, true, ct) : null;
            return Results.Created($"/api/admin/users/{user.Id}", new { user, invite = invitation });
        }).RequireAuthorization(AdminPolicies.ApiManage);
        users.MapPost("/{id:guid}/invite", async (Guid id, bool? sendEmail, UserService s, CancellationToken ct) =>
            Results.Ok(await s.InviteAsync(id, sendEmail ?? true, ct))).RequireAuthorization(AdminPolicies.ApiManage);
        users.MapPost("/{id:guid}/temporary-password", async (Guid id, UserService s, CancellationToken ct) =>
            Results.Ok(new { password = await s.SetTemporaryPasswordAsync(id, ct), mustChangePassword = true }))
            .RequireAuthorization(AdminPolicies.ApiManage);
        users.MapPost("/{id:guid}/password-reset-email", async (Guid id, UserService s, CancellationToken ct) =>
        {
            await s.SendPasswordResetAsync(id, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        users.MapPut("/{id:guid}", (Guid id, UserInput input, UserService s, CancellationToken ct) =>
            s.UpdateAsync(id, input, ct)).RequireAuthorization(AdminPolicies.ApiManage);
        users.MapDelete("/{id:guid}", async (Guid id, UserService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(id, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        users.MapPost("/{id:guid}/password", async (Guid id, PasswordInput input, UserService s, CancellationToken ct) =>
        {
            await s.SetPasswordAsync(id, input.Password, input.MustChangePassword, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        users.MapPost("/{id:guid}/unlock", async (Guid id, UserService s) =>
        {
            await s.UnlockAsync(id);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        // Роли пользователя во всех приложениях сразу (RoleRef = client_id + имя роли).
        users.MapGet("/{id:guid}/roles", (Guid id, AccessService s, CancellationToken ct) =>
            s.GetAssignmentsAsync(SubjectType.User, id.ToString(), ct));
        users.MapPut("/{id:guid}/roles", async (Guid id, List<RoleRef> roles, UserService u, AccessService s, CancellationToken ct) =>
        {
            if (await u.GetAsync(id, ct) is null) return Results.NotFound();
            await s.SetAssignmentsAsync(SubjectType.User, id.ToString(), roles, ct);
            return Results.Ok(await s.GetAssignmentsAsync(SubjectType.User, id.ToString(), ct));
        }).RequireAuthorization(AdminPolicies.ApiManage);

        apps.MapPut("/{clientId}/roles/{name}/requestable", async (string clientId, string name, bool value, AccessService s,
            CancellationToken ct) =>
        {
            await s.SetRoleRequestableAsync(clientId, name, value, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Персональные токены пользователей ----------
        // Возвращаются только метаданные (имя, префикс, сроки): сам токен хранится лишь как SHA-256.
        api.MapGet("/users/{id:guid}/tokens", (Guid id, PatService s, CancellationToken ct) => s.ListAsync(id, ct));
        api.MapDelete("/users/{id:guid}/tokens/{tokenId:guid}", async (Guid id, Guid tokenId, PatService s, CancellationToken ct) =>
        {
            await s.RevokeAsync(tokenId, id, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Заявки на доступ ----------
        var requests = api.MapGroup("/access-requests");
        requests.MapGet("/", (string? status, string? clientId, AccessRequestService s, CancellationToken ct) =>
            s.ListAsync(ParseStatus(status), clientId, ct: ct));
        requests.MapPost("/{id:guid}/approve", (Guid id, DecisionInput? input, ClaimsPrincipal me, AccessRequestService s,
            CancellationToken ct) => s.DecideAsync(id, true, Caller(me), input?.Comment, ct: ct)).RequireAuthorization(AdminPolicies.ApiManage);
        requests.MapPost("/{id:guid}/reject", (Guid id, DecisionInput? input, ClaimsPrincipal me, AccessRequestService s,
            CancellationToken ct) => s.DecideAsync(id, false, Caller(me), input?.Comment, ct: ct)).RequireAuthorization(AdminPolicies.ApiManage);

        // ---------- Сессии ----------
        // Сессия = постоянная авторизация OpenIddict (пользователь + клиент); её отзыв делает
        // недействительными все выданные по ней refresh-токены.
        var sessions = api.MapGroup("/sessions");
        sessions.MapGet("/", (string? subject, string? clientId, SessionService s, CancellationToken ct) =>
            s.ListAsync(subject, clientId, ct: ct));
        sessions.MapDelete("/{id:guid}", async (Guid id, SessionService s, CancellationToken ct) =>
        {
            await s.RevokeAsync(id, ct);
            return Results.NoContent();
        }).RequireAuthorization(AdminPolicies.ApiManage);
        users.MapDelete("/{id:guid}/sessions", async (Guid id, SessionService s, CancellationToken ct) =>
            Results.Ok(new { revoked = await s.RevokeBySubjectAsync(id.ToString(), ct) })).RequireAuthorization(AdminPolicies.ApiManage);
    }

    /// <summary>
    /// Разбор фильтра статуса заявок: null или "all" — все; нераспознанное значение — только ожидающие.
    /// </summary>
    public static AccessRequestStatus? ParseStatus(string? status) =>
        Enum.TryParse<AccessRequestStatus>(status, true, out var s) ? s : status is null or "all" ? null : AccessRequestStatus.Pending;

    /// <summary>Строка «кто выполнил действие» для аудита: "client:{client_id}" или "user:{логин}".</summary>
    public static string Caller(ClaimsPrincipal me) =>
        me.GetClaim(CustomClaims.SubjectType) == "client"
            ? $"client:{me.GetClaim(OpenIddictConstants.Claims.Subject)}"
            : $"user:{me.GetClaim(OpenIddictConstants.Claims.PreferredUsername) ?? me.GetClaim(OpenIddictConstants.Claims.Subject)}";

    private static async Task EnsureAppAsync(ApplicationService apps, string clientId, CancellationToken ct)
    {
        if (await apps.GetAsync(clientId, ct) is null)
            throw AdminException.NotFound($"Приложение '{clientId}'");
    }

    private static async ValueTask<object?> HandleErrors(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (AdminException ex)
        {
            return Results.Problem(detail: ex.Message, statusCode: ex.StatusCode);
        }
    }
}
