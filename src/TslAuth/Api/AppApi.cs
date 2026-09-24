using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Api;

/// <summary>
/// App API — самоуправление внешнего приложения (как client_credentials, scope tsl-auth-app).
/// Приложение видит и меняет только свои роли, матрицу доступа и пользователей своего среза.
/// Включается флагом «Самоуправление» в настройках приложения.
/// Группа /api/app защищена политикой <see cref="Policy"/>: Bearer-токен OpenIddict, выданный самому
/// клиенту (sub_type=client), с audience tsl-auth-app. Идентификатор приложения всегда берётся из sub
/// токена, а не из URL, — поэтому клиент физически не может обратиться к чужим данным.
/// Потребители — бэкенды внешних приложений, автоматизирующие управление своими пользователями и ролями.
/// </summary>
public static class AppApi
{
    public const string Policy = "app-self-management";

    /// <summary>Регистрирует политику авторизации App API (вызывается при настройке AddAuthorization).</summary>
    public static void AddAppApiPolicy(AuthorizationOptions options) =>
        options.AddPolicy(Policy, p => p
            .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireClaim(CustomClaims.SubjectType, "client")
            .AddRequirements(new AppSelfRequirement()));

    /// <summary>Регистрирует все маршруты /api/app/*.</summary>
    public static void MapAppApi(this IEndpointRouteBuilder endpoints)
    {
        var api = endpoints.MapGroup("/api/app")
            .RequireAuthorization(Policy)
            .AddEndpointFilter(ApiErrors.Handle)
            .AddEndpointFilter(new ApiAuditFilter(AuditTypes.AppApiChange))
            .WithTags("App (self-management)");

        // ---------- Журнал безопасности: только события своего приложения ----------
        api.MapGet("/audit", (ClaimsPrincipal me, DateTime? from, DateTime? to, string? type, AuditSeverity? minSeverity, Guid? userId,
            bool? success, long? beforeId, int? take, AuditService s, CancellationToken ct) =>
            s.QueryAsync(new AuditQuery(from, to, type, minSeverity, Client(me), userId, success, beforeId, take ?? 100), ct));

        // ---------- Оформление своей страницы входа ----------
        api.MapGet("/branding", (ClaimsPrincipal me, BrandingService s, CancellationToken ct) => s.GetAsync(Client(me), ct));
        api.MapPut("/branding", (ClaimsPrincipal me, LoginBranding branding, BrandingService s, CancellationToken ct) =>
            s.SetAsync(Client(me), branding, ct));

        // ---------- Матрица доступа своего приложения ----------
        api.MapGet("/matrix", (ClaimsPrincipal me, AccessService s, CancellationToken ct) => s.GetMatrixAsync(Client(me), ct));
        api.MapPut("/matrix", async (ClaimsPrincipal me, Dictionary<string, List<string>> matrix, AccessService s, CancellationToken ct) =>
        {
            await s.SetMatrixAsync(Client(me), matrix, ct);
            return await s.GetMatrixAsync(Client(me), ct);
        });
        api.MapPost("/permissions", (ClaimsPrincipal me, PermissionInput input, AccessService s, CancellationToken ct) =>
            s.AddPermissionAsync(Client(me), input.Name, input.Description, ct));
        api.MapDelete("/permissions/{name}", async (ClaimsPrincipal me, string name, AccessService s, CancellationToken ct) =>
        {
            await s.DeletePermissionAsync(Client(me), name, ct);
            return Results.NoContent();
        });
        api.MapPost("/roles", (ClaimsPrincipal me, RoleInput input, AccessService s, CancellationToken ct) =>
            s.AddRoleAsync(Client(me), input.Name, input.Description, input.Permissions, ct, input.Requestable, input.DisplayName));
        api.MapPut("/roles/{name}", (ClaimsPrincipal me, string name, RoleUpdateInput input, AccessService s, CancellationToken ct) =>
            s.UpdateRoleAsync(Client(me), name, input.DisplayName, input.Description, ct));
        api.MapPut("/roles/{name}/requestable", async (ClaimsPrincipal me, string name, bool value, AccessService s, CancellationToken ct) =>
        {
            await s.SetRoleRequestableAsync(Client(me), name, value, ct);
            return Results.NoContent();
        });

        // ---------- Заявки на роли этого приложения ----------
        // Client(me) передаётся в DecideAsync как ограничение: решать можно только заявки на роли своего приложения.
        api.MapGet("/access-requests", (ClaimsPrincipal me, string? status, AccessRequestService s, CancellationToken ct) =>
            s.ListAsync(AdminApi.ParseStatus(status), Client(me), ct: ct));
        api.MapPost("/access-requests/{id:guid}/approve", (ClaimsPrincipal me, Guid id, DecisionInput? input, AccessRequestService s,
            CancellationToken ct) => s.DecideAsync(id, true, AdminApi.Caller(me), input?.Comment, Client(me), ct));
        api.MapPost("/access-requests/{id:guid}/reject", (ClaimsPrincipal me, Guid id, DecisionInput? input, AccessRequestService s,
            CancellationToken ct) => s.DecideAsync(id, false, AdminApi.Caller(me), input?.Comment, Client(me), ct));
        api.MapPut("/roles/{name}/permissions", async (ClaimsPrincipal me, string name, List<string> permissions, AccessService s,
            CancellationToken ct) =>
        {
            await s.SetRolePermissionsAsync(Client(me), name, permissions, ct);
            return Results.NoContent();
        });
        api.MapDelete("/roles/{name}", async (ClaimsPrincipal me, string name, AccessService s, CancellationToken ct) =>
        {
            await s.DeleteRoleAsync(Client(me), name, ct);
            return Results.NoContent();
        });

        // ---------- Пользователи своего среза ----------
        // «Срез» — пользователи, созданные этим приложением или имеющие в нём роли. Пользователи общие
        // для всей системы, поэтому менять профиль/пароль можно только у созданных этим приложением,
        // а у остальных — лишь свои роли. /link — выдать роли уже существующему пользователю по логину.
        var users = api.MapGroup("/users");
        // Ответ — массив (как раньше), общее число — в заголовке X-Total-Count; skip/take — постраничная выборка.
        users.MapGet("/", async (ClaimsPrincipal me, int? skip, int? take, HttpResponse response, AppSelfService s, CancellationToken ct) =>
        {
            var page = await s.ListUsersAsync(Client(me), skip ?? 0, take ?? 500, ct);
            response.Headers["X-Total-Count"] = page.Total.ToString();
            return page.Items;
        });
        users.MapGet("/{id:guid}", (ClaimsPrincipal me, Guid id, AppSelfService s, CancellationToken ct) => s.GetUserAsync(Client(me), id, ct));
        users.MapPost("/", async (ClaimsPrincipal me, AppUserInput input, AppSelfService s, CancellationToken ct) =>
        {
            var (user, invite, temporaryPassword) = await s.CreateUserAsync(Client(me), input, ct);
            return Results.Created($"/api/app/users/{user.Id}", new { user, invite, temporaryPassword });
        });
        users.MapPost("/link", (ClaimsPrincipal me, AppUserLinkInput input, AppSelfService s, CancellationToken ct) =>
            s.LinkUserAsync(Client(me), input, ct));
        users.MapPut("/{id:guid}", (ClaimsPrincipal me, Guid id, AppUserInput input, AppSelfService s, CancellationToken ct) =>
            s.UpdateUserAsync(Client(me), id, input, ct));
        users.MapPut("/{id:guid}/roles", (ClaimsPrincipal me, Guid id, List<string> roles, AppSelfService s, CancellationToken ct) =>
            s.SetUserRolesAsync(Client(me), id, roles, ct));
        users.MapDelete("/{id:guid}", (ClaimsPrincipal me, Guid id, AppSelfService s, CancellationToken ct) =>
            s.DeleteUserAsync(Client(me), id, ct));
        users.MapPost("/{id:guid}/temporary-password", async (ClaimsPrincipal me, Guid id, AppSelfService s, CancellationToken ct) =>
            Results.Ok(new { password = await s.SetTemporaryPasswordAsync(Client(me), id, ct), mustChangePassword = true }));
        users.MapPost("/{id:guid}/invite", (ClaimsPrincipal me, Guid id, bool? sendEmail, AppSelfService s, CancellationToken ct) =>
            s.InviteAsync(Client(me), id, sendEmail ?? true, ct));
    }

    private static string Client(ClaimsPrincipal principal) => principal.GetClaim(Claims.Subject)!;

}

/// <summary>Требование политики App API; проверяется <see cref="AppSelfHandler"/>.</summary>
public sealed class AppSelfRequirement : IAuthorizationRequirement;

/// <summary>Самоуправление должно быть включено для приложения на момент запроса (проверка по БД).</summary>
public sealed class AppSelfHandler(ApplicationService apps) : AuthorizationHandler<AppSelfRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AppSelfRequirement requirement)
    {
        var clientId = context.User.GetClaim(Claims.Subject);
        // Системное приложение исключено (у него есть полноценный Admin API); флаг читается из БД на каждый
        // запрос, чтобы выключение самоуправления действовало сразу, не дожидаясь истечения токенов.
        if (clientId is not null && clientId != SystemApp.ClientId &&
            context.User.GetAudiences().Contains(SystemApp.AppApiScope) &&
            await apps.IsSelfManagementEnabledAsync(clientId))
        {
            context.Succeed(requirement);
        }
    }
}
