using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Validation.AspNetCore;
using TslAuth.Data;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Infrastructure;

/// <summary>
/// Политики авторизации админки (Ui*, cookie-вход) и Admin/Events API (Api*, bearer-токен OpenIddict).
/// Регистрируются в ServiceSetup; права берутся из матрицы доступа системного приложения tsl-auth-admin.
/// </summary>
public static class AdminPolicies
{
    public const string UiView = "admin-ui-view";
    public const string UiManage = "admin-ui-manage";
    public const string UiEvents = "admin-ui-events";
    public const string ApiView = "admin-api-view";
    public const string ApiManage = "admin-api-manage";
    public const string ApiEvents = "admin-api-events";

    /// <summary>Регистрирует все политики админки в опциях авторизации.</summary>
    public static void Register(AuthorizationOptions options)
    {
        // manage подразумевает view (и events): достаточно любого из разрешений.
        var view = new AdminPermissionRequirement(SystemApp.ViewPermission, SystemApp.ManagePermission);
        var manage = new AdminPermissionRequirement(SystemApp.ManagePermission);

        options.AddPolicy(UiView, p => p.RequireAuthenticatedUser().AddRequirements(view));
        options.AddPolicy(UiManage, p => p.RequireAuthenticatedUser().AddRequirements(manage));

        // API-политики явно используют схему валидации OpenIddict: cookie админки для API не принимается.
        const string bearer = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
        options.AddPolicy(ApiView, p => p.AddAuthenticationSchemes(bearer).RequireAuthenticatedUser().AddRequirements(view));
        options.AddPolicy(ApiManage, p => p.AddAuthenticationSchemes(bearer).RequireAuthenticatedUser().AddRequirements(manage));
        options.AddPolicy(ApiEvents, p => p.AddAuthenticationSchemes(bearer).RequireAuthenticatedUser()
            .AddRequirements(new AdminPermissionRequirement(SystemApp.EventsPermission, SystemApp.ManagePermission)));
        options.AddPolicy(UiEvents, p => p.RequireAuthenticatedUser()
            .AddRequirements(new AdminPermissionRequirement(SystemApp.EventsPermission, SystemApp.ManagePermission)));
    }
}

/// <summary>Требуется любое из перечисленных разрешений системного приложения.</summary>
public sealed class AdminPermissionRequirement(params string[] anyOf) : IAuthorizationRequirement
{
    public IReadOnlyList<string> AnyOf { get; } = anyOf;
}

/// <summary>
/// Права проверяются по БД на каждый запрос, а не по claims токена/cookie:
/// снятие роли администратора действует немедленно.
/// </summary>
public sealed class AdminPermissionHandler(AccessService access) : AuthorizationHandler<AdminPermissionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminPermissionRequirement requirement)
    {
        var (type, id) = GetSubject(context.User);
        if (id is null) return;

        foreach (var permission in requirement.AnyOf)
        {
            if (await access.HasPermissionAsync(type, id, SystemApp.ClientId, permission))
            {
                context.Succeed(requirement);
                return;
            }
        }
    }

    /// <summary>
    /// Определяет субъект: клиент (токен client_credentials с claim типа субъекта) или пользователь
    /// (cookie — NameIdentifier, токен — sub).
    /// </summary>
    public static (SubjectType Type, string? Id) GetSubject(ClaimsPrincipal user)
    {
        if (user.FindFirstValue(CustomClaims.SubjectType) == "client")
            return (SubjectType.Client, user.FindFirstValue(Claims.Subject));

        return (SubjectType.User, user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue(Claims.Subject));
    }
}
