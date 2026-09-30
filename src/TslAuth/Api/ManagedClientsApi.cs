using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Api;

/// <summary>
/// App API подчинённых клиентов: <c>/api/app/clients*</c>. Отдельная группа со своей политикой
/// <see cref="Policy"/>: чтение — сервисный токен владельца (client_credentials, aud tsl-auth-app) или делегированный;
/// изменения — только делегированный токен оператора (token exchange: <c>sub</c> = пользователь, <c>act.sub</c> = владелец,
/// <c>aud</c> содержит tsl-auth-app) с разрешением <c>managePermission</c> политики в матрице владелца — проверка по БД
/// на каждый запрос. <c>requireDelegation=false</c> в политике разрешает сервисный токен и для изменений (тестовые стенды).
/// Владелец всегда берётся из токена, не из URL; чужой клиент — 404. Лимит изменений — 30 в минуту на владельца.
/// </summary>
public static class ManagedClientsApi
{
    public const string Policy = "app-managed-clients";

    /// <summary>Регистрирует политику авторизации группы /api/app/clients.</summary>
    public static void AddManagedClientsPolicy(AuthorizationOptions options) =>
        options.AddPolicy(Policy, p => p
            .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .AddRequirements(new ManagedClientsRequirement()));

    /// <summary>Регистрирует маршруты /api/app/clients*.</summary>
    public static void MapManagedClientsApi(this IEndpointRouteBuilder endpoints)
    {
        var api = endpoints.MapGroup("/api/app/clients")
            .RequireAuthorization(Policy)
            .AddEndpointFilter(ApiErrors.Handle)
            .AddEndpointFilter<ManagedClientRateLimitFilter>()
            .WithTags("App (managed clients)");

        api.MapGet("/", (ClaimsPrincipal me, ManagedClientService s, CancellationToken ct) => s.ListAsync(Owner(me), ct));
        api.MapPost("/", async (ClaimsPrincipal me, ManagedClientInput input, ManagedClientService s, CancellationToken ct) =>
        {
            var created = await s.CreateAsync(Owner(me), input, Via(me), ct);
            return Results.Created($"/api/app/clients/{created.Client.ClientId}", created);
        });
        api.MapGet("/{clientId}", (ClaimsPrincipal me, string clientId, ManagedClientService s, CancellationToken ct) =>
            s.GetAsync(Owner(me), clientId, ct));
        api.MapPut("/{clientId}/keys", (ClaimsPrincipal me, string clientId, ManagedClientKeysInput input, ManagedClientService s,
            CancellationToken ct) => s.SetKeysAsync(Owner(me), clientId, input.Jwks, Via(me), ct));
        api.MapPost("/{clientId}/disable", (ClaimsPrincipal me, string clientId, ManagedClientService s, CancellationToken ct) =>
            s.SetDisabledAsync(Owner(me), clientId, true, Via(me), ct));
        api.MapPost("/{clientId}/enable", (ClaimsPrincipal me, string clientId, ManagedClientService s, CancellationToken ct) =>
            s.SetDisabledAsync(Owner(me), clientId, false, Via(me), ct));
        api.MapPost("/{clientId}/secret", async (ClaimsPrincipal me, string clientId, ManagedClientService s, CancellationToken ct) =>
            Results.Ok(new { clientSecret = await s.NewSecretAsync(Owner(me), clientId, Via(me), ct) }));
        api.MapDelete("/{clientId}", async (ClaimsPrincipal me, string clientId, ManagedClientService s, CancellationToken ct) =>
        {
            await s.DeleteAsync(Owner(me), clientId, Via(me), ct);
            return Results.NoContent();
        });
    }

    /// <summary>
    /// Владелец: для сервисного токена — сам клиент (<c>sub</c>), для делегированного — непосредственный актор
    /// (<c>act.sub</c>, RFC 8693). Наличие гарантирует политика; null — токен не подходит.
    /// </summary>
    public static string? OwnerOf(ClaimsPrincipal me)
    {
        // Токен клиента — только собственный токен владельца (client_credentials). Клиентский токен, полученный
        // обменом (есть act), выпущен для другого приложения-актора и владельцем не является: иначе приложение B,
        // обменяв сервисный токен A, действовало бы от имени A.
        if (me.GetClaim(CustomClaims.SubjectType) == "client")
            return me.GetClaim(CustomClaims.Actor) is { Length: > 0 } ? null : me.GetClaim(Claims.Subject);
        if (me.GetClaim(CustomClaims.Actor) is not { Length: > 0 } actor) return null;
        try
        {
            using var json = JsonDocument.Parse(actor);
            return json.RootElement.TryGetProperty(Claims.Subject, out var sub) && sub.ValueKind == JsonValueKind.String ? sub.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Owner(ClaimsPrincipal me) => OwnerOf(me)!;

    /// <summary>«Через кого» для аудита: у делегированного токена — владелец-актор; у сервисного — пусто.</summary>
    private static string? Via(ClaimsPrincipal me) => me.GetClaim(CustomClaims.SubjectType) == "client" ? null : OwnerOf(me);
}

/// <summary>Требование политики подчинённых клиентов; проверяется <see cref="ManagedClientsHandler"/>.</summary>
public sealed class ManagedClientsRequirement : IAuthorizationRequirement;

/// <summary>
/// Проверка доступа к /api/app/clients по БД на каждый запрос: политика подчинённых у владельца включена;
/// сервисный токен владельца — чтение (изменения — только при requireDelegation=false); делегированный токен
/// пользователя — активный пользователь с разрешением managePermission в матрице владельца.
/// </summary>
public sealed class ManagedClientsHandler(ManagedClientService managed, AccessService access, ApplicationService apps)
    : AuthorizationHandler<ManagedClientsRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, ManagedClientsRequirement requirement)
    {
        var user = context.User;
        if (!user.GetAudiences().Contains(SystemApp.AppApiScope)) return;
        var owner = ManagedClientsApi.OwnerOf(user);
        if (owner is null || owner == SystemApp.ClientId) return;
        var policy = await managed.GetPolicyAsync(owner);
        // Как и остальной App API: без включённого самоуправления владельца доступа нет (флаг читается из БД —
        // его снятие действует сразу, а не по истечении выданных токенов).
        if (policy is null || !await apps.IsSelfManagementEnabledAsync(owner)) return;

        var http = context.Resource as HttpContext;
        var read = http is null || HttpMethods.IsGet(http.Request.Method);

        if (user.GetClaim(CustomClaims.SubjectType) == "client")
        {
            if (read || !policy.RequireDelegation) context.Succeed(requirement);
            return;
        }

        // Делегированный токен: права оператора проверяются по матрице владельца (не по claims токена).
        var userId = user.GetClaim(Claims.Subject);
        if (userId is not null && await access.HasPermissionAsync(SubjectType.User, userId, owner, policy.ManagePermission))
            context.Succeed(requirement);
    }
}

/// <summary>Лимит изменений подчинённых на владельца (GET не считается); превышение — 429.</summary>
public sealed class ManagedClientRateLimitFilter(ManagedClientRateLimiter limiter) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        if (HttpMethods.IsGet(http.Request.Method)) return await next(context);
        var owner = ManagedClientsApi.OwnerOf(http.User) ?? "";
        using var lease = await limiter.AcquireAsync(owner, http.RequestAborted);
        if (!lease.IsAcquired)
            return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests,
                title: "Слишком много изменений подчинённых клиентов: подождите минуту.");
        return await next(context);
    }
}
