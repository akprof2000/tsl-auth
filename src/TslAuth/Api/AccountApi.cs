using System.Security.Claims;
using OpenIddict.Validation.AspNetCore;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Api;

/// <summary>Параметры выпуска своего токена: можно ли, приложения с ролями пользователя, сроки по политике.</summary>
public sealed record AccountTokenOptions(bool CanIssue, int MaxLifetimeDays, int DefaultLifetimeDays, List<AccountTokenApp> Applications);

/// <summary>Приложение, к которому может давать доступ токен пользователя.</summary>
public sealed record AccountTokenApp(string ClientId, string DisplayName);

/// <summary>Выпущенный токен: метаданные и сам секрет (показывается один раз).</summary>
public sealed record AccountTokenCreated(PatDto Token, string Secret);

/// <summary>
/// Самообслуживание персональных токенов (PAT) из интерфейсов ERP: пользователь своим access-токеном (Bearer, audience
/// tsl-auth-admin — его запрашивает оболочка) смотрит, выпускает и отзывает только свои токены. Право выпуска задаёт
/// политика PAT (<see cref="PatPolicy.RequiredPermission"/>) — обычно роль «Доступ по API»; проверка — в PatService.
/// Аналог страницы Account/Tokens для одностраничных приложений. Токены клиентов (subject_type=client) не принимаются.
/// </summary>
public static class AccountApi
{
    public const string Policy = "account-api";

    /// <summary>Регистрирует маршруты /api/account/*.</summary>
    public static void MapAccountApi(this IEndpointRouteBuilder endpoints)
    {
        var api = endpoints.MapGroup("/api/account")
            .RequireAuthorization(Policy)
            .AddEndpointFilter(ApiErrors.Handle)
            .AddEndpointFilter(new ApiAuditFilter(AuditTypes.AdminChange))
            .WithTags("Account");

        api.MapGet("/tokens/options", async (ClaimsPrincipal me, PatService pats, SettingsService settings, ApplicationService apps,
            CancellationToken ct) =>
        {
            var userId = UserId(me);
            var policy = (await settings.GetAsync(ct)).Pats;
            var names = (await apps.ListAsync(ct)).ToDictionary(a => a.ClientId, a => a.DisplayName ?? a.ClientId);
            var audiences = await pats.AvailableAudiencesAsync(userId, ct);
            return new AccountTokenOptions(await pats.CanIssueAsync(userId, ct), policy.MaxLifetimeDays,
                Math.Min(90, policy.MaxLifetimeDays),
                audiences.Select(a => new AccountTokenApp(a, names.GetValueOrDefault(a, a))).ToList());
        });
        api.MapGet("/tokens", (ClaimsPrincipal me, PatService pats, CancellationToken ct) => pats.ListAsync(UserId(me), ct));
        api.MapPost("/tokens", async (PatInput input, ClaimsPrincipal me, PatService pats, CancellationToken ct) =>
        {
            // Токен подключения сервиса-робота — только на странице Account/Tokens; здесь — токен для скриптов и интеграций.
            var (token, secret) = await pats.CreateAsync(UserId(me), input with { ClientId = null }, ct);
            return Results.Created($"/api/account/tokens/{token.Id}", new AccountTokenCreated(token, secret));
        });
        api.MapDelete("/tokens/{tokenId:guid}", async (Guid tokenId, ClaimsPrincipal me, PatService pats, CancellationToken ct) =>
        {
            await pats.RevokeAsync(tokenId, UserId(me), ct);
            return Results.NoContent();
        });
    }

    /// <summary>Политика: Bearer-токен OpenIddict пользователя (не клиента).</summary>
    public static void Register(Microsoft.AspNetCore.Authorization.AuthorizationOptions options) =>
        options.AddPolicy(Policy, p => p
            .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireAssertion(c => c.User.FindFirst(CustomClaims.SubjectType)?.Value == "user"
                                   && Guid.TryParse(c.User.FindFirst(Claims.Subject)?.Value, out _)));

    private static Guid UserId(ClaimsPrincipal me) => Guid.Parse(me.FindFirst(Claims.Subject)!.Value);
}
