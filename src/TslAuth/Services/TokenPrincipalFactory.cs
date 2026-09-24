using System.Collections.Immutable;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using TslAuth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Services;

/// <summary>
/// Формирует набор claims для токенов. Роли и разрешения читаются из матрицы доступа
/// при каждой выдаче (в т.ч. при refresh), поэтому изменения прав применяются без повторного входа.
/// Используется только AuthorizationController (authorization_code, password, refresh, client_credentials,
/// token exchange, PAT). Роли кладутся в токен как "client_id:role", плюс resource_access в стиле Keycloak.
/// </summary>
public sealed class TokenPrincipalFactory(IOpenIddictScopeManager scopes, AccessService access)
{
    /// <summary>Claims для токена пользователя: профиль, email (при scope email) и роли/разрешения.</summary>
    /// <param name="audiences">Явный список аудиторий (для PAT); по умолчанию — клиент + ресурсы запрошенных scope.</param>
    public async Task<ClaimsIdentity> CreateForUserAsync(AppUser user, string clientId, ImmutableArray<string> requestedScopes,
        CancellationToken ct = default, IReadOnlyCollection<string>? audiences = null)
    {
        var identity = NewIdentity();
        identity.SetClaim(Claims.Subject, user.Id.ToString())
            .SetClaim(Claims.Name, user.DisplayName ?? user.UserName)
            .SetClaim(Claims.PreferredUsername, user.UserName)
            .SetClaim(CustomClaims.SubjectType, "user");

        if (requestedScopes.Contains(Scopes.Email) && user.Email is not null)
        {
            identity.SetClaim(Claims.Email, user.Email);
            identity.SetClaim(Claims.EmailVerified, user.EmailConfirmed);
        }

        await AddAccessAsync(identity, SubjectType.User, user.Id.ToString(), clientId, requestedScopes, ct, audiences);
        return identity;
    }

    /// <summary>Claims для токена сервиса (client_credentials / token exchange от имени клиента).</summary>
    /// <param name="subjectClientId">Клиент — субъект токена (сервисная учётная запись).</param>
    /// <param name="requestingClientId">Кто запрашивает токен (отличается при token exchange).</param>
    public async Task<ClaimsIdentity> CreateForClientAsync(string subjectClientId, string? displayName, ImmutableArray<string> requestedScopes,
        string? requestingClientId = null, CancellationToken ct = default)
    {
        var identity = NewIdentity();
        identity.SetClaim(Claims.Subject, subjectClientId)
            .SetClaim(Claims.Name, displayName ?? subjectClientId)
            .SetClaim(CustomClaims.SubjectType, "client");

        await AddAccessAsync(identity, SubjectType.Client, subjectClientId, requestingClientId ?? subjectClientId, requestedScopes, ct);
        return identity;
    }

    /// <summary>
    /// RFC 8693: отмечает, что токен получен обменом. Цепочка сохраняется вложенными "act"
    /// (например, web → orders-api → billing-api).
    /// </summary>
    public static void AddActor(ClaimsIdentity identity, string actorClientId, string? previousActorJson)
    {
        var actor = new Dictionary<string, object> { [Claims.Subject] = actorClientId };
        if (!string.IsNullOrEmpty(previousActorJson))
            actor[CustomClaims.Actor] = JsonSerializer.Deserialize<JsonElement>(previousActorJson);

        var claim = new Claim(CustomClaims.Actor, JsonSerializer.Serialize(actor), JsonClaimValueTypes.Json);
        claim.SetDestinations(Destinations.AccessToken);
        identity.AddClaim(claim);
    }

    // Явно задаём типы claims имени и роли, чтобы IsInRole/Identity.Name работали с OIDC-claims (name, role).
    private static ClaimsIdentity NewIdentity() =>
        new(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

    private async Task AddAccessAsync(ClaimsIdentity identity, SubjectType type, string subjectId, string clientId,
        ImmutableArray<string> requestedScopes, CancellationToken ct, IReadOnlyCollection<string>? explicitAudiences = null)
    {
        identity.SetScopes(requestedScopes);

        // Аудитория токена: сам клиент + приложения, чьи scope были запрошены (или явный список для PAT).
        var audiences = new SortedSet<string>(StringComparer.Ordinal);
        if (explicitAudiences is not null)
        {
            // PAT: список приложений задан при выпуске, но в токен попадают только те, где у владельца есть роли
            // сейчас — снятые с тех пор права не должны оставлять JWT адресованным этому приложению.
            var current = await access.GetGrantsAsync(type, subjectId, explicitAudiences, ct);
            audiences.UnionWith(current.Where(g => g.Value.Roles.Count > 0).Select(g => g.Key));
        }
        else
        {
            audiences.Add(clientId);
            await foreach (var resource in scopes.ListResourcesAsync(requestedScopes, ct))
                audiences.Add(resource);
        }
        identity.SetResources(audiences);

        // Роли берутся только по приложениям-аудиториям: токен не раскрывает права в посторонних системах
        // и остаётся компактным.
        var grants = await access.GetGrantsAsync(type, subjectId, audiences, ct);

        identity.SetClaims(Claims.Role, grants.SelectMany(g => g.Value.Roles.Select(r => $"{g.Key}:{r}")).ToImmutableArray());
        identity.SetClaims(CustomClaims.Permissions, grants.SelectMany(g => g.Value.Permissions.Select(p => $"{g.Key}:{p}")).ToImmutableArray());

        if (grants.Count > 0)
        {
            var resourceAccess = grants.ToDictionary(g => g.Key, g => new { roles = g.Value.Roles, permissions = g.Value.Permissions });
            identity.AddClaim(new Claim(CustomClaims.ResourceAccess, JsonSerializer.Serialize(resourceAccess), JsonClaimValueTypes.Json));
        }

        identity.SetDestinations(claim => GetDestinations(claim, requestedScopes));
    }

    // Куда попадает claim: в access token — почти всё; в id_token — только при соответствующем scope
    // (profile/email/roles), как требует OIDC. Security stamp — служебный claim Identity, наружу не отдаётся.
    private static IEnumerable<string> GetDestinations(Claim claim, ImmutableArray<string> scopes)
    {
        switch (claim.Type)
        {
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;
                if (scopes.Contains(Scopes.Profile)) yield return Destinations.IdentityToken;
                yield break;

            case Claims.Email or Claims.EmailVerified:
                yield return Destinations.AccessToken;
                if (scopes.Contains(Scopes.Email)) yield return Destinations.IdentityToken;
                yield break;

            case Claims.Role or CustomClaims.Permissions or CustomClaims.ResourceAccess:
                yield return Destinations.AccessToken;
                if (scopes.Contains(Scopes.Roles)) yield return Destinations.IdentityToken;
                yield break;

            case CustomClaims.SubjectType:
                yield return Destinations.AccessToken;
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
