using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using TslAuth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Services;

/// <summary>Поддерживаемые grant types OAuth2 (значения, которые можно разрешить клиенту в настройках приложения).</summary>
public static class AppGrantTypes
{
    public const string AuthorizationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string Password = "password";
    public const string RefreshToken = "refresh_token";

    /// <summary>RFC 8693 — обмен токена пользователя на токен для другого приложения.</summary>
    public const string TokenExchange = GrantTypes.TokenExchange;

    public static readonly string[] All = [AuthorizationCode, ClientCredentials, Password, RefreshToken, TokenExchange];
}

/// <summary>Приложение (клиент OpenIddict) в удобном для UI/API виде: grant types и scopes извлечены из permissions.</summary>
public sealed record ApplicationDto(
    string ClientId,
    string? DisplayName,
    string ClientType,
    List<string> RedirectUris,
    List<string> PostLogoutRedirectUris,
    List<string> GrantTypes,
    List<string> Scopes,
    bool IsSystem,
    bool SelfManagement,
    bool SelfRegistration);

/// <summary>Входные данные для создания/изменения приложения (Admin API и страница Admin/Apps/Edit).</summary>
/// <param name="SelfManagement">
/// Разрешить приложению через App API (/api/app) управлять своими пользователями, ролями и матрицей.
/// Требует confidential-клиента; client_credentials и scope tsl-auth-app добавляются автоматически.
/// </param>
/// <param name="SelfRegistration">На странице входа приложения доступна самостоятельная регистрация с запросом ролей.</param>
public sealed record ApplicationInput(
    string ClientId,
    string? DisplayName,
    string ClientType,
    List<string>? RedirectUris,
    List<string>? PostLogoutRedirectUris,
    List<string>? GrantTypes,
    List<string>? Scopes,
    bool SelfManagement = false,
    bool SelfRegistration = false);

/// <summary>Результат создания/изменения: <c>ClientSecret</c> заполнен только когда секрет сгенерирован сейчас (показывается один раз).</summary>
public sealed record ApplicationSecretResult(ApplicationDto Application, string? ClientSecret);

/// <summary>
/// Регистрация клиентов OAuth2/OIDC (обёртка над хранилищем OpenIddict).
/// Переводит «человеческие» настройки (тип клиента, grant types, scopes) в permissions/requirements OpenIddict,
/// для каждого приложения заводит одноимённый scope-ресурс, при удалении чистит сессии и RBAC.
/// Используется Admin API, App API, страницами Admin/Apps и StartupInitializer (системное приложение).
/// Доп. флаги (системное, App API, саморегистрация) хранятся в Properties приложения OpenIddict.
/// </summary>
public sealed class ApplicationService(
    IOpenIddictApplicationManager applications,
    IOpenIddictScopeManager scopes,
    AccessService access,
    SessionService sessions,
    WebhookService webhooks)
{
    private const string SystemProperty = "tsl_system";
    private const string SelfManagementProperty = "tsl_self_management";
    private const string SelfRegistrationProperty = "tsl_self_registration";

    /// <summary>Стандартные scope OIDC, которые можно разрешать клиентам в дополнение к scope приложений.</summary>
    public static readonly string[] StandardScopes = [Scopes.Profile, Scopes.Email, Scopes.Roles];

    /// <summary>Все приложения; системное — первым.</summary>
    public async Task<List<ApplicationDto>> ListAsync(CancellationToken ct = default)
    {
        var result = new List<ApplicationDto>();
        await foreach (var app in applications.ListAsync(null, null, ct))
            result.Add(await ToDtoAsync(app, ct));
        return result.OrderBy(a => a.IsSystem ? 0 : 1).ThenBy(a => a.ClientId).ToList();
    }

    public async Task<ApplicationDto?> GetAsync(string clientId, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct);
        return app is null ? null : await ToDtoAsync(app, ct);
    }

    /// <summary>Все scope, доступные для назначения клиентам (стандартные + scope зарегистрированных приложений).</summary>
    public async Task<List<string>> ListAvailableScopesAsync(CancellationToken ct = default)
    {
        var result = new List<string>(StandardScopes);
        await foreach (var scope in scopes.ListAsync(null, null, ct))
            if (await scopes.GetNameAsync(scope, ct) is { } name && !result.Contains(name))
                result.Add(name);
        return result;
    }

    /// <summary>
    /// Регистрирует приложение. Для confidential-клиента генерирует секрет (или использует переданный —
    /// так StartupInitializer задаёт секрет из конфигурации).
    /// </summary>
    public async Task<ApplicationSecretResult> CreateAsync(ApplicationInput input, bool isSystem = false, string? secret = null,
        CancellationToken ct = default)
    {
        var clientId = Names.Validate(input.ClientId, "client_id");
        if (await applications.FindByClientIdAsync(clientId, ct) is not null)
            throw AdminException.Conflict($"Приложение '{clientId}' уже существует.");

        var descriptor = new OpenIddictApplicationDescriptor { ClientId = clientId };
        if (isSystem) descriptor.Properties[SystemProperty] = JsonSerializer.SerializeToElement(true);

        var confidential = Apply(descriptor, input);
        if (confidential) descriptor.ClientSecret = secret ??= GenerateSecret();
        else secret = null;

        // OpenIddict сохраняет только хэш секрета — открытое значение возвращаем вызывающему единственный раз.
        await applications.CreateAsync(descriptor, ct);

        // Каждое приложение одновременно является ресурсом (API): scope = client_id, audience = client_id.
        if (await scopes.FindByNameAsync(clientId, ct) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = clientId,
                DisplayName = input.DisplayName ?? clientId,
                Resources = { clientId }
            }, ct);
        }

        await webhooks.PublishAsync(WebhookEvents.ApplicationCreated, $"🧩 Зарегистрировано приложение {clientId}.",
            new { clientId, displayName = input.DisplayName }, ct);
        return new ApplicationSecretResult((await GetAsync(clientId, ct))!, secret);
    }

    /// <summary>Изменяет настройки приложения; client_id неизменяем. Системное приложение защищено от изменений.</summary>
    public async Task<ApplicationSecretResult> UpdateAsync(string clientId, ApplicationInput input, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        if (IsSystem(await applications.GetPropertiesAsync(app, ct)))
            throw new AdminException("Настройки системного приложения изменить нельзя.");

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, app, ct);
        var wasConfidential = descriptor.ClientType == ClientTypes.Confidential;

        var confidential = Apply(descriptor, input with { ClientId = clientId });
        // Секрет генерируется только при переходе public → confidential; существующий секрет не трогаем,
        // а при переходе в public — удаляем, чтобы старый секрет не продолжал работать.
        string? secret = null;
        if (confidential && !wasConfidential) descriptor.ClientSecret = secret = GenerateSecret();
        if (!confidential) descriptor.ClientSecret = null;

        await applications.UpdateAsync(app, descriptor, ct);

        // Синхронизируем отображаемое имя scope-ресурса с именем приложения.
        var scope = await scopes.FindByNameAsync(clientId, ct);
        if (scope is not null && input.DisplayName is not null)
        {
            var scopeDescriptor = new OpenIddictScopeDescriptor();
            await scopes.PopulateAsync(scopeDescriptor, scope, ct);
            scopeDescriptor.DisplayName = input.DisplayName;
            await scopes.UpdateAsync(scope, scopeDescriptor, ct);
        }

        return new ApplicationSecretResult((await GetAsync(clientId, ct))!, secret);
    }

    /// <summary>Генерирует новый секрет confidential-клиента; старый перестаёт действовать сразу.</summary>
    public async Task<string> RegenerateSecretAsync(string clientId, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        if (!await applications.HasClientTypeAsync(app, ClientTypes.Confidential, ct))
            throw new AdminException("Секрет есть только у confidential-клиентов.");

        var secret = GenerateSecret();
        await applications.UpdateAsync(app, secret, ct);
        return secret;
    }

    /// <summary>Удаляет приложение вместе с его токенами/сессиями, scope-ресурсом и RBAC-конфигурацией.</summary>
    public async Task DeleteAsync(string clientId, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        if (IsSystem(await applications.GetPropertiesAsync(app, ct)))
            throw new AdminException("Системное приложение нельзя удалить.");

        // Сначала отзываем выданные токены, пока приложение ещё существует и связи с ним можно найти.
        await sessions.RevokeByClientAsync(clientId, ct);
        await applications.DeleteAsync(app, ct);
        if (await scopes.FindByNameAsync(clientId, ct) is { } scope)
            await scopes.DeleteAsync(scope, ct);
        await access.RemoveApplicationAsync(clientId, ct);
        await webhooks.PublishAsync(WebhookEvents.ApplicationDeleted, $"🗑 Удалено приложение {clientId}.", new { clientId }, ct);
    }

    /// <summary>Переносит входные настройки в дескриптор OpenIddict (permissions, requirements, URI, флаги) с валидацией.</summary>
    /// <returns>true, если клиент confidential.</returns>
    private static bool Apply(OpenIddictApplicationDescriptor d, ApplicationInput input)
    {
        var confidential = (input.ClientType ?? "").Trim().ToLowerInvariant() switch
        {
            ClientTypes.Confidential => true,
            ClientTypes.Public => false,
            _ => throw new AdminException("ClientType должен быть 'public' или 'confidential'.")
        };

        // "token_exchange" — короткий алиас для полного URN RFC 8693.
        // openid и offline_access не хранятся как permissions: OpenIddict обрабатывает их особым образом.
        var grants = (input.GrantTypes ?? []).Select(g => g.Trim()).Where(g => g.Length > 0)
            .Select(g => g == "token_exchange" ? AppGrantTypes.TokenExchange : g).Distinct().ToList();
        var scopes = (input.Scopes ?? []).Select(s => s.Trim())
            .Where(s => s.Length > 0 && s != Scopes.OpenId && s != Scopes.OfflineAccess).Distinct().ToList();

        if (input.SelfManagement)
        {
            if (!confidential) throw new AdminException("Самоуправление (App API) доступно только confidential-клиентам.");
            if (!grants.Contains(AppGrantTypes.ClientCredentials)) grants.Add(AppGrantTypes.ClientCredentials);
            if (!scopes.Contains(SystemApp.AppApiScope)) scopes.Add(SystemApp.AppApiScope);
        }
        else
        {
            // Без флага доступ к App API не выдаётся, даже если scope передали вручную.
            scopes.Remove(SystemApp.AppApiScope);
        }

        var unknown = grants.Except(AppGrantTypes.All).ToList();
        if (unknown.Count > 0) throw new AdminException($"Неизвестные grant types: {string.Join(", ", unknown)}.");
        // Public-клиент не может хранить секрет, поэтому не должен получать токены «от своего имени».
        if (!confidential && (grants.Contains(AppGrantTypes.ClientCredentials) || grants.Contains(AppGrantTypes.TokenExchange)))
            throw new AdminException("client_credentials и token exchange доступны только confidential-клиентам.");

        if (input.SelfManagement) d.Properties[SelfManagementProperty] = JsonSerializer.SerializeToElement(true);
        else d.Properties.Remove(SelfManagementProperty);
        if (input.SelfRegistration) d.Properties[SelfRegistrationProperty] = JsonSerializer.SerializeToElement(true);
        else d.Properties.Remove(SelfRegistrationProperty);

        d.DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? input.ClientId : input.DisplayName.Trim();
        d.ClientType = confidential ? ClientTypes.Confidential : ClientTypes.Public;
        // Все клиенты — доверенные (регистрирует администратор), экран согласия не показываем.
        d.ConsentType = ConsentTypes.Implicit;

        d.RedirectUris.Clear();
        foreach (var uri in ParseUris(input.RedirectUris)) d.RedirectUris.Add(uri);
        d.PostLogoutRedirectUris.Clear();
        foreach (var uri in ParseUris(input.PostLogoutRedirectUris)) d.PostLogoutRedirectUris.Add(uri);

        if (grants.Contains(AppGrantTypes.AuthorizationCode) && d.RedirectUris.Count == 0)
            throw new AdminException("Для authorization_code необходим хотя бы один Redirect URI.");

        // Permissions пересобираются с нуля по принципу минимальных прав: только то, что нужно для выбранных grant types.
        d.Permissions.Clear();
        d.Requirements.Clear();
        d.Permissions.Add(Permissions.Endpoints.Revocation);
        if (confidential) d.Permissions.Add(Permissions.Endpoints.Introspection);
        if (grants.Count > 0) d.Permissions.Add(Permissions.Endpoints.Token);

        foreach (var grant in grants)
        {
            d.Permissions.Add(Permissions.Prefixes.GrantType + grant);
            if (grant == AppGrantTypes.AuthorizationCode)
            {
                d.Permissions.Add(Permissions.Endpoints.Authorization);
                d.Permissions.Add(Permissions.Endpoints.EndSession);
                d.Permissions.Add(Permissions.ResponseTypes.Code);
                // PKCE обязателен для всех клиентов (OAuth 2.1): защищает от перехвата кода авторизации.
                d.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            }
        }

        // Свой scope (приложение как ресурс) разрешён всегда.
        if (!string.IsNullOrEmpty(input.ClientId) && !scopes.Contains(input.ClientId)) scopes.Add(input.ClientId);
        foreach (var scope in scopes)
            d.Permissions.Add(Permissions.Prefixes.Scope + scope);

        return confidential;
    }

    private static IEnumerable<Uri> ParseUris(IEnumerable<string>? values)
    {
        foreach (var value in (values ?? []).Select(v => v.Trim()).Where(v => v.Length > 0).Distinct())
        {
            // Фрагмент в redirect URI запрещён спецификацией OAuth2 (RFC 6749, 3.1.2).
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
                throw new AdminException($"Некорректный URI: {value}");
            yield return uri;
        }
    }

    private async Task<ApplicationDto> ToDtoAsync(object app, CancellationToken ct)
    {
        var permissions = await applications.GetPermissionsAsync(app, ct);
        return new ApplicationDto(
            (await applications.GetClientIdAsync(app, ct))!,
            await applications.GetDisplayNameAsync(app, ct),
            await applications.GetClientTypeAsync(app, ct) ?? ClientTypes.Public,
            (await applications.GetRedirectUrisAsync(app, ct)).ToList(),
            (await applications.GetPostLogoutRedirectUrisAsync(app, ct)).ToList(),
            permissions.Where(p => p.StartsWith(Permissions.Prefixes.GrantType, StringComparison.Ordinal))
                .Select(p => p[Permissions.Prefixes.GrantType.Length..]).ToList(),
            permissions.Where(p => p.StartsWith(Permissions.Prefixes.Scope, StringComparison.Ordinal))
                .Select(p => p[Permissions.Prefixes.Scope.Length..]).ToList(),
            IsSystem(await applications.GetPropertiesAsync(app, ct)),
            Flag(await applications.GetPropertiesAsync(app, ct), SelfManagementProperty),
            Flag(await applications.GetPropertiesAsync(app, ct), SelfRegistrationProperty));
    }

    /// <summary>Включена ли для приложения самостоятельная регистрация (ссылка «Регистрация» на странице входа).</summary>
    public async Task<bool> IsSelfRegistrationEnabledAsync(string clientId, CancellationToken ct = default) =>
        await applications.FindByClientIdAsync(clientId, ct) is { } app &&
        Flag(await applications.GetPropertiesAsync(app, ct), SelfRegistrationProperty);

    /// <summary>Разрешён ли приложению доступ к App API (/api/app).</summary>
    public async Task<bool> IsSelfManagementEnabledAsync(string clientId, CancellationToken ct = default) =>
        await applications.FindByClientIdAsync(clientId, ct) is { } app &&
        Flag(await applications.GetPropertiesAsync(app, ct), SelfManagementProperty);

    private static bool IsSystem(IReadOnlyDictionary<string, JsonElement> properties) => Flag(properties, SystemProperty);

    private static bool Flag(IReadOnlyDictionary<string, JsonElement> properties, string name) =>
        properties.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.True;

    // 256 бит криптостойкой случайности в URL-safe Base64.
    private static string GenerateSecret() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
