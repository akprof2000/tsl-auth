using System.Security.Claims;
using System.Text.Json;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Services;

/// <summary>
/// Сроки жизни токенов: min(глобальная настройка, настройка приложения, запрошенное клиентом).
/// Клиент может только сократить срок (параметры expires_in / refresh_expires_in в секундах), но не увеличить.
/// Вызывается AuthorizationController перед каждой выдачей токенов; настройки приложения меняются
/// на странице Admin/Apps/Edit и через Admin API (хранятся в Properties клиента OpenIddict).
/// </summary>
public sealed class TokenLifetimeService(SettingsService settings, IOpenIddictApplicationManager applications)
{
    public const string AppProperty = "tsl_token_lifetimes";
    public const string RequestedAccessParameter = "expires_in";
    public const string RequestedRefreshParameter = "refresh_expires_in";

    /// <summary>Вид выдачи: обычный вход, token exchange (RFC 8693) или обмен PAT — у каждого свой срок access-токена.</summary>
    public enum Kind { Regular, Exchange, Pat }

    /// <summary>Записывает в identity сроки жизни access/refresh/id-токенов и кода авторизации (OpenIddict прочитает их при выдаче).</summary>
    public async Task ApplyAsync(ClaimsIdentity identity, string clientId, OpenIddictRequest? request, Kind kind)
    {
        var global = (await settings.GetAsync()).Tokens;
        var app = await GetForAppAsync(clientId);

        var access = kind switch
        {
            Kind.Exchange => Min(global.ExchangeTokenMinutes, app.ExchangeTokenMinutes),
            // Для PAT — только глобальная настройка: токен может адресоваться сразу нескольким приложениям.
            Kind.Pat => global.PatAccessTokenMinutes,
            _ => Min(global.AccessTokenMinutes, app.AccessTokenMinutes)
        };
        var accessLifetime = Cap(TimeSpan.FromMinutes(access), Requested(request, RequestedAccessParameter));
        var refreshLifetime = Cap(TimeSpan.FromDays(Min(global.RefreshTokenDays, app.RefreshTokenDays)),
            Requested(request, RequestedRefreshParameter));

        identity.SetAccessTokenLifetime(accessLifetime);
        identity.SetRefreshTokenLifetime(refreshLifetime);
        identity.SetIdentityTokenLifetime(TimeSpan.FromMinutes(global.IdentityTokenMinutes));
        identity.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(global.AuthorizationCodeMinutes));
    }

    /// <summary>Переопределения сроков для приложения; пустой объект, если не заданы или приложения нет.</summary>
    public async Task<AppTokenLifetimes> GetForAppAsync(string clientId)
    {
        if (await applications.FindByClientIdAsync(clientId) is not { } app) return new AppTokenLifetimes();
        var properties = await applications.GetPropertiesAsync(app);
        return properties.TryGetValue(AppProperty, out var json) && json.ValueKind == JsonValueKind.Object
            ? json.Deserialize<AppTokenLifetimes>() ?? new AppTokenLifetimes()
            : new AppTokenLifetimes();
    }

    /// <summary>Сохраняет сроки для приложения; они не могут превышать глобальные (приложение может только ужесточить).</summary>
    public async Task SetForAppAsync(string clientId, AppTokenLifetimes lifetimes, CancellationToken ct = default)
    {
        lifetimes.Validate();
        var global = (await settings.GetAsync(ct)).Tokens;
        if (lifetimes.AccessTokenMinutes > global.AccessTokenMinutes || lifetimes.RefreshTokenDays > global.RefreshTokenDays ||
            lifetimes.ExchangeTokenMinutes > global.ExchangeTokenMinutes)
            throw new AdminException("Срок для приложения не может превышать глобальную настройку сервера.");

        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, app, ct);
        if (lifetimes == new AppTokenLifetimes()) descriptor.Properties.Remove(AppProperty);
        else descriptor.Properties[AppProperty] = JsonSerializer.SerializeToElement(lifetimes);
        await applications.UpdateAsync(app, descriptor, ct);
    }

    private static int Min(int global, int? app) => app is { } a ? Math.Min(global, a) : global;

    // Некорректные/неположительные значения параметра просто игнорируются (используется максимум).
    private static TimeSpan? Requested(OpenIddictRequest? request, string name) =>
        request?.GetParameter(name) is { } p && long.TryParse((string?)p, out var seconds) && seconds > 0
            ? TimeSpan.FromSeconds(seconds)
            : null;

    private static TimeSpan Cap(TimeSpan max, TimeSpan? requested) => requested is { } r && r < max ? r : max;
}
