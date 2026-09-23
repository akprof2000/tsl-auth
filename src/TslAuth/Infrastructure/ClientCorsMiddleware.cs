using OpenIddict.Abstractions;

namespace TslAuth.Infrastructure;

/// <summary>
/// CORS для браузерных (SPA) клиентов — аналог «Web Origins» в Keycloak: разрешены только origin'ы,
/// входящие в redirect URI зарегистрированных приложений. Только для протокольных эндпоинтов;
/// админка и Admin API из браузера чужого origin недоступны.
/// Подключается в Program.cs до статики и маршрутизации, чтобы отвечать на preflight (OPTIONS) сразу.
/// </summary>
public sealed class ClientCorsMiddleware(RequestDelegate next, IServiceScopeFactory scopes)
{
    private static readonly string[] Paths = ["/connect/token", "/connect/userinfo", "/connect/revoke", "/.well-known"];
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
    private HashSet<string> _origins = [];
    private DateTime _loadedAt = DateTime.MinValue;

    public async Task InvokeAsync(HttpContext context)
    {
        var origin = context.Request.Headers.Origin.ToString();
        if (origin.Length == 0 || !Paths.Any(p => context.Request.Path.StartsWithSegments(p)))
        {
            await next(context);
            return;
        }

        if (!(await AllowedOriginsAsync()).Contains(origin))
        {
            await next(context); // без CORS-заголовков браузер сам заблокирует ответ
            return;
        }

        // Отражаем конкретный origin (не "*"); Vary — чтобы прокси не отдали кэш с чужим origin.
        var h = context.Response.Headers;
        h.AccessControlAllowOrigin = origin;
        h.Vary = "Origin";
        if (HttpMethods.IsOptions(context.Request.Method))
        {
            h.AccessControlAllowMethods = "GET, POST";
            h.AccessControlAllowHeaders = "Authorization, Content-Type";
            h.AccessControlMaxAge = "600";
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        await next(context);
    }

    /// <summary>
    /// Origin'ы из redirect/post-logout URI всех приложений. Кэш на 60 с: middleware — singleton,
    /// а изменения приложений на других экземплярах кластера подхватываются по истечении TTL.
    /// </summary>
    private async Task<HashSet<string>> AllowedOriginsAsync()
    {
        // Гонка при параллельной перезагрузке безопасна: множество заменяется целиком (без мутации общего экземпляра).
        if (DateTime.UtcNow - _loadedAt < CacheTtl) return _origins;

        using var scope = scopes.CreateScope();
        var apps = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await foreach (var app in apps.ListAsync(null, null))
            foreach (var uri in (await apps.GetRedirectUrisAsync(app)).Concat(await apps.GetPostLogoutRedirectUrisAsync(app)))
                if (Uri.TryCreate(uri, UriKind.Absolute, out var u))
                    origins.Add(u.GetLeftPart(UriPartial.Authority));

        (_origins, _loadedAt) = (origins, DateTime.UtcNow);
        return origins;
    }
}
