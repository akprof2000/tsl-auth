// Демо .NET: серверное веб-приложение (confidential client) со стандартным OIDC-middleware Microsoft.
// authorization code + PKCE, cookie-сессия, refresh-токен, вызов Go API с access-токеном пользователя,
// авторизация по разрешениям из матрицы доступа TSL Auth.
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["Auth:Issuer"] ?? "http://localhost:8080/";
var clientId = builder.Configuration["Auth:ClientId"] ?? "demo-dotnet";
var goApi = builder.Configuration["GoApiUrl"] ?? "http://localhost:5103";

builder.Services.AddHttpClient();
// Действия, меняющие состояние (выход, refresh), — только POST с antiforgery-токеном: GET-ссылку можно подсунуть
// с чужого сайта (картинкой, редиректом), и браузер отправит её с cookie сессии.
builder.Services.AddAntiforgery();
builder.Services.AddAuthorization(o =>
    // Разрешение из матрицы приложения demo-dotnet (claim "permissions" = "client:permission").
    o.AddPolicy("dashboard", p => p.RequireClaim("permissions", $"{clientId}:dashboard.view")));

// Cookie — локальная сессия приложения; OIDC используется только для входа (challenge), когда cookie нет.
builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(o => o.Cookie.Name = "demo_dotnet")
    .AddOpenIdConnect(o =>
    {
        o.Authority = issuer;
        o.RequireHttpsMetadata = issuer.StartsWith("https");
        o.ClientId = clientId;
        o.ClientSecret = builder.Configuration["Auth:ClientSecret"];
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.UsePkce = true;
        // SaveTokens: access/refresh/id-токены сохраняются в свойствах cookie-сессии (читаются через GetTokenAsync).
        o.SaveTokens = true;
        o.GetClaimsFromUserInfoEndpoint = false;
        // Не переименовывать claims в длинные URI Microsoft — оставить имена как в JWT ("role", "permissions").
        o.MapInboundClaims = false;
        o.TokenValidationParameters.NameClaimType = "name";
        o.TokenValidationParameters.RoleClaimType = "role";
        foreach (var s in new[] { "openid", "profile", "email", "roles", "offline_access", "demo-go-api" }) o.Scope.Add(s);

        // Роли/разрешения берём из access-токена (в нём права по матрице доступа).
        // Подпись access-токена здесь не проверяем: он только что получен напрямую от token endpoint по TLS,
        // а id_token уже проверен middleware.
        o.Events.OnTokenValidated = ctx =>
        {
            var access = new JwtSecurityTokenHandler().ReadJwtToken(ctx.TokenEndpointResponse!.AccessToken);
            var identity = (System.Security.Claims.ClaimsIdentity)ctx.Principal!.Identity!;
            foreach (var c in access.Claims.Where(c => c.Type is "permissions" or "role"))
                identity.AddClaim(new System.Security.Claims.Claim(c.Type, c.Value));
            return Task.CompletedTask;
        };
    });

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapGet("/", async (HttpContext ctx, IAntiforgery antiforgery) =>
{
    var user = ctx.User;
    if (user.Identity?.IsAuthenticated != true)
        return Html("<p>Вы не вошли.</p><a class='btn' href='/login'>Войти через TSL Auth</a>");

    var token = await ctx.GetTokenAsync("access_token");
    var expires = await ctx.GetTokenAsync("expires_at");
    var perms = user.FindAll("permissions").Select(c => c.Value).ToList();
    var af = antiforgery.GetAndStoreTokens(ctx);
    var afField = $"<input type='hidden' name='{E(af.FormFieldName)}' value='{E(af.RequestToken)}'>";
    return Html($"""
        <p>Вы вошли как <b>{E(user.Identity.Name)}</b>. Access-токен истекает: {E(expires)}</p>
        <p>Разрешения: {E(string.Join(", ", perms))}</p>
        <a class='btn' href='/dashboard'>Панель (нужно dashboard.view)</a>
        <a class='btn' href='/go-reports'>Вызвать Go API /api/reports</a>
        <form method='post' action='/refresh' style='display:inline'>{afField}<button class='btn'>Обновить токен (refresh)</button></form>
        <form method='post' action='/logout' style='display:inline'>{afField}<button class='btn'>Выйти</button></form>
        <h3>Claims access-токена</h3><pre>{E(JsonSerializer.Serialize(
            new JwtSecurityTokenHandler().ReadJwtToken(token).Payload, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))}</pre>
        """);
});

app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, [OpenIdConnectDefaults.AuthenticationScheme]));

// Выход из обеих схем: удаляется локальная cookie и выполняется редирект на end_session_endpoint сервера
// (middleware передаёт id_token_hint — сервер завершает сессию без страницы подтверждения).
app.MapPost("/logout", () => Results.SignOut(new AuthenticationProperties { RedirectUri = "/" },
        [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]))
    .WithMetadata(new RequireAntiforgeryTokenAttribute());

app.MapGet("/dashboard", (HttpContext ctx) => Html($"<p>✅ Доступ к панели разрешён матрицей доступа для {E(ctx.User.Identity!.Name)}.</p><a href='/'>← назад</a>"))
    .RequireAuthorization("dashboard");

// Вызов API от имени пользователя: access-токен из cookie-сессии передаётся как Bearer.
app.MapGet("/go-reports", async (HttpContext ctx, IHttpClientFactory http) =>
{
    var client = http.CreateClient();
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await ctx.GetTokenAsync("access_token"));
    var response = await client.GetAsync($"{goApi}/api/reports");
    return Html($"<p>Go API ответил <b>{(int)response.StatusCode}</b></p><pre>{E(await response.Content.ReadAsStringAsync())}</pre><a href='/'>← назад</a>");
}).RequireAuthorization();

// Продление сессии: refresh_token → новые токены, cookie перевыпускается.
async Task<IResult> Refresh(HttpContext ctx, IHttpClientFactory http, IConfiguration cfg)
{
    var result = await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    var response = await http.CreateClient().PostAsync($"{issuer.TrimEnd('/')}/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "refresh_token",
        ["client_id"] = clientId,
        ["client_secret"] = cfg["Auth:ClientSecret"] ?? "",
        ["refresh_token"] = result.Properties!.GetTokenValue("refresh_token")!
    }));
    var body = await response.Content.ReadFromJsonAsync<JsonElement>();
    if (!response.IsSuccessStatusCode)
        return Html($"<p>Refresh отклонён: {E(body.GetRawText())}</p><a href='/login'>Войти заново</a>");

    result.Properties.UpdateTokenValue("access_token", body.GetProperty("access_token").GetString()!);
    result.Properties.UpdateTokenValue("refresh_token", body.GetProperty("refresh_token").GetString()!);
    result.Properties.UpdateTokenValue("expires_at", DateTimeOffset.UtcNow.AddSeconds(body.GetProperty("expires_in").GetInt32()).ToString("o"));
    // Повторный SignIn перезаписывает cookie с новыми токенами (сервер ротирует refresh-токен — старый сохранять нельзя).
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal!, result.Properties);
    return Html("<p>✅ Токен обновлён через refresh_token (ротация: старый refresh больше не действует).</p><a href='/'>← назад</a>");
}

app.MapPost("/refresh", Refresh).RequireAuthorization().WithMetadata(new RequireAntiforgeryTokenAttribute());

app.MapGet("/health", () => "ok");
app.Run();

static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

static IResult Html(string body) => Results.Content($"""
    <!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>Демо .NET MVC</title>
    <style>body{"{"}font-family:Segoe UI,Arial;margin:0;background:#f3f0ff;color:#1e1646{"}"}header{"{"}background:#5b3fd6;color:#fff;padding:14px 20px{"}"}
    main{"{"}max-width:960px;margin:0 auto;padding:20px{"}"}.btn{"{"}display:inline-block;padding:8px 14px;margin:4px 4px 4px 0;border-radius:6px;background:#5b3fd6;color:#fff;text-decoration:none{"}"}
    pre{"{"}background:#fff;border:1px solid #d9d0ff;padding:12px;overflow:auto;font-size:12px{"}"}</style></head>
    <body><header><b>Демо .NET MVC</b> · серверный рендеринг, confidential client</header><main>{body}</main></body></html>
    """, "text/html; charset=utf-8");
