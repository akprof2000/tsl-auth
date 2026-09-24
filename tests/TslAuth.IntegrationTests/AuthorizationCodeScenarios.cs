using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using TslAuth.IntegrationTests.Infrastructure;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Основной поток входа — authorization code + PKCE через настоящую страницу входа (H8 ревизии):
/// выдача и обмен кода, refresh, introspection, revocation, выход, а также отказы: без code_challenge,
/// с неверным code_verifier, с чужим redirect_uri, повтор кода, prompt=none без сессии, временный пароль,
/// выход без id_token_hint (logout-CSRF). Выполняется на SQLite и PostgreSQL.
/// </summary>
public abstract partial class AuthorizationCodeScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private const string Password = "C0de-Fl0w-Passw0rd!";
    private const string RedirectUri = "https://app.example/cb";
    private const string PostLogoutUri = "https://app.example/";

    private sealed record Setup(string Api, string Client, string Secret, string UserName);

    private async Task<Setup> CreateAsync(bool mustChangePassword = false)
    {
        var admin = await fx.Factory.AdminAsync();
        var api = TestApi.Unique("api");
        var client = TestApi.Unique("web");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" } });
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = client, clientType = "confidential", grantTypes = new[] { "authorization_code", "refresh_token" },
            redirectUris = new[] { RedirectUri }, postLogoutRedirectUris = new[] { PostLogoutUri }, scopes = new[] { "profile", api }
        });
        var userName = TestApi.Unique("coder");
        await admin.PostJsonAsync("/api/admin/users", new
        {
            userName, email = $"{userName}@it.local", password = Password, mustChangePassword,
            roles = new[] { new { clientId = api, role = "reader" } }
        });
        return new Setup(api, client, created.GetProperty("clientSecret").GetString()!, userName);
    }

    // ---------- «Браузер»: cookie, без автоматических редиректов ----------

    private HttpClient Browser() => fx.Factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false, HandleCookies = true, BaseAddress = new Uri("http://localhost")
    });

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    private static async Task<string> AntiforgeryAsync(HttpClient browser, string page)
    {
        var html = await (await browser.GetAsync(page)).Content.ReadAsStringAsync();
        return AntiforgeryField().Match(html) is { Success: true } m
            ? WebUtility.HtmlDecode(m.Groups[1].Value)
            : throw new InvalidOperationException($"На странице {page} нет antiforgery-токена.");
    }

    /// <summary>Вход через форму /Account/Login; возвращает Location ответа.</summary>
    private static async Task<string> LoginAsync(HttpClient browser, string user, string returnUrl)
    {
        var page = "/Account/Login?ReturnUrl=" + Uri.EscapeDataString(returnUrl);
        var token = await AntiforgeryAsync(browser, page);
        var response = await browser.PostAsync(page, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Login"] = user, ["Password"] = Password, ["ReturnUrl"] = returnUrl, ["__RequestVerificationToken"] = token
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return response.Headers.Location!.ToString();
    }

    private static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string AuthorizeUrl(Setup s, string? challenge, string redirect = RedirectUri, Dictionary<string, string?>? extra = null)
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = s.Client, ["response_type"] = "code", ["redirect_uri"] = redirect,
            ["scope"] = $"openid offline_access profile {s.Api}", ["state"] = "st-123"
        };
        if (challenge is not null) { query["code_challenge"] = challenge; query["code_challenge_method"] = "S256"; }
        foreach (var (k, v) in extra ?? []) query[k] = v;
        return QueryHelpers.AddQueryString("/connect/authorize", query);
    }

    private static Dictionary<string, string> Query(string location) =>
        QueryHelpers.ParseQuery(new Uri(location).Query).ToDictionary(p => p.Key, p => p.Value.ToString());

    /// <summary>Вход и получение кода авторизации (после входа браузер возвращается на /connect/authorize).</summary>
    private async Task<(HttpClient Browser, string Code)> SignInAndGetCodeAsync(Setup s, string challenge)
    {
        var browser = Browser();
        var authorize = AuthorizeUrl(s, challenge);
        var afterLogin = await LoginAsync(browser, s.UserName, authorize);
        var response = await browser.GetAsync(afterLogin);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(RedirectUri, location);
        var query = Query(location);
        Assert.Equal("st-123", query["state"]);
        return (browser, query["code"]);
    }

    private Task<JsonElement> ExchangeCodeAsync(Setup s, string code, string verifier, bool expectSuccess = true) =>
        fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = s.Client, ["client_secret"] = s.Secret,
            ["code"] = code, ["code_verifier"] = verifier, ["redirect_uri"] = RedirectUri
        }, expectSuccess);

    // ---------- Успешный поток ----------

    [Fact]
    public async Task CodeFlow_WithPkce_IssuesTokens_AndCodeIsSingleUse()
    {
        var s = await CreateAsync();
        var (verifier, challenge) = Pkce();
        var (_, code) = await SignInAndGetCodeAsync(s, challenge);

        var tokens = await ExchangeCodeAsync(s, code, verifier);
        var claims = TestApi.Claims(tokens.GetProperty("access_token").GetString()!);
        Assert.Contains($"{s.Api}:read", claims.Strings("permissions"));
        Assert.True(tokens.TryGetProperty("id_token", out _));

        // Refresh продлевает сессию.
        var refreshed = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "refresh_token", ["client_id"] = s.Client, ["client_secret"] = s.Secret,
            ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!
        });
        Assert.True(refreshed.TryGetProperty("access_token", out _));

        // Повтор кода отвергается.
        var reused = await ExchangeCodeAsync(s, code, verifier, expectSuccess: false);
        Assert.Equal("invalid_grant", reused.GetProperty("error").GetString());
    }

    // ---------- Отказы ----------

    [Fact]
    public async Task Authorize_WithoutCodeChallenge_IsRejected()
    {
        var s = await CreateAsync();
        var browser = Browser();
        await LoginAsync(browser, s.UserName, "/");
        var response = await browser.GetAsync(AuthorizeUrl(s, challenge: null));
        // OpenIddict отклоняет запрос сразу (400 с invalid_request), код не выдаётся и в приложение не уходит.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_request", await response.Content.ReadAsStringAsync());
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Token_WithWrongCodeVerifier_IsRejected()
    {
        var s = await CreateAsync();
        var (_, challenge) = Pkce();
        var (_, code) = await SignInAndGetCodeAsync(s, challenge);
        var result = await ExchangeCodeAsync(s, code, Pkce().Verifier, expectSuccess: false);
        Assert.Equal("invalid_grant", result.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_WithForeignRedirectUri_DoesNotRedirect()
    {
        var s = await CreateAsync();
        var browser = Browser();
        await LoginAsync(browser, s.UserName, "/");
        var response = await browser.GetAsync(AuthorizeUrl(s, Pkce().Challenge, redirect: "https://evil.example/cb"));
        Assert.NotEqual(HttpStatusCode.Redirect, response.StatusCode);
        Assert.DoesNotContain("evil.example", response.Headers.Location?.ToString() ?? "");
    }

    [Fact]
    public async Task Authorize_PromptNone_WithoutSession_ReturnsLoginRequired()
    {
        var s = await CreateAsync();
        var response = await Browser().GetAsync(AuthorizeUrl(s, Pkce().Challenge, extra: new() { ["prompt"] = "none" }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("login_required", Query(response.Headers.Location!.ToString())["error"]);
    }

    [Fact]
    public async Task TemporaryPassword_RedirectsToChangePassword_WithoutCode()
    {
        var s = await CreateAsync(mustChangePassword: true);
        var browser = Browser();
        var afterLogin = await LoginAsync(browser, s.UserName, AuthorizeUrl(s, Pkce().Challenge));
        Assert.Contains("/Account/ChangePassword", afterLogin);
        Assert.DoesNotContain("code=", afterLogin);
    }

    // ---------- Introspection, revocation ----------

    [Fact]
    public async Task Introspection_AndRevocation_Work()
    {
        var s = await CreateAsync();
        var (verifier, challenge) = Pkce();
        var (_, code) = await SignInAndGetCodeAsync(s, challenge);
        var tokens = await ExchangeCodeAsync(s, code, verifier);
        var http = fx.Factory.CreateClient();

        async Task<JsonElement> IntrospectAsync(string token, string secret)
        {
            var response = await http.PostAsync("/connect/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = s.Client, ["client_secret"] = secret, ["token"] = token
            }));
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
        }

        var refresh = tokens.GetProperty("refresh_token").GetString()!;
        Assert.True((await IntrospectAsync(refresh, s.Secret)).GetProperty("active").GetBoolean());
        // Неверный секрет — invalid_client (пишется в журнал как попытка подбора).
        Assert.Equal("invalid_client", (await IntrospectAsync(refresh, "wrong-secret")).GetProperty("error").GetString());

        var revoke = await http.PostAsync("/connect/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = s.Client, ["client_secret"] = s.Secret, ["token"] = refresh
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.False((await IntrospectAsync(refresh, s.Secret)).GetProperty("active").GetBoolean());
        var afterRevoke = await http.TokenAsync(new()
        {
            ["grant_type"] = "refresh_token", ["client_id"] = s.Client, ["client_secret"] = s.Secret, ["refresh_token"] = refresh
        }, expectSuccess: false);
        Assert.Equal("invalid_grant", afterRevoke.GetProperty("error").GetString());
    }

    // ---------- Выход ----------

    [Fact]
    public async Task Logout_WithoutIdTokenHint_RequiresConfirmation_WithHint_IsImmediate()
    {
        var s = await CreateAsync();
        var (verifier, challenge) = Pkce();
        var (browser, code) = await SignInAndGetCodeAsync(s, challenge);
        var tokens = await ExchangeCodeAsync(s, code, verifier);

        // Сторонняя ссылка/картинка на /connect/logout без подсказки — только страница подтверждения, сессия цела.
        var hintless = await browser.GetAsync($"/connect/logout?post_logout_redirect_uri={Uri.EscapeDataString(PostLogoutUri)}");
        Assert.Equal(HttpStatusCode.Redirect, hintless.StatusCode);
        Assert.StartsWith("/Account/EndSession", hintless.Headers.Location!.ToString());
        var forged = await browser.PostAsync("/connect/logout", new FormUrlEncodedContent(new Dictionary<string, string>()));
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        var stillIn = await browser.GetAsync(AuthorizeUrl(s, Pkce().Challenge, extra: new() { ["prompt"] = "none" }));
        Assert.Contains("code=", stillIn.Headers.Location!.ToString());

        // С id_token_hint (запрос от самого приложения) — выход сразу.
        var withHint = await browser.GetAsync(QueryHelpers.AddQueryString("/connect/logout", new Dictionary<string, string?>
        {
            ["id_token_hint"] = tokens.GetProperty("id_token").GetString(), ["post_logout_redirect_uri"] = PostLogoutUri
        }));
        Assert.Equal(HttpStatusCode.Redirect, withHint.StatusCode);
        Assert.StartsWith(PostLogoutUri, withHint.Headers.Location!.ToString());
        var afterLogout = await browser.GetAsync(AuthorizeUrl(s, Pkce().Challenge, extra: new() { ["prompt"] = "none" }));
        Assert.Equal("login_required", Query(afterLogout.Headers.Location!.ToString())["error"]);
    }

    // ---------- form_post и CSP ----------

    [Fact]
    public async Task FormPost_ResponseMode_IsAllowedByCsp()
    {
        var s = await CreateAsync();
        var browser = Browser();
        await LoginAsync(browser, s.UserName, "/");
        var response = await browser.GetAsync(AuthorizeUrl(s, Pkce().Challenge, extra: new() { ["response_mode"] = "form_post" }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains(RedirectUri, html);
        Assert.Contains("name=\"code\"", html);
        // Автоотправку формы разрешает только хеш её скрипта в CSP (без 'unsafe-inline').
        var csp = string.Join(";", response.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("sha256-", csp);
        Assert.DoesNotContain("script-src 'self' 'unsafe-inline'", csp);
    }
}

/// <summary>Поток authorization code + PKCE на SQLite.</summary>
[Collection("sqlite-code")]
public sealed class SqliteAuthorizationCode(SqliteFixture fx) : AuthorizationCodeScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

/// <summary>Поток authorization code + PKCE на PostgreSQL.</summary>
[Collection("postgres-code")]
public sealed class PostgresAuthorizationCode(PostgresFixture fx) : AuthorizationCodeScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
