// Интеграционные сценарии решений заказчика по ЧТЗ 04.09.01: двухфакторный вход по ролям (В-9),
// отключение неактивных учётных записей (В-10). Сроки хранения журнала по умолчанию (В-5) проверяют unit-тесты.
// Запуск: dotnet test tests/TslAuth.IntegrationTests (для вариантов на PostgreSQL нужен Docker —
// контейнер поднимает Testcontainers). Сервис поднимается в процессе через WebApplicationFactory
// (см. Infrastructure/AuthFixture.cs). Коды второго фактора берутся тем же UserManager, что и у сервиса:
// почта в тестах не настроена, а бот вызывается по настоящему Bot API.

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.IntegrationTests.Infrastructure;
using TslAuth.Security;
using TslAuth.Services;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Двухфакторный вход по флагу роли и отключение неактивных учётных записей. Выполняется на SQLite и PostgreSQL.
/// </summary>
public abstract partial class TwoFactorScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private static readonly string Password = TestApi.NewPassword();
    private const string RedirectUri = "https://app.example/cb";

    private sealed record Setup(string Api, string Client, string Secret, string UserName, Guid UserId);

    /// <summary>Приложение-ресурс с ролью reader, клиент authorization code и пользователь с этой ролью.</summary>
    private async Task<Setup> CreateAsync(bool twoFactor, bool withEmail = true)
    {
        var admin = await fx.Factory.AdminAsync();
        var api = TestApi.Unique("api");
        var client = TestApi.Unique("web");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" } });
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = client, clientType = "confidential", grantTypes = new[] { "authorization_code", "refresh_token", "password" },
            redirectUris = new[] { RedirectUri }, scopes = new[] { "profile", api }
        });
        if (twoFactor)
            Assert.Equal(HttpStatusCode.NoContent,
                (await admin.PutAsync($"/api/admin/applications/{api}/roles/reader/two-factor?value=true", null)).StatusCode);
        var userName = TestApi.Unique("mfa");
        var user = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName, email = withEmail ? $"{userName}@it.local" : null, password = Password,
            roles = new[] { new { clientId = api, role = "reader" } }
        });
        return new Setup(api, client, created.GetProperty("clientSecret").GetString()!, userName,
            user.GetProperty("user").GetProperty("id").GetGuid());
    }

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

    /// <summary>Отправка формы входа; возвращает ответ (редирект или страницу с ошибкой).</summary>
    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient browser, string user, string returnUrl)
    {
        var page = "/Account/Login?ReturnUrl=" + Uri.EscapeDataString(returnUrl);
        var token = await AntiforgeryAsync(browser, page);
        return await browser.PostAsync(page, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Login"] = user, ["Password"] = Password, ["ReturnUrl"] = returnUrl, ["__RequestVerificationToken"] = token
        }));
    }

    /// <summary>Отправка кода на странице второго шага (обработчик Verify).</summary>
    private static async Task<HttpResponseMessage> PostCodeAsync(HttpClient browser, string twoFactorUrl, string provider, string code)
    {
        var token = await AntiforgeryAsync(browser, twoFactorUrl);
        var returnUrl = QueryHelpers.ParseQuery(new Uri(new Uri("http://localhost"), twoFactorUrl).Query)
            .TryGetValue("returnUrl", out var r) ? r.ToString() : "";
        return await browser.PostAsync("/Account/LoginTwoFactor?handler=Verify", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Provider"] = provider, ["Code"] = code, ["ReturnUrl"] = returnUrl, ["__RequestVerificationToken"] = token
        }));
    }

    /// <summary>Код второго фактора тем же генератором, что и у сервиса (TOTP по security stamp пользователя).</summary>
    private async Task<string> CodeAsync(Guid userId, string provider)
    {
        using var scope = fx.Factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
        var user = await users.FindByIdAsync(userId.ToString());
        return await users.GenerateTwoFactorTokenAsync(user!, provider);
    }

    private static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string AuthorizeUrl(Setup s, string challenge) => QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
    {
        ["client_id"] = s.Client, ["response_type"] = "code", ["redirect_uri"] = RedirectUri,
        ["scope"] = $"openid offline_access profile {s.Api}", ["state"] = "st-2fa",
        ["code_challenge"] = challenge, ["code_challenge_method"] = "S256"
    });

    private Task<JsonElement> PasswordGrantAsync(Setup s, bool expectSuccess) =>
        fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = s.Client, ["client_secret"] = s.Secret,
            ["username"] = s.UserName, ["password"] = Password, ["scope"] = $"openid {s.Api}"
        }, expectSuccess);

    // ---------- Двухфакторный вход (В-9) ----------

    /// <summary>
    /// Роль с флагом 2FA: после пароля — страница кода; неверный код отклоняется, верный код с почты завершает вход,
    /// код авторизации обменивается на токены с amr = pwd, otp, mfa; refresh сохраняет amr.
    /// </summary>
    [Fact]
    public async Task RoleWithTwoFactor_RequiresCode_AndTokensCarryAmr()
    {
        var s = await CreateAsync(twoFactor: true);
        var browser = Browser();
        var (verifier, challenge) = Pkce();
        var authorize = AuthorizeUrl(s, challenge);

        var login = await PostLoginAsync(browser, s.UserName, authorize);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var twoFactorUrl = login.Headers.Location!.ToString();
        Assert.Contains("/Account/LoginTwoFactor", twoFactorUrl);

        // Без кода сессии нет: /connect/authorize снова отправляет на вход.
        var early = await browser.GetAsync(authorize);
        Assert.Contains("/Account/Login", early.Headers.Location!.ToString());

        var wrong = await PostCodeAsync(browser, twoFactorUrl, TwoFactorProviders.Email, "000000");
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode); // страница с ошибкой, без входа

        var ok = await PostCodeAsync(browser, twoFactorUrl, TwoFactorProviders.Email, await CodeAsync(s.UserId, TwoFactorProviders.Email));
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        var back = await browser.GetAsync(ok.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        var callback = back.Headers.Location!.ToString();
        Assert.StartsWith(RedirectUri, callback);
        var code = QueryHelpers.ParseQuery(new Uri(callback).Query)["code"].ToString();

        var tokens = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = s.Client, ["client_secret"] = s.Secret,
            ["code"] = code, ["code_verifier"] = verifier, ["redirect_uri"] = RedirectUri
        });
        var amr = TestApi.Claims(tokens.GetProperty("access_token").GetString()!).Strings("amr");
        Assert.Contains("mfa", amr);
        Assert.Contains("pwd", amr);

        var refreshed = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "refresh_token", ["client_id"] = s.Client, ["client_secret"] = s.Secret,
            ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!
        });
        Assert.Contains("mfa", TestApi.Claims(refreshed.GetProperty("access_token").GetString()!).Strings("amr"));
    }

    /// <summary>Без флага 2FA вход обычный: сразу обратно в /connect/authorize, в токене amr = pwd.</summary>
    [Fact]
    public async Task RoleWithoutTwoFactor_SignsInWithPasswordOnly()
    {
        var s = await CreateAsync(twoFactor: false);
        var browser = Browser();
        var (verifier, challenge) = Pkce();
        var login = await PostLoginAsync(browser, s.UserName, AuthorizeUrl(s, challenge));
        Assert.Contains("/connect/authorize", login.Headers.Location!.ToString());
        var back = await browser.GetAsync(login.Headers.Location!.ToString());
        var code = QueryHelpers.ParseQuery(new Uri(back.Headers.Location!.ToString()).Query)["code"].ToString();
        var tokens = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "authorization_code", ["client_id"] = s.Client, ["client_secret"] = s.Secret,
            ["code"] = code, ["code_verifier"] = verifier, ["redirect_uri"] = RedirectUri
        });
        var amr = TestApi.Claims(tokens.GetProperty("access_token").GetString()!).Strings("amr");
        Assert.Contains("pwd", amr);
        Assert.DoesNotContain("mfa", amr);
    }

    /// <summary>Password grant закрыт для роли с 2FA (ввести код негде) и снова работает после снятия флага.</summary>
    [Fact]
    public async Task PasswordGrant_IsRejected_ForTwoFactorRole()
    {
        var s = await CreateAsync(twoFactor: true);
        var denied = await PasswordGrantAsync(s, expectSuccess: false);
        Assert.Equal("invalid_grant", denied.GetProperty("error").GetString());

        var admin = await fx.Factory.AdminAsync();
        await admin.PutAsync($"/api/admin/applications/{s.Api}/roles/reader/two-factor?value=false", null);
        Assert.True((await PasswordGrantAsync(s, expectSuccess: true)).TryGetProperty("access_token", out _));
    }

    /// <summary>Роль требует 2FA, но у учётной записи нет ни email, ни мессенджера: вход не выполняется, сессии нет.</summary>
    [Fact]
    public async Task TwoFactor_WithoutChannels_BlocksSignIn()
    {
        var s = await CreateAsync(twoFactor: true, withEmail: false);
        var browser = Browser();
        var login = await PostLoginAsync(browser, s.UserName, "/Account");
        Assert.Equal(HttpStatusCode.OK, login.StatusCode); // страница входа с ошибкой
        var account = await browser.GetAsync("/Account");
        Assert.Contains("/Account/Login", account.Headers.Location!.ToString());
    }

    /// <summary>
    /// Код в мессенджере: привязанный к учётной записи отправитель получает код по Bot API (/api/bot/2fa-code),
    /// код принимается на странице второго шага; для непривязанного отправителя — 404.
    /// </summary>
    [Fact]
    public async Task MessengerCode_FromBot_CompletesSignIn()
    {
        var s = await CreateAsync(twoFactor: true, withEmail: false);
        var admin = await fx.Factory.AdminAsync();
        var botClient = TestApi.Unique("bot");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = botClient, clientType = "confidential", grantTypes = new[] { "client_credentials" }, scopes = new[] { SystemApp.ClientId }
        });
        await admin.PutJsonAsync($"/api/admin/applications/{botClient}/service-roles", new[] { new { clientId = SystemApp.ClientId, role = SystemApp.ResetBotRole } });
        var token = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = botClient,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["scope"] = SystemApp.ClientId
        });
        var bot = fx.Factory.CreateClient().WithBearer(token.GetProperty("access_token").GetString()!);

        var externalId = TestApi.Unique("chat");
        Assert.Equal(HttpStatusCode.NotFound,
            (await bot.PostAsJsonAsync("/api/bot/2fa-code", new { provider = "chat", externalId })).StatusCode);

        string link;
        using (var scope = fx.Factory.Services.CreateScope())
            (link, _) = await scope.ServiceProvider.GetRequiredService<BotService>().CreateLinkCodeAsync(s.UserId);
        await bot.PostJsonAsync("/api/bot/link", new { provider = "chat", externalId, code = link });

        var browser = Browser();
        var login = await PostLoginAsync(browser, s.UserName, "/Account");
        var twoFactorUrl = login.Headers.Location!.ToString();
        Assert.Contains("/Account/LoginTwoFactor", twoFactorUrl);

        var reply = await bot.PostJsonAsync("/api/bot/2fa-code", new { provider = "chat", externalId });
        Assert.Equal(s.UserName, reply.GetProperty("userName").GetString());
        var ok = await PostCodeAsync(browser, twoFactorUrl, TwoFactorProviders.Messenger, reply.GetProperty("code").GetString()!);
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/Account")).StatusCode);
    }

    /// <summary>Флаг 2FA виден в матрице приложения и меняется только через Admin API (App API — нет маршрута).</summary>
    [Fact]
    public async Task TwoFactorFlag_IsShownInMatrix()
    {
        var s = await CreateAsync(twoFactor: true);
        var admin = await fx.Factory.AdminAsync();
        var matrix = await admin.GetJsonAsync($"/api/admin/applications/{s.Api}/matrix");
        var reader = matrix.GetProperty("roles").EnumerateArray().Single(r => r.GetProperty("name").GetString() == "reader");
        Assert.True(reader.GetProperty("requiresTwoFactor").GetBoolean());
    }

    // ---------- Неактивные учётные записи (В-10) ----------

    /// <summary>
    /// Обслуживание БД отключает учётную запись без входа дольше срока политики, но не трогает
    /// недавно входившего пользователя и администратора сервиса (его отключают только вручную).
    /// </summary>
    [Fact]
    public async Task Maintenance_DisablesInactiveUsers_ExceptAdministrators()
    {
        var admin = await fx.Factory.AdminAsync();
        var stale = TestApi.Unique("stale");
        var fresh = TestApi.Unique("fresh");
        var boss = TestApi.Unique("boss");
        var staleId = (await admin.PostJsonAsync("/api/admin/users", new { userName = stale, password = Password })).GetProperty("user").GetProperty("id").GetGuid();
        var freshId = (await admin.PostJsonAsync("/api/admin/users", new { userName = fresh, password = Password })).GetProperty("user").GetProperty("id").GetGuid();
        var bossId = (await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = boss, password = Password, roles = new[] { new { clientId = SystemApp.ClientId, role = SystemApp.AdministratorRole } }
        })).GetProperty("user").GetProperty("id").GetGuid();

        using (var scope = fx.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var old = DateTime.UtcNow.AddDays(-120);
            await db.Users.Where(u => u.Id == staleId || u.Id == bossId)
                .ExecuteUpdateAsync(u => u.SetProperty(x => x.LastLoginAt, old).SetProperty(x => x.CreatedAt, old));
            await db.Users.Where(u => u.Id == freshId).ExecuteUpdateAsync(u => u.SetProperty(x => x.LastLoginAt, DateTime.UtcNow.AddDays(-5)));
        }

        await TokenPruningService.RunOnceAsync(fx.Factory.Services.GetRequiredService<IServiceScopeFactory>(), CancellationToken.None);

        using (var scope = fx.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var active = await db.Users.AsNoTracking().Where(u => u.Id == staleId || u.Id == freshId || u.Id == bossId)
                .ToDictionaryAsync(u => u.Id, u => u.IsActive);
            Assert.False(active[staleId]);
            Assert.True(active[freshId]);
            Assert.True(active[bossId]);
            Assert.True(await db.AuditEntries.AnyAsync(a => a.Type == AuditTypes.DisabledInactive && a.SubjectUserId == staleId));
        }
    }
}

/// <summary>Двухфакторный вход и неактивные учётные записи на SQLite.</summary>
[Collection("sqlite-2fa")]
public sealed class SqliteTwoFactor(SqliteFixture fx) : TwoFactorScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

/// <summary>Двухфакторный вход и неактивные учётные записи на PostgreSQL.</summary>
[Collection("postgres-2fa")]
public sealed class PostgresTwoFactor(PostgresFixture fx) : TwoFactorScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
