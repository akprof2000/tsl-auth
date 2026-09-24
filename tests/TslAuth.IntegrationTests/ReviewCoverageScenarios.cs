using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore.Models;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.IntegrationTests.Infrastructure;
using TslAuth.Services;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Сценарии, которых не хватало тестам (M32 ревизии), и регрессионные проверки исправлений ядра:
/// лимиты частоты, окно повтора refresh, чужой клиент, временный/просроченный пароль и срок сессии при refresh,
/// права ролей администрирования, PAT, подпись вебхука, CORS, заголовки безопасности, приглашение по ссылке,
/// лимит сбросов через бота, App API, системные роли, удаление приложения, атомарность, история паролей,
/// языковые пакеты и дубли заявок при обновлении БД. Выполняются на SQLite и PostgreSQL.
/// </summary>
public abstract partial class ReviewCoverageScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private static readonly string Password = TestApi.NewPassword();

    // ---------- Подготовка ----------

    private async Task<(string Api, string Client)> AppsAsync(HttpClient admin, params string[] redirectUris)
    {
        var api = TestApi.Unique("api");
        var client = TestApi.Unique("web");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" }, requestable = true });
        await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = client, clientType = "public",
            grantTypes = redirectUris.Length > 0 ? new[] { "password", "refresh_token", "authorization_code" } : new[] { "password", "refresh_token" },
            redirectUris, scopes = new[] { "profile", api }
        });
        return (api, client);
    }

    private static async Task<(Guid Id, string Name)> UserAsync(HttpClient admin, string api, bool mustChange = false)
    {
        var name = TestApi.Unique("u");
        var created = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = name, email = $"{name}@it.local", password = Password, mustChangePassword = mustChange,
            roles = new[] { new { clientId = api, role = "reader" } }
        });
        return (created.GetProperty("user").GetProperty("id").GetGuid(), name);
    }

    private static Task<JsonElement> LoginAsync(HttpClient http, string client, string api, string user, bool expectSuccess = true) =>
        http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = user, ["password"] = Password,
            ["scope"] = $"openid offline_access {api}"
        }, expectSuccess);

    private static Task<JsonElement> RefreshAsync(HttpClient http, string client, string refresh, bool expectSuccess = true) =>
        http.TokenAsync(new() { ["grant_type"] = "refresh_token", ["client_id"] = client, ["refresh_token"] = refresh }, expectSuccess);

    /// <summary>Меняет настройки в БД на время действия и возвращает их прежнее значение при Dispose.</summary>
    private async Task<IAsyncDisposable> WithSettingsAsync(HttpClient admin, Action<JsonNode> change)
    {
        var original = (await admin.GetJsonAsync("/api/admin/settings")).GetRawText();
        var updated = JsonNode.Parse(original)!;
        change(updated);
        await (await admin.PutAsJsonAsync("/api/admin/settings", updated)).JsonAsync();
        return new Restore(async () => await (await admin.PutAsJsonAsync("/api/admin/settings", JsonNode.Parse(original))).JsonAsync());
    }

    private sealed class Restore(Func<Task> action) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync() => await action();
    }

    private static JsonNode Section(JsonNode settings, string name) => settings[name] ??= new JsonObject();

    // ---------- Лимиты частоты (M2, M32) ----------

    [Fact]
    public async Task RateLimit_TokenIntrospectRevoke_Return429()
    {
        using var limited = fx.Factory.WithWebHostBuilder(b => b.UseSetting("Security:TokenRequestsPerMinute", "3"));
        var http = limited.CreateClient();
        foreach (var path in new[] { "/connect/token", "/connect/introspect", "/connect/revoke" })
        {
            var codes = new List<HttpStatusCode>();
            for (var i = 0; i < 6; i++)
                codes.Add((await http.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = "nobody", ["client_secret"] = "guess-" + i, ["token"] = "x", ["grant_type"] = "client_credentials"
                }))).StatusCode);
            Assert.Contains(HttpStatusCode.TooManyRequests, codes);
        }
    }

    // ---------- Refresh (M1, L4, M32) ----------

    [Fact]
    public async Task Refresh_ReuseWithinLeeway_IsAccepted()
    {
        using var lenient = fx.Factory.WithWebHostBuilder(b => b.UseSetting("Auth:RefreshTokenReuseLeewaySeconds", "30"));
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await AppsAsync(admin);
        var (_, user) = await UserAsync(admin, api);
        var http = lenient.CreateClient();
        var first = await LoginAsync(http, client, api, user);
        var refresh = first.GetProperty("refresh_token").GetString()!;
        await RefreshAsync(http, client, refresh);
        // Повтор того же refresh-токена (сетевой ретрай клиента) в пределах окна — принимается.
        var retry = await RefreshAsync(http, client, refresh);
        Assert.True(retry.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task Refresh_WithForeignClient_IsRejected()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await AppsAsync(admin);
        var (_, other) = await AppsAsync(admin);
        var (_, user) = await UserAsync(admin, api);
        var http = fx.Factory.CreateClient();
        var tokens = await LoginAsync(http, client, api, user);
        var foreign = await RefreshAsync(http, other, tokens.GetProperty("refresh_token").GetString()!, expectSuccess: false);
        Assert.Equal("invalid_grant", foreign.GetProperty("error").GetString());
    }

    [Fact]
    public async Task M1_Refresh_WithTemporaryPassword_IsRejected()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await AppsAsync(admin);
        var (userId, user) = await UserAsync(admin, api);
        var http = fx.Factory.CreateClient();
        var tokens = await LoginAsync(http, client, api, user);

        // Признак «сменить пароль» появился уже после входа (без отзыва сессий) — продление всё равно запрещено.
        using (var scope = fx.Factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.Where(u => u.Id == userId)
                .ExecuteUpdateAsync(u => u.SetProperty(x => x.MustChangePassword, true));
        var refreshed = await RefreshAsync(http, client, tokens.GetProperty("refresh_token").GetString()!, expectSuccess: false);
        Assert.Equal("invalid_grant", refreshed.GetProperty("error").GetString());
    }

    [Fact]
    public async Task L4_Refresh_AfterMaxSessionDays_IsRejected()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await AppsAsync(admin);
        var (userId, user) = await UserAsync(admin, api);
        var http = fx.Factory.CreateClient();
        var tokens = await LoginAsync(http, client, api, user);

        // Сессия «началась» 100 дней назад (по умолчанию MaxSessionDays = 90).
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var subject = userId.ToString();
            await db.Set<OpenIddictEntityFrameworkCoreAuthorization<Guid>>().Where(a => a.Subject == subject)
                .ExecuteUpdateAsync(a => a.SetProperty(x => x.CreationDate, DateTime.UtcNow.AddDays(-100)));
        }
        var refreshed = await RefreshAsync(http, client, tokens.GetProperty("refresh_token").GetString()!, expectSuccess: false);
        Assert.Equal("invalid_grant", refreshed.GetProperty("error").GetString());
    }

    // ---------- Права ролей администрирования (M32) ----------

    private async Task<HttpClient> ServiceClientAsync(HttpClient admin, string role)
    {
        var client = TestApi.Unique(role);
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = client, clientType = "confidential", grantTypes = new[] { "client_credentials" }, scopes = new[] { SystemApp.ClientId }
        });
        await admin.PutJsonAsync($"/api/admin/applications/{client}/service-roles", new[] { new { clientId = SystemApp.ClientId, role } });
        var token = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = client,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["scope"] = SystemApp.ClientId
        });
        return fx.Factory.CreateClient().WithBearer(token.GetProperty("access_token").GetString()!);
    }

    [Fact]
    public async Task AdminRoles_AuditorReadsOnly_NotifierSeesOwnSubscriptions()
    {
        var admin = await fx.Factory.AdminAsync();
        var auditor = await ServiceClientAsync(admin, SystemApp.AuditorRole);
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync("/api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsJsonAsync("/api/admin/users",
            new { userName = TestApi.Unique("x"), password = Password })).StatusCode);

        var foreign = await admin.PostJsonAsync("/api/admin/webhooks",
            new { name = "admin-hook", url = "https://hooks.corp/admin", events = new[] { "*" } });
        var notifier = await ServiceClientAsync(admin, SystemApp.NotifierRole);
        var own = await notifier.PostJsonAsync("/api/admin/webhooks",
            new { name = "bot-hook", url = "https://hooks.corp/bot", events = new[] { "*" } });
        var visible = await notifier.GetJsonAsync("/api/admin/webhooks");
        Assert.Contains(visible.EnumerateArray(), s => s.GetProperty("id").GetGuid() == own.GetProperty("id").GetGuid());
        Assert.DoesNotContain(visible.EnumerateArray(), s => s.GetProperty("id").GetGuid() == foreign.GetProperty("id").GetGuid());
        Assert.Equal(HttpStatusCode.NotFound, (await notifier.DeleteAsync($"/api/admin/webhooks/{foreign.GetProperty("id").GetGuid()}")).StatusCode);

        // M6: подписка на адрес самого сервера или метаданные облака отклоняется.
        foreach (var url in new[] { "http://localhost:8080/x", "http://169.254.169.254/latest/meta-data" })
            Assert.Equal(HttpStatusCode.BadRequest, (await notifier.PostAsJsonAsync("/api/admin/webhooks",
                new { name = "ssrf", url, events = new[] { "*" } })).StatusCode);
    }

    // ---------- PAT (L10, M32) ----------

    private static Task<JsonElement> PatExchangeAsync(HttpClient http, string secret) =>
        http.TokenAsync(new() { ["grant_type"] = "urn:tsl:grant-type:pat", ["client_id"] = "tsl-pat", ["token"] = secret }, expectSuccess: false);

    [Fact]
    public async Task Pat_Expired_Disabled_Limited_AndRolesRechecked()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await AppsAsync(admin);
        var (api2, _) = await AppsAsync(admin);
        await admin.PostJsonAsync($"/api/admin/applications/{api2}/roles", new { name = "other" });
        var (userId, _) = await UserAsync(admin, api);
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", new[]
        {
            new { clientId = api, role = "reader" }, new { clientId = api2, role = "other" }
        });
        var http = fx.Factory.CreateClient();

        string secret;
        using (var scope = fx.Factory.Services.CreateScope())
            (_, secret) = await scope.ServiceProvider.GetRequiredService<PatService>().CreateAsync(userId, new PatInput("both", [api, api2], 30));

        // L10: роль в api2 снята — JWT по PAT больше не адресован api2.
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", new[] { new { clientId = api, role = "reader" } });
        var jwt = await PatExchangeAsync(http, secret);
        var aud = TestApi.Claims(jwt.GetProperty("access_token").GetString()!).Strings("aud");
        Assert.Contains(api, aud);
        Assert.DoesNotContain(api2, aud);

        // Без ролей ни в одном приложении токена — отказ.
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", Array.Empty<object>());
        Assert.Equal("invalid_grant", (await PatExchangeAsync(http, secret)).GetProperty("error").GetString());
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", new[] { new { clientId = api, role = "reader" } });

        // Истёкший токен.
        using (var scope = fx.Factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().PersonalAccessTokens.Where(t => t.UserId == userId)
                .ExecuteUpdateAsync(t => t.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddMinutes(-1)));
        Assert.Equal("invalid_grant", (await PatExchangeAsync(http, secret)).GetProperty("error").GetString());

        // Лимит токенов и отключение PAT политикой.
        await using (await WithSettingsAsync(admin, s => Section(s, "patPolicy")["maxTokensPerUser"] = 1))
        {
            using var scope = fx.Factory.Services.CreateScope();
            var pats = scope.ServiceProvider.GetRequiredService<PatService>();
            await pats.CreateAsync(userId, new PatInput("one", [api], 30));
            var limit = await Assert.ThrowsAsync<AdminException>(() => pats.CreateAsync(userId, new PatInput("two", [api], 30)));
            Assert.Equal("error.tokenLimit", limit.Key);
        }
        string fresh;
        using (var scope = fx.Factory.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().PersonalAccessTokens.Where(t => t.UserId == userId)
                .ExecuteUpdateAsync(t => t.SetProperty(x => x.RevokedAt, DateTime.UtcNow));
            (_, fresh) = await scope.ServiceProvider.GetRequiredService<PatService>().CreateAsync(userId, new PatInput("fresh", [api], 30));
        }
        await using (await WithSettingsAsync(admin, s => Section(s, "patPolicy")["enabled"] = false))
            Assert.Equal("invalid_grant", (await PatExchangeAsync(http, fresh)).GetProperty("error").GetString());
    }

    // ---------- Доставка вебхука с подписью (M32) ----------

    private sealed class CapturingHandler(string host) : HttpMessageHandler
    {
        public readonly TaskCompletionSource<(string Body, string? Signature, string? Event)> Received =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = await request.Content!.ReadAsStringAsync(ct);
            var type = request.Headers.TryGetValues("X-TSL-Event", out var e) ? e.First() : null;
            // Тестовое событие уходит во все подписки — ловим только доставку в свою.
            if (type == WebhookEvents.Test && request.RequestUri?.Host == host)
                Received.TrySetResult((body, request.Headers.TryGetValues("X-TSL-Signature", out var s) ? s.First() : null, type));
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    [Fact]
    public async Task WebhookDelivery_IsSignedWithSubscriptionSecret()
    {
        var admin = await fx.Factory.AdminAsync();
        var host = $"hooks-{Guid.NewGuid():N}.corp";
        const string secret = "whsec-coverage";
        var subscription = await admin.PostJsonAsync("/api/admin/webhooks", new
        {
            name = "signed", url = $"https://{host}/in", events = new[] { WebhookEvents.Test }, secret
        });
        (await admin.PostAsync("/api/admin/webhooks/test", null)).EnsureSuccessStatusCode();

        // Отправка одной доставки тем же кодом диспетчера, но с HTTP-заглушкой — без гонки с фоновым диспетчером
        // тестового сервиса за очередь (он работает с настоящей сетью).
        var capture = new CapturingHandler(host);
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var subscriptionId = subscription.GetProperty("id").GetGuid();
            var delivery = await db.WebhookDeliveries.Include(d => d.Subscription).Include(d => d.Event)
                .FirstAsync(d => d.SubscriptionId == subscriptionId);
            var dispatcher = new WebhookDispatcher(fx.Factory.Services.GetRequiredService<IServiceScopeFactory>(),
                new StubHttpClientFactory(capture), Microsoft.Extensions.Logging.Abstractions.NullLogger<WebhookDispatcher>.Instance);
            await dispatcher.SendAsync(delivery, CancellationToken.None);
            Assert.Equal(WebhookDeliveryStatus.Succeeded, delivery.Status);
        }

        var (body, signature, type) = await capture.Received.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(WebhookEvents.Test, type);
        Assert.Equal(WebhookService.Sign(secret, body), signature);
        using var payload = JsonDocument.Parse(body);
        Assert.Equal(WebhookEvents.Test, payload.RootElement.GetProperty("event").GetString());
    }

    // ---------- CORS и заголовки безопасности (M32) ----------

    [Fact]
    public async Task Cors_AllowsOnlyRegisteredSpaOrigins()
    {
        var admin = await fx.Factory.AdminAsync();
        var spaOrigin = $"https://spa-{Guid.NewGuid():N}.example";
        await AppsAsync(admin, $"{spaOrigin}/callback");
        var http = fx.Factory.CreateClient();

        async Task<string?> PreflightAsync(string origin)
        {
            var request = new HttpRequestMessage(HttpMethod.Options, "/connect/token");
            request.Headers.Add("Origin", origin);
            request.Headers.Add("Access-Control-Request-Method", "POST");
            var response = await http.SendAsync(request);
            return response.Headers.TryGetValues("Access-Control-Allow-Origin", out var v) ? v.First() : null;
        }

        Assert.Equal(spaOrigin, await PreflightAsync(spaOrigin));
        Assert.Null(await PreflightAsync("https://evil.example"));
    }

    [Fact]
    public async Task SecurityHeaders_ArePresent()
    {
        var response = await fx.Factory.CreateClient().GetAsync("/Account/Login");
        string Header(string name) => string.Join(";", response.Headers.TryGetValues(name, out var v) ? v : []);
        var csp = Header("Content-Security-Policy");
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        Assert.Equal("DENY", Header("X-Frame-Options"));
        Assert.Equal("nosniff", Header("X-Content-Type-Options"));
        Assert.Equal("no-referrer", Header("Referrer-Policy"));
    }

    // ---------- Приглашение по ссылке (M32) ----------

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    [Fact]
    public async Task Invite_AcceptViaLink_SetsPassword()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await AppsAsync(admin);
        var name = TestApi.Unique("inv");
        var created = await admin.PostJsonAsync("/api/admin/users?invite=true", new
        {
            userName = name, email = $"{name}@it.local", roles = new[] { new { clientId = api, role = "reader" } }
        });
        var link = new Uri(created.GetProperty("invite").GetProperty("link").GetString()!);
        var browser = fx.Factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        var page = link.PathAndQuery;
        var html = await (await browser.GetAsync(page)).Content.ReadAsStringAsync();
        var token = WebUtility.HtmlDecode(AntiforgeryField().Match(html).Groups[1].Value);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(link.Query);
        var accepted = await browser.PostAsync(page, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Uid"] = query["uid"]!, ["Token"] = query["token"]!, ["Password"] = Password, ["Confirm"] = Password,
            ["__RequestVerificationToken"] = token
        }));
        Assert.True(accepted.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK, $"{(int)accepted.StatusCode}");
        Assert.True((await LoginAsync(fx.Factory.CreateClient(), client, api, name)).TryGetProperty("access_token", out _));

        // Ссылка одноразовая.
        var another = TestApi.NewPassword();
        var again = await browser.PostAsync(page, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Uid"] = query["uid"]!, ["Token"] = query["token"]!, ["Password"] = another, ["Confirm"] = another,
            ["__RequestVerificationToken"] = token
        }));
        Assert.NotEqual(HttpStatusCode.Redirect, again.StatusCode);
    }

    // ---------- Лимит сбросов через бота (M16, M32) ----------

    [Fact]
    public async Task BotReset_IsLimitedPerHour()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await AppsAsync(admin);
        var (userId, _) = await UserAsync(admin, api);
        var bot = await ServiceClientAsync(admin, SystemApp.ResetBotRole);
        string code;
        using (var scope = fx.Factory.Services.CreateScope())
            (code, _) = await scope.ServiceProvider.GetRequiredService<BotService>().CreateLinkCodeAsync(userId);
        var externalId = TestApi.Unique("ext");
        await bot.PostJsonAsync("/api/bot/link", new { provider = "mattermost", externalId = $"  {externalId}  ", code }); // L20: пробелы

        await using (await WithSettingsAsync(admin, s => Section(s, "botResetPolicy")["maxPerUserPerHour"] = 1))
        {
            await bot.PostJsonAsync("/api/bot/password-reset", new { provider = "mattermost", externalId });
            var second = await bot.PostAsJsonAsync("/api/bot/password-reset", new { provider = "mattermost", externalId });
            Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        }
    }

    // ---------- Регистрация без взаимной блокировки на SQLite (регрессия M13) ----------

    [Fact]
    public async Task SelfRegistration_WithRequest_CompletesQuickly()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await AppsAsync(admin);
        await admin.PutJsonAsync($"/api/admin/applications/{client}", new
        {
            clientId = client, clientType = "public", grantTypes = new[] { "password", "refresh_token" },
            scopes = new[] { "profile", api }, selfRegistration = true
        });
        var watch = System.Diagnostics.Stopwatch.StartNew();
        using (var scope = fx.Factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<AccessRequestService>().RegisterAsync(client,
                new RegistrationInput(TestApi.Unique("reg"), null, null, Password, [new RoleRef(api, "reader")], "быстро"));
        // Регистрация публикует события в отдельном соединении БД; внутри общей транзакции на SQLite это ждало
        // снятия блокировки записи ~30 с (UI-тест упирался в таймаут).
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"Регистрация заняла {watch.Elapsed.TotalSeconds:F1} с");
    }

    // ---------- Кабинет с временным паролем (M3) ----------

    [Fact]
    public async Task M3_AccountPages_RequirePasswordChange()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await AppsAsync(admin);
        var (_, user) = await UserAsync(admin, api, mustChange: true);
        var browser = fx.Factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        var html = await (await browser.GetAsync("/Account/Login")).Content.ReadAsStringAsync();
        var token = WebUtility.HtmlDecode(AntiforgeryField().Match(html).Groups[1].Value);
        await browser.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Login"] = user, ["Password"] = Password, ["__RequestVerificationToken"] = token
        }));
        foreach (var page in new[] { "/Account/Tokens", "/Account/Messenger", "/Account/RequestAccess" })
        {
            var response = await browser.GetAsync(page);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Contains("/Account/ChangePassword", response.Headers.Location!.ToString());
        }
    }

    // ---------- App API (M7, M8) ----------

    [Fact]
    public async Task AppApi_HidesForeignProfiles_AndAppliesProfileChanges()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await AppsAsync(admin);
        var (_, stranger) = await UserAsync(admin, api);

        var app = TestApi.Unique("selfapp");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = app, clientType = "confidential", grantTypes = Array.Empty<string>(), selfManagement = true
        });
        var token = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = app,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["scope"] = SystemApp.AppApiScope
        });
        var self = fx.Factory.CreateClient().WithBearer(token.GetProperty("access_token").GetString()!);
        await self.PostJsonAsync("/api/app/roles", new { name = "support", displayName = "Поддержка" });

        // M7: привязанный «чужой» пользователь — без email и флагов.
        var linked = await self.PostJsonAsync("/api/app/users/link", new { login = stranger, roles = new[] { "support" } });
        Assert.Equal(JsonValueKind.Null, linked.GetProperty("email").ValueKind);
        Assert.False(linked.GetProperty("createdByThisApp").GetBoolean());

        // M8: у своего пользователя смена email сбрасывает подтверждение, переданный пароль применяется.
        var own = (await self.PostJsonAsync("/api/app/users", new { userName = TestApi.Unique("own"), email = $"{Guid.NewGuid():N}@it.local", roles = new[] { "support" } }))
            .GetProperty("user");
        var ownId = own.GetProperty("id").GetGuid();
        using (var scope = fx.Factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.Where(u => u.Id == ownId)
                .ExecuteUpdateAsync(u => u.SetProperty(x => x.EmailConfirmed, true));
        var appSet = TestApi.NewPassword();
        await self.PutJsonAsync($"/api/app/users/{ownId}", new
        {
            userName = own.GetProperty("userName").GetString(), email = $"{Guid.NewGuid():N}@it.local", password = appSet
        });
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var user = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.AsNoTracking().FirstAsync(u => u.Id == ownId);
            Assert.False(user.EmailConfirmed);
            Assert.True(await scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AppUser>>()
                .CheckPasswordAsync(user, appSet));
        }

        // M14: постранично с общим числом в заголовке.
        var page = await self.GetAsync("/api/app/users?take=1");
        Assert.Equal("2", page.Headers.GetValues("X-Total-Count").Single());
        Assert.Equal(1, (await page.JsonAsync()).GetArrayLength());
    }

    // ---------- Системные роли, удаление приложения, атомарность (M9, M12, M13) ----------

    [Fact]
    public async Task SystemRoles_CannotBeMadeRequestable_OrRenamed()
    {
        var admin = await fx.Factory.AdminAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.PutAsync(
            $"/api/admin/applications/{SystemApp.ClientId}/roles/{SystemApp.AdministratorRole}/requestable?value=true", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.PutAsJsonAsync(
            $"/api/admin/applications/{SystemApp.ClientId}/roles/{SystemApp.AdministratorRole}", new { displayName = "Хозяин" })).StatusCode);
    }

    [Fact]
    public async Task DeletingApplication_ReleasesOwnership_AndRoleCreationIsAtomic()
    {
        var admin = await fx.Factory.AdminAsync();
        var app = TestApi.Unique("owner");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = app, clientType = "confidential", grantTypes = Array.Empty<string>(), selfManagement = true
        });
        var token = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = app,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["scope"] = SystemApp.AppApiScope
        });
        var self = fx.Factory.CreateClient().WithBearer(token.GetProperty("access_token").GetString()!);

        // M13: роль с несуществующим разрешением не создаётся «наполовину».
        Assert.Equal(HttpStatusCode.NotFound, (await self.PostAsJsonAsync("/api/app/roles",
            new { name = "half", permissions = new[] { "missing" } })).StatusCode);
        Assert.DoesNotContain((await admin.GetJsonAsync($"/api/admin/applications/{app}/matrix")).GetProperty("roles").EnumerateArray(),
            r => r.GetProperty("name").GetString() == "half");

        var userId = (await self.PostJsonAsync("/api/app/users", new { userName = TestApi.Unique("owned") })).GetProperty("user").GetProperty("id").GetGuid();

        // M12: после удаления приложения пользователь больше никому не «принадлежит».
        (await admin.DeleteAsync($"/api/admin/applications/{app}")).EnsureSuccessStatusCode();
        using var scope = fx.Factory.Services.CreateScope();
        var owner = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.Where(u => u.Id == userId)
            .Select(u => u.CreatedByClientId).SingleAsync();
        Assert.Null(owner);
    }

    // ---------- История паролей, языковые пакеты (L3, L22) ----------

    [Fact]
    public async Task PasswordHistory_IsTrimmedToPolicy()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await AppsAsync(admin);
        var (userId, _) = await UserAsync(admin, api);
        await using (await WithSettingsAsync(admin, s => Section(s, "passwordPolicy")["historyCount"] = 2))
        {
            for (var i = 0; i < 5; i++)
                (await admin.PostAsJsonAsync($"/api/admin/users/{userId}/password", new { password = TestApi.NewPassword() })).EnsureSuccessStatusCode();
        }
        using var scope = fx.Factory.Services.CreateScope();
        Assert.Equal(2, await scope.ServiceProvider.GetRequiredService<AuthDbContext>().PasswordHistory.CountAsync(h => h.UserId == userId));
    }

    [Fact]
    public async Task LanguagePack_WithBrokenPlaceholder_IsRejected()
    {
        var admin = await fx.Factory.AdminAsync();
        var bad = await admin.PutAsJsonAsync("/api/admin/languages/de", new
        {
            name = "Deutsch", strings = new Dictionary<string, string> { ["policy.minLength"] = "mindestens {0 Zeichen" }
        });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
    }

    // ---------- Дубли ожидающих заявок при обновлении БД (L24) ----------

    [Fact]
    public async Task L24_DuplicatePendingRequests_AreClosedByMigration()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await AppsAsync(admin);
        var (userId, _) = await UserAsync(admin, api);
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", Array.Empty<object>());

        await fx.RestartAsync(async () =>
        {
            await using var db = fx.CreateDbContext();
            // Схема до индекса (предыдущая миграция) и две одинаковые ожидающие заявки — как в старой БД.
            await db.GetService<IMigrator>().MigrateAsync("RoleDisplayName");
            var roleId = await db.AccessRoles.Where(r => r.ClientId == api && r.Name == "reader").Select(r => r.Id).SingleAsync();
            db.AccessRequests.AddRange(
                new AccessRequest { UserId = userId, RoleId = roleId, CreatedAt = DateTime.UtcNow.AddMinutes(-2) },
                new AccessRequest { UserId = userId, RoleId = roleId, CreatedAt = DateTime.UtcNow.AddMinutes(-1) });
            await db.SaveChangesAsync();
        });

        var pending = await (await fx.Factory.AdminAsync()).GetJsonAsync($"/api/admin/access-requests?status=pending&clientId={api}");
        Assert.Equal(1, pending.EnumerateArray().Count(r => r.GetProperty("userId").GetGuid() == userId));
    }
}

/// <summary>Покрытие и регрессии ревизии на SQLite.</summary>
[Collection("sqlite-coverage")]
public sealed class SqliteReviewCoverage(SqliteFixture fx) : ReviewCoverageScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

/// <summary>Покрытие и регрессии ревизии на PostgreSQL.</summary>
[Collection("postgres-coverage")]
public sealed class PostgresReviewCoverage(PostgresFixture fx) : ReviewCoverageScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
