using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;
using TslAuth.Data;
using TslAuth.IntegrationTests.Infrastructure;
using TslAuth.Services;

namespace TslAuth.IntegrationTests;

/// <summary>Сквозные сценарии. Одинаковый набор выполняется на SQLite и на PostgreSQL.</summary>
public abstract class AuthScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    protected TFixture Fx => fx;
    private const string Password = "Str0ng-Passw0rd!";

    // ---------- Подготовка данных ----------

    /// <summary>Ресурс-API с матрицей: роли reader(read) и writer(read,write) + public-клиент с password/refresh.</summary>
    private async Task<(string Api, string Client)> CreateAppsAsync(HttpClient admin, bool selfRegistration = false)
    {
        var api = TestApi.Unique("api");
        var client = TestApi.Unique("web");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "write" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" }, requestable = true });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "writer", permissions = new[] { "read", "write" } });
        await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = client, clientType = "public", grantTypes = new[] { "password", "refresh_token" },
            scopes = new[] { "profile", api }, selfRegistration
        });
        return (api, client);
    }

    private async Task<(Guid Id, string Name)> CreateUserAsync(HttpClient admin, string api, string role)
    {
        var name = TestApi.Unique("user");
        var created = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = name, email = $"{name}@it.local", password = Password,
            roles = new[] { new { clientId = api, role } }
        });
        return (created.GetProperty("user").GetProperty("id").GetGuid(), name);
    }

    private Task<JsonElement> PasswordGrantAsync(HttpClient http, string client, string api, string user, string password = Password,
        bool expectSuccess = true, Dictionary<string, string>? extra = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = user, ["password"] = password,
            ["scope"] = $"openid offline_access {api}"
        };
        foreach (var (k, v) in extra ?? []) form[k] = v;
        return http.TokenAsync(form, expectSuccess);
    }

    private static Task<JsonElement> RefreshAsync(HttpClient http, string client, string refresh, bool expectSuccess = true) =>
        http.TokenAsync(new() { ["grant_type"] = "refresh_token", ["client_id"] = client, ["refresh_token"] = refresh }, expectSuccess);

    // ---------- OIDC / JWT ----------

    [Fact]
    public async Task Discovery_Jwks_And_SignatureValidation()
    {
        var http = fx.Factory.CreateClient();
        var discovery = await http.GetJsonAsync("/.well-known/openid-configuration");
        Assert.Equal("http://localhost/", discovery.GetProperty("issuer").GetString());
        var grants = discovery.GetProperty("grant_types_supported").EnumerateArray().Select(g => g.GetString()).ToList();
        Assert.Contains("urn:ietf:params:oauth:grant-type:token-exchange", grants);
        Assert.Contains("urn:tsl:grant-type:pat", grants);

        var jwks = new JsonWebKeySet(await http.GetStringAsync("/.well-known/jwks"));
        var admin = await fx.Factory.AdminAsync();
        var token = admin.DefaultRequestHeaders.Authorization!.Parameter!;
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "http://localhost/", ValidAudience = SystemApp.ClientId, IssuerSigningKeys = jwks.GetSigningKeys()
        });
        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task AdminApi_RequiresTokenAndRole()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await fx.Factory.CreateClient().GetAsync("/api/admin/users")).StatusCode);

        // Клиент без роли в tsl-auth-admin получает 403, даже со scope tsl-auth-admin.
        var admin = await fx.Factory.AdminAsync();
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = TestApi.Unique("norole"), clientType = "confidential", grantTypes = new[] { "client_credentials" },
            scopes = new[] { SystemApp.ClientId }
        });
        var client = created.GetProperty("application").GetProperty("clientId").GetString()!;
        var token = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = client,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["scope"] = SystemApp.ClientId
        });
        var noRole = fx.Factory.CreateClient().WithBearer(token.GetProperty("access_token").GetString()!);
        Assert.Equal(HttpStatusCode.Forbidden, (await noRole.GetAsync("/api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task PasswordGrant_Jwt_HasMatrixPermissions()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (_, user) = await CreateUserAsync(admin, api, "writer");

        var token = await PasswordGrantAsync(fx.Factory.CreateClient(), client, api, user);
        var claims = TestApi.Claims(token.GetProperty("access_token").GetString()!);
        Assert.Contains(api, claims.Strings("aud"));
        Assert.Contains($"{api}:read", claims.Strings("permissions"));
        Assert.Contains($"{api}:write", claims.Strings("permissions"));
        Assert.Contains($"{api}:writer", claims.Strings("role"));
        Assert.Equal("user", claims.GetProperty("subject_type").GetString());
        Assert.True(token.TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task Refresh_RotatesToken_AndReflectsMatrixChanges()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (userId, user) = await CreateUserAsync(admin, api, "reader");
        var http = fx.Factory.CreateClient();
        var first = await PasswordGrantAsync(http, client, api, user);
        Assert.DoesNotContain($"{api}:write", TestApi.Claims(first.GetProperty("access_token").GetString()!).Strings("permissions"));

        // Администратор повышает роль — новое право появляется при refresh, без повторного входа.
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", new[] { new { clientId = api, role = "writer" } });
        var second = await RefreshAsync(http, client, first.GetProperty("refresh_token").GetString()!);
        Assert.Contains($"{api}:write", TestApi.Claims(second.GetProperty("access_token").GetString()!).Strings("permissions"));

        // Ротация: использованный refresh-токен повторно не принимается.
        var reuse = await RefreshAsync(http, client, first.GetProperty("refresh_token").GetString()!, expectSuccess: false);
        Assert.Equal("invalid_grant", reuse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task DeactivatedUser_CannotRefresh()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (userId, user) = await CreateUserAsync(admin, api, "reader");
        var http = fx.Factory.CreateClient();
        var token = await PasswordGrantAsync(http, client, api, user);

        await admin.PutJsonAsync($"/api/admin/users/{userId}", new { userName = user, isActive = false });
        var refresh = await RefreshAsync(http, client, token.GetProperty("refresh_token").GetString()!, expectSuccess: false);
        Assert.Equal("invalid_grant", refresh.GetProperty("error").GetString());
        var login = await PasswordGrantAsync(http, client, api, user, expectSuccess: false);
        Assert.Equal("invalid_grant", login.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RevokedSession_CannotRefresh()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (userId, user) = await CreateUserAsync(admin, api, "reader");
        var http = fx.Factory.CreateClient();
        var token = await PasswordGrantAsync(http, client, api, user);

        var sessions = await admin.GetJsonAsync($"/api/admin/sessions?subject={userId}");
        Assert.Equal(1, sessions.GetArrayLength());
        (await admin.DeleteAsync($"/api/admin/sessions/{sessions[0].GetProperty("id").GetGuid()}")).EnsureSuccessStatusCode();

        var refresh = await RefreshAsync(http, client, token.GetProperty("refresh_token").GetString()!, expectSuccess: false);
        Assert.Equal("invalid_grant", refresh.GetProperty("error").GetString());
    }

    [Fact]
    public async Task WrongPassword_LocksOut_AndIsAudited()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (userId, user) = await CreateUserAsync(admin, api, "reader");
        var http = fx.Factory.CreateClient();
        for (var i = 0; i < 5; i++) await PasswordGrantAsync(http, client, api, user, "wrong", expectSuccess: false);

        // Даже верный пароль не принимается; текст ошибки тот же, что для неверного пароля (не раскрывает существование).
        var locked = await PasswordGrantAsync(http, client, api, user, expectSuccess: false);
        Assert.Equal("invalid_grant", locked.GetProperty("error").GetString());
        Assert.False(locked.TryGetProperty("access_token", out _));

        var audit = await admin.GetJsonAsync($"/api/admin/audit?userId={userId}&type=auth.");
        Assert.Contains(audit.EnumerateArray(), e => e.GetProperty("type").GetString() == AuditTypes.LockedOut);
        Assert.Contains(audit.EnumerateArray(), e => e.GetProperty("type").GetString() == AuditTypes.LoginFailed);
    }

    [Fact]
    public async Task TemporaryPassword_MustBeChangedBeforeTokens()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (userId, user) = await CreateUserAsync(admin, api, "reader");
        var temp = (await admin.PostJsonAsync($"/api/admin/users/{userId}/temporary-password", new { })).GetProperty("password").GetString()!;

        var result = await PasswordGrantAsync(fx.Factory.CreateClient(), client, api, user, temp, expectSuccess: false);
        Assert.Equal("invalid_grant", result.GetProperty("error").GetString());
        Assert.Contains("временный", result.GetProperty("error_description").GetString());
    }

    // ---------- Token exchange ----------

    [Fact]
    public async Task TokenExchange_KeepsUser_UsesTargetMatrix_AddsActor()
    {
        var admin = await fx.Factory.AdminAsync();
        var (target, _) = await CreateAppsAsync(admin);
        var (userApi, client) = await CreateAppsAsync(admin);

        // Промежуточный сервис: confidential, token exchange, может запрашивать scope целевого API.
        var middle = TestApi.Unique("middle");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = middle, clientType = "confidential", grantTypes = new[] { "token_exchange" }, scopes = new[] { target }
        });
        await admin.PutJsonAsync($"/api/admin/applications/{client}", new
        {
            clientId = client, clientType = "public", grantTypes = new[] { "password", "refresh_token" },
            scopes = new[] { "profile", userApi, middle }
        });
        var (userId, user) = await CreateUserAsync(admin, userApi, "reader");
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", new[]
        {
            new { clientId = userApi, role = "reader" }, new { clientId = target, role = "writer" }
        });

        var http = fx.Factory.CreateClient();
        var userToken = (await http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = user, ["password"] = Password, ["scope"] = middle
        })).GetProperty("access_token").GetString()!;

        var exchanged = await http.TokenAsync(new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["client_id"] = middle,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["subject_token"] = userToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token", ["scope"] = target
        });
        var claims = TestApi.Claims(exchanged.GetProperty("access_token").GetString()!);
        Assert.Equal(user, claims.GetProperty("preferred_username").GetString());
        Assert.Contains(target, claims.Strings("aud"));
        Assert.Contains($"{target}:write", claims.Strings("permissions"));
        Assert.Equal(middle, claims.GetProperty("act").GetProperty("sub").GetString());

        // Токен, выданный НЕ для промежуточного сервиса, обменять нельзя.
        var foreign = (await http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = user, ["password"] = Password, ["scope"] = userApi
        })).GetProperty("access_token").GetString()!;
        var rejected = await http.TokenAsync(new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["client_id"] = middle,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["subject_token"] = foreign,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token", ["scope"] = target
        }, expectSuccess: false);
        Assert.True(rejected.TryGetProperty("error", out _));
    }

    // ---------- Сроки жизни ----------

    [Fact]
    public async Task TokenLifetime_ClientCanShorten_ButNotExtend()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (_, user) = await CreateUserAsync(admin, api, "reader");
        var http = fx.Factory.CreateClient();

        var shorter = await PasswordGrantAsync(http, client, api, user, extra: new() { ["expires_in"] = "60" });
        Assert.InRange(shorter.GetProperty("expires_in").GetInt32(), 55, 60);

        var longer = await PasswordGrantAsync(http, client, api, user, extra: new() { ["expires_in"] = "999999" });
        Assert.InRange(longer.GetProperty("expires_in").GetInt32(), 850, 900); // глобальный максимум 15 минут

        // Переопределение приложения тоже ограничено глобальным значением.
        var tooLong = await admin.PutAsJsonAsync($"/api/admin/applications/{client}/token-lifetimes", new { accessTokenMinutes = 60 });
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
        await admin.PutJsonAsync($"/api/admin/applications/{client}/token-lifetimes", new { accessTokenMinutes = 2 });
        var appCapped = await PasswordGrantAsync(http, client, api, user);
        Assert.InRange(appCapped.GetProperty("expires_in").GetInt32(), 115, 120);
    }

    // ---------- App API ----------

    [Fact]
    public async Task AppApi_SeesOnlyItsOwnSlice()
    {
        var admin = await fx.Factory.AdminAsync();
        var (otherApi, _) = await CreateAppsAsync(admin);
        var (_, stranger) = await CreateUserAsync(admin, otherApi, "reader");

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

        await self.PostJsonAsync("/api/app/permissions", new { name = "tickets.read" });
        await self.PostJsonAsync("/api/app/roles", new { name = "support", permissions = new[] { "tickets.read" } });
        var createdUser = await self.PostJsonAsync("/api/app/users", new { userName = TestApi.Unique("own"), roles = new[] { "support" } });
        Assert.False(string.IsNullOrEmpty(createdUser.GetProperty("temporaryPassword").GetString()));

        var list = await self.GetJsonAsync("/api/app/users");
        Assert.Equal(1, list.GetArrayLength());
        Assert.DoesNotContain(list.EnumerateArray(), u => u.GetProperty("userName").GetString() == stranger);

        // Чужие роли назначить нельзя, admin API недоступен.
        var foreignRole = await self.PutAsJsonAsync($"/api/app/users/{createdUser.GetProperty("user").GetProperty("id")}/roles", new[] { "reader" });
        Assert.Equal(HttpStatusCode.NotFound, foreignRole.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await self.GetAsync("/api/admin/users")).StatusCode);

        // Приложение видит в журнале только свои события.
        var audit = await self.GetJsonAsync("/api/app/audit");
        Assert.All(audit.EnumerateArray(), e => Assert.Equal(app, e.GetProperty("clientId").GetString()));

        // Удаление своего пользователя — полное; привязка существующего — только отвязка.
        var own = createdUser.GetProperty("user").GetProperty("id").GetGuid();
        Assert.True((await (await self.DeleteAsync($"/api/app/users/{own}")).JsonAsync()).GetProperty("deleted").GetBoolean());
        await self.PostJsonAsync("/api/app/users/link", new { login = stranger, roles = new[] { "support" } });
        var linked = (await self.GetJsonAsync("/api/app/users"))[0].GetProperty("id").GetGuid();
        var unlink = await (await self.DeleteAsync($"/api/app/users/{linked}")).JsonAsync();
        Assert.False(unlink.GetProperty("deleted").GetBoolean());
        Assert.Equal(1, (await admin.GetJsonAsync($"/api/admin/users?search={stranger}")).GetProperty("total").GetInt32());
    }

    // ---------- Политика паролей ----------

    [Fact]
    public async Task PasswordPolicy_FromDatabase_IsEnforced()
    {
        var admin = await fx.Factory.AdminAsync();
        var settings = await admin.GetJsonAsync("/api/admin/settings");
        try
        {
            await admin.PutAsJsonAsync("/api/admin/settings", new
            {
                auditRetentionDays = 365, eventsRetentionDays = 30, tokensRetentionHours = 24,
                passwordPolicy = new { minLength = 12, requireUppercase = true, requireLowercase = true, requireDigit = true,
                    requireSymbol = true, minUniqueChars = 6, historyCount = 2, maxAgeDays = 0, maxFailedAttempts = 5, lockoutMinutes = 15 }
            });
            var weak = await admin.PostAsJsonAsync("/api/admin/users", new { userName = TestApi.Unique("weak"), password = "Short1!" });
            Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);

            var user = await admin.PostJsonAsync("/api/admin/users", new { userName = TestApi.Unique("strong"), password = "Very-Str0ng-Pass" });
            var id = user.GetProperty("user").GetProperty("id").GetGuid();
            (await admin.PostAsJsonAsync($"/api/admin/users/{id}/password", new { password = "Another-Str0ng-1" })).EnsureSuccessStatusCode();
            var reused = await admin.PostAsJsonAsync($"/api/admin/users/{id}/password", new { password = "Very-Str0ng-Pass" });
            Assert.Equal(HttpStatusCode.BadRequest, reused.StatusCode); // история паролей
        }
        finally
        {
            await admin.PutAsJsonAsync("/api/admin/settings", settings);
        }
    }

    // ---------- PAT ----------

    [Fact]
    public async Task PersonalAccessToken_ExchangesForJwt_AndCanBeRevoked()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await CreateAppsAsync(admin);
        var (userId, _) = await CreateUserAsync(admin, api, "reader");

        string secret;
        using (var scope = fx.Factory.Services.CreateScope())
            (_, secret) = await scope.ServiceProvider.GetRequiredService<PatService>()
                .CreateAsync(userId, new PatInput("ci", [api], 30));

        var http = fx.Factory.CreateClient();
        var token = await http.TokenAsync(new() { ["grant_type"] = "urn:tsl:grant-type:pat", ["client_id"] = "tsl-pat", ["token"] = secret });
        var claims = TestApi.Claims(token.GetProperty("access_token").GetString()!);
        Assert.Contains(api, claims.Strings("aud"));
        Assert.Contains($"{api}:read", claims.Strings("permissions"));
        Assert.True(claims.TryGetProperty("pat_id", out var patId));

        (await admin.DeleteAsync($"/api/admin/users/{userId}/tokens/{patId.GetString()}")).EnsureSuccessStatusCode();
        var revoked = await http.TokenAsync(new() { ["grant_type"] = "urn:tsl:grant-type:pat", ["client_id"] = "tsl-pat", ["token"] = secret },
            expectSuccess: false);
        Assert.Equal("invalid_grant", revoked.GetProperty("error").GetString());
    }

    // ---------- Бот ----------

    [Fact]
    public async Task Bot_LinkAndResetPassword()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await CreateAppsAsync(admin);
        var (userId, user) = await CreateUserAsync(admin, api, "reader");

        var bot = TestApi.Unique("bot");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = bot, clientType = "confidential", grantTypes = new[] { "client_credentials" }, scopes = new[] { SystemApp.ClientId }
        });
        await admin.PutJsonAsync($"/api/admin/applications/{bot}/service-roles", new[] { new { clientId = SystemApp.ClientId, role = SystemApp.ResetBotRole } });
        var botToken = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = bot,
            ["client_secret"] = created.GetProperty("clientSecret").GetString()!, ["scope"] = SystemApp.ClientId
        });
        var botHttp = fx.Factory.CreateClient().WithBearer(botToken.GetProperty("access_token").GetString()!);

        // Боту нельзя в admin API — только /api/bot.
        Assert.Equal(HttpStatusCode.Forbidden, (await botHttp.GetAsync("/api/admin/users")).StatusCode);

        var notLinked = await botHttp.PostAsJsonAsync("/api/bot/password-reset", new { provider = "mattermost", externalId = "u-1" });
        Assert.Equal(HttpStatusCode.NotFound, notLinked.StatusCode);

        string code;
        using (var scope = fx.Factory.Services.CreateScope())
            (code, _) = await scope.ServiceProvider.GetRequiredService<BotService>().CreateLinkCodeAsync(userId);

        var bad = await botHttp.PostAsJsonAsync("/api/bot/link", new { provider = "mattermost", externalId = "u-1", code = "WRONG123" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        await botHttp.PostJsonAsync("/api/bot/link", new { provider = "mattermost", externalId = "u-1", code });

        var who = await botHttp.PostJsonAsync("/api/bot/whois", new { provider = "mattermost", externalId = "u-1" });
        Assert.Equal(user, who.GetProperty("userName").GetString());

        var reset = await botHttp.PostJsonAsync("/api/bot/password-reset", new { provider = "mattermost", externalId = "u-1" });
        Assert.Equal("link", reset.GetProperty("mode").GetString());
        Assert.Contains("/Account/ResetPassword?uid=", reset.GetProperty("resetLink").GetString());
    }

    [Fact]
    public async Task Bot_LockAndForcePasswordChange()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (officerId, officer) = await CreateUserAsync(admin, api, "reader");
        var (victimId, victim) = await CreateUserAsync(admin, api, "reader");
        var (bystanderId, bystander) = await CreateUserAsync(admin, api, "reader");

        // Бот безопасности: все три разрешения. Бот только со сбросом пароля в /lock не попадает.
        var bot = TestApi.Unique("secbot");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = bot, clientType = "confidential", grantTypes = new[] { "client_credentials" }, scopes = new[] { SystemApp.ClientId }
        });
        await admin.PutJsonAsync($"/api/admin/applications/{bot}/service-roles", new[] { new { clientId = SystemApp.ClientId, role = SystemApp.ResetBotRole } });
        var secret = created.GetProperty("clientSecret").GetString()!;
        async Task<HttpClient> BotHttpAsync()
        {
            var token = await fx.Factory.CreateClient().TokenAsync(new()
            {
                ["grant_type"] = "client_credentials", ["client_id"] = bot, ["client_secret"] = secret, ["scope"] = SystemApp.ClientId
            });
            return fx.Factory.CreateClient().WithBearer(token.GetProperty("access_token").GetString()!);
        }
        var botHttp = await BotHttpAsync();
        Assert.Equal(HttpStatusCode.Forbidden,
            (await botHttp.PostAsJsonAsync("/api/bot/lock", new { provider = "chat", externalId = "o-1" })).StatusCode);
        await admin.PutJsonAsync($"/api/admin/applications/{bot}/service-roles", new[] { new { clientId = SystemApp.ClientId, role = SystemApp.SecurityBotRole } });

        // Привязываем офицера и обычного пользователя.
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var s = scope.ServiceProvider.GetRequiredService<BotService>();
            var (c1, _) = await s.CreateLinkCodeAsync(officerId);
            await botHttp.PostJsonAsync("/api/bot/link", new { provider = "chat", externalId = "o-1", code = c1 });
            var (c2, _) = await s.CreateLinkCodeAsync(bystanderId);
            await botHttp.PostJsonAsync("/api/bot/link", new { provider = "chat", externalId = "b-1", code = c2 });
        }

        // Без роли security-officer чужую учётку заблокировать нельзя.
        Assert.Equal(HttpStatusCode.Forbidden,
            (await botHttp.PostAsJsonAsync("/api/bot/lock", new { provider = "chat", externalId = "o-1", target = victim })).StatusCode);
        await admin.PutJsonAsync($"/api/admin/users/{officerId}/roles",
            new[] { new { clientId = api, role = "reader" }, new { clientId = SystemApp.ClientId, role = SystemApp.SecurityOfficerRole } });

        // Офицер блокирует: пользователь перестаёт входить, refresh отзывается.
        var victimTokens = await PasswordGrantAsync(fx.Factory.CreateClient(), client, api, victim);
        var locked = await botHttp.PostJsonAsync("/api/bot/lock", new { provider = "chat", externalId = "o-1", target = victim });
        Assert.True(locked.GetProperty("changed").GetBoolean());
        Assert.False(locked.GetProperty("self").GetBoolean());
        Assert.False((await admin.GetJsonAsync($"/api/admin/users/{victimId}")).GetProperty("isActive").GetBoolean());
        await PasswordGrantAsync(fx.Factory.CreateClient(), client, api, victim, expectSuccess: false);
        await RefreshAsync(fx.Factory.CreateClient(), client, victimTokens.GetProperty("refresh_token").GetString()!, expectSuccess: false);

        // Себя разблокировать нельзя даже офицеру; чужого — можно.
        Assert.Equal(HttpStatusCode.Forbidden,
            (await botHttp.PostAsJsonAsync("/api/bot/unlock", new { provider = "chat", externalId = "o-1" })).StatusCode);
        var unlocked = await botHttp.PostJsonAsync("/api/bot/unlock", new { provider = "chat", externalId = "o-1", target = victim });
        Assert.True(unlocked.GetProperty("changed").GetBoolean());
        await PasswordGrantAsync(fx.Factory.CreateClient(), client, api, victim);

        // Принудительная смена пароля: флаг выставлен, вход по паролю через password grant запрещён до смены.
        var forced = await botHttp.PostJsonAsync("/api/bot/force-password-change", new { provider = "chat", externalId = "o-1", target = victim });
        Assert.Equal(victim, forced.GetProperty("userName").GetString());
        Assert.True((await admin.GetJsonAsync($"/api/admin/users/{victimId}")).GetProperty("mustChangePassword").GetBoolean());

        // Обычный пользователь: только над собой. Самоблокировка — сценарий «телефон украли».
        Assert.Equal(HttpStatusCode.Forbidden,
            (await botHttp.PostAsJsonAsync("/api/bot/force-password-change", new { provider = "chat", externalId = "b-1", target = officer })).StatusCode);
        var selfLock = await botHttp.PostJsonAsync("/api/bot/lock", new { provider = "chat", externalId = "b-1" });
        Assert.True(selfLock.GetProperty("self").GetBoolean());
        Assert.Equal(bystander, selfLock.GetProperty("userName").GetString());
        // Заблокированный отправитель больше ничего не может.
        Assert.Equal(HttpStatusCode.Forbidden,
            (await botHttp.PostAsJsonAsync("/api/bot/force-password-change", new { provider = "chat", externalId = "b-1" })).StatusCode);
    }

    // ---------- События ----------

    [Fact]
    public async Task Events_LongPolling_ReturnsNewEvents()
    {
        var admin = await fx.Factory.AdminAsync();
        var start = (await admin.GetJsonAsync("/api/admin/events?after=0&limit=500")).GetProperty("next").GetInt64();
        var pending = admin.GetJsonAsync($"/api/admin/events?after={start}&wait=15&types=user.created");
        await Task.Delay(300);
        await admin.PostJsonAsync("/api/admin/users", new { userName = TestApi.Unique("evt"), password = Password });

        var result = await pending;
        var events = result.GetProperty("events");
        Assert.True(events.GetArrayLength() >= 1);
        Assert.Equal("user.created", events[0].GetProperty("event").GetString());
        Assert.False(string.IsNullOrEmpty(events[0].GetProperty("text").GetString()));
    }

    // ---------- Заявки на доступ ----------

    [Fact]
    public async Task AccessRequest_ApprovalGrantsRole()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin, selfRegistration: true);

        Guid userId;
        using (var scope = fx.Factory.Services.CreateScope())
        {
            // Для приложения без флага самостоятельной регистрации регистрироваться нельзя.
            var ex = await Assert.ThrowsAsync<AdminException>(() => scope.ServiceProvider.GetRequiredService<AccessRequestService>()
                .RegisterAsync(api, new RegistrationInput(TestApi.Unique("x"), null, null, Password, [new RoleRef(api, "reader")], null)));
            Assert.Equal(StatusCodes.Status403Forbidden, ex.StatusCode);
        }
        await admin.PutJsonAsync($"/api/admin/applications/{api}", new { clientId = api, clientType = "public", selfRegistration = true });
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var requests = scope.ServiceProvider.GetRequiredService<AccessRequestService>();
            // Запросить можно только роль, помеченную как «запрашиваемая».
            var ex = await Assert.ThrowsAsync<AdminException>(() => requests.RegisterAsync(api,
                new RegistrationInput(TestApi.Unique("x"), null, null, Password, [new RoleRef(api, "writer")], null)));
            Assert.Contains("нельзя запросить", ex.Message);
            userId = await requests.RegisterAsync(api, new RegistrationInput(TestApi.Unique("reg"), null, null, Password, [new RoleRef(api, "reader")], "нужен доступ"));
        }

        var pending = await admin.GetJsonAsync($"/api/admin/access-requests?status=pending&clientId={api}");
        Assert.Equal(1, pending.GetArrayLength());
        Assert.Empty((await admin.GetJsonAsync($"/api/admin/users/{userId}/roles")).EnumerateArray());

        await admin.PostJsonAsync($"/api/admin/access-requests/{pending[0].GetProperty("id").GetGuid()}/approve", new { comment = "ok" });
        var roles = await admin.GetJsonAsync($"/api/admin/users/{userId}/roles");
        Assert.Contains(roles.EnumerateArray(), r => r.GetProperty("role").GetString() == "reader");
    }

    // ---------- Роли: техническое имя и название для пользователей ----------

    [Fact]
    public async Task Role_TechnicalNameForTokens_DisplayNameForUsers()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin, selfRegistration: true);

        // Техническое имя: только строчные латинские без пробелов; название — любой текст.
        foreach (var bad in new[] { "Manager", "orders manager", "менеджер", "app:role" })
        {
            var rejected = await admin.PostAsJsonAsync($"/api/admin/applications/{api}/roles", new { name = bad, displayName = "Роль" });
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        }
        var role = await admin.PostJsonAsync($"/api/admin/applications/{api}/roles",
            new { name = "orders-manager", displayName = "Менеджер по заказам", permissions = new[] { "read" }, requestable = true });
        Assert.Equal("orders-manager", role.GetProperty("name").GetString());
        Assert.Equal("Менеджер по заказам", role.GetProperty("displayName").GetString());

        // Техническое имя уникально в приложении, а название может повторяться.
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync($"/api/admin/applications/{api}/roles",
            new { name = "orders-manager", displayName = "Другое" })).StatusCode);
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "orders-manager-2", displayName = "Менеджер по заказам" });

        // Название меняется, техническое имя — нет.
        var updated = await admin.PutJsonAsync($"/api/admin/applications/{api}/roles/orders-manager",
            new { displayName = "Менеджер заказов", description = "Ведёт заказы" });
        Assert.Equal("orders-manager", updated.GetProperty("name").GetString());
        Assert.Equal("Менеджер заказов", updated.GetProperty("displayName").GetString());

        // Страница регистрации показывает пользователю название, техническое имя уходит только значением чекбокса.
        var returnUrl = Uri.EscapeDataString($"/connect/authorize?client_id={client}&response_type=code");
        var page = await fx.Factory.CreateClient().GetStringAsync($"/Account/Register?returnUrl={returnUrl}");
        Assert.Contains("<b>Менеджер заказов</b>", page);
        Assert.Contains($"value=\"{api}|orders-manager\"", page);
        Assert.DoesNotContain("<b>orders-manager</b>", page);

        // Заявка: у администратора и бота — оба имени; после одобрения в токене — техническое имя.
        Guid userId;
        var userName = TestApi.Unique("reg");
        using (var scope = fx.Factory.Services.CreateScope())
            userId = await scope.ServiceProvider.GetRequiredService<AccessRequestService>().RegisterAsync(client,
                new RegistrationInput(userName, null, null, Password, [new RoleRef(api, "orders-manager")], null));
        var pending = (await admin.GetJsonAsync($"/api/admin/access-requests?status=pending&clientId={api}"))[0];
        Assert.Equal("orders-manager", pending.GetProperty("role").GetString());
        Assert.Equal("Менеджер заказов", pending.GetProperty("roleDisplayName").GetString());
        await admin.PostJsonAsync($"/api/admin/access-requests/{pending.GetProperty("id").GetGuid()}/approve", new { comment = "ok" });

        var claims = TestApi.Claims((await PasswordGrantAsync(fx.Factory.CreateClient(), client, api, userName))
            .GetProperty("access_token").GetString()!);
        Assert.Contains($"{api}:orders-manager", claims.Strings("role"));
        Assert.DoesNotContain(claims.Strings("role"), r => r.Contains("Менеджер"));
        Assert.NotEqual(Guid.Empty, userId);

        // Системные роли получили названия для пользователей.
        var system = await admin.GetJsonAsync($"/api/admin/applications/{SystemApp.ClientId}/matrix");
        var administrator = system.GetProperty("roles").EnumerateArray().Single(r => r.GetProperty("name").GetString() == SystemApp.AdministratorRole);
        Assert.Equal("Администратор", administrator.GetProperty("displayName").GetString());
    }

    // ---------- Хранение ----------

    [Fact]
    public async Task PersonalData_IsEncryptedAtRest()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _) = await CreateAppsAsync(admin);
        var (userId, user) = await CreateUserAsync(admin, api, "reader");

        using var scope = fx.Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var conn = db.Database.GetDbConnection();
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT \"UserName\", \"Email\", \"NormalizedUserName\", \"PasswordHash\" FROM \"AspNetUsers\" WHERE \"Id\" = @id";
        var p = cmd.CreateParameter();
        p.ParameterName = "@id";
        p.Value = Fx is SqliteFixture ? userId.ToString().ToUpperInvariant() : userId;
        cmd.Parameters.Add(p);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.StartsWith("enc1:", reader.GetString(0));
        Assert.DoesNotContain(user, reader.GetString(0));
        Assert.StartsWith("enc1:", reader.GetString(1));
        Assert.StartsWith("bi1:", reader.GetString(2));
        Assert.StartsWith("AQAAAA", reader.GetString(3)); // Identity v3 hash (PBKDF2)
    }

    [Fact]
    public async Task Restart_KeepsKeys_Sessions_AndRefreshTokens()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, client) = await CreateAppsAsync(admin);
        var (_, user) = await CreateUserAsync(admin, api, "reader");
        var token = await PasswordGrantAsync(fx.Factory.CreateClient(), client, api, user);
        var jwksBefore = await fx.Factory.CreateClient().GetStringAsync("/.well-known/jwks");

        // Второй экземпляр на той же БД (перезапуск / соседний узел кластера).
        await using var second = fx.Start();
        var http2 = second.CreateClient();
        Assert.Equal(jwksBefore, await http2.GetStringAsync("/.well-known/jwks"));

        var refreshed = await RefreshAsync(http2, client, token.GetProperty("refresh_token").GetString()!);
        var jwks = new JsonWebKeySet(jwksBefore);
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(refreshed.GetProperty("access_token").GetString()!,
            new TokenValidationParameters { ValidIssuer = "http://localhost/", ValidAudience = api, IssuerSigningKeys = jwks.GetSigningKeys() });
        Assert.True(validation.IsValid);
    }

    // ---------- Локализация ----------

    [Fact]
    public async Task LoginPage_IsLocalized()
    {
        var http = fx.Factory.CreateClient();
        var en = await http.GetStringAsync("/Account/Login?lang=en");
        Assert.Contains("Sign in", en);
        var ru = await fx.Factory.CreateClient().GetStringAsync("/Account/Login?lang=ru");
        Assert.Contains("Вход", ru);
    }
}

/// <summary>Запуск сквозных сценариев на SQLite.</summary>
[Collection("sqlite")]
public sealed class SqliteScenarios(SqliteFixture fx) : AuthScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

/// <summary>Запуск сквозных сценариев на PostgreSQL (Testcontainers).</summary>
[Collection("postgres")]
public sealed class PostgresScenarios(PostgresFixture fx) : AuthScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
