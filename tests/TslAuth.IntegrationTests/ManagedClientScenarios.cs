// Интеграционные сценарии подчинённых клиентов и входа по ключу (docs/task-managed-clients.md, раздел 4):
// владелец заводит подчинённого через App API делегированным токеном оператора, подчинённый входит по
// private_key_jwt (ES256), политика ограничивает роли/префикс/число, отключение отзывает токены, чужой клиент — 404,
// jti одноразовый на всех узлах. Одинаковый набор выполняется на SQLite и PostgreSQL.

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.EntityFrameworkCore.Models;
using TslAuth.IntegrationTests.Infrastructure;
using TslAuth.Services;

namespace TslAuth.IntegrationTests;

public abstract class ManagedClientScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private const string Issuer = "http://localhost/";
    private static readonly string Password = TestApi.NewPassword();

    /// <summary>Владелец с политикой подчинённых, его оператор и public-клиент для входа оператора.</summary>
    private sealed record Owner(string ClientId, string Secret, string Web, string OperatorName, Guid OperatorId, string Prefix);

    /// <summary>Ключ подчинённого: закрытая часть остаётся в тесте, в сервис уходит только открытый JWK.</summary>
    private sealed record ClientKey(ECDsa Key, string Kid, JsonElement Jwk);

    // ---------- Подготовка ----------

    private async Task<Owner> CreateOwnerAsync(HttpClient admin, bool requireDelegation = true, int maxClients = 200,
        int lifetime = 5, string[]? authMethods = null, int inactiveDays = 0)
    {
        var owner = TestApi.Unique("owner");
        var web = TestApi.Unique("opweb");
        var prefix = owner[..8] + "-agent-";
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = owner, clientType = "confidential", grantTypes = new[] { "client_credentials", "token_exchange" },
            selfManagement = true
        });
        var secret = created.GetProperty("clientSecret").GetString()!;
        await admin.PostJsonAsync($"/api/admin/applications/{owner}/permissions", new { name = "agents.manage" });
        await admin.PostJsonAsync($"/api/admin/applications/{owner}/permissions", new { name = "upload" });
        await admin.PostJsonAsync($"/api/admin/applications/{owner}/roles", new { name = "agents-admin", permissions = new[] { "agents.manage" } });
        await admin.PostJsonAsync($"/api/admin/applications/{owner}/roles", new { name = "uploader", permissions = new[] { "upload" } });
        await admin.PostJsonAsync($"/api/admin/applications/{owner}/roles", new { name = "other", permissions = Array.Empty<string>() });
        await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = web, clientType = "public", grantTypes = new[] { "password" }, scopes = new[] { owner }
        });
        await admin.PutJsonAsync($"/api/admin/applications/{owner}/managed-clients-policy", new
        {
            prefix, roles = new[] { "uploader" }, authMethods = authMethods ?? ["private_key_jwt"], maxClients,
            accessTokenLifetime = lifetime, requireDelegation, managePermission = "agents.manage", inactiveDays
        });

        var name = TestApi.Unique("operator");
        var user = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = name, email = $"{name}@it.local", password = Password, roles = new[] { new { clientId = owner, role = "agents-admin" } }
        });
        return new Owner(owner, secret, web, name, user.GetProperty("user").GetProperty("id").GetGuid(), prefix);
    }

    /// <summary>Делегированный токен: вход оператора через public-клиент → token exchange владельцем на scope tsl-auth-app.</summary>
    private async Task<HttpClient> DelegatedAsync(Owner o, string? userName = null)
    {
        var http = fx.Factory.CreateClient();
        var user = await http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = o.Web, ["username"] = userName ?? o.OperatorName, ["password"] = Password,
            ["scope"] = o.ClientId
        });
        var exchanged = await http.TokenAsync(new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["client_id"] = o.ClientId, ["client_secret"] = o.Secret,
            ["subject_token"] = user.GetProperty("access_token").GetString()!,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token", ["scope"] = SystemApp.AppApiScope
        });
        return fx.Factory.CreateClient().WithBearer(exchanged.GetProperty("access_token").GetString()!);
    }

    /// <summary>Сервисный токен владельца (client_credentials, scope tsl-auth-app).</summary>
    private async Task<HttpClient> ServiceAsync(Owner o)
    {
        var token = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = o.ClientId, ["client_secret"] = o.Secret, ["scope"] = SystemApp.AppApiScope
        });
        return fx.Factory.CreateClient().WithBearer(token.GetProperty("access_token").GetString()!);
    }

    private static ClientKey NewKey(ECCurve? curve = null)
    {
        var ecdsa = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(false);
        var x = Base64UrlEncoder.Encode(p.Q.X!);
        var y = Base64UrlEncoder.Encode(p.Q.Y!);
        var crv = curve is null ? "P-256" : "P-384";
        var jwk = JsonSerializer.Deserialize<JsonElement>($$"""{"kty":"EC","crv":"{{crv}}","x":"{{x}}","y":"{{y}}"}""");
        return new ClientKey(ecdsa, ManagedClientKeys.Thumbprint(x, y), jwk);
    }

    private static object Jwks(params ClientKey[] keys) => new { keys = keys.Select(k => k.Jwk).ToArray() };

    /// <summary>
    /// Клиентский assertion (RFC 7523): iss = sub = client_id, aud = issuer, jti случайный, exp = iat + lifetime,
    /// заголовок typ = client-authentication+jwt (явная типизация, которую требует OpenIddict).
    /// </summary>
    private const string AssertionType = "client-authentication+jwt";
    private static string Assertion(string clientId, ClientKey key, int lifetimeSeconds = 60, string? jti = null, string? aud = null,
        DateTime? issuedAt = null)
    {
        var now = issuedAt ?? DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = aud ?? Issuer,
            TokenType = AssertionType,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddSeconds(lifetimeSeconds),
            Claims = new Dictionary<string, object> { ["sub"] = clientId, ["jti"] = jti ?? Guid.NewGuid().ToString("N") },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key.Key) { KeyId = key.Kid }, SecurityAlgorithms.EcdsaSha256)
        };
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    private static Task<JsonElement> KeyTokenAsync(HttpClient http, string clientId, string assertion, string scope, bool expectSuccess = true) =>
        http.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["scope"] = scope,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", ["client_assertion"] = assertion
        }, expectSuccess);

    private static async Task<JsonElement> CreateManagedAsync(HttpClient delegated, ClientKey key, string? suffix = null, string[]? roles = null) =>
        (await delegated.PostJsonAsync("/api/app/clients", new
        {
            clientIdSuffix = suffix ?? TestApi.Unique("a")[2..], displayName = "Агент", roles = roles ?? ["uploader"], jwks = Jwks(key)
        })).GetProperty("client");

    // ---------- Сценарии ----------

    /// <summary>Владелец создаёт подчинённого с ключом; тот получает токен по private_key_jwt с ролью владельца и сроком из политики; повтор assertion — отказ.</summary>
    [Fact]
    public async Task Managed_PrivateKeyJwt_IssuesToken_WithRoleAndPolicyLifetime_AndRejectsReplay()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin, lifetime: 3);
        var delegated = await DelegatedAsync(o);
        var key = NewKey();
        var client = await CreateManagedAsync(delegated, key);
        var clientId = client.GetProperty("clientId").GetString()!;
        Assert.StartsWith(o.Prefix, clientId);
        Assert.Equal(key.Kid, client.GetProperty("keys")[0].GetProperty("kid").GetString());
        Assert.False(client.GetProperty("hasSecret").GetBoolean());

        var assertion = Assertion(clientId, key);
        var token = await KeyTokenAsync(fx.Factory.CreateClient(), clientId, assertion, o.ClientId);
        Assert.InRange(token.GetProperty("expires_in").GetInt32(), 178, 180); // 3 минуты из политики (минус секунды на обработку)
        var claims = TestApi.Claims(token.GetProperty("access_token").GetString()!);
        Assert.Equal(clientId, claims.GetProperty("sub").GetString());
        Assert.Equal("client", claims.GetProperty("subject_type").GetString());
        Assert.Contains($"{o.ClientId}:uploader", claims.Strings("role"));
        Assert.Contains(o.ClientId, claims.Strings("aud"));

        // Тот же assertion второй раз — jti уже использован.
        var replay = await KeyTokenAsync(fx.Factory.CreateClient(), clientId, assertion, o.ClientId, expectSuccess: false);
        Assert.Equal("invalid_client", replay.GetProperty("error").GetString());

        // Карточка: последний выданный токен виден владельцу, аудит содержит действие оператора через владельца.
        var card = await delegated.GetJsonAsync($"/api/app/clients/{clientId}");
        Assert.NotNull(card.GetProperty("lastTokenIssuedAt").GetString());
        var service = await ServiceAsync(o);
        await fx.Factory.Services.GetRequiredService<AuditService>().FlushAsync();
        var audit = await service.GetJsonAsync("/api/app/audit?type=managed_client.change");
        var entry = audit.EnumerateArray().First(e => e.GetProperty("details").GetProperty("action").GetString() == "created");
        Assert.Equal($"user:{o.OperatorId}", entry.GetProperty("actor").GetString());
        Assert.Equal(o.ClientId, entry.GetProperty("details").GetProperty("via").GetString());
    }

    /// <summary>Отказы: чужая подпись, alg=none, HS256 с открытым ключом, срок больше 5 минут, неверная aud, чужая кривая при регистрации.</summary>
    [Fact]
    public async Task Managed_BadAssertions_AreRejected_WithInvalidClient()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var delegated = await DelegatedAsync(o);
        var key = NewKey();
        var clientId = (await CreateManagedAsync(delegated, key)).GetProperty("clientId").GetString()!;
        var http = fx.Factory.CreateClient();

        async Task Rejected(string assertion)
        {
            var r = await KeyTokenAsync(http, clientId, assertion, o.ClientId, expectSuccess: false);
            Assert.True("invalid_client" == r.GetProperty("error").GetString(), r.ToString());
        }

        await Rejected(Assertion(clientId, NewKey() with { Kid = key.Kid }));          // подпись другим ключом с тем же kid
        await Rejected(Assertion(clientId, key, lifetimeSeconds: 600));                // exp − iat > 5 минут
        await Rejected(Assertion(clientId, key, aud: "https://other.example/"));       // aud не наш
        await Rejected(Assertion(clientId, key, issuedAt: DateTime.UtcNow.AddMinutes(-10))); // истёк

        // alg=none: заголовок без подписи.
        var payload = JsonSerializer.Serialize(new
        {
            iss = clientId, sub = clientId, aud = Issuer, jti = Guid.NewGuid().ToString("N"),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), exp = DateTimeOffset.UtcNow.AddSeconds(60).ToUnixTimeSeconds()
        });
        var none = Base64UrlEncoder.Encode($$"""{"alg":"none","typ":"{{AssertionType}}"}""") + "." + Base64UrlEncoder.Encode(payload) + ".";
        await Rejected(none);

        // HS256 «атака подменой алгоритма»: HMAC открытым ключом (координаты x|y) как секретом.
        var p = key.Key.ExportParameters(false);
        var hsHeader = Base64UrlEncoder.Encode($$"""{"alg":"HS256","typ":"{{AssertionType}}","kid":"{{key.Kid}}"}""");
        var hsBody = Base64UrlEncoder.Encode(payload);
        var hsSig = Base64UrlEncoder.Encode(HMACSHA256.HashData(p.Q.X!.Concat(p.Q.Y!).ToArray(), Encoding.ASCII.GetBytes($"{hsHeader}.{hsBody}")));
        await Rejected($"{hsHeader}.{hsBody}.{hsSig}");

        // Ключ другой кривой не регистрируется.
        var bad = await delegated.PostAsJsonAsync("/api/app/clients", new { roles = new[] { "uploader" }, jwks = Jwks(NewKey(ECCurve.NamedCurves.nistP384)) });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        // Закрытый ключ не принимается.
        var priv = JsonSerializer.Deserialize<JsonElement>("""{"keys":[{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","d":"secret"}]}""");
        Assert.Equal(HttpStatusCode.BadRequest, (await delegated.PostAsJsonAsync("/api/app/clients", new { roles = new[] { "uploader" }, jwks = priv })).StatusCode);

        // Правильный assertion после отказов по-прежнему принимается (отказы не блокируют клиента ниже порога).
        await KeyTokenAsync(http, clientId, Assertion(clientId, key), o.ClientId);

        // Discovery объявляет способ и алгоритм.
        var discovery = await http.GetJsonAsync("/.well-known/openid-configuration");
        Assert.Contains("private_key_jwt", discovery.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal("ES256", discovery.GetProperty("token_endpoint_auth_signing_alg_values_supported")[0].GetString());
    }

    /// <summary>Отключение: нет токена, introspection старого токена active=false, вебхук application.disabled; включение возвращает доступ; удаление — 404.</summary>
    [Fact]
    public async Task Managed_Disable_RevokesTokens_PublishesEvent_Enable_Delete()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var delegated = await DelegatedAsync(o);
        var key = NewKey();
        var clientId = (await CreateManagedAsync(delegated, key)).GetProperty("clientId").GetString()!;
        var http = fx.Factory.CreateClient();
        var token = (await KeyTokenAsync(http, clientId, Assertion(clientId, key), o.ClientId)).GetProperty("access_token").GetString()!;
        var cursor = (await admin.GetJsonAsync("/api/admin/events?after=0&limit=500")).GetProperty("next").GetInt64();

        var disabled = await delegated.PostJsonAsync($"/api/app/clients/{clientId}/disable", new { });
        Assert.True(disabled.GetProperty("disabled").GetBoolean());
        Assert.Equal("invalid_client", (await KeyTokenAsync(http, clientId, Assertion(clientId, key), o.ClientId, false)).GetProperty("error").GetString());

        // Introspection владельцем: выданный ранее токен отозван.
        var intro = await (await http.PostAsync("/connect/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = o.ClientId, ["client_secret"] = o.Secret, ["token"] = token
        }))).JsonAsync();
        Assert.False(intro.GetProperty("active").GetBoolean());

        var events = await admin.GetJsonAsync($"/api/admin/events?after={cursor}&wait=5&types=application.disabled");
        var ev = events.GetProperty("events").EnumerateArray().Single(e => e.GetProperty("data").GetProperty("clientId").GetString() == clientId);
        Assert.Equal(o.ClientId, ev.GetProperty("data").GetProperty("owner").GetString());

        // Админ видит владельца и статус в карточке приложения.
        var dto = await admin.GetJsonAsync($"/api/admin/applications/{clientId}");
        Assert.Equal(o.ClientId, dto.GetProperty("owner").GetString());
        Assert.True(dto.GetProperty("disabled").GetBoolean());

        await delegated.PostJsonAsync($"/api/app/clients/{clientId}/enable", new { });
        await KeyTokenAsync(http, clientId, Assertion(clientId, key), o.ClientId);

        Assert.Equal(HttpStatusCode.NoContent, (await delegated.DeleteAsync($"/api/app/clients/{clientId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await delegated.GetAsync($"/api/app/clients/{clientId}")).StatusCode);
        Assert.Equal("invalid_client", (await KeyTokenAsync(http, clientId, Assertion(clientId, key), o.ClientId, false)).GetProperty("error").GetString());
    }

    /// <summary>Чужой подчинённый и обычное приложение — 404; роль вне белого списка — 400; Admin API не расширяет подчинённого; предел числа.</summary>
    [Fact]
    public async Task Managed_Foreign404_RoleWhitelist_AdminBypassBlocked_MaxClients()
    {
        var admin = await fx.Factory.AdminAsync();
        var a = await CreateOwnerAsync(admin, maxClients: 2);
        var b = await CreateOwnerAsync(admin);
        var da = await DelegatedAsync(a);
        var db = await DelegatedAsync(b);
        var mine = (await CreateManagedAsync(da, NewKey())).GetProperty("clientId").GetString()!;

        // Чужой владелец: 404 на всех маршрутах; не подчинённое приложение — тоже 404.
        Assert.Equal(HttpStatusCode.NotFound, (await db.GetAsync($"/api/app/clients/{mine}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await db.PostAsJsonAsync($"/api/app/clients/{mine}/disable", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await db.DeleteAsync($"/api/app/clients/{mine}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await da.GetAsync($"/api/app/clients/{b.ClientId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await da.GetAsync($"/api/app/clients/{SystemApp.ClientId}")).StatusCode);
        Assert.Empty((await db.GetJsonAsync("/api/app/clients")).EnumerateArray());

        // Роль не из белого списка и client_id без префикса — 400.
        var wrongRole = await da.PostAsJsonAsync("/api/app/clients", new { roles = new[] { "other" }, jwks = Jwks(NewKey()) });
        Assert.Equal(HttpStatusCode.BadRequest, wrongRole.StatusCode);
        var wrongId = await da.PostAsJsonAsync("/api/app/clients", new { clientId = "no-prefix-" + Guid.NewGuid().ToString("N")[..6], roles = new[] { "uploader" }, jwks = Jwks(NewKey()) });
        Assert.Equal(HttpStatusCode.BadRequest, wrongId.StatusCode);
        // Секрет запрещён политикой (только private_key_jwt).
        Assert.Equal(HttpStatusCode.BadRequest, (await da.PostAsJsonAsync("/api/app/clients", new { roles = new[] { "uploader" }, requestSecret = true })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await da.PostAsJsonAsync($"/api/app/clients/{mine}/secret", new { })).StatusCode);

        // Admin API: изменить подчинённого (чужие scope, tsl-auth-admin) нельзя — 400; чужие роли — 400; свои из белого списка — можно.
        var update = await admin.PutAsJsonAsync($"/api/admin/applications/{mine}", new
        {
            clientId = mine, clientType = "confidential", grantTypes = new[] { "client_credentials" }, scopes = new[] { SystemApp.ClientId }
        });
        Assert.Equal(HttpStatusCode.BadRequest, update.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/admin/applications/{mine}/secret", new { })).StatusCode);
        var foreignRole = await admin.PutAsJsonAsync($"/api/admin/applications/{mine}/service-roles",
            new[] { new { clientId = SystemApp.ClientId, role = SystemApp.AdministratorRole } });
        Assert.Equal(HttpStatusCode.BadRequest, foreignRole.StatusCode);
        var otherRole = await admin.PutAsJsonAsync($"/api/admin/applications/{mine}/service-roles", new[] { new { clientId = a.ClientId, role = "other" } });
        Assert.Equal(HttpStatusCode.BadRequest, otherRole.StatusCode);
        await admin.PutJsonAsync($"/api/admin/applications/{mine}/service-roles", new[] { new { clientId = a.ClientId, role = "uploader" } });
        // Токен подчинённого не содержит ролей других приложений.
        Assert.DoesNotContain(mine, (await admin.GetJsonAsync("/api/admin/applications")).EnumerateArray()
            .Where(x => x.GetProperty("scopes").EnumerateArray().Any(s => s.GetString() == SystemApp.ClientId)).Select(x => x.GetProperty("clientId").GetString()));

        // Предел maxClients = 2.
        await CreateManagedAsync(da, NewKey());
        var over = await da.PostAsJsonAsync("/api/app/clients", new { roles = new[] { "uploader" }, jwks = Jwks(NewKey()) });
        Assert.Equal(HttpStatusCode.BadRequest, over.StatusCode);
        Assert.Equal(2, (await admin.GetJsonAsync($"/api/admin/applications/{a.ClientId}/managed-clients")).GetArrayLength());

        // Удаление владельца удаляет его подчинённых.
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/admin/applications/{a.ClientId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/admin/applications/{mine}")).StatusCode);
    }

    /// <summary>Сервисный токен без делегирования — только чтение (403 на изменения); оператор без разрешения — 403; requireDelegation=false разрешает сервисный токен.</summary>
    [Fact]
    public async Task Managed_Delegation_IsRequired_ForChanges()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var service = await ServiceAsync(o);
        Assert.Equal(HttpStatusCode.OK, (await service.GetAsync("/api/app/clients")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await service.PostAsJsonAsync("/api/app/clients", new { roles = new[] { "uploader" }, jwks = Jwks(NewKey()) })).StatusCode);

        // Оператор без agents.manage (роль uploader).
        var name = TestApi.Unique("nobody");
        await admin.PostJsonAsync("/api/admin/users", new { userName = name, email = $"{name}@it.local", password = Password, roles = new[] { new { clientId = o.ClientId, role = "uploader" } } });
        var nobody = await DelegatedAsync(o, name);
        Assert.Equal(HttpStatusCode.Forbidden, (await nobody.GetAsync("/api/app/clients")).StatusCode);

        // Владелец без политики — 403 даже с делегированным токеном.
        var plain = await CreateOwnerAsync(admin);
        await admin.DeleteAsync($"/api/admin/applications/{plain.ClientId}/managed-clients-policy");
        Assert.Equal(HttpStatusCode.Forbidden, (await (await DelegatedAsync(plain)).GetAsync("/api/app/clients")).StatusCode);

        // Тестовый стенд: requireDelegation=false — сервисный токен создаёт подчинённого; секрет разрешён политикой.
        var lax = await CreateOwnerAsync(admin, requireDelegation: false, authMethods: ["private_key_jwt", "client_secret"]);
        var laxService = await ServiceAsync(lax);
        var created = await laxService.PostJsonAsync("/api/app/clients", new { roles = new[] { "uploader" }, requestSecret = true });
        var secret = created.GetProperty("clientSecret").GetString()!;
        var clientId = created.GetProperty("client").GetProperty("clientId").GetString()!;
        Assert.True(created.GetProperty("client").GetProperty("hasSecret").GetBoolean());
        var token = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = secret, ["scope"] = lax.ClientId
        });
        Assert.Contains($"{lax.ClientId}:uploader", TestApi.Claims(token.GetProperty("access_token").GetString()!).Strings("role"));
        // Новый секрет отменяет старый.
        var rotated = (await laxService.PostJsonAsync($"/api/app/clients/{clientId}/secret", new { })).GetProperty("clientSecret").GetString()!;
        Assert.Equal("invalid_client", (await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = secret
        }, false)).GetProperty("error").GetString());
        await fx.Factory.CreateClient().TokenAsync(new() { ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = rotated });
        // Подчинённому не выдать чужой scope.
        var foreign = await fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = rotated, ["scope"] = SystemApp.AppApiScope
        }, false);
        Assert.Contains(foreign.GetProperty("error").GetString(), new[] { "invalid_scope", "invalid_request" });
        Assert.False(foreign.TryGetProperty("access_token", out _));
    }

    /// <summary>Смена ключа с двумя kid: оба работают, после удаления старого — только новый; второй узел кластера видит использованный jti.</summary>
    [Fact]
    public async Task Managed_KeyRotation_TwoKids_AndClusterSharedJti()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var delegated = await DelegatedAsync(o);
        var oldKey = NewKey();
        var newKey = NewKey();
        var clientId = (await CreateManagedAsync(delegated, oldKey)).GetProperty("clientId").GetString()!;
        var http = fx.Factory.CreateClient();

        var both = await delegated.PutJsonAsync($"/api/app/clients/{clientId}/keys", new { jwks = Jwks(oldKey, newKey) });
        Assert.Equal(2, both.GetProperty("keys").GetArrayLength());
        await KeyTokenAsync(http, clientId, Assertion(clientId, oldKey), o.ClientId);
        await KeyTokenAsync(http, clientId, Assertion(clientId, newKey), o.ClientId);

        await delegated.PutJsonAsync($"/api/app/clients/{clientId}/keys", new { jwks = Jwks(newKey) });
        Assert.Equal("invalid_client", (await KeyTokenAsync(http, clientId, Assertion(clientId, oldKey), o.ClientId, false)).GetProperty("error").GetString());
        // Три ключа сразу — 400.
        Assert.Equal(HttpStatusCode.BadRequest, (await delegated.PutAsJsonAsync($"/api/app/clients/{clientId}/keys", new { jwks = Jwks(NewKey(), NewKey(), NewKey()) })).StatusCode);

        // Второй узел на той же БД: assertion, использованный на первом, отвергается на втором.
        await using var second = fx.Start();
        var http2 = second.CreateClient();
        var assertion = Assertion(clientId, newKey);
        await KeyTokenAsync(http, clientId, assertion, o.ClientId);
        Assert.Equal("invalid_client", (await KeyTokenAsync(http2, clientId, assertion, o.ClientId, false)).GetProperty("error").GetString());
        await KeyTokenAsync(http2, clientId, Assertion(clientId, newKey), o.ClientId);

        // Использованные jti лежат в общей таблице и чистятся обслуживанием после истечения.
        await using var db = fx.CreateDbContext();
        Assert.True(await db.ClientAssertionJtis.CountAsync(j => j.ClientId == clientId) >= 3);
        await db.ClientAssertionJtis.Where(j => j.ClientId == clientId).ExecuteUpdateAsync(s => s.SetProperty(j => j.ExpiresAt, DateTime.UtcNow.AddMinutes(-1)));
        await admin.PostJsonAsync("/api/admin/maintenance/run", new { });
        Assert.Equal(0, await db.ClientAssertionJtis.CountAsync(j => j.ClientId == clientId));
    }

    /// <summary>Отключение обычного приложения администратором: client_credentials и authorize отвечают invalid_client; включение возвращает.</summary>
    [Fact]
    public async Task Admin_DisablesApplication_TokenAndAuthorizeRefused()
    {
        var admin = await fx.Factory.AdminAsync();
        var clientId = TestApi.Unique("svc");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId, clientType = "confidential", grantTypes = new[] { "client_credentials", "authorization_code" },
            redirectUris = new[] { "https://svc.local/cb" }
        });
        var secret = created.GetProperty("clientSecret").GetString()!;
        var http = fx.Factory.CreateClient();
        Dictionary<string, string> form = new() { ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = secret };
        await http.TokenAsync(form);

        var dto = await admin.PostJsonAsync($"/api/admin/applications/{clientId}/disable", new { });
        Assert.True(dto.GetProperty("disabled").GetBoolean());
        Assert.Equal("invalid_client", (await http.TokenAsync(form, false)).GetProperty("error").GetString());
        var authorize = await http.GetAsync($"/connect/authorize?client_id={clientId}&response_type=code&redirect_uri=https%3A%2F%2Fsvc.local%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
        // invalid_client OpenIddict отдаёт со статусом 401 (и на authorize — страницей ошибки без редиректа).
        Assert.Equal(HttpStatusCode.Unauthorized, authorize.StatusCode);
        Assert.Contains("invalid_client", await authorize.Content.ReadAsStringAsync());
        // Системное приложение отключить нельзя.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync($"/api/admin/applications/{SystemApp.ClientId}/disable", new { })).StatusCode);

        await admin.PostJsonAsync($"/api/admin/applications/{clientId}/enable", new { });
        await http.TokenAsync(form);
    }

    /// <summary>Политика: только администратор (App API её не меняет), требования к владельцу, роли из матрицы; ApplicationDto содержит политику.</summary>
    [Fact]
    public async Task Policy_OnlyAdmin_ValidatesOwnerAndRoles()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var dto = await admin.GetJsonAsync($"/api/admin/applications/{o.ClientId}");
        Assert.Equal(o.Prefix, dto.GetProperty("managedClients").GetProperty("prefix").GetString());
        Assert.Equal(o.Prefix, (await admin.GetJsonAsync($"/api/admin/applications/{o.ClientId}/managed-clients-policy")).GetProperty("prefix").GetString());

        // Роль вне матрицы, чужой поток, плохой префикс — 400.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync($"/api/admin/applications/{o.ClientId}/managed-clients-policy",
            new { prefix = o.Prefix, roles = new[] { "missing" } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync($"/api/admin/applications/{o.ClientId}/managed-clients-policy",
            new { prefix = o.Prefix, roles = new[] { "uploader" }, grantTypes = new[] { "password" } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync($"/api/admin/applications/{o.ClientId}/managed-clients-policy",
            new { prefix = "Bad Prefix", roles = new[] { "uploader" } })).StatusCode);
        // Public-клиент без самоуправления не может быть владельцем.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync($"/api/admin/applications/{o.Web}/managed-clients-policy",
            new { prefix = "x-", roles = Array.Empty<string>() })).StatusCode);
        // Подчинённый не может стать владельцем.
        var delegated = await DelegatedAsync(o);
        var managed = (await CreateManagedAsync(delegated, NewKey())).GetProperty("clientId").GetString()!;
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync($"/api/admin/applications/{managed}/managed-clients-policy",
            new { prefix = "x-", roles = Array.Empty<string>() })).StatusCode);

        // App API владельца не имеет маршрута политики: только чтение своих клиентов.
        Assert.Equal(HttpStatusCode.NotFound, (await delegated.PutAsJsonAsync("/api/app/clients-policy", new { prefix = "x-" })).StatusCode);
        // Список подчинённых в Admin API.
        Assert.Single((await admin.GetJsonAsync($"/api/admin/applications/{o.ClientId}/managed-clients")).EnumerateArray());
    }

    /// <summary>Предел неактивности: подчинённый без токенов дольше inactiveDays отключается обслуживанием с событием.</summary>
    [Fact]
    public async Task Managed_InactiveClient_IsDisabledByMaintenance()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin, inactiveDays: 7);
        var delegated = await DelegatedAsync(o);
        var stale = (await CreateManagedAsync(delegated, NewKey())).GetProperty("clientId").GetString()!;
        var fresh = (await CreateManagedAsync(delegated, NewKey())).GetProperty("clientId").GetString()!;

        // Дата создания «состаривается» прямо в свойствах клиента (токенов он не получал).
        await using (var db = fx.CreateDbContext())
        {
            var app = await db.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>().SingleAsync(a => a.ClientId == stale);
            using var json = JsonDocument.Parse(app.Properties!);
            var props = json.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone() as object);
            props[ApplicationService.CreatedAtProperty] = DateTime.UtcNow.AddDays(-30);
            app.Properties = JsonSerializer.Serialize(props);
            await db.SaveChangesAsync();
        }

        var result = await admin.PostJsonAsync("/api/admin/maintenance/run", new { });
        Assert.True(result.GetProperty("inactiveClients").GetInt32() >= 1);
        Assert.True((await delegated.GetJsonAsync($"/api/app/clients/{stale}")).GetProperty("disabled").GetBoolean());
        Assert.False((await delegated.GetJsonAsync($"/api/app/clients/{fresh}")).GetProperty("disabled").GetBoolean());
    }

    /// <summary>Серия отказов аутентификации клиента блокирует client_id на минуту (узел со строгим порогом).</summary>
    [Fact]
    public async Task ClientAuthFailures_BlockClientId()
    {
        await using var strict = fx.Start(new() { ["Security__ClientAuthFailuresPerMinute"] = "3" });
        var admin = await strict.AdminAsync();
        var clientId = TestApi.Unique("brute");
        var created = await admin.PostJsonAsync("/api/admin/applications", new { clientId, clientType = "confidential", grantTypes = new[] { "client_credentials" } });
        var secret = created.GetProperty("clientSecret").GetString()!;
        var http = strict.CreateClient();
        for (var i = 0; i < 3; i++)
            await http.TokenAsync(new() { ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = "wrong" }, false);
        // Даже правильный секрет теперь отклоняется — клиент заблокирован.
        var blocked = await http.TokenAsync(new() { ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = secret }, false);
        Assert.Equal("invalid_client", blocked.GetProperty("error").GetString());
        Assert.Contains("минуту", blocked.GetProperty("error_description").GetString());
        // Другой клиент не затронут.
        await strict.AdminAsync();
    }

    // ---------- Регрессии ревизии кода ----------

    /// <summary>Приложение B, обменявшее сервисный токен владельца A, не получает App API и подчинённых A (токен с act — не токен A).</summary>
    [Fact]
    public async Task ExchangedClientToken_DoesNotActAsOwner()
    {
        var admin = await fx.Factory.AdminAsync();
        var a = await CreateOwnerAsync(admin);
        var b = TestApi.Unique("relay");
        var bSecret = (await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = b, clientType = "confidential", grantTypes = new[] { "client_credentials", "token_exchange" }, selfManagement = true
        })).GetProperty("clientSecret").GetString()!;
        // A вызывает B: токен A с audience B.
        await admin.PutJsonAsync($"/api/admin/applications/{a.ClientId}", new
        {
            clientId = a.ClientId, clientType = "confidential", grantTypes = new[] { "client_credentials", "token_exchange" },
            selfManagement = true, scopes = new[] { b }
        });
        var http = fx.Factory.CreateClient();
        var aToken = await http.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = a.ClientId, ["client_secret"] = a.Secret, ["scope"] = b
        });
        var exchanged = await http.TokenAsync(new()
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["client_id"] = b, ["client_secret"] = bSecret,
            ["subject_token"] = aToken.GetProperty("access_token").GetString()!,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token", ["scope"] = SystemApp.AppApiScope
        });
        var relay = fx.Factory.CreateClient().WithBearer(exchanged.GetProperty("access_token").GetString()!);
        Assert.Equal(HttpStatusCode.Forbidden, (await relay.GetAsync("/api/app/clients")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await relay.GetAsync("/api/app/matrix")).StatusCode);
        // Собственный сервисный токен A по-прежнему работает.
        Assert.Equal(HttpStatusCode.OK, (await (await ServiceAsync(a)).GetAsync("/api/app/clients")).StatusCode);
    }

    /// <summary>Снятие «Самоуправления» у владельца закрывает /api/app/clients сразу, в том числе для уже выданных токенов.</summary>
    [Fact]
    public async Task SelfManagementOff_ClosesManagedClientsApi()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var service = await ServiceAsync(o);
        Assert.Equal(HttpStatusCode.OK, (await service.GetAsync("/api/app/clients")).StatusCode);
        await admin.PutJsonAsync($"/api/admin/applications/{o.ClientId}", new
        {
            clientId = o.ClientId, clientType = "confidential", grantTypes = new[] { "client_credentials", "token_exchange" }, selfManagement = false
        });
        Assert.Equal(HttpStatusCode.Forbidden, (await service.GetAsync("/api/app/clients")).StatusCode);
    }

    /// <summary>Активный агент не отключается по неактивности, даже когда его старые токены уже удалены обслуживанием.</summary>
    [Fact]
    public async Task ActiveAgent_NotDisabled_AfterTokensPruned()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin, inactiveDays: 7);
        var delegated = await DelegatedAsync(o);
        var key = NewKey();
        var clientId = (await CreateManagedAsync(delegated, key)).GetProperty("clientId").GetString()!;
        await KeyTokenAsync(fx.Factory.CreateClient(), clientId, Assertion(clientId, key), o.ClientId);

        await using (var db = fx.CreateDbContext())
        {
            // Клиент «создан» 30 дней назад, строки токенов удалены (как после обслуживания через сутки).
            var app = await db.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>().SingleAsync(x => x.ClientId == clientId);
            using var json = JsonDocument.Parse(app.Properties!);
            var props = json.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone() as object);
            props[ApplicationService.CreatedAtProperty] = DateTime.UtcNow.AddDays(-30);
            app.Properties = JsonSerializer.Serialize(props);
            await db.SaveChangesAsync();
            await db.Set<OpenIddictEntityFrameworkCoreToken<Guid>>().Where(t => t.Application!.ClientId == clientId).ExecuteDeleteAsync();
        }

        await admin.PostJsonAsync("/api/admin/maintenance/run", new { });
        var card = await delegated.GetJsonAsync($"/api/app/clients/{clientId}");
        Assert.False(card.GetProperty("disabled").GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, card.GetProperty("lastTokenIssuedAt").ValueKind);
    }

    /// <summary>Снять политику при живых подчинённых нельзя; срок токена подчинённого через Admin API не задаётся (400, а не молчаливое игнорирование).</summary>
    [Fact]
    public async Task PolicyRemoval_And_Lifetimes_ForManaged_AreRefused()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var clientId = (await CreateManagedAsync(await DelegatedAsync(o), NewKey())).GetProperty("clientId").GetString()!;
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.DeleteAsync($"/api/admin/applications/{o.ClientId}/managed-clients-policy")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync($"/api/admin/applications/{clientId}/token-lifetimes",
            new { accessTokenMinutes = 2 })).StatusCode);
    }

    /// <summary>
    /// Ошибки встроенных проверок assertion наружу — только invalid_client без подробностей: чужой client_id (iss≠client_id),
    /// iat в миллисекундах (раньше — 500), неверная aud на introspection.
    /// </summary>
    [Fact]
    public async Task AssertionErrors_AreNormalized_OnAllEndpoints()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var delegated = await DelegatedAsync(o);
        var keyA = NewKey();
        var a = (await CreateManagedAsync(delegated, keyA)).GetProperty("clientId").GetString()!;
        var b = (await CreateManagedAsync(delegated, NewKey())).GetProperty("clientId").GetString()!;
        var http = fx.Factory.CreateClient();

        static void AssertOpaque(JsonElement r)
        {
            Assert.Equal("invalid_client", r.GetProperty("error").GetString());
            Assert.Equal("The client assertion is invalid.", r.GetProperty("error_description").GetString());
        }

        // Assertion агента A, но client_id = B.
        AssertOpaque(await KeyTokenAsync(http, b, Assertion(a, keyA), o.ClientId, false));

        // iat в миллисекундах.
        var now = DateTime.UtcNow;
        var hugeIat = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = a, Audience = Issuer, TokenType = AssertionType, NotBefore = now, Expires = now.AddSeconds(60),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = a, ["jti"] = Guid.NewGuid().ToString("N"), ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(keyA.Key) { KeyId = keyA.Kid }, SecurityAlgorithms.EcdsaSha256)
        });
        AssertOpaque(await KeyTokenAsync(http, a, hugeIat, o.ClientId, false));

        // Неверная aud на /connect/introspect.
        var intro = await http.PostAsync("/connect/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = a, ["token"] = "x",
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = Assertion(a, keyA, aud: "https://other.example/")
        }));
        AssertOpaque(await intro.Content.ReadFromJsonAsync<JsonElement>());
    }

    /// <summary>Отключение подчинённого администратором (Admin API) видно владельцу в его журнале; удаление владельца удаляет подчинённых с записью в журнал.</summary>
    [Fact]
    public async Task AdminActions_OnManaged_AreVisibleToOwner()
    {
        var admin = await fx.Factory.AdminAsync();
        var o = await CreateOwnerAsync(admin);
        var clientId = (await CreateManagedAsync(await DelegatedAsync(o), NewKey())).GetProperty("clientId").GetString()!;
        await admin.PostJsonAsync($"/api/admin/applications/{clientId}/disable", new { });
        await fx.Factory.Services.GetRequiredService<AuditService>().FlushAsync();
        var audit = await (await ServiceAsync(o)).GetJsonAsync("/api/app/audit?type=managed_client.change");
        Assert.Contains(audit.EnumerateArray(), e =>
            e.GetProperty("details").GetProperty("action").GetString() == "disabled" &&
            e.GetProperty("details").GetProperty("clientId").GetString() == clientId);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/admin/applications/{o.ClientId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/admin/applications/{clientId}")).StatusCode);
    }
}

[Collection("sqlite-managed")]
public sealed class SqliteManagedClientScenarios(SqliteFixture fx) : ManagedClientScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

[Collection("postgres-managed")]
public sealed class PostgresManagedClientScenarios(PostgresFixture fx) : ManagedClientScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
