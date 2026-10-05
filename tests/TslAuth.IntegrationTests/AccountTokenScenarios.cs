// Самообслуживание персональных токенов из интерфейсов ERP (/api/account/tokens): пользователь своим access-токеном
// выпускает, видит и отзывает только свои токены; выпуск — только с разрешением из политики PAT (роль «Доступ по API»).
// Запуск: dotnet test tests/TslAuth.IntegrationTests (вариант на PostgreSQL — через Testcontainers, нужен Docker).

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using TslAuth.IntegrationTests.Infrastructure;

namespace TslAuth.IntegrationTests;

/// <summary>
/// /api/account/tokens: без разрешения — выпуск запрещён (403), пункт «можно выпускать» = false; после назначения роли —
/// токен выпускается, секрет один раз, обменивается на JWT; чужой токен не отозвать; клиентский токен API не принимает.
/// </summary>
public abstract class AccountTokenScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private const string Password = "Acc0unt-Token-Pass!";

    /// <summary>Приложение-ресурс с ролью reader, приложение «доступ по API» с ролью api-user и публичный клиент с паролем.</summary>
    private static async Task<(string Api, string Gate, string Client)> SetupAsync(HttpClient admin)
    {
        var api = TestApi.Unique("api");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" } });

        var gate = TestApi.Unique("gate");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = gate, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{gate}/permissions", new { name = "api-tokens.issue" });
        await admin.PostJsonAsync($"/api/admin/applications/{gate}/roles", new { name = "api-user", permissions = new[] { "api-tokens.issue" } });

        var client = TestApi.Unique("spa");
        await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = client, clientType = "public", grantTypes = new[] { "password" }, scopes = new[] { "tsl-auth-admin", api }
        });
        return (api, gate, client);
    }

    private static async Task<(Guid Id, string Name)> UserAsync(HttpClient admin, string api)
    {
        var name = TestApi.Unique("acc");
        var created = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = name, email = $"{name}@it.local", password = Password, roles = new[] { new { clientId = api, role = "reader" } }
        });
        return (created.GetProperty("user").GetProperty("id").GetGuid(), name);
    }

    /// <summary>Клиент с access-токеном пользователя (как у оболочки: audience tsl-auth-admin).</summary>
    private async Task<HttpClient> AsUserAsync(string client, string user)
    {
        var http = fx.Factory.CreateClient();
        var token = await http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = user, ["password"] = Password, ["scope"] = "tsl-auth-admin"
        });
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.GetProperty("access_token").GetString());
        return http;
    }

    /// <summary>Политика PAT требует разрешение; возвращает восстановление исходных настроек.</summary>
    private static async Task<Func<Task>> RequirePermissionAsync(HttpClient admin, string permission)
    {
        var original = (await admin.GetJsonAsync("/api/admin/settings")).GetRawText();
        var updated = JsonNode.Parse(original)!;
        updated["patPolicy"] = new JsonObject { ["enabled"] = true, ["maxLifetimeDays"] = 365, ["maxTokensPerUser"] = 20,
            ["requiredPermission"] = permission };
        await (await admin.PutAsJsonAsync("/api/admin/settings", updated)).JsonAsync();
        return async () => await (await admin.PutAsJsonAsync("/api/admin/settings", JsonNode.Parse(original))).JsonAsync();
    }

    [Fact]
    public async Task Issue_RequiresPermission_ThenWorksAndExchanges()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, gate, client) = await SetupAsync(admin);
        var restore = await RequirePermissionAsync(admin, $"{gate}:api-tokens.issue");
        try
        {
            var (userId, name) = await UserAsync(admin, api);
            var me = await AsUserAsync(client, name);

            // Без роли «Доступ по API»: выпуск недоступен.
            var options = await me.GetJsonAsync("/api/account/tokens/options");
            Assert.False(options.GetProperty("canIssue").GetBoolean());
            Assert.Contains(options.GetProperty("applications").EnumerateArray(), a => a.GetProperty("clientId").GetString() == api);
            var denied = await me.PostAsJsonAsync("/api/account/tokens", new { name = "скрипт", audiences = new[] { api }, expiresInDays = 30 });
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

            // Администратор назначает роль — выпуск доступен сразу, без перезахода.
            await (await admin.PutAsJsonAsync($"/api/admin/users/{userId}/roles", new[]
            {
                new { clientId = api, role = "reader" }, new { clientId = gate, role = "api-user" }
            })).JsonAsync();
            Assert.True((await me.GetJsonAsync("/api/account/tokens/options")).GetProperty("canIssue").GetBoolean());
            var created = await me.PostJsonAsync("/api/account/tokens", new { name = "скрипт", audiences = new[] { api }, expiresInDays = 30 });
            var secret = created.GetProperty("secret").GetString()!;
            Assert.StartsWith("tslpat_", secret);

            // В списке — только метаданные (без секрета); токен обменивается на JWT с правами владельца.
            var list = await me.GetJsonAsync("/api/account/tokens");
            var item = Assert.Single(list.EnumerateArray());
            Assert.False(item.TryGetProperty("secret", out _));
            var jwt = await fx.Factory.CreateClient().TokenAsync(new()
            {
                ["grant_type"] = "urn:tsl:grant-type:pat", ["client_id"] = "tsl-pat", ["token"] = secret
            });
            Assert.False(string.IsNullOrEmpty(jwt.GetProperty("access_token").GetString()));

            // Отзыв своего токена.
            var id = item.GetProperty("id").GetGuid();
            Assert.Equal(HttpStatusCode.NoContent, (await me.DeleteAsync($"/api/account/tokens/{id}")).StatusCode);
            Assert.False((await me.GetJsonAsync("/api/account/tokens")).EnumerateArray().Single().GetProperty("isActive").GetBoolean());
        }
        finally { await restore(); }
    }

    [Fact]
    public async Task ForeignToken_NotRevoked_ClientToken_Rejected()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api, _, client) = await SetupAsync(admin);
        var (_, owner) = await UserAsync(admin, api);
        var (_, other) = await UserAsync(admin, api);
        var ownerHttp = await AsUserAsync(client, owner);
        var created = await ownerHttp.PostJsonAsync("/api/account/tokens", new { name = "мой", audiences = new[] { api }, expiresInDays = 7 });
        var id = created.GetProperty("token").GetProperty("id").GetGuid();

        var otherHttp = await AsUserAsync(client, other);
        Assert.Equal(HttpStatusCode.NotFound, (await otherHttp.DeleteAsync($"/api/account/tokens/{id}")).StatusCode);
        Assert.Empty((await otherHttp.GetJsonAsync("/api/account/tokens")).EnumerateArray());

        // Токен клиента (client_credentials Admin API) не является пользователем — API отвечает 403.
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.GetAsync("/api/account/tokens")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await fx.Factory.CreateClient().GetAsync("/api/account/tokens")).StatusCode);
    }
}

[Collection("sqlite-account-tokens")]
public sealed class SqliteAccountTokenScenarios(SqliteFixture fx) : AccountTokenScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

[Collection("postgres-account-tokens")]
public sealed class PostgresAccountTokenScenarios(PostgresFixture fx) : AccountTokenScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
