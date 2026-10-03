// Сервис-робот работает вместо пользователя с его правами: пользователь выписывает токен подключения (PAT, привязанный
// к сервису), сервис обменивает его на JWT со своими учётными данными (grant urn:tsl:grant-type:pat).
// Запуск: dotnet test tests/TslAuth.IntegrationTests (вариант на PostgreSQL — через Testcontainers, нужен Docker).

using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using TslAuth.Data;
using TslAuth.IntegrationTests.Infrastructure;
using TslAuth.Services;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Токен подключения сервиса-робота: права и приложения пользователя (в том числе «все приложения» по текущим ролям),
/// claim act с роботом, обмен только самим роботом, отказы при отзыве, отключении и удалении. SQLite и PostgreSQL.
/// </summary>
public abstract class RobotTokenScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private sealed record Robot(string ClientId, string Secret);

    // ---------- Подготовка ----------

    /// <summary>Приложение-ресурс с разрешением read и ролью reader.</summary>
    private static async Task<string> ApiAsync(HttpClient admin)
    {
        var api = TestApi.Unique("api");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" } });
        return api;
    }

    /// <summary>Confidential-клиент; <paramref name="robot"/> — с разрешением работать по токенам подключения.</summary>
    private static async Task<Robot> ClientAsync(HttpClient admin, bool robot = true)
    {
        var id = TestApi.Unique(robot ? "robot" : "svc");
        var created = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = id, clientType = "confidential",
            grantTypes = robot ? new[] { "connection_token" } : new[] { "client_credentials" }
        });
        return new Robot(id, created.GetProperty("clientSecret").GetString()!);
    }

    private static async Task<Guid> UserAsync(HttpClient admin, params string[] apis)
    {
        var name = TestApi.Unique("u");
        var created = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = name, email = $"{name}@it.local", password = TestApi.NewPassword(),
            roles = apis.Select(a => new { clientId = a, role = "reader" }).ToArray()
        });
        return created.GetProperty("user").GetProperty("id").GetGuid();
    }

    private async Task<string> IssueAsync(Guid userId, PatInput input)
    {
        using var scope = fx.Factory.Services.CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<PatService>().CreateAsync(userId, input)).Secret;
    }

    private static Task<JsonElement> ExchangeAsync(HttpClient http, string clientId, string? secret, string token) =>
        http.TokenAsync(secret is null
            ? new() { ["grant_type"] = PatService.GrantType, ["client_id"] = clientId, ["token"] = token }
            : new() { ["grant_type"] = PatService.GrantType, ["client_id"] = clientId, ["client_secret"] = secret, ["token"] = token },
            expectSuccess: false);

    private static string? Error(JsonElement response) => response.TryGetProperty("error", out var e) ? e.GetString() : null;

    private static JsonElement Jwt(JsonElement response) => TestApi.Claims(response.GetProperty("access_token").GetString()!);

    // ---------- Сценарии ----------

    /// <summary>
    /// Робот получает JWT пользователя: sub — пользователь, act.sub — робот, права — текущие права пользователя во всех его
    /// приложениях (новая роль подхватывается без нового токена, снятая — пропадает).
    /// </summary>
    [Fact]
    public async Task Robot_ActsWithUserRights_InAllUserApplications()
    {
        var admin = await fx.Factory.AdminAsync();
        var (api1, api2) = (await ApiAsync(admin), await ApiAsync(admin));
        var robot = await ClientAsync(admin);
        var userId = await UserAsync(admin, api1);
        var token = await IssueAsync(userId, new PatInput("робот отчётов", [], 30, AllApplications: true, ClientId: robot.ClientId));
        var http = fx.Factory.CreateClient();

        var first = await ExchangeAsync(http, robot.ClientId, robot.Secret, token);
        Assert.Null(Error(first));
        var claims = Jwt(first);
        Assert.Equal(userId.ToString(), claims.GetProperty("sub").GetString());
        Assert.Equal(robot.ClientId, JsonDocument.Parse(claims.GetProperty("act").ToString()).RootElement.GetProperty("sub").GetString());
        Assert.Contains(api1, claims.Strings("aud"));
        Assert.Contains($"{api1}:read", claims.Strings("permissions"));
        Assert.False(first.TryGetProperty("refresh_token", out _));

        // Роль в api2 выдана позже — JWT робота адресован и api2; роль в api1 снята — api1 пропадает.
        await admin.PutJsonAsync($"/api/admin/users/{userId}/roles", new[] { new { clientId = api2, role = "reader" } });
        var second = Jwt(await ExchangeAsync(http, robot.ClientId, robot.Secret, token));
        Assert.Contains(api2, second.Strings("aud"));
        Assert.DoesNotContain(api1, second.Strings("aud"));
        Assert.Contains($"{api2}:read", second.Strings("permissions"));

        // Токен виден пользователю как токен подключения этого робота ко всем приложениям.
        using var scope = fx.Factory.Services.CreateScope();
        var listed = (await scope.ServiceProvider.GetRequiredService<PatService>().ListAsync(userId)).Single();
        Assert.True(listed.AllApplications);
        Assert.Equal(robot.ClientId, listed.ClientId);
        Assert.NotNull(listed.LastUsedAt);
    }

    /// <summary>Обменять токен подключения может только робот, которому он выписан, и только со своим секретом.</summary>
    [Fact]
    public async Task ConnectionToken_OnlyItsRobot_WithItsSecret()
    {
        var admin = await fx.Factory.AdminAsync();
        var api = await ApiAsync(admin);
        var (robot, other) = (await ClientAsync(admin), await ClientAsync(admin));
        var userId = await UserAsync(admin, api);
        var token = await IssueAsync(userId, new PatInput("робот", [api], 30, ClientId: robot.ClientId));
        var script = await IssueAsync(userId, new PatInput("скрипт", [api], 30));
        var http = fx.Factory.CreateClient();

        // Выбранные приложения (не «все»): JWT только для них, act — робот.
        var ok = Jwt(await ExchangeAsync(http, robot.ClientId, robot.Secret, token));
        Assert.Equal([api], ok.Strings("aud"));

        Assert.Equal("invalid_grant", Error(await ExchangeAsync(http, other.ClientId, other.Secret, token)));   // чужой робот
        Assert.Equal("invalid_grant", Error(await ExchangeAsync(http, PatService.PatClientId, null, token)));   // как скрипт
        Assert.Equal("invalid_client", Error(await ExchangeAsync(http, robot.ClientId, "wrong-secret", token))); // без секрета робота
        Assert.Equal("invalid_grant", Error(await ExchangeAsync(http, robot.ClientId, robot.Secret, script)));  // токен для скриптов

        // Обычный PAT скрипта по-прежнему работает через tsl-pat и без claim act.
        var plain = Jwt(await ExchangeAsync(http, PatService.PatClientId, null, script));
        Assert.False(plain.TryGetProperty("act", out _));

        // Сервис без разрешения на токены подключения не может обменивать их даже со своим секретом.
        var plainService = await ClientAsync(admin, robot: false);
        Assert.Equal("unauthorized_client", Error(await ExchangeAsync(http, plainService.ClientId, plainService.Secret, token)));
    }

    /// <summary>Выпустить токен подключения можно только роботу, которому администратор это разрешил.</summary>
    [Fact]
    public async Task ConnectionToken_Issued_OnlyToAllowedRobots()
    {
        var admin = await fx.Factory.AdminAsync();
        var api = await ApiAsync(admin);
        var robot = await ClientAsync(admin);
        var plainService = await ClientAsync(admin, robot: false);
        var userId = await UserAsync(admin, api);

        using var scope = fx.Factory.Services.CreateScope();
        var pats = scope.ServiceProvider.GetRequiredService<PatService>();
        var services = await pats.ServiceClientsAsync();
        Assert.Contains(services, s => s.ClientId == robot.ClientId);
        Assert.DoesNotContain(services, s => s.ClientId == plainService.ClientId || s.ClientId == PatService.PatClientId);

        var denied = await Assert.ThrowsAsync<AdminException>(() =>
            pats.CreateAsync(userId, new PatInput("x", [api], 30, ClientId: plainService.ClientId)));
        Assert.Equal("error.tokenServiceInvalid", denied.Key);

        // Public-клиенту разрешение не выдаётся: токен подключения обменивается только с секретом или ключом.
        var response = await admin.PostAsJsonAsync("/api/admin/applications", new
        {
            clientId = TestApi.Unique("spa"), clientType = "public", grantTypes = new[] { "connection_token" }
        });
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);

        // Отключённому роботу новый токен не выписывается (новая область: как в отдельном запросе, без кэша EF).
        await admin.PostJsonAsync($"/api/admin/applications/{robot.ClientId}/disable", new { });
        using var after = fx.Factory.Services.CreateScope();
        Assert.DoesNotContain(await after.ServiceProvider.GetRequiredService<PatService>().ServiceClientsAsync(), s => s.ClientId == robot.ClientId);
    }

    /// <summary>Отзыв токена, отключение пользователя или робота и удаление робота прекращают выдачу JWT.</summary>
    [Fact]
    public async Task ConnectionToken_Stops_OnRevoke_UserOrRobotDisabled_RobotDeleted()
    {
        var admin = await fx.Factory.AdminAsync();
        var api = await ApiAsync(admin);
        var robot = await ClientAsync(admin);
        var userId = await UserAsync(admin, api);
        var token = await IssueAsync(userId, new PatInput("робот", [], 30, AllApplications: true, ClientId: robot.ClientId));
        var http = fx.Factory.CreateClient();
        Assert.Null(Error(await ExchangeAsync(http, robot.ClientId, robot.Secret, token)));

        // Робот отключён администратором — клиент отвергается целиком.
        await admin.PostAsJsonAsync($"/api/admin/applications/{robot.ClientId}/disable", new { });
        Assert.Equal("invalid_client", Error(await ExchangeAsync(http, robot.ClientId, robot.Secret, token)));
        await admin.PostAsJsonAsync($"/api/admin/applications/{robot.ClientId}/enable", new { });
        Assert.Null(Error(await ExchangeAsync(http, robot.ClientId, robot.Secret, token)));

        // Пользователь отключён — робот больше не действует от его имени.
        using (var scope = fx.Factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.Where(u => u.Id == userId)
                .ExecuteUpdateAsync(u => u.SetProperty(x => x.IsActive, false));
        Assert.Equal("invalid_grant", Error(await ExchangeAsync(http, robot.ClientId, robot.Secret, token)));
        using (var scope = fx.Factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.Where(u => u.Id == userId)
                .ExecuteUpdateAsync(u => u.SetProperty(x => x.IsActive, true));

        // Пользователь отозвал токен.
        Guid tokenId;
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var pats = scope.ServiceProvider.GetRequiredService<PatService>();
            tokenId = (await pats.ListAsync(userId)).Single().Id;
            await pats.RevokeAsync(tokenId, userId);
        }
        Assert.Equal("invalid_grant", Error(await ExchangeAsync(http, robot.ClientId, robot.Secret, token)));

        // Робот удалён — все выписанные ему токены отзываются (новое приложение с тем же client_id их не получит).
        var fresh = await IssueAsync(userId, new PatInput("робот 2", [api], 30, ClientId: robot.ClientId));
        Assert.True((await admin.DeleteAsync($"/api/admin/applications/{robot.ClientId}")).IsSuccessStatusCode);
        using (var scope = fx.Factory.Services.CreateScope())
            Assert.All(await scope.ServiceProvider.GetRequiredService<AuthDbContext>().PersonalAccessTokens
                    .Where(t => t.UserId == userId).ToListAsync(), t => Assert.NotNull(t.RevokedAt));
        Assert.NotEqual("", fresh);
    }
}

[Collection("sqlite-robot")]
public sealed class SqliteRobotTokenScenarios(SqliteFixture fx) : RobotTokenScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

[Collection("postgres-robot")]
public sealed class PostgresRobotTokenScenarios(PostgresFixture fx) : RobotTokenScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
