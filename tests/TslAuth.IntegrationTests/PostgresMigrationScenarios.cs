using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.IntegrationTests.Infrastructure;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Переход с одиночного режима (SQLite) на кластер (PostgreSQL) командой <c>admin migrate-to-postgres</c>:
/// все данные переносятся со сверкой, после чего сервис на PostgreSQL работает для пользователей как раньше —
/// те же пароли, права, сессии (refresh-токены) и ключи подписи.
/// </summary>
[Collection("postgres-migration")]
public sealed class PostgresMigrationScenarios(SqliteFixture sqlite) : IClassFixture<SqliteFixture>, IAsyncLifetime
{
    private const string Password = "M1grate-Passw0rd!";
    private readonly PostgresFixture _pg = new();

    // Кластер на PostgreSQL уже стартовал и создал свои начальные данные — приёмник непустой.
    public Task InitializeAsync() => _pg.InitializeAsync();
    public Task DisposeAsync() => _pg.DisposeAsync();

    [Fact]
    public async Task SqliteData_MovesToPostgres_AndUsersKeepWorking()
    {
        // ---------- Данные одиночного режима ----------
        var admin = await sqlite.Factory.AdminAsync();
        var api = TestApi.Unique("api");
        var web = TestApi.Unique("web");
        var svc = TestApi.Unique("svc");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "write" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "writer", permissions = new[] { "read", "write" } });
        await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = web, clientType = "public", grantTypes = new[] { "password", "refresh_token" }, scopes = new[] { "profile", api }
        });
        var service = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = svc, clientType = "confidential", grantTypes = new[] { "client_credentials" }, scopes = new[] { api }
        });
        await admin.PutJsonAsync($"/api/admin/applications/{svc}/service-roles", new[] { new { clientId = api, role = "writer" } });
        var userName = TestApi.Unique("user");
        var created = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName, email = $"{userName}@it.local", password = Password, roles = new[] { new { clientId = api, role = "writer" } }
        });
        var userId = created.GetProperty("user").GetProperty("id").GetGuid();

        var session = await PasswordGrantAsync(sqlite.Factory.CreateClient(), web, api, userName, Password);
        var permissionsBefore = Permissions(session);
        var jwksBefore = await sqlite.Factory.CreateClient().GetStringAsync("/.well-known/jwks");

        // ---------- Перенос: кластер остановлен, данные SQLite заменяют его стартовые данные ----------
        IReadOnlyList<PostgresMigration.TableResult> results = [];
        await _pg.RestartAsync(async () =>
        {
            using var scope = sqlite.Factory.Services.CreateScope();
            var source = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

            // Без --overwrite непустой приёмник не трогается.
            var refused = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                PostgresMigration.RunAsync(source, _pg.ConnectionString, overwrite: false, NullLogger.Instance));
            Assert.Contains("уже есть данные", refused.Message);

            results = await PostgresMigration.RunAsync(source, _pg.ConnectionString, overwrite: true, NullLogger.Instance);
        });

        // Сверка: каждая таблица перенесена полностью и без искажений.
        Assert.NotEmpty(results);
        Assert.All(results, r => Assert.True(r.Ok, $"{r.Table}: {r.SourceRows} → {r.TargetRows}"));
        Assert.Contains(results, r => r.Table == "AspNetUsers" && r.TargetRows >= 2);
        Assert.Contains(results, r => r.Table == "OpenIddictTokens" && r.TargetRows > 0);

        // ---------- Сервис на PostgreSQL ----------
        var http = _pg.Factory.CreateClient();
        Assert.Equal(jwksBefore, await http.GetStringAsync("/.well-known/jwks")); // ключи подписи перенесены

        // Сессия, начатая в одиночном режиме, продолжается в кластере.
        var refreshed = await http.TokenAsync(new()
        {
            ["grant_type"] = "refresh_token", ["client_id"] = web, ["refresh_token"] = session.GetProperty("refresh_token").GetString()!
        });
        Assert.Equal(permissionsBefore, Permissions(refreshed));

        // Старый пароль, права, сервисный клиент со старым секретом.
        Assert.Equal(permissionsBefore, Permissions(await PasswordGrantAsync(http, web, api, userName, Password)));
        var svcToken = await http.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = svc,
            ["client_secret"] = service.GetProperty("clientSecret").GetString()!, ["scope"] = api
        });
        Assert.Contains($"{api}:write", Permissions(svcToken));

        // Администрирование: зашифрованные данные читаются, изменения сохраняются.
        var pgAdmin = await _pg.Factory.AdminAsync();
        var card = await pgAdmin.GetJsonAsync($"/api/admin/users/{userId}");
        var user = card.TryGetProperty("user", out var u) ? u : card;
        Assert.Equal($"{userName}@it.local", user.GetProperty("email").GetString());
        (await pgAdmin.PostAsJsonAsync($"/api/admin/users/{userId}/unlock", new { })).EnsureSuccessStatusCode();

        // Счётчики автоинкремента продолжают с перенесённых значений (иначе новые записи журнала конфликтовали бы по ключу).
        await using var db = _pg.CreateDbContext();
        var maxBefore = await db.AuditEntries.MaxAsync(a => (long?)a.Id) ?? 0;
        db.AuditEntries.Add(new AuditEntry { Type = "test.migration", OccurredAt = DateTime.UtcNow, Success = true });
        await db.SaveChangesAsync();
        Assert.True(await db.AuditEntries.MaxAsync(a => a.Id) > maxBefore);
    }

    private static Task<JsonElement> PasswordGrantAsync(HttpClient http, string client, string api, string user, string password) =>
        http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = user, ["password"] = password,
            ["scope"] = $"openid offline_access {api}"
        });

    private static string[] Permissions(JsonElement token) =>
        TestApi.Claims(token.GetProperty("access_token").GetString()!).Strings("permissions").Order().ToArray();
}
