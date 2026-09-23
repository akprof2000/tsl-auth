using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using TslAuth.IntegrationTests.Infrastructure;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Обновление версии на живых данных: БД первой версии (только миграция InitialCreate) с пользователями,
/// паролями, приложениями, матрицей прав и выданными токенами → запуск текущей версии, которая сама
/// докатывает схему. Пользователи не должны заметить обновления: тот же пароль, те же права,
/// выданные до обновления access- и refresh-токены продолжают работать, смена пароля не требуется.
///
/// Как получается «старая» БД: данные создаются обычными сценариями, затем сервис останавливается и схема
/// откатывается штатными Down-миграциями EF до InitialCreate — новые столбцы и таблицы удаляются, а записи
/// в таблицах первой версии (пользователи, роли, клиенты, авторизации, токены, ключи) остаются как есть.
/// </summary>
public abstract class UpgradeScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private const string FirstVersion = "InitialCreate";
    private const string Password = "Upgr4de-Passw0rd!";

    [Fact]
    public async Task OldDatabase_IsUpgraded_AndUsersKeepWorking()
    {
        // ---------- Данные «старой версии» ----------
        var admin = await fx.Factory.AdminAsync();
        var api = TestApi.Unique("api");
        var web = TestApi.Unique("web");
        var svc = TestApi.Unique("svc");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "write" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" } });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "writer", permissions = new[] { "read", "write" } });
        await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = web, clientType = "public", grantTypes = new[] { "password", "refresh_token" }, scopes = new[] { "profile", api }
        });
        var service = await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = svc, clientType = "confidential", grantTypes = new[] { "client_credentials" }, scopes = new[] { api }
        });
        var svcSecret = service.GetProperty("clientSecret").GetString()!;
        await admin.PutJsonAsync($"/api/admin/applications/{svc}/service-roles", new[] { new { clientId = api, role = "reader" } });

        var writer = await CreateUserAsync(admin, api, "writer");
        var reader = await CreateUserAsync(admin, api, "reader");

        // Пользователь вошёл до обновления: у него на руках access- и refresh-токен.
        var before = await PasswordGrantAsync(fx.Factory.CreateClient(), web, api, writer.Name);
        var oldAccess = before.GetProperty("access_token").GetString()!;
        var oldRefresh = before.GetProperty("refresh_token").GetString()!;
        var jwksBefore = await fx.Factory.CreateClient().GetStringAsync("/.well-known/jwks");
        var permissionsBefore = TestApi.Claims(oldAccess).Strings("permissions").Order().ToArray();
        var allMigrations = await AppliedMigrationsAsync();

        // ---------- Остановка и откат схемы до первой версии ----------
        await fx.RestartAsync(async () =>
        {
            await using var db = fx.CreateDbContext();
            await db.GetService<IMigrator>().MigrateAsync(FirstVersion);
            Assert.Equal([FirstVersion], (await db.Database.GetAppliedMigrationsAsync()).Select(Name));
        });

        // ---------- Новая версия запущена: схема докатана автоматически ----------
        Assert.Equal(allMigrations, await AppliedMigrationsAsync());
        var http = fx.Factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/ready")).StatusCode);

        // Ключи подписи пережили обновление: токен, выданный старой версией, проходит проверку.
        Assert.Equal(jwksBefore, await http.GetStringAsync("/.well-known/jwks"));
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(oldAccess, new TokenValidationParameters
        {
            ValidIssuer = "http://localhost/", ValidAudience = api,
            IssuerSigningKeys = new JsonWebKeySet(await http.GetStringAsync("/.well-known/jwks")).GetSigningKeys()
        });
        Assert.True(validation.IsValid, validation.Exception?.Message);
        var userinfo = await fx.Factory.CreateClient().WithBearer(oldAccess).GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.OK, userinfo.StatusCode);

        // Сессия продолжается: refresh-токен старой версии принимается, права те же.
        var refreshed = await http.TokenAsync(new() { ["grant_type"] = "refresh_token", ["client_id"] = web, ["refresh_token"] = oldRefresh });
        Assert.Equal(permissionsBefore, TestApi.Claims(refreshed.GetProperty("access_token").GetString()!).Strings("permissions").Order());

        // Включаем срок действия пароля: у старых пользователей даты смены пароля нет (столбец появился позже),
        // вместо неё берётся дата создания — недавно созданных пользователей сменить пароль не заставят.
        await SetPasswordMaxAgeAsync(await fx.Factory.AdminAsync(), 90);

        // Вход со старым паролем, права из матрицы на месте.
        var writerLogin = TestApi.Claims((await PasswordGrantAsync(http, web, api, writer.Name)).GetProperty("access_token").GetString()!);
        Assert.Equal(permissionsBefore, writerLogin.Strings("permissions").Order());
        Assert.Contains($"{api}:writer", writerLogin.Strings("role"));
        var readerLogin = TestApi.Claims((await PasswordGrantAsync(http, web, api, reader.Name)).GetProperty("access_token").GetString()!);
        Assert.Equal([$"{api}:read"], readerLogin.Strings("permissions"));

        // Сервисный клиент работает со старым секретом и старыми правами.
        var svcToken = await http.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = svc, ["client_secret"] = svcSecret, ["scope"] = api
        });
        Assert.Contains($"{api}:read", TestApi.Claims(svcToken.GetProperty("access_token").GetString()!).Strings("permissions"));

        // Зашифрованные персональные данные читаются, смена пароля не требуется.
        var adminAfter = await fx.Factory.AdminAsync();
        var card = await adminAfter.GetJsonAsync($"/api/admin/users/{writer.Id}");
        var user = card.TryGetProperty("user", out var u) ? u : card;
        Assert.Equal(writer.Name, user.GetProperty("userName").GetString());
        Assert.Equal($"{writer.Name}@it.local", user.GetProperty("email").GetString());
        Assert.False(user.GetProperty("mustChangePassword").GetBoolean());

        // Новые возможности работают на старых данных: смена пароля пишет историю (таблица из поздней миграции).
        (await adminAfter.PostAsJsonAsync($"/api/admin/users/{writer.Id}/password", new { password = "N3w-Upgr4de-Pass!" })).EnsureSuccessStatusCode();
        await PasswordGrantAsync(http, web, api, writer.Name, "N3w-Upgr4de-Pass!");

        await SetPasswordMaxAgeAsync(adminAfter, 0);
    }

    [Fact]
    public async Task RepeatedStart_OnUpgradedDatabase_ChangesNothing()
    {
        var before = await AppliedMigrationsAsync();
        await fx.RestartAsync();
        Assert.Equal(before, await AppliedMigrationsAsync());
        Assert.Equal(HttpStatusCode.OK, (await fx.Factory.CreateClient().GetAsync("/health/ready")).StatusCode);
    }

    private async Task<string[]> AppliedMigrationsAsync()
    {
        await using var db = fx.CreateDbContext();
        return (await db.Database.GetAppliedMigrationsAsync()).Select(Name).ToArray();
    }

    /// <summary>"20260923124720_InitialCreate" → "InitialCreate": у SQLite и PostgreSQL разные метки времени.</summary>
    private static string Name(string migrationId) => migrationId[(migrationId.IndexOf('_') + 1)..];

    private static async Task<(Guid Id, string Name)> CreateUserAsync(HttpClient admin, string api, string role)
    {
        var name = TestApi.Unique("user");
        var created = await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = name, email = $"{name}@it.local", password = Password, roles = new[] { new { clientId = api, role } }
        });
        return (created.GetProperty("user").GetProperty("id").GetGuid(), name);
    }

    private static Task<JsonElement> PasswordGrantAsync(HttpClient http, string client, string api, string user, string password = Password) =>
        http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = user, ["password"] = password,
            ["scope"] = $"openid offline_access {api}"
        });

    private static async Task SetPasswordMaxAgeAsync(HttpClient admin, int days)
    {
        var settings = JsonNode.Parse((await admin.GetJsonAsync("/api/admin/settings")).GetRawText())!;
        settings["passwordPolicy"] ??= new JsonObject(); // null — настройки не сохранялись, действуют значения по умолчанию
        settings["passwordPolicy"]!["maxAgeDays"] = days;
        await (await admin.PutAsJsonAsync("/api/admin/settings", settings)).JsonAsync();
    }
}

/// <summary>Обновление на SQLite (одиночный режим).</summary>
[Collection("sqlite-upgrade")]
public sealed class SqliteUpgradeScenarios(SqliteFixture fx) : UpgradeScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

/// <summary>Обновление на PostgreSQL (кластер).</summary>
[Collection("postgres-upgrade")]
public sealed class PostgresUpgradeScenarios(PostgresFixture fx) : UpgradeScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
