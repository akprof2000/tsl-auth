using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using TslAuth.IntegrationTests.Infrastructure;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Самовосстановление схемы (SchemaRepair): БД испорчена или в неизвестном состоянии — сервис при старте
/// сам пересобирает схему, переносит данные и продолжает работать. Пользователи входят с прежними паролями,
/// права на месте. Каждый сценарий ломает БД при остановленном сервисе и запускает его заново.
/// </summary>
public abstract class SchemaRepairScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private static readonly string Password = TestApi.NewPassword();

    /// <summary>Фикстура для сценариев наследников (без повторного захвата параметра конструктора).</summary>
    protected TFixture Fixture => fx;

    [Fact]
    public async Task PartiallyBrokenSchema_IsRebuilt_DataKept()
    {
        var (web, api, user) = await PrepareAsync();

        // Удалены таблица и столбец, а история миграций говорит, что схема полная.
        await fx.RestartAsync(() => SqlAsync(
            "DROP TABLE \"PasswordHistory\"",
            "ALTER TABLE \"AspNetUsers\" DROP COLUMN \"LastLoginAt\""));

        await AssertWorksAsync(web, api, user);
    }

    [Fact]
    public async Task UnknownMigrationHistory_IsRebuilt()
    {
        var (web, api, user) = await PrepareAsync();

        // Чужая миграция «в прошлом» — схема не из этой ветки версий.
        await fx.RestartAsync(() => SqlAsync(
            "INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ('20200101000000_ForeignBranch', '9.0.0')"));

        await AssertWorksAsync(web, api, user);
        Assert.DoesNotContain("20200101000000_ForeignBranch", await AppliedAsync());
    }

    [Fact]
    public async Task MissingMigrationHistory_IsRebuilt()
    {
        var (web, api, user) = await PrepareAsync();

        // Таблицы есть, истории нет (схему создали скриптом или восстановили частично).
        await fx.RestartAsync(() => SqlAsync("DROP TABLE \"__EFMigrationsHistory\""));

        await AssertWorksAsync(web, api, user);
        Assert.Equal(fx.CreateDbContext().Database.GetMigrations(), await AppliedAsync());
    }

    [Fact]
    public async Task NewerSchema_StopsStart_UntilFixed()
    {
        const string future = "29990101000000_FromTheFuture";
        // Схема новее сервиса (откат образа): без Database__AllowDowngrade запуск останавливается и ничего не меняет.
        var error = await Assert.ThrowsAnyAsync<Exception>(() => fx.RestartAsync(() => SqlAsync(
            $"INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ('{future}', '99.0.0')")));
        Assert.Contains("новее версии сервиса", Flatten(error));
        Assert.Contains(future, await AppliedAsync());

        await fx.RestartAsync(() => SqlAsync($"DELETE FROM \"__EFMigrationsHistory\" WHERE \"MigrationId\" = '{future}'"));
        Assert.Equal(HttpStatusCode.OK, (await fx.Factory.CreateClient().GetAsync("/health/ready")).StatusCode);
    }

    // ---------- Помощники ----------

    private async Task<(string Web, string Api, string User)> PrepareAsync()
    {
        var admin = await fx.Factory.AdminAsync();
        var api = TestApi.Unique("api");
        var web = TestApi.Unique("web");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = api, clientType = "public", grantTypes = Array.Empty<string>() });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/permissions", new { name = "read" });
        await admin.PostJsonAsync($"/api/admin/applications/{api}/roles", new { name = "reader", permissions = new[] { "read" } });
        await admin.PostJsonAsync("/api/admin/applications", new
        {
            clientId = web, clientType = "public", grantTypes = new[] { "password" }, scopes = new[] { "profile", api }
        });
        var user = TestApi.Unique("user");
        await admin.PostJsonAsync("/api/admin/users", new
        {
            userName = user, email = $"{user}@it.local", password = Password, roles = new[] { new { clientId = api, role = "reader" } }
        });
        await LoginAsync(web, api, user); // до поломки всё работает
        return (web, api, user);
    }

    private async Task AssertWorksAsync(string web, string api, string user)
    {
        var http = fx.Factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/ready")).StatusCode);
        var token = await LoginAsync(web, api, user);
        Assert.Contains($"{api}:read", TestApi.Claims(token.GetProperty("access_token").GetString()!).Strings("permissions"));

        await using var db = fx.CreateDbContext();
        Assert.Empty(await TslAuth.Infrastructure.SchemaRepair.CompareWithModelAsync(db));
    }

    private Task<JsonElement> LoginAsync(string web, string api, string user) =>
        fx.Factory.CreateClient().TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = web, ["username"] = user, ["password"] = Password, ["scope"] = $"openid {api}"
        });

    private async Task SqlAsync(params string[] statements)
    {
        await using var db = fx.CreateDbContext();
        foreach (var sql in statements) await db.Database.ExecuteSqlRawAsync(sql);
    }

    private async Task<List<string>> AppliedAsync()
    {
        await using var db = fx.CreateDbContext();
        return (await db.Database.GetAppliedMigrationsAsync()).ToList();
    }

    private static string Flatten(Exception ex) => ex.InnerException is null ? ex.Message : ex.Message + " → " + Flatten(ex.InnerException);
}

[Collection("sqlite-repair")]
public sealed class SqliteSchemaRepairScenarios(SqliteFixture fx) : SchemaRepairScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>
{
    /// <summary>
    /// Физически повреждённый файл SQLite: середина файла перезаписана мусором. Сервис стартует — читаемые
    /// данные перенесены, повреждённая копия сохранена рядом с БД для ручного разбора.
    /// </summary>
    [Fact]
    public async Task CorruptedSqliteFile_IsSalvaged()
    {
        var admin = await Fixture.Factory.AdminAsync();
        for (var i = 0; i < 40; i++)
            await admin.PostJsonAsync("/api/admin/users", new { userName = TestApi.Unique("bulk"), password = TestApi.NewPassword() });

        await Fixture.RestartAsync(async () =>
        {
            await using var db = Fixture.CreateDbContext();
            await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(TRUNCATE)");
            await db.Database.CloseConnectionAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            await using var file = File.Open(Fixture.DatabasePath, FileMode.Open, FileAccess.ReadWrite);
            var garbage = new byte[16 * 1024];
            Random.Shared.NextBytes(garbage);
            file.Position = file.Length / 2;
            await file.WriteAsync(garbage);
        });

        Assert.Equal(HttpStatusCode.OK, (await Fixture.Factory.CreateClient().GetAsync("/health/ready")).StatusCode);
        Assert.NotEmpty(Directory.GetFiles(Path.GetDirectoryName(Fixture.DatabasePath)!, "auth.db.backup-*"));
        // Администратор есть в любом случае: если его строка была на испорченной странице, сид создаст его заново.
        Assert.Equal(HttpStatusCode.OK, (await (await Fixture.Factory.AdminAsync()).GetAsync("/api/admin/users")).StatusCode);
    }
}

[Collection("postgres-repair")]
public sealed class PostgresSchemaRepairScenarios(PostgresFixture fx) : SchemaRepairScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
