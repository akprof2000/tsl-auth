using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using TslAuth.Data;

namespace TslAuth.IntegrationTests.Infrastructure;

/// <summary>
/// Поднимает сервис целиком (WebApplicationFactory) на выбранной БД. Конфигурация передаётся переменными
/// окружения — так её видит код Program ещё до построения хоста. Тесты не параллелятся (см. xunit.runner.json).
/// </summary>
public abstract class AuthFixture : IAsyncLifetime
{
    public const string MasterKey = "dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzLWxvbmctISE="; // 32 байта, только для тестов
    public const string AdminClientId = "it-admin";
    public const string AdminClientSecret = "it-admin-secret";
    public const string AdminUser = "admin";
    public const string AdminPassword = "Boot-Str4p-Secret!";

    public WebApplicationFactory<Program> Factory { get; private set; } = null!;
    private Dictionary<string, string> _database = [];

    /// <summary>Строка подключения к БД этого экземпляра.</summary>
    public string ConnectionString => _database["Database__ConnectionString"];

    protected abstract Task<Dictionary<string, string>> DatabaseSettingsAsync();
    public abstract string ProviderName { get; }

    public async Task InitializeAsync()
    {
        _database = await DatabaseSettingsAsync();
        Factory = Start();
        await Factory.CreateClient().GetAsync("/health/ready");
    }

    /// <summary>Новый экземпляр сервиса на той же БД — эмуляция перезапуска/второго узла кластера.</summary>
    public WebApplicationFactory<Program> Start()
    {
        var settings = new Dictionary<string, string>
        {
            ["ASPNETCORE_ENVIRONMENT"] = "Testing",
            ["Encryption__MasterKey"] = MasterKey,
            ["Auth__Issuer"] = "http://localhost/",
            ["Auth__RequireHttps"] = "false",
            ["Auth__RefreshTokenReuseLeewaySeconds"] = "0",
            ["Bootstrap__AdminUserName"] = AdminUser,
            ["Bootstrap__AdminPassword"] = AdminPassword,
            ["Bootstrap__AdminApiClientId"] = AdminClientId,
            ["Bootstrap__AdminApiClientSecret"] = AdminClientSecret,
            ["Security__TokenRequestsPerMinute"] = "100000",
            ["Security__LoginAttemptsPerMinute"] = "100000",
            ["Logging__LogLevel__Default"] = "Warning"
        };
        foreach (var (k, v) in settings.Concat(_database)) Environment.SetEnvironmentVariable(k, v);
        return new WebApplicationFactory<Program>();
    }

    /// <summary>
    /// Останавливает сервис, выполняет действие над БД без него и запускает сервис заново —
    /// так тесты обновления эмулируют замену версии на той же базе.
    /// </summary>
    public async Task RestartAsync(Func<Task>? whileStopped = null)
    {
        await Factory.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (whileStopped is not null) await whileStopped();
        Factory = Start();
        await Factory.CreateClient().GetAsync("/health/ready");
    }

    /// <summary>Контекст БД напрямую, в обход сервиса (откат схемы и проверки в тестах обновления).</summary>
    public AuthDbContext CreateDbContext()
    {
        var cs = _database["Database__ConnectionString"];
        return _database["Database__Provider"] == "Postgres"
            ? new PostgresAuthDbContext(new DbContextOptionsBuilder<PostgresAuthDbContext>().UseNpgsql(cs).Options)
            : new SqliteAuthDbContext(new DbContextOptionsBuilder<SqliteAuthDbContext>().UseSqlite(cs).Options);
    }

    public virtual async Task DisposeAsync() => await Factory.DisposeAsync();
}

/// <summary>SQLite-файл во временном каталоге; каталог удаляется после тестов.</summary>
public sealed class SqliteFixture : AuthFixture
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tslauth-it-" + Guid.NewGuid().ToString("N"));
    public override string ProviderName => "SQLite";

    protected override Task<Dictionary<string, string>> DatabaseSettingsAsync()
    {
        Directory.CreateDirectory(_dir);
        return Task.FromResult(new Dictionary<string, string>
        {
            ["Database__Provider"] = "Sqlite",
            ["Database__ConnectionString"] = $"Data Source={Path.Combine(_dir, "auth.db")}"
        });
    }

    public string DatabasePath => Path.Combine(_dir, "auth.db");

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }
}

/// <summary>Настоящий PostgreSQL в контейнере; базу сервис создаёт сам (проверка автосоздания и миграций).</summary>
public sealed class PostgresFixture : AuthFixture
{
    private readonly PostgreSqlContainer _pg = new PostgreSqlBuilder("postgres:17-alpine").Build();
    public override string ProviderName => "PostgreSQL";

    protected override async Task<Dictionary<string, string>> DatabaseSettingsAsync()
    {
        await _pg.StartAsync();
        var cs = new Npgsql.NpgsqlConnectionStringBuilder(_pg.GetConnectionString()) { Database = "tsl_auth_it" };
        return new Dictionary<string, string>
        {
            ["Database__Provider"] = "Postgres",
            ["Database__ConnectionString"] = cs.ConnectionString
        };
    }

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _pg.DisposeAsync();
    }
}

/// <summary>Короткие помощники для HTTP-вызовов к сервису.</summary>
public static class TestApi
{
    public static async Task<JsonElement> TokenAsync(this HttpClient client, Dictionary<string, string> form, bool expectSuccess = true)
    {
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(form));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (expectSuccess && !response.IsSuccessStatusCode)
            throw new InvalidOperationException($"token: {(int)response.StatusCode} {body}");
        return body;
    }

    public static async Task<HttpClient> AdminAsync(this WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        var token = await client.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = AuthFixture.AdminClientId,
            ["client_secret"] = AuthFixture.AdminClientSecret, ["scope"] = "tsl-auth-admin"
        });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.GetProperty("access_token").GetString());
        return client;
    }

    public static HttpClient WithBearer(this HttpClient client, string token)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public static async Task<JsonElement> JsonAsync(this HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"{(int)response.StatusCode}: {text}");
        return text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    public static async Task<JsonElement> PostJsonAsync(this HttpClient c, string url, object body) =>
        await (await c.PostAsJsonAsync(url, body)).JsonAsync();

    public static async Task<JsonElement> PutJsonAsync(this HttpClient c, string url, object body) =>
        await (await c.PutAsJsonAsync(url, body)).JsonAsync();

    public static async Task<JsonElement> GetJsonAsync(this HttpClient c, string url) => await (await c.GetAsync(url)).JsonAsync();

    /// <summary>Декодирует payload JWT без проверки подписи (проверка — отдельный тест).</summary>
    public static JsonElement Claims(string jwt)
    {
        var payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload += new string('=', (4 - payload.Length % 4) % 4);
        return JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement.Clone();
    }

    public static string[] Strings(this JsonElement claims, string name) =>
        !claims.TryGetProperty(name, out var v) ? []
        : v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Select(x => x.GetString()!).ToArray()
        : [v.GetString()!];

    public static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid().ToString("N")[..8]}";
}
