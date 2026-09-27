using System.Net;
using System.Net.Http.Json;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using Microsoft.AspNetCore.Mvc.Testing;
using TslAuth.Infrastructure;
using TslAuth.IntegrationTests.Infrastructure;

namespace TslAuth.IntegrationTests;

/// <summary>
/// OpenBao в контейнере (dev-режим) + TSL Auth, который берёт секреты из него по AppRole:
/// мастер-ключ, пароль администратора и секрет клиента Admin API. Значения из переменных окружения
/// фикстуры намеренно другие — побеждает хранилище.
/// </summary>
public sealed class OpenBaoFixture : AuthFixture
{
    public const string RootToken = "it-root";
    public const string VaultAdminSecret = "admin-secret-from-openbao";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tslauth-bao-" + Guid.NewGuid().ToString("N"));
    private readonly IContainer _bao = new ContainerBuilder()
        .WithImage("openbao/openbao:2.4.1")
        .WithCommand("server", "-dev", $"-dev-root-token-id={RootToken}", "-dev-listen-address=0.0.0.0:8200")
        .WithPortBinding(8200, true)
        .WithWaitStrategy(Wait.ForUnixContainer().UntilHttpRequestIsSucceeded(r => r.ForPort(8200).ForPath("/v1/sys/health")))
        .Build();

    public override string ProviderName => "SQLite + OpenBao";
    public string Address => $"http://{_bao.Hostname}:{_bao.GetMappedPublicPort(8200)}";
    public string RoleId { get; private set; } = "";
    public string SecretIdFile => Path.Combine(_dir, "secret_id");

    protected override async Task<Dictionary<string, string>> DatabaseSettingsAsync()
    {
        Directory.CreateDirectory(_dir);
        await _bao.StartAsync();
        using var http = Admin();
        await Post(http, "v1/sys/auth/approle", new { type = "approle" });
        await http.PutAsync("v1/sys/policies/acl/tsl-auth",
            JsonContent.Create(new { policy = "path \"secret/data/tsl-auth\" { capabilities = [\"read\"] }" }));
        await Post(http, "v1/auth/approle/role/tsl-auth", new { token_policies = "tsl-auth", token_ttl = "5m" });
        await Post(http, "v1/secret/data/tsl-auth", new
        {
            data = new Dictionary<string, string>
            {
                ["Encryption__MasterKey"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
                ["Bootstrap__AdminApiClientSecret"] = VaultAdminSecret,
            }
        });
        RoleId = (await (await http.GetAsync("v1/auth/approle/role/tsl-auth/role-id")).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>())
            .GetProperty("data").GetProperty("role_id").GetString()!;
        var secretId = await (await http.PostAsync("v1/auth/approle/role/tsl-auth/secret-id", null)).Content
            .ReadFromJsonAsync<System.Text.Json.JsonElement>();
        await File.WriteAllTextAsync(SecretIdFile, secretId.GetProperty("data").GetProperty("secret_id").GetString() + "\n");
        return new Dictionary<string, string>
        {
            ["Database__Provider"] = "Sqlite",
            ["Database__ConnectionString"] = $"Data Source={Path.Combine(_dir, "auth.db")}"
        };
    }

    protected override Dictionary<string, string> ExtraSettings() => new()
    {
        ["OpenBao__Address"] = Address,
        ["OpenBao__Path"] = "tsl-auth",
        ["OpenBao__RoleId"] = RoleId,
        ["OpenBao__SecretIdFile"] = SecretIdFile,
    };

    /// <summary>Распечатать dev-хранилище: ключ dev-режим печатает в журнал контейнера.</summary>
    public async Task UnsealAsync()
    {
        var (stdout, _) = await _bao.GetLogsAsync();
        var key = System.Text.RegularExpressions.Regex.Match(stdout, @"Unseal Key: (\S+)").Groups[1].Value;
        using var http = Admin();
        (await http.PostAsJsonAsync("v1/sys/unseal", new { key })).EnsureSuccessStatusCode();
    }

    public HttpClient Admin() => new() { BaseAddress = new Uri(Address + "/"), DefaultRequestHeaders = { { "X-Vault-Token", RootToken } } };

    private static async Task Post(HttpClient http, string url, object body) =>
        (await http.PostAsJsonAsync(url, body)).EnsureSuccessStatusCode();

    public override async Task DisposeAsync()
    {
        await base.DisposeAsync();
        await _bao.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }
}

[Collection("openbao")]
public sealed class OpenBaoScenarios(OpenBaoFixture fx) : IClassFixture<OpenBaoFixture>
{
    [Fact]
    public async Task Secrets_ComeFromOpenBao_AndOverrideEnvironment()
    {
        var http = fx.Factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/ready")).StatusCode);

        // Секрет клиента Admin API — из OpenBao; значение из окружения фикстуры больше не действует.
        var fromVault = await http.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = AuthFixture.AdminClientId,
            ["client_secret"] = OpenBaoFixture.VaultAdminSecret, ["scope"] = "tsl-auth-admin"
        });
        Assert.False(string.IsNullOrEmpty(fromVault.GetProperty("access_token").GetString()));
        var fromEnv = await http.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = AuthFixture.AdminClientId,
            ["client_secret"] = AuthFixture.AdminClientSecret, ["scope"] = "tsl-auth-admin"
        }, expectSuccess: false);
        Assert.Equal("invalid_client", fromEnv.GetProperty("error").GetString());
    }

    [Fact]
    public async Task WrongSecretId_StopsStart_WithoutRetries()
    {
        var options = new OpenBaoOptions { Address = fx.Address, RoleId = fx.RoleId, SecretIdFile = WriteTemp("not-a-secret-id"), Retries = 30 };
        var started = DateTime.UtcNow;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => OpenBaoConfiguration.LoadAsync(options, _ => TimeSpan.FromSeconds(2)));
        Assert.Contains("approle/login", error.Message);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5), "ошибка доступа не должна повторяться");
    }

    [Fact]
    public async Task UnreachableOpenBao_Retries_ThenFails()
    {
        var options = new OpenBaoOptions { Address = "http://127.0.0.1:1", RoleId = "x", SecretIdFile = WriteTemp("y"), Retries = 3 };
        var attempts = 0;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            OpenBaoConfiguration.LoadAsync(options, _ => { attempts++; return TimeSpan.Zero; }));
        Assert.Equal(2, attempts);
        Assert.Contains("секреты не получены", error.Message);
    }

    [Fact]
    public async Task SealedOpenBao_IsWaitedFor()
    {
        // Запечатываем хранилище и распечатывать не будем: сервис должен ждать (повторы), а не падать сразу.
        using var admin = fx.Admin();
        var sealedResponse = await admin.PostAsync("v1/sys/seal", null);
        try
        {
            var options = new OpenBaoOptions { Address = fx.Address, RoleId = fx.RoleId, SecretIdFile = fx.SecretIdFile, Retries = 2 };
            var attempts = 0;
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                OpenBaoConfiguration.LoadAsync(options, _ => { attempts++; return TimeSpan.Zero; }));
            Assert.Equal(1, attempts);
            Assert.Contains("секреты не получены", error.Message);
        }
        finally
        {
            sealedResponse.EnsureSuccessStatusCode();
            await fx.UnsealAsync();
        }
    }

    private static string WriteTemp(string value)
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, value);
        return path;
    }
}
