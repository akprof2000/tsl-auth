using Microsoft.Extensions.Logging.Abstractions;
using TslAuth.Infrastructure;
using TslAuth.Options;
using TslAuth.Security;

namespace TslAuth.UnitTests;

public class OpenBaoTests
{
    [Theory]
    [InlineData("Encryption__MasterKey", "Encryption:MasterKey")]
    [InlineData("Observability__Loki__Password", "Observability:Loki:Password")]
    [InlineData("Smtp:Password", "Smtp:Password")]
    public void SecretKey_IsConfigurationKey(string key, string expected) => Assert.Equal(expected, OpenBaoConfiguration.NormalizeKey(key));

    [Fact]
    public void NoAddress_MeansDisabled() => Assert.False(new OpenBaoOptions().Enabled);

    [Fact]
    public async Task NoCredentials_IsConfigurationError()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            OpenBaoConfiguration.LoadAsync(new OpenBaoOptions { Address = "http://127.0.0.1:1" }, _ => TimeSpan.Zero));
        Assert.Contains("AppRole", error.Message);
    }

    [Fact]
    public async Task MissingSecretIdFile_IsConfigurationError()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            OpenBaoConfiguration.LoadAsync(new OpenBaoOptions { Address = "http://127.0.0.1:1", RoleId = "r", SecretIdFile = "/nope/secret_id" },
                _ => TimeSpan.Zero));
        Assert.Contains("не найден", error.Message);
    }

    [Fact]
    public void KeyFromVault_DifferentFromLocalMasterKey_StopsStart()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        var local = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        File.WriteAllText(Path.Combine(dir, "master.key"), local);
        var db = new DatabaseOptions { ConnectionString = $"Data Source={Path.Combine(dir, "auth.db")}" };

        var other = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var error = Assert.Throws<InvalidOperationException>(() =>
            MasterKeyResolver.Resolve(new EncryptionOptions { MasterKey = other }, db, dir, NullLogger.Instance));
        Assert.Contains("не совпадает", error.Message);

        // Тот же ключ, перенесённый в хранилище, принимается.
        Assert.Equal(Convert.FromBase64String(local), MasterKeyResolver.Resolve(new EncryptionOptions { MasterKey = local }, db, dir, NullLogger.Instance));
        Directory.Delete(dir, true);
    }
}
