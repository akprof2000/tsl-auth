// Unit-тесты конфигурации OpenBao: нормализация ключей, ошибки настройки, сверка мастер-ключа.
// Запуск: dotnet test tests/TslAuth.UnitTests. Внешние зависимости не нужны: проверяются
// отдельные классы сервиса без поднятия HTTP-хоста и БД.

using Microsoft.Extensions.Logging.Abstractions;
using TslAuth.Infrastructure;
using TslAuth.Options;
using TslAuth.Security;

namespace TslAuth.UnitTests;

public class OpenBaoTests
{
    /// <summary>Ключ секрета в OpenBao преобразуется в ключ конфигурации .NET.</summary>
    [Theory]
    [InlineData("Encryption__MasterKey", "Encryption:MasterKey")]
    [InlineData("Observability__Prometheus__Token", "Observability:Prometheus:Token")]
    [InlineData("Smtp:Password", "Smtp:Password")]
    public void SecretKey_IsConfigurationKey(string key, string expected) => Assert.Equal(expected, OpenBaoConfiguration.NormalizeKey(key));

    [Fact]
    public void NoAddress_MeansDisabled() => Assert.False(new OpenBaoOptions().Enabled);

    /// <summary>Адрес задан, а учётных данных AppRole нет — ошибка конфигурации.</summary>
    [Fact]
    public async Task NoCredentials_IsConfigurationError()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            OpenBaoConfiguration.LoadAsync(new OpenBaoOptions { Address = "http://127.0.0.1:1" }, _ => TimeSpan.Zero));
        Assert.Contains("AppRole", error.Message);
    }

    /// <summary>Файл secret_id не найден — ошибка конфигурации.</summary>
    [Fact]
    public async Task MissingSecretIdFile_IsConfigurationError()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            OpenBaoConfiguration.LoadAsync(new OpenBaoOptions { Address = "http://127.0.0.1:1", RoleId = "r", SecretIdFile = "/nope/secret_id" },
                _ => TimeSpan.Zero));
        Assert.Contains("не найден", error.Message);
    }

    /// <summary>Мастер-ключ из хранилища не совпал с локальным — старт останавливается, чтобы не потерять данные.</summary>
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
