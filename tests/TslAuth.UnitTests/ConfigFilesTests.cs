// Unit-тесты загрузки файла настроек по APPSETTINGS_PATH.
// Запуск: dotnet test tests/TslAuth.UnitTests. Внешние зависимости не нужны: проверяются
// отдельные классы сервиса без поднятия HTTP-хоста и БД.

using Microsoft.AspNetCore.Builder;
using TslAuth.Infrastructure;

namespace TslAuth.UnitTests;

/// <summary>
/// Файл настроек вне каталога приложения (APPSETTINGS_PATH): MVP хранит в нём и секреты.
/// Регрессия: абсолютный путь резолвился относительно ContentRoot (/app/etc/... вместо /etc/...).
/// </summary>
public class ConfigFilesTests
{
    /// <summary>Абсолютный APPSETTINGS_PATH вне ContentRoot читается; переменные окружения имеют приоритет.</summary>
    [Fact]
    public void AppSettingsPath_OutsideContentRoot_IsLoaded_AndEnvironmentWins()
    {
        var contentRoot = Directory.CreateTempSubdirectory("tsl-root-").FullName;
        var configDir = Directory.CreateTempSubdirectory("tsl-etc-").FullName;
        var file = Path.Combine(configDir, "appsettings.json");
        File.WriteAllText(file, """{ "Smtp": { "Password": "from-file", "UserName": "file-user", "From": "file-from" } }""");
        Environment.SetEnvironmentVariable(ConfigFiles.PathVariable, file);
        Environment.SetEnvironmentVariable("Smtp__UserName", "env-user");
        // Пустая переменная (compose передаёт "${SMTP_PASSWORD:-}") не должна затирать секрет из файла.
        Environment.SetEnvironmentVariable("Smtp__Password", "");
        try
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = contentRoot });
            ConfigFiles.Attach(builder);
            EmptyEnvironmentVariables.Ignore(builder.Configuration);

            Assert.Equal("from-file", builder.Configuration["Smtp:Password"]);
            Assert.Equal("env-user", builder.Configuration["Smtp:UserName"]);   // переменная окружения перекрывает файл
        }
        finally
        {
            Environment.SetEnvironmentVariable(ConfigFiles.PathVariable, null);
            Environment.SetEnvironmentVariable("Smtp__UserName", null);
            Environment.SetEnvironmentVariable("Smtp__Password", null);
            Directory.Delete(contentRoot, true);
            Directory.Delete(configDir, true);
        }
    }

    /// <summary>Указанный, но отсутствующий файл настроек останавливает старт.</summary>
    [Fact]
    public void AppSettingsPath_Missing_StopsStart()
    {
        Environment.SetEnvironmentVariable(ConfigFiles.PathVariable, Path.Combine(Path.GetTempPath(), "nope-" + Guid.NewGuid(), "appsettings.json"));
        try
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = Path.GetTempPath() });
            Assert.Throws<InvalidOperationException>(() => ConfigFiles.Attach(builder));
        }
        finally { Environment.SetEnvironmentVariable(ConfigFiles.PathVariable, null); }
    }
}
