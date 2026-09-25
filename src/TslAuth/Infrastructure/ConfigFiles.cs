using Microsoft.Extensions.Configuration.Json;

namespace TslAuth.Infrastructure;

/// <summary>
/// Откуда берётся appsettings.json. Стандартно ASP.NET Core читает его только из каталога приложения; здесь добавлены
/// два способа держать настройки отдельно от файлов сервиса (в контейнере /app принадлежит root и доступен только на чтение):
/// <list type="bullet">
/// <item>переменная <c>APPSETTINGS_PATH</c> — путь к файлу (или к каталогу с appsettings.json); указан, но не существует —
/// ошибка старта, а не молчаливая работа на значениях по умолчанию;</item>
/// <item>если в каталоге приложения нет appsettings.json, он ищется в родительских каталогах до корня диска
/// (то же для appsettings.{Environment}.json).</item>
/// </list>
/// Приоритет прежний: файлы → переменные окружения → аргументы командной строки; уровни логирования из БД — поверх всего.
/// </summary>
public static class ConfigFiles
{
    public const string PathVariable = "APPSETTINGS_PATH";

    /// <summary>Подключает найденные файлы и возвращает описания источников для записи в лог после старта.</summary>
    public static List<string> Attach(WebApplicationBuilder builder)
    {
        var used = new List<string>();
        var explicitPath = Environment.GetEnvironmentVariable(PathVariable);
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            var path = Path.GetFullPath(explicitPath.Trim());
            if (Directory.Exists(path)) path = Path.Combine(path, "appsettings.json");
            if (!File.Exists(path))
                throw new InvalidOperationException($"{PathVariable}: файл настроек '{path}' не найден.");
            Add(builder, path);
            used.Add($"{path} (из {PathVariable})");
            return used;
        }

        var root = builder.Environment.ContentRootPath;
        foreach (var name in new[] { "appsettings.json", $"appsettings.{builder.Environment.EnvironmentName}.json" })
        {
            if (File.Exists(Path.Combine(root, name))) continue; // стандартный источник уже подключён
            if (FindUpwards(root, name) is { } found)
            {
                Add(builder, found);
                used.Add($"{found} (найден выше каталога приложения)");
            }
        }
        return used;
    }

    /// <summary>Ищет файл в родительских каталогах (сам каталог start уже проверен вызывающим кодом).</summary>
    internal static string? FindUpwards(string start, string fileName)
    {
        for (var dir = Directory.GetParent(start); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, fileName);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    // Источник вставляется сразу после встроенных appsettings*.json: переменные окружения и аргументы,
    // добавленные CreateBuilder позже, по-прежнему имеют приоритет над файлом.
    private static void Add(WebApplicationBuilder builder, string path)
    {
        var sources = builder.Configuration.Sources;
        var index = sources.Select((s, i) => (s, i)).LastOrDefault(x => x.s is JsonConfigurationSource).i;
        sources.Insert(index + 1, new JsonConfigurationSource { Path = path, Optional = false, ReloadOnChange = true });
    }
}
