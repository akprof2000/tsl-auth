using Microsoft.Extensions.Configuration.EnvironmentVariables;

namespace TslAuth.Infrastructure;

/// <summary>
/// Пустая переменная окружения = «не задана». docker compose передаёт в контейнер все переменные из списка, в том числе
/// пустые (<c>Bootstrap__AdminApiClientSecret: "${BOOTSTRAP_API_CLIENT_SECRET:-}"</c>), а в конфигурации ASP.NET Core пустая
/// строка — тоже значение: она перекрыла бы секрет из файла настроек (MVP хранит секреты в appsettings.json).
/// Поэтому источник переменных окружения заменяется на тот же, но без пустых значений. Непустые переменные
/// по-прежнему перекрывают файл.
/// </summary>
public static class EmptyEnvironmentVariables
{
    public static void Ignore(IConfigurationBuilder configuration)
    {
        var sources = configuration.Sources;
        for (var i = 0; i < sources.Count; i++)
            if (sources[i] is EnvironmentVariablesConfigurationSource env)
                sources[i] = new Source { Prefix = env.Prefix };
    }

    private sealed class Source : IConfigurationSource
    {
        public string? Prefix { get; init; }
        public IConfigurationProvider Build(IConfigurationBuilder builder) => new Provider(Prefix);
    }

    private sealed class Provider(string? prefix) : EnvironmentVariablesConfigurationProvider(prefix)
    {
        public override void Load()
        {
            base.Load();
            foreach (var key in Data.Where(p => string.IsNullOrEmpty(p.Value)).Select(p => p.Key).ToList())
                Data.Remove(key);
        }
    }
}
