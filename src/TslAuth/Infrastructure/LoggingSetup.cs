using System.Diagnostics;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Compact;
using Serilog.Sinks.Grafana.Loki;
using Serilog.Sinks.OpenTelemetry;
using TslAuth.Options;
using TslAuth.Services;

namespace TslAuth.Infrastructure;

/// <summary>
/// Журналирование через Serilog: консоль (текст или JSON), Grafana Loki и OTLP — по настройкам Observability.
/// Уровни: значения по умолчанию — из <c>Logging:LogLevel</c> (формат ASP.NET Core, совместим с прежними
/// переменными <c>Logging__LogLevel__*</c>); поверх них — настройки из БД (админка → «Настройки» →
/// «Журналирование»), которые меняют глубину логирования на всех узлах без перезапуска (см. <see cref="LogLevels"/>).
/// Секция <c>Serilog</c> в appsettings.json тоже читается: через неё подключаются дополнительные sink'и
/// (файл, Seq, syslog) без пересборки.
/// </summary>
public static class LoggingSetup
{
    public static void AddTslLogging(this WebApplicationBuilder builder, ObservabilityOptions observability)
    {
        var levels = new LogLevels(builder.Configuration.GetSection("Logging:LogLevel"));
        builder.Services.AddSingleton(levels);
        builder.Services.AddHostedService<LogLevelSyncService>();

        // Фильтры самого ASP.NET Core (LoggerFilterOptions из секции Logging) отключаем: иначе уровень, поднятый
        // в настройках сервиса до Debug, отсекался бы статическим правилом из конфигурации ещё до Serilog.
        builder.Services.PostConfigure<LoggerFilterOptions>(o =>
        {
            o.Rules.Clear();
            o.MinLevel = LogLevel.Trace;
        });

        var format = builder.Configuration["Logging:Format"] ?? "Text";
        var json = format.Equals("Json", StringComparison.OrdinalIgnoreCase);
        var instance = InstanceId(observability);

        // preserveStaticLogger: логгер принадлежит хосту, а не статическому Log.Logger — иначе второй хост в том же
        // процессе (интеграционные тесты поднимают несколько экземпляров) подменял бы и закрывал логгер первого.
        builder.Services.AddSerilog((services, cfg) =>
        {
            cfg.MinimumLevel.ControlledBy(levels.Root)
                .Filter.With(levels)
                .Enrich.FromLogContext()
                // TraceId/SpanId текущего запроса — свойствами записи: по ним Grafana связывает строку лога в Loki
                // (и в файле, и в JSON-консоли) со span'ом в Tempo.
                .Enrich.With<TraceEnricher>()
                .Enrich.WithProperty("service", observability.ServiceName)
                .Enrich.WithProperty("instance", instance)
                .ReadFrom.Configuration(builder.Configuration);

            const string template = "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}";
            if (json)
                cfg.WriteTo.Console(new RenderedCompactJsonFormatter());
            else
                cfg.WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}");

            // Файл на диске (для запуска вне контейнера; в контейнере ротацию делает Docker): новый файл каждый день
            // и по достижении размера, на диске не больше RetainedFiles файлов, ротированные сжимаются в .gz.
            var file = builder.Configuration.GetSection("Logging:File").Get<FileLogOptions>() ?? new FileLogOptions();
            if (!string.IsNullOrWhiteSpace(file.Path))
                AddFile(cfg, file, json ? new RenderedCompactJsonFormatter() : null, template);

            var loki = observability.Loki;
            if (loki.Enabled)
            {
                var labels = ParseLabels(loki.Labels)
                    .Prepend(new LokiLabel { Key = "instance", Value = instance })
                    .Prepend(new LokiLabel { Key = "service", Value = observability.ServiceName })
                    .ToArray();
                cfg.WriteTo.GrafanaLoki(loki.Url!.TrimEnd('/'),
                    labels: labels,
                    // Уровень — метка потока: по нему Grafana раскрашивает строки и строит гистограммы без разбора текста.
                    handleLogLevelAsLabel: true,
                    credentials: string.IsNullOrEmpty(loki.Username) ? null
                        : new LokiCredentials { Login = loki.Username, Password = loki.Password ?? "" },
                    tenant: string.IsNullOrWhiteSpace(loki.Tenant) ? null : loki.Tenant,
                    restrictedToMinimumLevel: ParseLevel(loki.MinimumLevel) ?? LogEventLevel.Information,
                    batchSizeLimit: loki.BatchSize,
                    queueLimit: loki.QueueLimit,
                    period: TimeSpan.FromSeconds(Math.Max(1, loki.PeriodSeconds)),
                    // Строка — JSON с полями сообщения (уровень, категория, параметры шаблона): Loki разбирает его
                    // конвейером `| json`.
                    textFormatter: new LokiJsonTextFormatter());
            }

            var otlp = observability.OpenTelemetry;
            if (otlp.Enabled && otlp.Logs)
            {
                cfg.WriteTo.OpenTelemetry(o =>
                {
                    o.Endpoint = ObservabilitySetup.SignalEndpoint(otlp, "logs");
                    o.Protocol = otlp.IsHttp ? OtlpProtocol.HttpProtobuf : OtlpProtocol.Grpc;
                    o.Headers = ObservabilitySetup.ParseHeaders(otlp.Headers);
                    o.ResourceAttributes = ObservabilitySetup.ResourceAttributes(observability, instance);
                });
            }
        }, preserveStaticLogger: true);
    }

    /// <summary>
    /// Файловый sink с ограничением места: при Compress ротированный файл сразу сжимается (<see cref="GzipArchiveHooks"/>),
    /// на диске остаётся текущий файл и не более RetainedFiles−1 архивов; без сжатия — RetainedFiles обычных файлов.
    /// Вызывается и из тестов (tests/TslAuth.UnitTests) на временном каталоге.
    /// </summary>
    internal static void AddFile(LoggerConfiguration cfg, FileLogOptions file, Serilog.Formatting.ITextFormatter? formatter, string template)
    {
        var retained = Math.Max(1, file.RetainedFiles);
        var size = Math.Max(1, file.SizeLimitMb) * 1024L * 1024L;
        var hooks = file.Compress ? new GzipArchiveHooks(retained - 1) : null;
        if (formatter is not null)
            cfg.WriteTo.File(formatter, file.Path!, rollingInterval: RollingInterval.Day, rollOnFileSizeLimit: true,
                fileSizeLimitBytes: size, retainedFileCountLimit: file.Compress ? 1 : retained, hooks: hooks);
        else
            cfg.WriteTo.File(file.Path!, outputTemplate: template, rollingInterval: RollingInterval.Day, rollOnFileSizeLimit: true,
                fileSizeLimitBytes: size, retainedFileCountLimit: file.Compress ? 1 : retained, hooks: hooks);
    }

    /// <summary>Идентификатор экземпляра для метрик и логов: настройка или имя хоста (в контейнере — его id).</summary>
    public static string InstanceId(ObservabilityOptions o) =>
        string.IsNullOrWhiteSpace(o.InstanceId) ? Environment.MachineName : o.InstanceId.Trim();

    /// <summary>Разбирает «k=v,k2=v2» в метки Loki; элементы без «=» — ошибка старта (опечатка не должна пройти молча).</summary>
    internal static List<LokiLabel> ParseLabels(string? value) =>
        ObservabilitySetup.ParsePairs(value, "Observability:Loki:Labels")
            .Select(p => new LokiLabel { Key = p.Key, Value = p.Value }).ToList();

    /// <summary>Уровень в терминах ASP.NET Core (Trace…Critical, None) → Serilog; неизвестный — null.</summary>
    public static LogEventLevel? ParseLevel(string? level) => level?.Trim().ToLowerInvariant() switch
    {
        "trace" or "verbose" => LogEventLevel.Verbose,
        "debug" => LogEventLevel.Debug,
        "information" or "info" => LogEventLevel.Information,
        "warning" or "warn" => LogEventLevel.Warning,
        "error" => LogEventLevel.Error,
        "critical" or "fatal" => LogEventLevel.Fatal,
        "none" or "off" => LogLevels.Off,
        _ => null
    };
}

/// <summary>Добавляет в запись TraceId и SpanId текущей операции (Serilog берёт их из Activity.Current).</summary>
public sealed class TraceEnricher : ILogEventEnricher
{
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory factory)
    {
        if (logEvent.TraceId is { } trace) logEvent.AddPropertyIfAbsent(factory.CreateProperty("TraceId", trace.ToHexString()));
        if (logEvent.SpanId is { } span) logEvent.AddPropertyIfAbsent(factory.CreateProperty("SpanId", span.ToHexString()));
    }
}

/// <summary>Секция Logging:File — журнал на диске (по умолчанию выключен: логи идут в stdout).</summary>
public sealed class FileLogOptions
{
    /// <summary>Путь-шаблон: <c>logs/tsl-auth-.log</c> → <c>logs/tsl-auth-20260925.log</c>, <c>…_001.log</c> при переполнении.</summary>
    public string? Path { get; set; }

    /// <summary>Размер, при котором начинается новый файл, МБ.</summary>
    public int SizeLimitMb { get; set; } = 20;

    /// <summary>Сколько файлов держать на диске всего (текущий + архивы); старые удаляются.</summary>
    public int RetainedFiles { get; set; } = 5;

    /// <summary>Сжимать ротированные файлы в .gz.</summary>
    public bool Compress { get; set; } = true;
}

/// <summary>
/// Архивация ротированных файлов журнала: перед тем как sink удалит файл (лимит retainedFileCountLimit),
/// он сжимается в <c>имя.gz</c> рядом, а архивов оставляется не больше <paramref name="retainedArchives"/>.
/// Ошибки архивации не мешают журналированию (сообщение — в Serilog SelfLog).
/// </summary>
public sealed class GzipArchiveHooks(int retainedArchives) : Serilog.Sinks.File.FileLifecycleHooks
{
    public override void OnFileDeleting(string path)
    {
        try
        {
            if (retainedArchives > 0)
            {
                using (var source = File.OpenRead(path))
                using (var target = File.Create(path + ".gz"))
                using (var gzip = new System.IO.Compression.GZipStream(target, System.IO.Compression.CompressionLevel.Fastest))
                    source.CopyTo(gzip);
            }
            // Архивы того же журнала (общий префикс имени) — старше лимита удаляются.
            var dir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!;
            var name = System.IO.Path.GetFileName(path);
            var prefix = name.Length > 12 ? name[..(name.Length - 12)] : name; // без «yyyyMMdd.log» — префикс шаблона
            var stale = Directory.GetFiles(dir, prefix + "*.gz").OrderByDescending(f => new FileInfo(f).LastWriteTimeUtc)
                .Skip(retainedArchives);
            foreach (var old in stale) File.Delete(old);
        }
        catch (Exception ex)
        {
            Serilog.Debugging.SelfLog.WriteLine("Архивация журнала {0}: {1}", path, ex);
        }
    }
}

/// <summary>
/// Действующие уровни логирования по категориям. Источник по умолчанию — конфигурация (<c>Logging:LogLevel</c>),
/// поверх — настройки из БД; правило выбирается по самому длинному совпадающему префиксу категории
/// (как в ASP.NET Core). Корневой переключатель Serilog держится на минимальном из уровней, а точная отсечка
/// делается фильтром — так новые категории из настроек начинают действовать сразу, без пересборки логгера.
/// </summary>
public sealed class LogLevels : ILogEventFilter
{
    /// <summary>«Выключено»: выше любого реального уровня Serilog, ни одно событие не проходит.</summary>
    public const LogEventLevel Off = (LogEventLevel)(LogEventLevel.Fatal + 1);

    public LoggingLevelSwitch Root { get; } = new(LogEventLevel.Information);

    private readonly LogEventLevel _configDefault;
    private readonly Dictionary<string, LogEventLevel> _configOverrides;
    private volatile Rules _rules;

    public LogLevels(IConfiguration logLevelSection)
    {
        _configDefault = LoggingSetup.ParseLevel(logLevelSection["Default"]) ?? LogEventLevel.Information;
        _configOverrides = logLevelSection.GetChildren()
            .Where(c => c.Key != "Default" && LoggingSetup.ParseLevel(c.Value) is not null)
            .ToDictionary(c => c.Key, c => LoggingSetup.ParseLevel(c.Value)!.Value, StringComparer.OrdinalIgnoreCase);
        _rules = Build(null);
        Root.MinimumLevel = _rules.Minimum;
    }

    /// <summary>Уровень по умолчанию из конфигурации (показывается в админке как подсказка).</summary>
    public string ConfigDefault => Describe(_configDefault);

    /// <summary>Переопределения из конфигурации (категория → уровень).</summary>
    public IReadOnlyDictionary<string, string> ConfigOverrides =>
        _configOverrides.ToDictionary(o => o.Key, o => Describe(o.Value));

    /// <summary>Применяет настройки из БД (null — только конфигурация). Вызывается при старте и при каждом изменении.</summary>
    public void Apply(LoggingSettings? settings)
    {
        var rules = Build(settings);
        _rules = rules;
        Root.MinimumLevel = rules.Minimum;
    }

    /// <summary>Действующий уровень для категории.</summary>
    public LogEventLevel LevelFor(string? category)
    {
        var rules = _rules;
        if (category is null) return rules.Default;
        foreach (var (prefix, level) in rules.Overrides)
            if (category.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return level;
        return rules.Default;
    }

    public bool IsEnabled(LogEvent logEvent)
    {
        var category = logEvent.Properties.TryGetValue("SourceContext", out var v) && v is ScalarValue { Value: string s } ? s : null;
        return logEvent.Level >= LevelFor(category);
    }

    private Rules Build(LoggingSettings? settings)
    {
        var @default = LoggingSetup.ParseLevel(settings?.DefaultLevel) ?? _configDefault;
        var overrides = new Dictionary<string, LogEventLevel>(_configOverrides, StringComparer.OrdinalIgnoreCase);
        foreach (var (category, level) in settings?.Overrides ?? [])
            if (LoggingSetup.ParseLevel(level) is { } parsed) overrides[category.Trim()] = parsed;
        // Длинные префиксы первыми: «Microsoft.AspNetCore» точнее, чем «Microsoft».
        var ordered = overrides.OrderByDescending(o => o.Key.Length).Select(o => (o.Key, o.Value)).ToArray();
        var minimum = ordered.Select(o => o.Value).Append(@default).Min();
        return new Rules(@default, ordered, minimum);
    }

    public static string Describe(LogEventLevel level) => level switch
    {
        LogEventLevel.Verbose => "Trace",
        LogEventLevel.Debug => "Debug",
        LogEventLevel.Information => "Information",
        LogEventLevel.Warning => "Warning",
        LogEventLevel.Error => "Error",
        LogEventLevel.Fatal => "Critical",
        _ => "None"
    };

    private sealed record Rules(LogEventLevel Default, (string Prefix, LogEventLevel Level)[] Overrides, LogEventLevel Minimum);
}

/// <summary>
/// Переносит уровни логирования из настроек в БД в <see cref="LogLevels"/>: опрос раз в 5 секунд через кэш
/// SettingsService (к БД — не чаще его TTL), так что узел, на котором настройки не меняли, применяет их за ≤ 35 с.
/// </summary>
public sealed class LogLevelSyncService(SettingsService settings, LogLevels levels, ILogger<LogLevelSyncService> logger)
    : BackgroundService
{
    private LoggingSettings? _applied;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        try
        {
            do
            {
                try
                {
                    var current = (await settings.GetAsync(stoppingToken)).LoggingPolicy;
                    if (Equals(current, _applied)) continue;
                    levels.Apply(current);
                    _applied = current;
                    logger.LogInformation("Уровни логирования: по умолчанию {Default}, переопределений: {Overrides}.",
                        LogLevels.Describe(levels.LevelFor(null)), current?.Overrides?.Count ?? 0);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogDebug(ex, "Не удалось прочитать настройки логирования.");
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) { }
    }

    // Record с Dictionary сравнивается по ссылке — сравниваем содержимое.
    private static bool Equals(LoggingSettings? a, LoggingSettings? b)
    {
        if (a is null || b is null) return a is null && b is null;
        if (!string.Equals(a.DefaultLevel, b.DefaultLevel, StringComparison.OrdinalIgnoreCase)) return false;
        var x = a.Overrides ?? [];
        var y = b.Overrides ?? [];
        return x.Count == y.Count && x.All(p => y.TryGetValue(p.Key, out var v) && string.Equals(v, p.Value, StringComparison.OrdinalIgnoreCase));
    }
}
