using System.Net;
using Microsoft.Extensions.Configuration;
using Serilog.Events;
using Serilog.Parsing;
using TslAuth.Infrastructure;
using TslAuth.Options;
using TslAuth.Services;

namespace TslAuth.UnitTests;

/// <summary>Уровни логирования: конфигурация по умолчанию, настройки из БД поверх, выбор по самому длинному префиксу.</summary>
public sealed class LogLevelsTests
{
    private static LogLevels FromConfig(params (string Key, string Value)[] pairs) =>
        new(new ConfigurationBuilder()
            .AddInMemoryCollection(pairs.ToDictionary(p => "Logging:LogLevel:" + p.Key, p => (string?)p.Value))
            .Build().GetSection("Logging:LogLevel"));

    [Fact]
    public void Config_DefaultAndOverrides()
    {
        var levels = FromConfig(("Default", "Information"), ("Microsoft", "Warning"), ("Microsoft.AspNetCore", "Error"));
        Assert.Equal(LogEventLevel.Information, levels.LevelFor("TslAuth.Startup"));
        Assert.Equal(LogEventLevel.Warning, levels.LevelFor("Microsoft.Hosting.Lifetime"));
        Assert.Equal(LogEventLevel.Error, levels.LevelFor("Microsoft.AspNetCore.Routing")); // самый длинный префикс
        Assert.Equal(LogEventLevel.Information, levels.Root.MinimumLevel);                  // минимум по всем правилам
        Assert.Equal("Information", levels.ConfigDefault);
        Assert.Equal("Warning", levels.ConfigOverrides["Microsoft"]);
    }

    [Fact]
    public void Settings_OverrideConfig_AndRevert()
    {
        var levels = FromConfig(("Default", "Warning"), ("Microsoft", "Error"));
        levels.Apply(new LoggingSettings("Debug", new() { ["Microsoft.AspNetCore"] = "Trace", ["Npgsql"] = "None" }));
        Assert.Equal(LogEventLevel.Debug, levels.LevelFor("TslAuth.Audit"));
        Assert.Equal(LogEventLevel.Error, levels.LevelFor("Microsoft.Hosting")); // правило конфигурации сохраняется
        Assert.Equal(LogEventLevel.Verbose, levels.LevelFor("Microsoft.AspNetCore.Hosting"));
        Assert.Equal(LogLevels.Off, levels.LevelFor("Npgsql.Command"));
        Assert.Equal(LogEventLevel.Verbose, levels.Root.MinimumLevel); // корневой переключатель опускается до самого низкого

        levels.Apply(null); // настройки из БД сброшены — снова только конфигурация
        Assert.Equal(LogEventLevel.Warning, levels.LevelFor("TslAuth.Audit"));
        Assert.Equal(LogEventLevel.Warning, levels.Root.MinimumLevel);
    }

    [Fact]
    public void Filter_UsesSourceContext()
    {
        var levels = FromConfig(("Default", "Information"), ("Noisy", "Error"));
        Assert.True(levels.IsEnabled(Event(LogEventLevel.Information, "TslAuth.Startup")));
        Assert.False(levels.IsEnabled(Event(LogEventLevel.Warning, "Noisy.Component")));
        Assert.True(levels.IsEnabled(Event(LogEventLevel.Error, "Noisy.Component")));
        Assert.True(levels.IsEnabled(Event(LogEventLevel.Information, null))); // без категории — уровень по умолчанию
    }

    [Theory]
    [InlineData("Trace", LogEventLevel.Verbose)]
    [InlineData("information", LogEventLevel.Information)]
    [InlineData("Critical", LogEventLevel.Fatal)]
    [InlineData("None", LogLevels.Off)]
    public void ParseLevel_AspNetCoreNames(string name, LogEventLevel expected) => Assert.Equal(expected, LoggingSetup.ParseLevel(name));

    [Fact]
    public void ParseLevel_Unknown_IsNull() => Assert.Null(LoggingSetup.ParseLevel("loud"));

    [Fact]
    public void LoggingSettings_Validate()
    {
        new LoggingSettings("Debug", new() { ["Microsoft"] = "Warning" }).Validate();
        Assert.Throws<AdminException>(() => new LoggingSettings("Loud").Validate());
        Assert.Throws<AdminException>(() => new LoggingSettings(null, new() { ["Microsoft"] = "Quiet" }).Validate());
        Assert.Throws<AdminException>(() => new LoggingSettings(null, new() { ["with space"] = "Debug" }).Validate());
    }

    private static LogEvent Event(LogEventLevel level, string? source)
    {
        var properties = new List<LogEventProperty>();
        if (source is not null) properties.Add(new LogEventProperty("SourceContext", new ScalarValue(source)));
        return new LogEvent(DateTimeOffset.UtcNow, level, null, new MessageTemplateParser().Parse("x"), properties);
    }
}

/// <summary>Разбор настроек мониторинга и защита эндпоинта метрик.</summary>
public sealed class ObservabilitySetupTests
{
    [Theory]
    [InlineData("grpc", "http://collector:4317", "traces", "http://collector:4317")]
    [InlineData("http", "http://collector:4318", "traces", "http://collector:4318/v1/traces")]
    [InlineData("http", "http://collector:4318/", "logs", "http://collector:4318/v1/logs")]
    [InlineData("http", "http://loki:3100/otlp/v1/logs", "logs", "http://loki:3100/otlp/v1/logs")] // путь задан — как есть
    public void SignalEndpoint(string protocol, string endpoint, string signal, string expected) =>
        Assert.Equal(expected, ObservabilitySetup.SignalEndpoint(new OpenTelemetryOptions { Endpoint = endpoint, Protocol = protocol }, signal));

    [Fact]
    public void ParsePairs_HeadersAndLabels()
    {
        var headers = ObservabilitySetup.ParseHeaders("Authorization=Bearer abc=def, X-Scope-OrgID=team1");
        Assert.Equal("Bearer abc=def", headers["Authorization"]); // «=» внутри значения допустим
        Assert.Equal("team1", headers["X-Scope-OrgID"]);
        Assert.Empty(ObservabilitySetup.ParseHeaders(" "));
        Assert.Throws<InvalidOperationException>(() => ObservabilitySetup.ParseHeaders("no-equals"));
        var labels = LoggingSetup.ParseLabels("env=prod;dc=msk");
        Assert.Equal(["env", "dc"], labels.Select(l => l.Key));
    }

    [Fact]
    public void ResourceAttributes_CustomOverridesDefaults()
    {
        var attributes = ObservabilitySetup.ResourceAttributes(
            new ObservabilityOptions { ServiceName = "auth", ResourceAttributes = "deployment.environment=prod,service.version=9.9.9" }, "node1");
        Assert.Equal("auth", attributes["service.name"]);
        Assert.Equal("node1", attributes["service.instance.id"]);
        Assert.Equal("prod", attributes["deployment.environment"]);
        Assert.Equal("9.9.9", attributes["service.version"]);
    }

    [Fact]
    public void Read_ValidatesAddresses()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Observability:Prometheus:Enabled"] = "true",
            ["Observability:OpenTelemetry:Endpoint"] = "http://collector:4317",
            ["Observability:OpenTelemetry:Metrics"] = "false",
            ["Observability:Loki:Url"] = "http://loki:3100"
        }).Build();
        var o = ObservabilitySetup.Read(config);
        Assert.True(o.MetricsEnabled && o.TracingEnabled && o.Loki.Enabled);

        var bad = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Observability:Loki:Url"] = "loki:3100" }).Build();
        Assert.Throws<InvalidOperationException>(() => ObservabilitySetup.Read(bad));

        // Ничего не задано — ни метрик, ни трассировок: экспортёры не создаются.
        var none = ObservabilitySetup.Read(new ConfigurationBuilder().Build());
        Assert.False(none.MetricsEnabled || none.TracingEnabled || none.Loki.Enabled);
    }

    [Fact]
    public void PrometheusGuard_NetworksAndToken()
    {
        var open = new PrometheusGuard(new PrometheusOptions());
        Assert.Null(open.Check(IPAddress.Parse("10.0.0.5"), null));     // частная сеть — разрешена по умолчанию
        Assert.Null(open.Check(IPAddress.Parse("::ffff:172.18.0.9"), null));
        Assert.Null(open.Check(null, null));                            // запрос внутри процесса
        Assert.Equal(403, open.Check(IPAddress.Parse("93.184.216.34"), null));

        var restricted = new PrometheusGuard(new PrometheusOptions { AllowedNetworks = "10.20.0.0/16", Token = "s3cret" });
        Assert.Equal(403, restricted.Check(IPAddress.Parse("10.21.0.1"), "Bearer s3cret"));
        Assert.Equal(401, restricted.Check(IPAddress.Parse("10.20.0.1"), null));
        Assert.Equal(401, restricted.Check(IPAddress.Parse("10.20.0.1"), "Bearer wrong"));
        Assert.Null(restricted.Check(IPAddress.Parse("10.20.0.1"), "Bearer s3cret"));
    }

    /// <summary>Файловый журнал не растёт бесконечно: ротация по размеру, архивы .gz, на диске не больше RetainedFiles файлов.</summary>
    [Fact]
    public void FileLog_RotatesAndArchives_WithinLimit()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tslauth-log-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var options = new FileLogOptions { Path = Path.Combine(dir, "tsl-auth-.log"), SizeLimitMb = 1, RetainedFiles = 3, Compress = true };
            var cfg = new Serilog.LoggerConfiguration();
            LoggingSetup.AddFile(cfg, options, null, "{Message}{NewLine}");
            using (var logger = cfg.CreateLogger())
            {
                var line = new string('x', 200);
                for (var i = 0; i < 40_000; i++) logger.Information("{I} {Line}", i, line); // ≈ 8 МБ → 8 ротаций
            }

            var files = Directory.GetFiles(dir).Select(Path.GetFileName).Order().ToList();
            Assert.True(files.Count <= 3, string.Join(", ", files));
            Assert.Single(files, f => f!.EndsWith(".log"));                  // текущий файл
            Assert.Equal(2, files.Count(f => f!.EndsWith(".log.gz")));        // архивы: RetainedFiles − 1
            Assert.True(new FileInfo(Path.Combine(dir, files.First(f => f!.EndsWith(".gz"))!)).Length < 1024 * 1024 / 4); // сжато
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void ConfigFiles_FindUpwards()
    {
        var root = Path.Combine(Path.GetTempPath(), "tslauth-cfg-" + Guid.NewGuid().ToString("N"));
        var app = Path.Combine(root, "etc", "app");
        Directory.CreateDirectory(app);
        try
        {
            Assert.Null(ConfigFiles.FindUpwards(app, "appsettings.json"));
            var expected = Path.Combine(root, "appsettings.json");
            File.WriteAllText(expected, "{}");
            Assert.Equal(expected, ConfigFiles.FindUpwards(app, "appsettings.json"));
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
}
