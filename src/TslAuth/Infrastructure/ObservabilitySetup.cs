using System.Net;
using System.Security.Cryptography;
using System.Text;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using TslAuth.Options;

namespace TslAuth.Infrastructure;

/// <summary>
/// Метрики и трассировки через OpenTelemetry. Подключаются только к тому, что настроено:
/// Prometheus — эндпоинт <c>/metrics</c> (pull), OTLP — отправка в коллектор (push). Без настроек ни MeterProvider,
/// ни TracerProvider не создаются, инструменты ASP.NET Core и прикладные счётчики остаются без слушателей.
/// Логи (Serilog → консоль/Loki/OTLP) — в <see cref="LoggingSetup"/>.
/// </summary>
public static class ObservabilitySetup
{
    /// <summary>Читает секцию Observability, подставляя секреты из файлов и стандартную переменную OTLP.</summary>
    public static ObservabilityOptions Read(IConfiguration config)
    {
        var o = config.GetSection(ObservabilityOptions.Section).Get<ObservabilityOptions>() ?? new ObservabilityOptions();
        o.Prometheus.Token = SecretFile.Read(o.Prometheus.TokenFile, "Observability:Prometheus:TokenFile") ?? o.Prometheus.Token;
        o.OpenTelemetry.Headers = SecretFile.Read(o.OpenTelemetry.HeadersFile, "Observability:OpenTelemetry:HeadersFile") ?? o.OpenTelemetry.Headers;
        o.Loki.Password = SecretFile.Read(o.Loki.PasswordFile, "Observability:Loki:PasswordFile") ?? o.Loki.Password;
        if (string.IsNullOrWhiteSpace(o.OpenTelemetry.Endpoint))
            o.OpenTelemetry.Endpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
        if (o.OpenTelemetry.Enabled && !IsHttpUrl(o.OpenTelemetry.Endpoint))
            throw new InvalidOperationException($"Observability:OpenTelemetry:Endpoint: '{o.OpenTelemetry.Endpoint}' — ожидается адрес http(s)://хост:порт.");
        if (o.Loki.Enabled && !IsHttpUrl(o.Loki.Url))
            throw new InvalidOperationException($"Observability:Loki:Url: '{o.Loki.Url}' — ожидается адрес http(s)://хост:порт.");
        if (o.OpenTelemetry.TraceSamplingRatio is < 0 or > 1)
            throw new InvalidOperationException("Observability:OpenTelemetry:TraceSamplingRatio: значение от 0 до 1.");
        return o;
    }

    private static bool IsHttpUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    public static void AddTslObservability(this WebApplicationBuilder builder, ObservabilityOptions o)
    {
        builder.Services.AddSingleton<TslAuthMetrics>();
        builder.Services.AddSingleton(o);
        if (!o.MetricsEnabled && !o.TracingEnabled) return;

        var instance = LoggingSetup.InstanceId(o);
        var otel = builder.Services.AddOpenTelemetry().ConfigureResource(r => r
            .AddService(o.ServiceName, serviceVersion: typeof(ObservabilitySetup).Assembly.GetName().Version?.ToString(3), serviceInstanceId: instance)
            .AddAttributes(ResourceAttributes(o, instance).Where(a => a.Key is not ("service.name" or "service.instance.id" or "service.version"))));

        if (o.MetricsEnabled)
        {
            builder.Services.AddHostedService<ObservabilityStatsService>();
            otel.WithMetrics(m =>
            {
                // Встроенные измерители .NET (без отдельных пакетов): HTTP-сервер и Kestrel, лимиты, исходящие запросы
                // (вебхуки), среда выполнения (GC, пул потоков), EF Core и Npgsql — плюс прикладные счётчики.
                m.AddMeter("Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Server.Kestrel", "Microsoft.AspNetCore.RateLimiting",
                    "Microsoft.AspNetCore.Diagnostics", "System.Net.Http", "System.Runtime", "Microsoft.EntityFrameworkCore", "Npgsql",
                    TslAuthMetrics.MeterName);
                if (o.Prometheus.Enabled)
                    m.AddPrometheusExporter(p => p.ScrapeResponseCacheDurationMilliseconds = 0);
                if (o.OpenTelemetry.Enabled && o.OpenTelemetry.Metrics)
                    m.AddOtlpExporter((exporter, reader) =>
                    {
                        Configure(exporter, o.OpenTelemetry, "metrics");
                        reader.PeriodicExportingMetricReaderOptions.ExportIntervalMilliseconds =
                            Math.Max(1, o.OpenTelemetry.MetricsExportIntervalSeconds) * 1000;
                    });
            });
        }

        if (o.TracingEnabled)
        {
            otel.WithTracing(t =>
            {
                t.AddAspNetCoreInstrumentation(a =>
                    {
                        // Пробы и опрос метрик не трассируем: это шум с интервалом в секунды.
                        a.Filter = ctx => !IsInfrastructure(ctx.Request.Path, o.Prometheus.Path);
                        a.RecordException = true;
                    })
                    .AddHttpClientInstrumentation()
                    // Npgsql публикует span'ы запросов к PostgreSQL сам (без пакета инструментации).
                    .AddSource("Npgsql", TslAuthMetrics.ActivitySourceName)
                    .SetSampler(new ParentBasedSampler(new TraceIdRatioBasedSampler(o.OpenTelemetry.TraceSamplingRatio)))
                    .AddOtlpExporter(exporter => Configure(exporter, o.OpenTelemetry, "traces"));
            });
        }
    }

    /// <summary>
    /// Эндпоинт метрик — до маршрутизации, аутентификации и лимитов: у Prometheus нет cookie и он не должен
    /// упираться в rate limit. Доступ ограничен подсетями и (или) bearer-токеном.
    /// </summary>
    public static void UseTslObservability(this WebApplication app, ObservabilityOptions o)
    {
        if (!o.Prometheus.Enabled) return;
        var path = new PathString(o.Prometheus.Path);
        var guard = new PrometheusGuard(o.Prometheus);
        app.Use(async (ctx, next) =>
        {
            if (!ctx.Request.Path.Equals(path, StringComparison.OrdinalIgnoreCase) || guard.Check(ctx) is not { } status)
            {
                await next();
                return;
            }
            ctx.Response.StatusCode = status;
            if (status == StatusCodes.Status401Unauthorized) ctx.Response.Headers.WWWAuthenticate = "Bearer";
        });
        app.UseOpenTelemetryPrometheusScrapingEndpoint(o.Prometheus.Path);
    }

    private static void Configure(OtlpExporterOptions exporter, OpenTelemetryOptions o, string signal)
    {
        exporter.Endpoint = new Uri(SignalEndpoint(o, signal));
        exporter.Protocol = o.IsHttp ? OtlpExportProtocol.HttpProtobuf : OtlpExportProtocol.Grpc;
        var headers = ParseHeaders(o.Headers);
        if (headers.Count > 0) exporter.Headers = string.Join(",", headers.Select(h => $"{h.Key}={h.Value}"));
    }

    /// <summary>
    /// Адрес для сигнала: для http/protobuf стандарт требует путь /v1/traces, /v1/metrics, /v1/logs — он добавляется,
    /// если в настройке указан только адрес коллектора; для gRPC адрес используется как есть.
    /// </summary>
    public static string SignalEndpoint(OpenTelemetryOptions o, string signal)
    {
        var endpoint = o.Endpoint!.Trim();
        if (!o.IsHttp) return endpoint;
        var uri = new Uri(endpoint);
        return uri.AbsolutePath is "" or "/" ? $"{endpoint.TrimEnd('/')}/v1/{signal}" : endpoint;
    }

    /// <summary>Заголовки OTLP «k=v,k2=v2» → словарь (для Serilog) — тот же формат, что у OTEL_EXPORTER_OTLP_HEADERS.</summary>
    public static Dictionary<string, string> ParseHeaders(string? value) =>
        ParsePairs(value, "Observability:OpenTelemetry:Headers").ToDictionary(p => p.Key, p => p.Value);

    /// <summary>Атрибуты ресурса для всех сигналов; пользовательские (ResourceAttributes) поверх стандартных.</summary>
    public static Dictionary<string, object> ResourceAttributes(ObservabilityOptions o, string instance)
    {
        var attributes = new Dictionary<string, object>
        {
            ["service.name"] = o.ServiceName,
            ["service.instance.id"] = instance,
            ["service.version"] = typeof(ObservabilitySetup).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"
        };
        foreach (var (k, v) in ParsePairs(o.ResourceAttributes, "Observability:ResourceAttributes")) attributes[k] = v;
        return attributes;
    }

    /// <summary>«k=v,k2=v2» (разделители — запятая или точка с запятой); элемент без «=» — ошибка старта.</summary>
    internal static List<(string Key, string Value)> ParsePairs(string? value, string setting)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        var pairs = new List<(string, string)>();
        foreach (var item in value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = item.IndexOf('=');
            if (eq <= 0) throw new InvalidOperationException($"{setting}: '{item}' — ожидается ключ=значение.");
            pairs.Add((item[..eq].Trim(), item[(eq + 1)..].Trim()));
        }
        return pairs;
    }

    internal static bool IsInfrastructure(PathString path, string metricsPath) =>
        path.StartsWithSegments("/health") || path.Equals(metricsPath, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Проверка доступа к /metrics: подсети (по умолчанию loopback и частные) и необязательный bearer-токен.</summary>
public sealed class PrometheusGuard(PrometheusOptions options)
{
    private readonly List<IPNetwork> _networks = ServiceSetup.ParseKnownNetworks(options.AllowedNetworks, "Observability:Prometheus:AllowedNetworks");
    private readonly byte[]? _token = string.IsNullOrWhiteSpace(options.Token) ? null : Encoding.UTF8.GetBytes(options.Token.Trim());

    /// <summary>null — доступ разрешён; иначе код ответа (403 — чужая сеть, 401 — нет или неверный токен).</summary>
    public int? Check(HttpContext ctx) => Check(ctx.Connection.RemoteIpAddress, ctx.Request.Headers.Authorization.ToString());

    public int? Check(IPAddress? remote, string? authorization)
    {
        // Адреса нет у запросов внутри процесса (тесты, healthcheck-команда) — считаем их локальными.
        if (remote is not null)
        {
            var address = remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote;
            if (!_networks.Any(n => n.Contains(address))) return StatusCodes.Status403Forbidden;
        }
        if (_token is null) return null;
        const string prefix = "Bearer ";
        if (authorization is null || !authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return StatusCodes.Status401Unauthorized;
        var presented = Encoding.UTF8.GetBytes(authorization[prefix.Length..].Trim());
        return CryptographicOperations.FixedTimeEquals(presented, _token) ? null : StatusCodes.Status401Unauthorized;
    }
}
