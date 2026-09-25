namespace TslAuth.Options;

/// <summary>
/// Секция "Observability": подключение внешних систем мониторинга. Каждая подсистема включается отдельно и только
/// когда она реально подключена: метрики собираются, если задан экспорт в Prometheus или OTLP; трассировки —
/// если задан OTLP-адрес; логи в Loki — если задан его адрес. Ничего не задано — накладных расходов нет.
/// </summary>
public sealed class ObservabilityOptions
{
    public const string Section = "Observability";

    /// <summary>service.name в метриках, трассировках и логах (метка service в Loki).</summary>
    public string ServiceName { get; set; } = "tsl-auth";

    /// <summary>service.instance.id / метка instance; пусто — имя хоста (в контейнере — его id, в кластере — auth1…auth3).</summary>
    public string? InstanceId { get; set; }

    /// <summary>Дополнительные атрибуты ресурса: <c>deployment.environment=prod,dc=msk</c>.</summary>
    public string? ResourceAttributes { get; set; }

    public PrometheusOptions Prometheus { get; set; } = new();
    public OpenTelemetryOptions OpenTelemetry { get; set; } = new();
    public LokiOptions Loki { get; set; } = new();

    /// <summary>Есть ли кому отдавать метрики (иначе счётчики не собираются вовсе).</summary>
    public bool MetricsEnabled => Prometheus.Enabled || (OpenTelemetry.Enabled && OpenTelemetry.Metrics);

    public bool TracingEnabled => OpenTelemetry.Enabled && OpenTelemetry.Traces;
}

/// <summary>Эндпоинт для сбора метрик Prometheus (pull-модель: Prometheus сам опрашивает каждый узел).</summary>
public sealed class PrometheusOptions
{
    public bool Enabled { get; set; }

    public string Path { get; set; } = "/metrics";

    /// <summary>
    /// Подсети (CIDR через запятую), откуда разрешён опрос. Пусто — loopback и частные сети (там живёт Prometheus
    /// закрытого контура). Метрики раскрывают имена приложений и объёмы отказов — наружу их отдавать не нужно.
    /// </summary>
    public string? AllowedNetworks { get; set; }

    /// <summary>Bearer-токен для опроса (в Prometheus — <c>authorization.credentials</c>); пусто — без токена.</summary>
    public string? Token { get; set; }

    /// <summary>Тот же токен из файла (docker secrets).</summary>
    public string? TokenFile { get; set; }
}

/// <summary>
/// Экспорт по OTLP в OpenTelemetry Collector или напрямую в бэкенд (Tempo, Jaeger, Loki ≥ 3.0 принимают OTLP).
/// Включается заданием адреса; если адрес пуст, берётся стандартная переменная OTEL_EXPORTER_OTLP_ENDPOINT.
/// </summary>
public sealed class OpenTelemetryOptions
{
    /// <summary>Адрес: grpc — <c>http://otel-collector:4317</c>, http — <c>http://otel-collector:4318</c> (пути /v1/* добавляются сами).</summary>
    public string? Endpoint { get; set; }

    /// <summary><c>grpc</c> или <c>http</c> (http/protobuf).</summary>
    public string Protocol { get; set; } = "grpc";

    /// <summary>Заголовки запросов к коллектору: <c>Authorization=Bearer …,X-Scope-OrgID=tenant</c>.</summary>
    public string? Headers { get; set; }

    /// <summary>Те же заголовки из файла (docker secrets) — токен не виден в окружении процесса.</summary>
    public string? HeadersFile { get; set; }

    public bool Traces { get; set; } = true;
    public bool Metrics { get; set; } = true;
    public bool Logs { get; set; } = true;

    /// <summary>Доля трассируемых входящих запросов (0–1); решение родителя (trace-context клиента) уважается.</summary>
    public double TraceSamplingRatio { get; set; } = 1.0;

    /// <summary>Период отправки метрик, сек.</summary>
    public int MetricsExportIntervalSeconds { get; set; } = 30;

    public bool Enabled => !string.IsNullOrWhiteSpace(Endpoint);

    public bool IsHttp => Protocol.Equals("http", StringComparison.OrdinalIgnoreCase)
                          || Protocol.Equals("http/protobuf", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Отправка логов прямо в Grafana Loki (push API, любая версия Loki); включается заданием адреса.</summary>
public sealed class LokiOptions
{
    /// <summary>Адрес Loki: <c>http://loki:3100</c>.</summary>
    public string? Url { get; set; }

    /// <summary>Статические метки потока: <c>env=prod,dc=msk</c>. Метки service, instance и level добавляются всегда.</summary>
    public string? Labels { get; set; }

    /// <summary>Идентификатор арендатора (X-Scope-OrgID) для Loki в multi-tenant режиме.</summary>
    public string? Tenant { get; set; }

    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? PasswordFile { get; set; }

    /// <summary>Минимальный уровень для отправки (Trace, Debug, Information, Warning, Error, Critical).</summary>
    public string MinimumLevel { get; set; } = "Information";

    public int BatchSize { get; set; } = 500;
    public int PeriodSeconds { get; set; } = 2;

    /// <summary>Сколько записей держать в очереди при недоступности Loki (старые отбрасываются).</summary>
    public int QueueLimit { get; set; } = 10_000;

    public bool Enabled => !string.IsNullOrWhiteSpace(Url);
}
