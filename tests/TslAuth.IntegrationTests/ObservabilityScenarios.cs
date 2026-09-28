// Интеграционные сценарии наблюдаемости: метрики /metrics (их забирает VictoriaMetrics), уровни логов и OTLP
// (приёмники подменяются локальным HTTP-сервером-заглушкой).
// Запуск: dotnet test tests/TslAuth.IntegrationTests (для вариантов на PostgreSQL нужен Docker —
// контейнер поднимает Testcontainers). Сервис поднимается в процессе через WebApplicationFactory
// (см. Infrastructure/AuthFixture.cs), админ-клиент и токены получаются через TestApi.

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TslAuth.Infrastructure;
using TslAuth.IntegrationTests.Infrastructure;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Мониторинг: эндпоинт /metrics (выключен по умолчанию, токен, прикладные счётчики), уровни логирования из настроек
/// в БД (применяются без перезапуска), трассировки/метрики/логи по OTLP (логи в стенде идут только в stdout, их собирает Vector) —
/// на заглушке-приёмнике внутри теста, без внешних систем.
/// </summary>
public abstract class ObservabilityScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    /// <summary>По умолчанию /metrics выключен.</summary>
    [Fact]
    public async Task Metrics_DisabledByDefault()
    {
        var response = await fx.Factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>С включёнными метриками и токеном /metrics отдаёт счётчики приложения.</summary>
    [Fact]
    public async Task Metrics_WithToken_ExposesApplicationCounters()
    {
        using var factory = fx.Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Observability:Prometheus:Enabled", "true");
            b.UseSetting("Observability:Prometheus:Token", "probe-token");
        });
        await factory.AdminAsync();                                   // выдача токена → счётчик tokens.issued
        await factory.CreateClient().TokenAsync(new()                 // отказ → счётчик tokens.rejected
        {
            ["grant_type"] = "client_credentials", ["client_id"] = AuthFixture.AdminClientId, ["client_secret"] = "wrong"
        }, expectSuccess: false);

        var anonymous = await factory.CreateClient().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal("Bearer", anonymous.Headers.WwwAuthenticate.ToString());

        var body = await factory.CreateClient().WithBearer("probe-token").GetStringAsync("/metrics");
        Assert.Contains("tsl_auth_tokens_issued_total", body);
        Assert.Contains("grant_type=\"client_credentials\"", body);
        Assert.Contains("tsl_auth_tokens_rejected_total", body);
        Assert.Contains("error=\"invalid_client\"", body);
        Assert.Contains("tsl_auth_audit_events_total", body);
        Assert.Contains("http_server_request_duration_seconds", body); // встроенные метрики ASP.NET Core
        Assert.Contains("tsl_auth_users{", body);
    }

    /// <summary>Уровни логов меняются через настройки в БД без перезапуска.</summary>
    [Fact]
    public async Task LogLevels_ChangeFromSettings_WithoutRestart()
    {
        var admin = await fx.Factory.AdminAsync();
        var before = await admin.GetJsonAsync("/api/admin/settings");
        var levels = fx.Factory.Services.GetRequiredService<LogLevels>();
        try
        {
            var bad = await admin.PutAsJsonAsync("/api/admin/settings", Merge(before, new { loggingPolicy = new { defaultLevel = "Loud" } }));
            Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);

            (await admin.PutAsJsonAsync("/api/admin/settings", Merge(before, new
            {
                loggingPolicy = new { defaultLevel = "Debug", overrides = new Dictionary<string, string> { ["TslAuth.Probe"] = "Trace" } }
            }))).EnsureSuccessStatusCode();

            // Фоновая синхронизация опрашивает настройки раз в 5 с.
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (levels.LevelFor("TslAuth.Probe") != Serilog.Events.LogEventLevel.Verbose && DateTime.UtcNow < deadline)
                await Task.Delay(200);
            Assert.Equal(Serilog.Events.LogEventLevel.Verbose, levels.LevelFor("TslAuth.Probe"));
            Assert.Equal(Serilog.Events.LogEventLevel.Debug, levels.LevelFor("TslAuth.Other"));
            // Логгер этого хоста живёт независимо от других экземпляров в процессе (preserveStaticLogger).
            Assert.True(fx.Factory.Services.GetRequiredService<ILoggerFactory>().CreateLogger("TslAuth.Probe").IsEnabled(LogLevel.Trace));
        }
        finally
        {
            await admin.PutAsJsonAsync("/api/admin/settings", before);
        }
    }

    /// <summary>
    /// Трассы, метрики и логи доходят до OTLP-приёмника, если их включить (заглушка ждёт запросы с таймаутом).
    /// Других сетевых приёмников логов у сервиса нет: в стенде логи идут только в stdout и их забирает Vector.
    /// </summary>
    [Fact]
    public async Task Otlp_ReceivesSignals_AndNoOtherLogSink()
    {
        await using var sink = await Receiver.StartAsync();
        using var factory = fx.Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Observability:OpenTelemetry:Endpoint", sink.Url);
            b.UseSetting("Observability:OpenTelemetry:Protocol", "http");
            b.UseSetting("Observability:OpenTelemetry:Headers", "X-Probe=yes");
            b.UseSetting("Observability:OpenTelemetry:MetricsExportIntervalSeconds", "1");
            b.UseSetting("Logging:LogLevel:Default", "Information");
        });
        var marker = "otlp-probe-" + Guid.NewGuid().ToString("N");
        await factory.AdminAsync(); // запрос → span и метрики
        factory.Services.GetRequiredService<ILoggerFactory>().CreateLogger("TslAuth.Probe").LogWarning("Проверка {Marker}", marker);

        // OTLP по http/protobuf: пути /v1/* добавлены к адресу, заголовки переданы, все три сигнала пришли.
        foreach (var signal in new[] { "traces", "metrics", "logs" })
        {
            var request = await sink.WaitAsync($"/v1/{signal}", _ => true);
            Assert.Equal("application/x-protobuf", request.ContentType);
            Assert.Equal("yes", request.Headers["X-Probe"]);
        }
        var traces = sink.Bodies("/v1/traces");
        Assert.Contains(traces, t => t.Contains("connect/token") && t.Contains("tsl_auth.grant_type"));
        await sink.WaitAsync("/v1/logs", body => body.Contains(marker));
        // Кроме OTLP сервис никуда не отправляет данные (отправки логов в хранилище напрямую нет).
        Assert.All(sink.Paths(), p => Assert.StartsWith("/v1/", p));
    }

    /// <summary>Объединяет текущие настройки (JSON) с изменяемыми полями, чтобы не затирать остальное.</summary>
    private static Dictionary<string, object?> Merge(JsonElement current, object changes)
    {
        var result = current.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value);
        foreach (var p in JsonSerializer.SerializeToElement(changes).EnumerateObject()) result[p.Name] = p.Value;
        return result;
    }

    /// <summary>Приёмник HTTP внутри теста: запоминает все POST (OTLP) для проверки.</summary>
    private sealed class Receiver : IAsyncDisposable
    {
        public sealed record Request(string Path, string Body, string? ContentType, Dictionary<string, string> Headers);

        private readonly WebApplication _app;
        private readonly List<Request> _requests = [];
        public string Url { get; private set; } = "";

        private Receiver(WebApplication app) => _app = app;

        public static async Task<Receiver> StartAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var app = builder.Build();
            var receiver = new Receiver(app);
            app.MapPost("/{**path}", async (HttpContext ctx) =>
            {
                // Тело OTLP — protobuf: текстовые строки (маршруты, имена тегов) в нём видны и так.
                using var ms = new MemoryStream();
                await ctx.Request.Body.CopyToAsync(ms);
                var body = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                lock (receiver._requests)
                    receiver._requests.Add(new Request(ctx.Request.Path, body, ctx.Request.ContentType,
                        ctx.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString())));
                return Results.NoContent();
            });
            await app.StartAsync();
            receiver.Url = app.Urls.First();
            return receiver;
        }

        public async Task<Request> WaitAsync(string path, Func<string, bool> predicate)
        {
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (DateTime.UtcNow < deadline)
            {
                lock (_requests)
                    if (_requests.FirstOrDefault(r => r.Path == path && predicate(r.Body)) is { } found) return found;
                await Task.Delay(200);
            }
            lock (_requests)
                throw new TimeoutException($"Нет запроса {path}; получено: {string.Join(", ", _requests.Select(r => r.Path).Distinct())}");
        }

        public List<string> Bodies(string path)
        {
            lock (_requests) return _requests.Where(r => r.Path == path).Select(r => r.Body).ToList();
        }

        /// <summary>Все пути, на которые приходили запросы.</summary>
        public List<string> Paths()
        {
            lock (_requests) return _requests.Select(r => r.Path).Distinct().ToList();
        }

        public async ValueTask DisposeAsync()
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }
}

/// <summary>Мониторинг на SQLite.</summary>
[Collection("sqlite-observability")]
public sealed class SqliteObservability(SqliteFixture fx) : ObservabilityScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

/// <summary>Мониторинг на PostgreSQL.</summary>
[Collection("postgres-observability")]
public sealed class PostgresObservability(PostgresFixture fx) : ObservabilityScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;
