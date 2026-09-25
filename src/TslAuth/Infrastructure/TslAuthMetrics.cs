using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Infrastructure;

/// <summary>
/// Прикладные метрики и данные для трассировок. Счётчики — стандартный <see cref="Meter"/> «TslAuth»:
/// пока нет экспортёра (Prometheus/OTLP не подключены), инструменты без слушателей ничего не считают,
/// поэтому вызовы из горячего пути (выдача токенов, аудит) остаются бесплатными.
/// Имена метрик — по соглашениям OpenTelemetry (точки); экспортёр Prometheus превращает их в
/// <c>tsl_auth_tokens_issued_total</c> и т.п.
/// Пишут: AuthorizationController (выдача), TokenErrorAuditHandler (отказы), AuditService (события, переполнение),
/// WebhookDispatcher (доставки); значения gauge обновляет <see cref="ObservabilityStatsService"/>.
/// </summary>
public sealed class TslAuthMetrics : IDisposable
{
    public const string MeterName = "TslAuth";
    public const string ActivitySourceName = "TslAuth";

    private static readonly string Version = typeof(TslAuthMetrics).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    private readonly Meter _meter = new(MeterName, Version);
    private readonly Counter<long> _tokensIssued;
    private readonly Counter<long> _tokensRejected;
    private readonly Counter<long> _auditEvents;
    private readonly Counter<long> _auditDropped;
    private readonly Counter<long> _webhookDeliveries;

    /// <summary>Снимок состояния БД для gauge-метрик (обновляется фоновой задачей раз в минуту).</summary>
    private volatile Snapshot _snapshot = new(0, 0, 0, 0, false);

    /// <summary>Источник собственных span'ов (обслуживание БД, доставка вебхуков).</summary>
    public static readonly ActivitySource Activities = new(ActivitySourceName, Version);

    public TslAuthMetrics()
    {
        _tokensIssued = _meter.CreateCounter<long>("tsl_auth.tokens.issued", "{token}",
            "Выданные токены по типу гранта и приложению");
        _tokensRejected = _meter.CreateCounter<long>("tsl_auth.tokens.rejected", "{request}",
            "Отклонённые запросы токенов по типу гранта и коду ошибки OAuth");
        _auditEvents = _meter.CreateCounter<long>("tsl_auth.audit.events", "{event}",
            "События журнала безопасности по типу, важности и исходу (входы, блокировки, изменения)");
        _auditDropped = _meter.CreateCounter<long>("tsl_auth.audit.dropped", "{event}",
            "Информационные события аудита, отброшенные из-за переполнения очереди (БД журнала не успевает)");
        _webhookDeliveries = _meter.CreateCounter<long>("tsl_auth.webhooks.deliveries", "{delivery}",
            "Попытки доставки вебхуков по результату");

        _meter.CreateObservableGauge("tsl_auth.sessions.active", () => _snapshot.Sessions, "{session}",
            "Действующие сессии (авторизации с неистёкшим токеном)");
        _meter.CreateObservableGauge("tsl_auth.users", () => new[]
        {
            new Measurement<long>(_snapshot.ActiveUsers, new KeyValuePair<string, object?>("status", "active")),
            new Measurement<long>(_snapshot.InactiveUsers, new KeyValuePair<string, object?>("status", "inactive"))
        }, "{user}", "Учётные записи по статусу");
        _meter.CreateObservableGauge("tsl_auth.applications", () => _snapshot.Applications, "{application}",
            "Зарегистрированные приложения (клиенты OAuth)");
        _meter.CreateObservableGauge("tsl_auth.database.up", () => _snapshot.DatabaseUp ? 1 : 0, "1",
            "Доступность БД при последнем опросе (1 — доступна)");
    }

    /// <summary>Выдан токен; в текущий span запроса добавляются тип гранта и приложение.</summary>
    public void TokenIssued(string grantType, string clientId)
    {
        _tokensIssued.Add(1, new("grant_type", grantType), new("client_id", clientId));
        Activity.Current?.SetTag("tsl_auth.grant_type", grantType).SetTag("tsl_auth.client_id", clientId);
    }

    public void TokenRejected(string? grantType, string error, string? clientId)
    {
        _tokensRejected.Add(1, new("grant_type", grantType ?? "unknown"), new("error", error));
        Activity.Current?.SetTag("tsl_auth.grant_type", grantType).SetTag("tsl_auth.client_id", clientId)
            .SetTag("tsl_auth.error", error);
    }

    /// <summary>
    /// Событие аудита: счётчик по типу и, если запрос трассируется, событие в span'е — в трассировке видно,
    /// что именно произошло (вход, отказ, изменение), без обращения к журналу.
    /// </summary>
    public void AuditEvent(string type, AuditSeverity severity, bool success, string? clientId)
    {
        _auditEvents.Add(1, new("type", type), new("severity", severity.ToString().ToLowerInvariant()),
            new("success", success ? "true" : "false"));
        if (Activity.Current is { IsAllDataRequested: true } activity)
            activity.AddEvent(new ActivityEvent("audit", tags: new ActivityTagsCollection
            {
                ["tsl_auth.audit.type"] = type,
                ["tsl_auth.audit.severity"] = severity.ToString().ToLowerInvariant(),
                ["tsl_auth.audit.success"] = success,
                ["tsl_auth.client_id"] = clientId
            }));
    }

    public void AuditDropped() => _auditDropped.Add(1);

    /// <summary>Результат попытки доставки вебхука: succeeded, retry (будет повтор) или failed (попытки исчерпаны).</summary>
    public void WebhookDelivery(string result) => _webhookDeliveries.Add(1, new KeyValuePair<string, object?>("result", result));

    /// <summary>Снимок для gauge-метрик; собирается одним запросом на таблицу (см. <see cref="ObservabilityStatsService"/>).</summary>
    public async Task RefreshAsync(AuthDbContext db, CancellationToken ct)
    {
        try
        {
            var now = DateTime.UtcNow;
            var sessions = await db.Set<OpenIddictEntityFrameworkCoreAuthorization<Guid>>()
                .CountAsync(a => a.Status == OpenIddict.Abstractions.OpenIddictConstants.Statuses.Valid && a.Tokens.Any(t =>
                    t.Status == OpenIddict.Abstractions.OpenIddictConstants.Statuses.Valid && (t.ExpirationDate == null || t.ExpirationDate > now)), ct);
            var active = await db.Users.CountAsync(u => u.IsActive, ct);
            var inactive = await db.Users.CountAsync(u => !u.IsActive, ct);
            var apps = await db.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>().CountAsync(ct);
            _snapshot = new Snapshot(sessions, active, inactive, apps, true);
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            // БД недоступна: счётчики оставляем прежними, но метрика доступности показывает проблему.
            _snapshot = _snapshot with { DatabaseUp = false };
            throw;
        }
    }

    public void Dispose() => _meter.Dispose();

    private sealed record Snapshot(long Sessions, long ActiveUsers, long InactiveUsers, long Applications, bool DatabaseUp);
}

/// <summary>
/// Раз в минуту обновляет gauge-метрики из БД. Регистрируется только при включённом экспорте метрик:
/// без Prometheus/OTLP лишние запросы к БД не нужны.
/// </summary>
public sealed class ObservabilityStatsService(IServiceScopeFactory scopes, TslAuthMetrics metrics,
    ILogger<ObservabilityStatsService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            do
            {
                try
                {
                    using var scope = scopes.CreateScope();
                    await metrics.RefreshAsync(scope.ServiceProvider.GetRequiredService<AuthDbContext>(), stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex, "Не удалось обновить метрики состояния из БД.");
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) { }
    }
}
