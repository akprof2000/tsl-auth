using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Infrastructure;

/// <summary>
/// Периодическое обслуживание БД по срокам хранения из настроек (таблица SystemSettings):
/// истёкшие/отозванные токены и авторизации, журнал безопасности (по типам событий), лента событий.
/// Работает на каждом экземпляре; удаление идемпотентно, так что параллельный запуск не вредит, лишь дублирует работу.
/// </summary>
public sealed class TokenPruningService(IServiceScopeFactory scopes, ILogger<TokenPruningService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    /// <summary>Периодически удаляет просроченные токены и авторизации OpenIddict.</summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Случайная задержка, чтобы экземпляры кластера не чистили БД одновременно.
        await Task.Delay(TimeSpan.FromSeconds(Random.Shared.Next(60, 600)), stoppingToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);

        using var timer = new PeriodicTimer(Interval);
        do
        {
            try
            {
                await RunOnceAsync(scopes, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Ошибка обслуживания БД.");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    /// <summary>
    /// Один проход очистки; возвращает число удалённых записей по категориям.
    /// Вызывается также вручную — из настроек админки и Admin API.
    /// </summary>
    public static async Task<object> RunOnceAsync(IServiceScopeFactory scopes, CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var sp = scope.ServiceProvider;
        var settings = await sp.GetRequiredService<SettingsService>().GetAsync(ct);
        var logger = sp.GetRequiredService<ILogger<TokenPruningService>>();

        // PruneAsync OpenIddict удаляет только неактивные (истёкшие/отозванные/погашенные) записи старше порога —
        // действующие refresh-токены не затрагиваются.
        var threshold = DateTimeOffset.UtcNow.AddHours(-settings.TokensRetentionHours);
        var tokens = await sp.GetRequiredService<IOpenIddictTokenManager>().PruneAsync(threshold, ct);
        var authorizations = await sp.GetRequiredService<IOpenIddictAuthorizationManager>().PruneAsync(threshold, ct);
        var audit = await sp.GetRequiredService<AuditService>().PruneAsync(settings, ct);

        var eventsThreshold = DateTime.UtcNow.AddDays(-settings.EventsRetentionDays);
        var events = await sp.GetRequiredService<AuthDbContext>().WebhookEvents
            .Where(e => e.OccurredAt < eventsThreshold).ExecuteDeleteAsync(ct);

        // Отключение неактивных учётных записей (решение В-10 ЧТЗ). Параллельный запуск на других узлах безопасен:
        // SetActiveAsync возвращает false для уже отключённой записи, поэтому аудит пишется один раз на запись.
        var inactive = 0;
        if (settings.Inactivity.Enabled)
        {
            var auditService = sp.GetRequiredService<AuditService>();
            var webhooks = sp.GetRequiredService<WebhookService>();
            foreach (var (id, name) in await sp.GetRequiredService<UserService>().DisableInactiveAsync(settings.Inactivity.DisableAfterDays, ct))
            {
                inactive++;
                await auditService.WriteAsync(AuditTypes.DisabledInactive, true, AuditSeverity.Warning, null, id,
                    new { days = settings.Inactivity.DisableAfterDays }, "system", "обслуживание");
                await webhooks.PublishAsync(WebhookEvents.SecurityAlert,
                    $"⏸ Учётная запись {name} отключена: нет входа более {settings.Inactivity.DisableAfterDays} дней.",
                    new { userId = id, userName = name, reason = "inactive" }, ct);
            }
        }

        var result = new { tokens, authorizations, audit, events, inactive };
        logger.LogInformation("Обслуживание БД: {@Result}", result);
        return result;
    }
}
