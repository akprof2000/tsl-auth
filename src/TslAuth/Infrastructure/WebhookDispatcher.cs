using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Infrastructure;

/// <summary>
/// Доставка вебхуков из outbox. Экземпляр «захватывает» доставку условным UPDATE (LockedUntil),
/// поэтому в кластере каждое событие отправляется одним экземпляром; при падении экземпляра
/// блокировка истекает и доставку подхватывает другой. Повторы — с экспоненциальной задержкой.
/// Записи WebhookDeliveries создаёт WebhookService при публикации события; здесь — только отправка.
/// </summary>
public sealed class WebhookDispatcher(IServiceScopeFactory scopes, IHttpClientFactory http, ILogger<WebhookDispatcher> logger)
    : BackgroundService
{
    public const string HttpClientName = "webhooks";
    private const int MaxAttempts = 8;
    private static readonly TimeSpan LockDuration = TimeSpan.FromSeconds(60);
    private static readonly string Instance = $"{Environment.MachineName}:{Environment.ProcessId}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await DispatchBatchAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Ошибка диспетчера вебхуков.");
            }
        }
    }

    private async Task DispatchBatchAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var now = DateTime.UtcNow;

        // Сначала только id кандидатов (без блокировки), затем каждый захватывается атомарно ниже.
        var candidates = await db.WebhookDeliveries.AsNoTracking()
            .Where(d => d.Status == WebhookDeliveryStatus.Pending && d.NextAttemptAt <= now && (d.LockedUntil == null || d.LockedUntil < now))
            .OrderBy(d => d.NextAttemptAt).Select(d => d.Id).Take(20).ToListAsync(ct);

        foreach (var id in candidates)
        {
            // Условный UPDATE — оптимистичный захват без транзакций и SELECT FOR UPDATE: работает одинаково
            // на SQLite и PostgreSQL; обновит строку только тот экземпляр, который успел первым.
            var lockUntil = DateTime.UtcNow + LockDuration;
            var claimed = await db.WebhookDeliveries
                .Where(d => d.Id == id && d.Status == WebhookDeliveryStatus.Pending && (d.LockedUntil == null || d.LockedUntil < now))
                .ExecuteUpdateAsync(s => s.SetProperty(d => d.LockedUntil, lockUntil).SetProperty(d => d.LockedBy, Instance), ct);
            if (claimed == 0) continue; // забрал другой экземпляр

            var delivery = await db.WebhookDeliveries.Include(d => d.Subscription).Include(d => d.Event).FirstAsync(d => d.Id == id, ct);
            // Доставки идут последовательно; таймаут HTTP-клиента (10 с) меньше LockDuration, так что захват не истечёт посреди отправки.
            await SendAsync(delivery, ct);
            delivery.LockedUntil = null;
            await db.SaveChangesAsync(ct);
        }
    }

    /// <summary>
    /// Одна попытка отправки. Результат (статус, ошибка, время следующей попытки) записывается в delivery;
    /// сохраняет вызывающий код.
    /// </summary>
    private async Task SendAsync(WebhookDelivery delivery, CancellationToken ct)
    {
        var dto = WebhookService.ToDto(delivery.Event);
        var body = JsonSerializer.Serialize(new
        {
            id = dto.Id,
            @event = dto.Event,
            occurredAt = dto.OccurredAt,
            text = dto.Text,
            data = dto.Data
        });

        delivery.Attempts++;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, delivery.Subscription.Url)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            // X-TSL-Delivery — идентификатор для дедупликации у получателя (доставка «как минимум один раз»);
            // X-TSL-Signature — HMAC тела секретом подписки, получатель проверяет подлинность.
            request.Headers.Add("X-TSL-Event", dto.Event);
            request.Headers.Add("X-TSL-Delivery", delivery.Id.ToString());
            if (delivery.Subscription.Secret is not null)
                request.Headers.Add("X-TSL-Signature", WebhookService.Sign(delivery.Subscription.Secret, body));

            using var response = await http.CreateClient(HttpClientName).SendAsync(request, ct);
            delivery.LastStatusCode = (int)response.StatusCode;
            if (response.IsSuccessStatusCode)
            {
                delivery.Status = WebhookDeliveryStatus.Succeeded;
                delivery.DeliveredAt = DateTime.UtcNow;
                delivery.LastError = null;
                return;
            }
            delivery.LastError = $"HTTP {(int)response.StatusCode}";
        }
        // Таймаут HttpClient тоже приходит как OperationCanceledException — это ошибка доставки;
        // пробрасываем отмену только при остановке сервиса.
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            delivery.LastError = ex.Message[..Math.Min(ex.Message.Length, 1000)];
        }

        if (delivery.Attempts >= MaxAttempts)
        {
            delivery.Status = WebhookDeliveryStatus.Failed;
            logger.LogWarning("Вебхук {Delivery} ({Url}) не доставлен после {Attempts} попыток: {Error}",
                delivery.Id, delivery.Subscription.Url, delivery.Attempts, delivery.LastError);
        }
        else
        {
            // Задержки 5 с, 15 с, 45 с, … (×3), но не более часа.
            delivery.NextAttemptAt = DateTime.UtcNow + TimeSpan.FromSeconds(Math.Min(3600, 5 * Math.Pow(3, delivery.Attempts - 1)));
        }
    }
}
