using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;

namespace TslAuth.Services;

/// <summary>Типы событий ленты/вебхуков; подписка может выбрать их подмножество или "*" (все).</summary>
public static class WebhookEvents
{
    public const string AccessRequestCreated = "access_request.created";
    public const string AccessRequestApproved = "access_request.approved";
    public const string AccessRequestRejected = "access_request.rejected";
    public const string UserRegistered = "user.registered";
    public const string UserCreated = "user.created";
    public const string UserDeleted = "user.deleted";
    public const string UserLockedOut = "user.locked_out";
    public const string ApplicationCreated = "application.created";
    public const string ApplicationDeleted = "application.deleted";
    public const string Test = "test";

    /// <summary>События журнала безопасности уровня warning/critical.</summary>
    public const string SecurityAlert = "security.alert";

    public static readonly string[] All =
    [
        SecurityAlert, AccessRequestCreated, AccessRequestApproved, AccessRequestRejected, UserRegistered, UserCreated,
        UserDeleted, UserLockedOut, ApplicationCreated, ApplicationDeleted, Test
    ];
}

/// <summary>Событие в формате, общем для вебхуков, long-polling и SSE.</summary>
/// <param name="Text">Готовое сообщение для мессенджера (совместимо с incoming webhooks Mattermost/Rocket.Chat/Slack).</param>
public sealed record EventDto(long Id, string Event, DateTime OccurredAt, string Text, JsonElement Data);

/// <summary>Подписка на вебхуки; сам секрет не возвращается — только признак HasSecret.</summary>
public sealed record SubscriptionDto(Guid Id, string Name, string Url, List<string> Events, bool IsEnabled, bool HasSecret,
    string? CreatedBy, DateTime CreatedAt);

/// <summary>
/// Входные данные подписки. Events пусто или содержит "*" — все события.
/// При обновлении Secret = null сохраняет прежний секрет, пустая строка — удаляет его.
/// </summary>
public sealed record SubscriptionInput(string Name, string Url, List<string>? Events, string? Secret, bool IsEnabled = true);

/// <summary>Состояние доставки одного события одной подписке (для диагностики на странице Admin/Webhooks).</summary>
public sealed record DeliveryDto(Guid Id, long EventId, string Event, string Status, int Attempts, int? LastStatusCode,
    string? LastError, DateTime NextAttemptAt, DateTime? DeliveredAt);

/// <summary>
/// Публикация событий (журнал в БД) + подписки. Доставку вебхуков выполняет <see cref="Infrastructure.WebhookDispatcher"/>;
/// боты без входящего порта читают ту же ленту через long-polling или SSE.
/// Публикуют события сервисы (пользователи, заявки, приложения, аудит), AuthorizationController и страница входа;
/// ленту читает Api/EventsApi.cs, подписками управляют Admin/Webhooks и API.
/// </summary>
public sealed class WebhookService(AuthDbContext db, IServiceScopeFactory scopes, Infrastructure.WebhookTargetPolicy targets,
    ILogger<WebhookService> logger)
{
    /// <summary>
    /// Сохраняет событие в ленту и ставит в очередь доставки (таблица в БД, по принципу outbox) для подходящих подписок.
    /// Сама HTTP-отправка — позже, в WebhookDispatcher, с повторами. Не бросает исключений, кроме отмены.
    /// Пишет в собственном scope БД: сбой публикации не оставляет «висящих» сущностей в DbContext вызывающего
    /// сервиса (иначе его следующий SaveChanges повторил бы неудачную вставку и упал уже в основной операции).
    /// </summary>
    /// <param name="onlyCreatedBy">Доставить только подпискам этих владельцев (тестовое событие бота — только в его подписки).</param>
    public async Task PublishAsync(string type, string text, object data, CancellationToken ct = default,
        IReadOnlyCollection<string>? onlyCreatedBy = null)
    {
        try
        {
            using var scope = scopes.CreateScope();
            var own = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var ev = new WebhookEvent { Type = type, Text = text, Data = JsonSerializer.Serialize(data) };
            own.WebhookEvents.Add(ev);
            // Первое сохранение нужно, чтобы получить автоинкрементный Id события для записей доставки.
            await own.SaveChangesAsync(ct);

            var subscriptions = await own.WebhookSubscriptions.AsNoTracking().Where(s => s.IsEnabled).ToListAsync(ct);
            foreach (var s in subscriptions.Where(s => Matches(s.Events, type) && (onlyCreatedBy is null || (s.CreatedBy is { } by && onlyCreatedBy.Contains(by)))))
                own.WebhookDeliveries.Add(new WebhookDelivery { SubscriptionId = s.Id, EventId = ev.Id });
            await own.SaveChangesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Уведомления не должны ломать основную операцию (вход, заявку и т.п.).
            logger.LogError(ex, "Не удалось опубликовать событие {Type}.", type);
        }
    }

    /// <summary>События с Id больше курсора <paramref name="after"/> (по возрастанию Id, не более 500).</summary>
    public async Task<List<EventDto>> ListEventsAsync(long after, int limit = 100, IReadOnlyCollection<string>? types = null,
        CancellationToken ct = default)
    {
        // Окно «успокоения» 1 с: событие с меньшим id может закоммититься позже события с большим
        // (параллельные транзакции на разных экземплярах) — не отдаём свежие, чтобы курсор ничего не пропустил.
        var settled = DateTime.UtcNow.AddSeconds(-1);
        var query = db.WebhookEvents.AsNoTracking().Where(e => e.Id > after && e.OccurredAt <= settled);
        if (types is { Count: > 0 }) query = query.Where(e => types.Contains(e.Type));
        var rows = await query.OrderBy(e => e.Id).Take(Math.Clamp(limit, 1, 500)).ToListAsync(ct);
        return rows.Select(ToDto).ToList();
    }

    /// <summary>Long-polling: ждёт появления событий до <paramref name="wait"/> (проверка БД раз в секунду — работает в кластере).</summary>
    public async Task<List<EventDto>> WaitForEventsAsync(long after, TimeSpan wait, int limit, IReadOnlyCollection<string>? types,
        CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + wait;
        while (true)
        {
            var events = await ListEventsAsync(after, limit, types, ct);
            if (events.Count > 0 || DateTime.UtcNow >= deadline) return events;
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
    }

    /// <summary>Id последнего события — начальный курсор для клиента, которому не нужна история.</summary>
    public async Task<long> LatestEventIdAsync(CancellationToken ct = default) =>
        await db.WebhookEvents.MaxAsync(e => (long?)e.Id, ct) ?? 0;

    // ---------- Подписки ----------

    public async Task<List<SubscriptionDto>> ListSubscriptionsAsync(CancellationToken ct = default) =>
        (await db.WebhookSubscriptions.AsNoTracking().OrderBy(s => s.CreatedAt).ToListAsync(ct)).Select(ToDto).ToList();

    public async Task<SubscriptionDto> CreateSubscriptionAsync(SubscriptionInput input, string createdBy, CancellationToken ct = default)
    {
        var entity = new WebhookSubscription { Name = "", Url = "", CreatedBy = createdBy };
        Apply(entity, input);
        db.WebhookSubscriptions.Add(entity);
        await db.SaveChangesAsync(ct);
        return ToDto(entity);
    }

    public async Task<SubscriptionDto> UpdateSubscriptionAsync(Guid id, SubscriptionInput input, CancellationToken ct = default)
    {
        var entity = await db.WebhookSubscriptions.FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AdminException.NotFound("Подписка");
        var secret = entity.Secret;
        Apply(entity, input);
        entity.Secret = input.Secret is null ? secret : entity.Secret; // null — оставить прежний секрет
        await db.SaveChangesAsync(ct);
        return ToDto(entity);
    }

    public async Task DeleteSubscriptionAsync(Guid id, CancellationToken ct = default)
    {
        if (await db.WebhookSubscriptions.Where(s => s.Id == id).ExecuteDeleteAsync(ct) == 0)
            throw AdminException.NotFound("Подписка");
    }

    /// <summary>Последние доставки подписки, новые первыми.</summary>
    public async Task<List<DeliveryDto>> ListDeliveriesAsync(Guid subscriptionId, int take = 50, CancellationToken ct = default) =>
        await db.WebhookDeliveries.AsNoTracking().Where(d => d.SubscriptionId == subscriptionId)
            .OrderByDescending(d => d.EventId).Take(take)
            .Select(d => new DeliveryDto(d.Id, d.EventId, d.Event.Type, d.Status.ToString().ToLower(), d.Attempts,
                d.LastStatusCode, d.LastError, d.NextAttemptAt, d.DeliveredAt))
            .ToListAsync(ct);

    /// <summary>
    /// Подпись тела запроса HMAC-SHA256 секретом подписки (формат "sha256=hex", как у GitHub):
    /// получатель проверяет, что вебхук пришёл от TslAuth и не изменён.
    /// </summary>
    public static string Sign(string secret, string body) =>
        "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body)));

    public static EventDto ToDto(WebhookEvent e) =>
        new(e.Id, e.Type, e.OccurredAt, e.Text, JsonSerializer.Deserialize<JsonElement>(e.Data));

    private static bool Matches(string events, string type) =>
        events == "*" || events.Split(',', StringSplitOptions.TrimEntries).Contains(type);

    private void Apply(WebhookSubscription entity, SubscriptionInput input)
    {
        if (string.IsNullOrWhiteSpace(input.Name)) throw new AdminException("Укажите название подписки.");
        // Только http(s): схемы вроде file:// не должны попадать в HTTP-клиент диспетчера.
        if (!Uri.TryCreate(input.Url?.Trim(), UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            throw new AdminException("URL вебхука должен быть абсолютным http(s)-адресом.");
        if (uri.AbsoluteUri.Length > 2000) throw new AdminException("URL вебхука: не длиннее 2000 символов.");
        if (targets.Reject(uri) is { } reason) throw new AdminException(reason);

        var events = (input.Events ?? []).Select(e => e.Trim()).Where(e => e.Length > 0).Distinct().ToList();
        var unknown = events.Where(e => e != "*" && !WebhookEvents.All.Contains(e)).ToList();
        if (unknown.Count > 0) throw new AdminException($"Неизвестные события: {string.Join(", ", unknown)}.");

        entity.Name = input.Name.Trim();
        // AbsoluteUri, а не ToString(): ToString() разэкранирует адрес (%2F → /), и сохранялся бы другой URL.
        entity.Url = uri.AbsoluteUri;
        entity.Events = events.Count == 0 || events.Contains("*") ? "*" : string.Join(",", events);
        entity.Secret = string.IsNullOrWhiteSpace(input.Secret) ? null : input.Secret;
        entity.IsEnabled = input.IsEnabled;
    }

    private static SubscriptionDto ToDto(WebhookSubscription s) =>
        new(s.Id, s.Name, s.Url, s.Events.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(), s.IsEnabled,
            s.Secret is not null, s.CreatedBy, s.CreatedAt);
}
