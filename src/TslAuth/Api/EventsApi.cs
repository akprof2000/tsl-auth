using System.Net.ServerSentEvents;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;
using TslAuth.Infrastructure;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Api;

/// <summary>
/// Интеграция внешних ботов-уведомителей. Три способа получать события (выбирайте любой):
///   1) long-polling:  GET /api/admin/events?after={id}&amp;wait=30
///   2) SSE-поток:     GET /api/admin/events/stream   (Last-Event-ID для продолжения после обрыва)
///   3) вебхуки:       POST /api/admin/webhooks — бот подписывает свой URL сам.
/// Нужна роль notifier (разрешение events) или administrator в системном приложении.
/// Источник событий — таблица <see cref="TslAuth.Data.WebhookEvent"/>; её автоинкрементный Id служит курсором.
/// Все три способа читают БД напрямую, поэтому работают в кластере без общей шины сообщений:
/// бот может переподключаться к любому экземпляру и продолжать с того же курсора.
/// </summary>
public static class EventsApi
{
    /// <summary>Регистрирует маршруты /api/admin/events и /api/admin/webhooks.</summary>
    public static void MapEventsApi(this IEndpointRouteBuilder endpoints)
    {
        var events = endpoints.MapGroup("/api/admin/events").RequireAuthorization(AdminPolicies.ApiEvents).WithTags("Events");

        // Long-polling: запрос висит до wait секунд (максимум 60), пока не появятся события после курсора.
        // WebhookService отдаёт только события старше ~1 с («окно успокоения»): параллельные транзакции
        // могут закоммитить меньший Id позже большего, и без окна курсор перепрыгнул бы через него.
        events.MapGet("/", async (long? after, int? wait, int? limit, string? types, WebhookService s, CancellationToken ct) =>
        {
            var filter = ParseTypes(types);
            var items = await s.WaitForEventsAsync(after ?? 0, TimeSpan.FromSeconds(Math.Clamp(wait ?? 0, 0, 60)),
                limit ?? 100, filter, ct);
            // Курсор для следующего запроса — id последнего полученного события.
            return new { events = items, next = items.Count > 0 ? items[^1].Id : after ?? 0 };
        });

        // SSE: явный ?after важнее заголовка Last-Event-ID, который браузер/клиент шлёт при автопереподключении.
        // Без обоих курсоров поток начинается «с текущего момента» (см. StreamAsync).
        events.MapGet("/stream", (HttpContext http, long? after, string? types, IServiceScopeFactory scopes, CancellationToken ct) =>
        {
            long? cursor = after ?? (long.TryParse(http.Request.Headers["Last-Event-ID"], out var last) ? last : null);
            http.Response.Headers["X-Accel-Buffering"] = "no"; // nginx не должен буферизовать поток
            return TypedResults.ServerSentEvents(StreamAsync(cursor, ParseTypes(types), scopes, ct));
        });

        // Подписки на вебхуки. Доставка идёт через outbox (WebhookDelivery) с повторами и подписью HMAC.
        var hooks = endpoints.MapGroup("/api/admin/webhooks").RequireAuthorization(AdminPolicies.ApiEvents).WithTags("Events")
            .AddEndpointFilter(HandleErrors)
            .AddEndpointFilter(new ApiAuditFilter(AuditTypes.AdminChange));

        // Администратор видит все подписки, бот-notifier — только созданные им самим.
        hooks.MapGet("/", async (ClaimsPrincipal me, WebhookService s, IAuthorizationService auth, CancellationToken ct) =>
        {
            var all = await s.ListSubscriptionsAsync(ct);
            return (await auth.AuthorizeAsync(me, AdminPolicies.ApiManage)).Succeeded
                ? all
                : all.Where(x => x.CreatedBy == Caller(me)).ToList();
        });
        hooks.MapPost("/", async (ClaimsPrincipal me, SubscriptionInput input, WebhookService s, CancellationToken ct) =>
        {
            var created = await s.CreateSubscriptionAsync(input, Caller(me), ct);
            return Results.Created($"/api/admin/webhooks/{created.Id}", created);
        });
        hooks.MapPut("/{id:guid}", async (ClaimsPrincipal me, Guid id, SubscriptionInput input, WebhookService s,
            IAuthorizationService auth, CancellationToken ct) =>
        {
            await EnsureOwnerAsync(me, id, s, auth, ct);
            return await s.UpdateSubscriptionAsync(id, input, ct);
        });
        hooks.MapDelete("/{id:guid}", async (ClaimsPrincipal me, Guid id, WebhookService s, IAuthorizationService auth,
            CancellationToken ct) =>
        {
            await EnsureOwnerAsync(me, id, s, auth, ct);
            await s.DeleteSubscriptionAsync(id, ct);
            return Results.NoContent();
        });
        hooks.MapGet("/{id:guid}/deliveries", async (ClaimsPrincipal me, Guid id, WebhookService s, IAuthorizationService auth,
            CancellationToken ct) =>
        {
            await EnsureOwnerAsync(me, id, s, auth, ct);
            return await s.ListDeliveriesAsync(id, 100, ct);
        });
        hooks.MapPost("/test", async (ClaimsPrincipal me, WebhookService s, CancellationToken ct) =>
        {
            await s.PublishAsync(WebhookEvents.Test, $"🔔 Тестовое событие TSL Auth от {Caller(me)}", new { by = Caller(me) }, ct);
            return Results.Accepted();
        });
    }

    // Генератор SSE-потока: опрашивает БД раз в секунду, пока клиент не отключится.
    // DbContext не держится открытым на всё время соединения — на каждую итерацию создаётся свой scope,
    // иначе долгоживущий поток удерживал бы соединение с БД и копил отслеживаемые сущности.
    private static async IAsyncEnumerable<SseItem<EventDto>> StreamAsync(long? after, IReadOnlyCollection<string>? types,
        IServiceScopeFactory scopes, [EnumeratorCancellation] CancellationToken ct)
    {
        // Без курсора стартуем с последнего события: новый подписчик не получает всю историю.
        long cursor;
        using (var scope = scopes.CreateScope())
            cursor = after ?? await scope.ServiceProvider.GetRequiredService<WebhookService>().LatestEventIdAsync(ct);

        var idle = 0;
        while (!ct.IsCancellationRequested)
        {
            List<EventDto> batch;
            using (var scope = scopes.CreateScope())
                batch = await scope.ServiceProvider.GetRequiredService<WebhookService>().ListEventsAsync(cursor, 100, types, ct);

            // EventId каждого сообщения — Id события: клиент вернёт его в Last-Event-ID при переподключении.
            foreach (var e in batch)
            {
                cursor = e.Id;
                yield return new SseItem<EventDto>(e, e.Event) { EventId = e.Id.ToString(), ReconnectionInterval = TimeSpan.FromSeconds(3) };
            }

            if (batch.Count == 0 && ++idle % 15 == 0)
            {
                // Пульс раз в ~15 с: держит соединение через прокси и позволяет боту заметить обрыв.
                // Data — пустой объект: default(JsonElement) не сериализуется и обрывал поток на первом же пульсе.
                yield return new SseItem<EventDto>(new EventDto(cursor, "ping", DateTime.UtcNow, "", EmptyData), "ping");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(1), ct); }
            catch (OperationCanceledException) { yield break; }
        }
    }

    private static readonly JsonElement EmptyData = JsonDocument.Parse("{}").RootElement.Clone();

    private static IReadOnlyCollection<string>? ParseTypes(string? types) =>
        string.IsNullOrWhiteSpace(types) ? null : types.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string Caller(ClaimsPrincipal me) => AdminApi.Caller(me);

    // Бот (роль notifier) видит и меняет только свои подписки; администратор — все.
    private static async Task EnsureOwnerAsync(ClaimsPrincipal me, Guid id, WebhookService s, IAuthorizationService auth,
        CancellationToken ct)
    {
        var sub = (await s.ListSubscriptionsAsync(ct)).FirstOrDefault(x => x.Id == id) ?? throw AdminException.NotFound("Подписка");
        if (sub.CreatedBy != Caller(me) && !(await auth.AuthorizeAsync(me, AdminPolicies.ApiManage)).Succeeded)
            throw AdminException.NotFound("Подписка");
    }

    private static async ValueTask<object?> HandleErrors(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try { return await next(context); }
        catch (AdminException ex) { return Results.Problem(detail: ex.Message, statusCode: ex.StatusCode); }
    }
}
