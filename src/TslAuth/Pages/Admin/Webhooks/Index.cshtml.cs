using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Webhooks;

/// <summary>
/// Подписки на события (вебхуки): список, создание/редактирование (Id в query — выбранная подписка),
/// журнал доставок, лента последних событий, удаление и отправка тестового события.
/// Просмотр — политика UiView, изменения — UiManage. Использует WebhookService и UserManager (автор для аудита).
/// </summary>
public sealed class IndexModel(WebhookService webhooks, UserManager<AppUser> users) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public Guid? Id { get; set; }

    [BindProperty] public string Name { get; set; } = "";
    [BindProperty] public string HookUrl { get; set; } = "";
    // Секрет подписки не возвращается в форму при редактировании (пустое значение — не менять, решает WebhookService).
    [BindProperty] public string? Secret { get; set; }
    [BindProperty] public List<string> Events { get; set; } = ["*"];
    [BindProperty] public bool IsEnabled { get; set; } = true;

    public List<SubscriptionDto> Items { get; private set; } = [];
    public List<DeliveryDto> Deliveries { get; private set; } = [];
    public List<EventDto> RecentEvents { get; private set; } = [];

    /// <summary>Загружает подписки, 20 последних событий и, если выбрана подписка, её данные и журнал доставок.</summary>
    public async Task OnGetAsync(CancellationToken ct)
    {
        await LoadListsAsync(ct);
        if (Id is { } id && Items.FirstOrDefault(s => s.Id == id) is { } current)
            (Name, HookUrl, Events, IsEnabled) = (current.Name, current.Url, current.Events, current.IsEnabled);
    }

    /// <summary>Создаёт новую подписку или обновляет выбранную (по Id).</summary>
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        var input = new SubscriptionInput(Name, HookUrl, Events, Secret, IsEnabled);
        SubscriptionDto? saved = null;
        if (!await TryAsync(async () => saved = Id is { } id
                ? await webhooks.UpdateSubscriptionAsync(id, input, ct)
                : await webhooks.CreateSubscriptionAsync(input, $"user:{users.GetUserId(User)}", ct)))
        {
            // Только списки: введённые в форму значения не перезатираются сохранёнными.
            await LoadListsAsync(ct);
            return Page();
        }

        Flash("Подписка сохранена.");
        return RedirectToPage(new { id = saved!.Id });
    }

    /// <summary>Удаляет выбранную подписку; при ошибке остаёмся на странице с сообщением.</summary>
    public async Task<IActionResult> OnPostDeleteAsync(CancellationToken ct)
    {
        if (Id is null || !await TryAsync(() => webhooks.DeleteSubscriptionAsync(Id.Value, ct)))
        {
            if (Id is null) ModelState.AddModelError("", "Подписка не выбрана.");
            await OnGetAsync(ct);
            return Page();
        }

        Flash("Подписка удалена.");
        return RedirectToPage(new { id = (Guid?)null });
    }

    /// <summary>Публикует тестовое событие — проверка доставки всем подходящим подписчикам.</summary>
    public async Task<IActionResult> OnPostTestAsync(CancellationToken ct)
    {
        await webhooks.PublishAsync(WebhookEvents.Test, $"🔔 Тестовое событие TSL Auth ({users.GetUserName(User)})",
            new { by = users.GetUserName(User) }, ct);
        Flash("Тестовое событие опубликовано — оно появится в ленте и будет доставлено подписчикам.");
        return RedirectToPage(new { id = Id });
    }

    /// <summary>Подписки, лента последних событий и журнал доставок выбранной подписки.</summary>
    private async Task LoadListsAsync(CancellationToken ct)
    {
        Items = await webhooks.ListSubscriptionsAsync(ct);
        // Лента событий читается «после id», поэтому берём окно из 20 последних и разворачиваем (новые сверху).
        var latest = await webhooks.LatestEventIdAsync(ct);
        RecentEvents = (await webhooks.ListEventsAsync(Math.Max(0, latest - 20), 20, ct: ct)).AsEnumerable().Reverse().ToList();
        if (Id is { } id && Items.Any(s => s.Id == id))
            Deliveries = await webhooks.ListDeliveriesAsync(id, 30, ct);
    }
}
