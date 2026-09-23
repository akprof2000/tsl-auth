using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Привязка мессенджера для сброса пароля через бота.
/// Требует аутентификации (конвенция AuthorizePage). Использует BotService (одноразовые коды привязки,
/// список и удаление привязок) и UserManager.
/// </summary>
public sealed class MessengerModel(BotService bot, UserManager<AppUser> users) : PageModel
{
    public List<LinkedIdentityDto> Items { get; private set; } = [];
    public string? Code { get; private set; }
    public DateTime? CodeExpiresAt { get; private set; }

    private Guid UserId => Guid.Parse(users.GetUserId(User)!);

    public async Task OnGetAsync(CancellationToken ct) => Items = await bot.ListAsync(UserId, ct);

    /// <summary>
    /// Генерирует короткоживущий код привязки: пользователь отправляет его боту, и бот связывает
    /// свой аккаунт мессенджера с этой учётной записью. Код показывается сразу, без редиректа.
    /// </summary>
    public async Task<IActionResult> OnPostCodeAsync(CancellationToken ct)
    {
        (Code, var expires) = await bot.CreateLinkCodeAsync(UserId, ct);
        CodeExpiresAt = expires;
        Items = await bot.ListAsync(UserId, ct);
        return Page();
    }

    /// <summary>Удаляет привязку мессенджера (только свою — сервис проверяет владельца).</summary>
    public async Task<IActionResult> OnPostRemoveAsync(Guid identityId, CancellationToken ct)
    {
        await bot.RemoveAsync(UserId, identityId, ct);
        TempData["Flash"] = "messenger.removed";
        return RedirectToPage();
    }
}
