using Microsoft.AspNetCore.Mvc;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Sessions;

/// <summary>
/// Активные сессии (авторизации OpenIddict) с фильтром по приложению и отзывом.
/// Просмотр — политика UiView, отзыв — UiManage (проверяется в AdminPageModel). Использует SessionService.
/// </summary>
public sealed class IndexModel(SessionService sessions) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public string? ClientId { get; set; }

    public List<SessionDto> Items { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken ct) => Items = await sessions.ListAsync(null, ClientId, 500, ct);

    /// <summary>Отзывает сессию; при ошибке заново показывает список с сообщением.</summary>
    public async Task<IActionResult> OnPostRevokeAsync(Guid sessionId, CancellationToken ct)
    {
        if (!await TryAsync(() => sessions.RevokeAsync(sessionId, ct)))
        {
            await OnGetAsync(ct);
            return Page();
        }

        Flash("Сессия отозвана: refresh-токен больше не действует, выданный access-токен истечёт по сроку.");
        return RedirectToPage(new { clientId = ClientId });
    }
}
