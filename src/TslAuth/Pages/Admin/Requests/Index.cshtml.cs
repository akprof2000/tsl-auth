using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Requests;

/// <summary>
/// Заявки пользователей на роли: список с фильтром по статусу, одобрение (роль назначается) и отклонение.
/// Просмотр — политика UiView, решения — UiManage. Использует AccessRequestService и UserManager (имя решившего для аудита).
/// </summary>
public sealed class IndexModel(AccessRequestService requests, UserManager<AppUser> users) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public string Status { get; set; } = "pending";

    public List<AccessRequestDto> Items { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken ct)
    {
        // Неизвестное значение статуса (например, "all") — показываем заявки во всех статусах.
        AccessRequestStatus? status = Enum.TryParse<AccessRequestStatus>(Status, true, out var s) ? s : null;
        Items = await requests.ListAsync(status, ct: ct);
    }

    public Task<IActionResult> OnPostApproveAsync(Guid requestId, string? comment, CancellationToken ct) =>
        DecideAsync(requestId, true, comment, ct);

    public Task<IActionResult> OnPostRejectAsync(Guid requestId, string? comment, CancellationToken ct) =>
        DecideAsync(requestId, false, comment, ct);

    /// <summary>Общая логика одобрения/отклонения; решивший фиксируется как "user:имя".</summary>
    private async Task<IActionResult> DecideAsync(Guid id, bool approve, string? comment, CancellationToken ct)
    {
        if (!await TryAsync(() => requests.DecideAsync(id, approve, $"user:{users.GetUserName(User)}", comment, ct: ct)))
        {
            await OnGetAsync(ct);
            return Page();
        }

        Flash(approve ? "Заявка одобрена, роль назначена." : "Заявка отклонена.");
        return RedirectToPage(new { status = Status });
    }
}
