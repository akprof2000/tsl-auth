using Microsoft.AspNetCore.Mvc;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Users;

/// <summary>
/// Список пользователей с поиском и постраничным выводом (P — номер страницы с нуля, по 50 записей).
/// Доступ — политика UiView. Использует UserService.
/// </summary>
public sealed class IndexModel(UserService users) : AdminPageModel
{
    private const int PageSize = 50;

    [BindProperty(SupportsGet = true)] public string? Search { get; set; }
    [BindProperty(SupportsGet = true)] public int P { get; set; }

    public PagedResult<UserDto> Result { get; private set; } = new([], 0);
    public int Pages => Math.Max(1, (Result.Total + PageSize - 1) / PageSize);

    public async Task OnGetAsync(CancellationToken ct) =>
        Result = await users.ListAsync(Search, Math.Max(0, P) * PageSize, PageSize, ct);
}
