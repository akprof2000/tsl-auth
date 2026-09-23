using TslAuth.Services;

namespace TslAuth.Pages.Admin.Apps;

/// <summary>
/// Список зарегистрированных приложений (OIDC-клиентов). Доступ — политика UiView.
/// Использует ApplicationService.
/// </summary>
public sealed class IndexModel(ApplicationService apps) : AdminPageModel
{
    public List<ApplicationDto> Items { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken ct) => Items = await apps.ListAsync(ct);
}
