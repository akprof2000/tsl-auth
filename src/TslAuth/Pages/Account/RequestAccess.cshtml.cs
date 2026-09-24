using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Запрос дополнительных ролей уже зарегистрированным пользователем.
/// Требует аутентификации (конвенция AuthorizePage). Приложение берётся из ClientId или из returnUrl.
/// Использует BrandingService, AccessRequestService (заявки), AccessService (уже выданные роли) и UserManager.
/// </summary>
public sealed class RequestAccessModel(
    BrandingService branding,
    AccessRequestService requests,
    AccessService access,
    UserManager<AppUser> users) : UserPageModel
{
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
    [BindProperty(SupportsGet = true)] public string? ClientId { get; set; }
    [BindProperty] public List<string> Roles { get; set; } = [];
    [BindProperty] public string? Comment { get; set; }

    public string? AppClientId { get; private set; }
    public List<RequestableRole> Requestable { get; private set; } = [];
    public HashSet<string> Assigned { get; private set; } = [];  // ключи "client_id|роль"
    public List<AccessRequestDto> MyRequests { get; private set; } = [];
    public string? Message { get; private set; }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    /// <summary>Создаёт заявки на выбранные роли от имени текущего пользователя.</summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        if (AppClientId is null) return Page();
        try
        {
            // Заявка всегда создаётся от имени текущего пользователя (id из cookie), а не из данных формы.
            var created = await requests.CreateAsync(Guid.Parse(users.GetUserId(User)!), AppClientId,
                RegisterModel.ParseRoles(Roles), Comment, ct);
            // Пустой результат — все выбранные роли уже выданы или уже запрошены.
            Message = created.Count > 0 ? "request.sent" : "request.nothing";
            // Перезагрузка, чтобы в списке «Мои заявки» появились только что созданные.
            await LoadAsync(ct);
        }
        catch (AdminException ex)
        {
            AddError(ex);
        }
        return Page();
    }

    /// <summary>Загружает запрашиваемые роли приложения, уже выданные пользователю роли и его заявки.</summary>
    private async Task LoadAsync(CancellationToken ct)
    {
        ViewData["ReturnUrl"] = ReturnUrl;
        AppClientId = ClientId ?? (await branding.ResolveFromReturnUrlAsync(ReturnUrl, ct))?.ClientId;
        var userId = users.GetUserId(User)!;
        if (AppClientId is not null)
        {
            Requestable = await requests.ListRequestableRolesAsync(AppClientId, ct);
            Assigned = (await access.GetAssignmentsAsync(SubjectType.User, userId, ct))
                .Select(r => $"{r.ClientId}|{r.Role}").ToHashSet();
        }
        MyRequests = await requests.ListAsync(null, null, Guid.Parse(userId), ct);
    }
}
