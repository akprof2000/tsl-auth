using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Персональные токены доступа текущего пользователя (как в GitHub).
/// Требует аутентификации (конвенция AuthorizePage); пользователь видит и отзывает только свои токены.
/// Использует PatService, SettingsService (политика PAT: срок жизни) и UserManager.
/// </summary>
public sealed class TokensModel(PatService pats, SettingsService settings, UserManager<AppUser> users) : PageModel
{
    [BindProperty] public string Name { get; set; } = "";
    [BindProperty] public List<string> Audiences { get; set; } = [];
    [BindProperty] public int? ExpiresInDays { get; set; }

    public List<PatDto> Items { get; private set; } = [];
    public List<string> Available { get; private set; } = [];
    public PatPolicy Policy { get; private set; } = new();
    public string? CreatedSecret { get; private set; }

    private Guid UserId => Guid.Parse(users.GetUserId(User)!);

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    /// <summary>Выпускает новый токен и показывает его секрет.</summary>
    public async Task<IActionResult> OnPostCreateAsync(CancellationToken ct)
    {
        try
        {
            var (_, secret) = await pats.CreateAsync(UserId, new PatInput(Name, Audiences, ExpiresInDays), ct);
            // Секрет показывается только один раз в ответе на этот POST (без редиректа): в БД хранится лишь хэш,
            // повторно получить значение невозможно.
            CreatedSecret = secret;
            Name = "";
        }
        catch (AdminException ex)
        {
            ModelState.AddModelError("", ex.Message);
        }
        await LoadAsync(ct);
        return Page();
    }

    /// <summary>Отзывает токен; UserId передаётся в сервис, чтобы нельзя было отозвать чужой токен.</summary>
    public async Task<IActionResult> OnPostRevokeAsync(Guid tokenId, CancellationToken ct)
    {
        await pats.RevokeAsync(tokenId, UserId, ct);
        TempData["Flash"] = "tokens.revoked";
        return RedirectToPage();
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        Policy = (await settings.GetAsync(ct)).Pats;
        Items = await pats.ListAsync(UserId, ct);
        Available = await pats.AvailableAudiencesAsync(UserId, ct);
        // Срок по умолчанию — 90 дней, но не больше максимума из политики.
        ExpiresInDays ??= Math.Min(90, Policy.MaxLifetimeDays);
    }
}
