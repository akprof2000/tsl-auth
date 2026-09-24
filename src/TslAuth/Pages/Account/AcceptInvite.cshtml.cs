using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Активация учётной записи по приглашению: пользователь сам задаёт пароль.
/// Доступна анонимно: доступ подтверждается invite-токеном из ссылки (Uid + Token).
/// Использует AccountLinks (проверка токена), UserService (активация), UserManager и AuditService.
/// </summary>
public sealed class AcceptInviteModel(UserService userService, UserManager<AppUser> users, AccountLinks links, AuditService audit) : UserPageModel
{
    [BindProperty(SupportsGet = true)] public Guid Uid { get; set; }
    [BindProperty(SupportsGet = true)] public string Token { get; set; } = "";

    [BindProperty, Required(ErrorMessage = "validation.required"), DataType(DataType.Password)]
    public string Password { get; set; } = "";

    [BindProperty, DataType(DataType.Password), Compare(nameof(Password), ErrorMessage = "password.mismatch")]
    public string Confirm { get; set; } = "";

    public string? UserName { get; private set; }
    public bool Valid { get; private set; }
    public bool Done { get; private set; }

    public async Task OnGetAsync() => await LoadAsync();

    /// <summary>Повторно проверяет приглашение и задаёт пароль, активируя учётную запись.</summary>
    public async Task<IActionResult> OnPostAsync()
    {
        // Токен проверяется заново и на POST: форму можно отправить в обход GET или после истечения ссылки.
        if (!await LoadAsync()) return Page();
        if (!ModelState.IsValid) return Page();

        try
        {
            Done = await userService.AcceptInviteAsync(Uid, Token, Password);
            await audit.WriteAsync(AuditTypes.InviteAccepted, Done, Done ? Data.AuditSeverity.Info : Data.AuditSeverity.Warning, null, Uid);
            // Не удалось (например, токен уже использован параллельным запросом) — показываем «приглашение недействительно».
            if (!Done) Valid = false;
        }
        catch (AdminException ex)
        {
            AddError(ex);
        }

        return Page();
    }

    /// <summary>Находит пользователя и проверяет invite-токен; заполняет Valid и UserName для представления.</summary>
    private async Task<bool> LoadAsync()
    {
        var user = await users.FindByIdAsync(Uid.ToString());
        Valid = user is not null && await links.ValidateInviteAsync(user, Token);
        UserName = user?.UserName;
        return Valid;
    }
}
