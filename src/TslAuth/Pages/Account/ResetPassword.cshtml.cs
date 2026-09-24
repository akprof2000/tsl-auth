using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Установка нового пароля по ссылке из письма (одноразовая, 2 часа).
/// Доступна анонимно: право на сброс подтверждается токеном из ссылки (Uid + Token в query).
/// Использует UserService (проверка токена и смена пароля) и AuditService.
/// </summary>
public sealed class ResetPasswordModel(UserService users, AuditService audit) : UserPageModel
{
    [BindProperty(SupportsGet = true)] public Guid Uid { get; set; }
    [BindProperty(SupportsGet = true)] public string Token { get; set; } = "";

    [BindProperty, Required(ErrorMessage = "validation.required"), DataType(DataType.Password)]
    public string Password { get; set; } = "";

    [BindProperty, DataType(DataType.Password), Compare(nameof(Password), ErrorMessage = "password.mismatch")]
    public string Confirm { get; set; } = "";

    public bool Done { get; private set; }

    public void OnGet() { }

    /// <summary>Проверяет токен и устанавливает новый пароль; результат (в т.ч. неудачный) пишется в аудит.</summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        if (!ModelState.IsValid) return Page();

        IdentityResult result;
        try
        {
            result = await users.CompletePasswordResetAsync(Uid, Token, Password, ct);
        }
        catch (AdminException ex)
        {
            AddError(ex);
            return Page();
        }
        await audit.WriteAsync(AuditTypes.PasswordReset, result.Succeeded,
            result.Succeeded ? Data.AuditSeverity.Info : Data.AuditSeverity.Warning, null, Uid,
            new { via = "email_link", errors = result.Errors.Select(e => e.Code) });
        if (!result.Succeeded)
        {
            // Невалидный/просроченный/использованный токен показываем понятным сообщением «ссылка недействительна»,
            // нарушения политики пароля — как есть (уже переведены), прочее — общим текстом.
            AddIdentityErrors(result.Errors, code => code == "InvalidToken" ? "reset.invalidLink" : null);
            return Page();
        }

        Done = true;
        return Page();
    }
}
