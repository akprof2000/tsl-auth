using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;

namespace TslAuth.Pages.Account;

/// <summary>
/// Смена пароля (обязательна после входа с временным паролем).
/// Требует аутентификации (конвенция AuthorizePage). Сюда же перенаправляют Login при истёкшем/временном пароле
/// и MustChangePasswordFilter при попытке открыть админку. Использует UserManager, SignInManager и AuditService.
/// </summary>
public sealed class ChangePasswordModel(UserManager<AppUser> users, SignInManager<AppUser> signIn, Services.AuditService audit) : PageModel
{
    [BindProperty, Required(ErrorMessage = "validation.required"), DataType(DataType.Password)]
    public string Current { get; set; } = "";

    [BindProperty, Required(ErrorMessage = "validation.required"), DataType(DataType.Password)]
    public string Password { get; set; } = "";

    [BindProperty, DataType(DataType.Password), Compare(nameof(Password), ErrorMessage = "password.mismatch")]
    public string Confirm { get; set; } = "";

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public bool Forced { get; private set; }

    public async Task OnGetAsync() => Forced = (await users.GetUserAsync(User))?.MustChangePassword == true;

    /// <summary>Проверяет текущий пароль, устанавливает новый и снимает флаг обязательной смены.</summary>
    public async Task<IActionResult> OnPostAsync()
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        Forced = user.MustChangePassword;
        if (!ModelState.IsValid) return Page();

        if (Current == Password)
        {
            ModelState.AddModelError(nameof(Password), "change.sameAsCurrent");
            return Page();
        }

        var result = await users.ChangePasswordAsync(user, Current, Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Code == "PasswordMismatch" ? "change.wrongCurrent" : error.Description);
            return Page();
        }

        var wasTemporary = user.MustChangePassword;
        user.MustChangePassword = false;
        await users.UpdateAsync(user);
        // Смена пароля меняет security stamp — перевыпускаем cookie, иначе текущая сессия станет недействительной.
        await signIn.RefreshSignInAsync(user);
        await audit.WriteAsync(Services.AuditTypes.PasswordChanged, true, Data.AuditSeverity.Info, null, user.Id, new { wasTemporary });

        TempData["Flash"] = "change.done";
        // Возврат только на локальный адрес (защита от open redirect).
        return LocalRedirect(Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : "/Admin");
    }
}
