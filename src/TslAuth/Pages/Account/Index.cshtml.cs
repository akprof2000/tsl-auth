using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;

namespace TslAuth.Pages.Account;

/// <summary>
/// Личный кабинет: ссылки на токены, мессенджер, запрос доступа, смену пароля и выход.
/// Сюда ведут вход и смена пароля без returnUrl для пользователей без прав администрирования
/// (см. <see cref="UserPageModel.HomeAsync"/>). Требует аутентификации. Использует UserManager.
/// </summary>
[Authorize]
public sealed class IndexModel(UserManager<AppUser> users) : UserPageModel
{
    public string UserName { get; private set; } = "";
    public bool IsAdmin { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await users.GetUserAsync(User);
        if (user is null) return Challenge();
        // Временный/истёкший пароль — сначала смена, как и для админки.
        if (user.MustChangePassword) return RedirectToPage("/Account/ChangePassword", new { returnUrl = "/Account" });
        UserName = user.UserName ?? "";
        IsAdmin = await HomeAsync(HttpContext, User) == "/Admin";
        return Page();
    }
}
