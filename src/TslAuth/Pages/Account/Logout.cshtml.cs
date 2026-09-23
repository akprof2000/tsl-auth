using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;

namespace TslAuth.Pages.Account;

/// <summary>
/// Выход из cookie-сессии Identity. Доступна анонимно. Использует SignInManager.
/// </summary>
public sealed class LogoutModel(SignInManager<AppUser> signIn) : PageModel
{
    // Выход только через POST (с antiforgery-токеном), чтобы сторонний сайт не мог разлогинить пользователя ссылкой/картинкой.
    public IActionResult OnGet() => RedirectToPage("/Account/Login");

    /// <summary>Завершает сессию и возвращает на страницу входа.</summary>
    public async Task<IActionResult> OnPostAsync()
    {
        await signIn.SignOutAsync();
        return RedirectToPage("/Account/Login");
    }
}
