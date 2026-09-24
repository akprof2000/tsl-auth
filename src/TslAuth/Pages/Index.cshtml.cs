using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Pages.Account;

namespace TslAuth.Pages;

/// <summary>
/// Корень сайта. Редирект выполняется в обработчике, а не из тела представления: так он происходит до начала
/// рендеринга и не зависит от буферизации ответа. Вошедший — «домой» по правам, аноним — на страницу входа.
/// </summary>
public sealed class IndexModel : PageModel
{
    public async Task<IActionResult> OnGetAsync() =>
        User.Identity?.IsAuthenticated == true
            ? LocalRedirect(await UserPageModel.HomeAsync(HttpContext, User))
            : RedirectToPage("/Account/Login");
}
