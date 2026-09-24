using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Infrastructure;
using TslAuth.Localization;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Базовая модель пользовательских страниц /Account: всё, что видит пользователь (ошибки форм и flash-сообщения),
/// — на его языке. Ошибки в ModelState хранятся ключами пакета (их переводит _Errors), готовый текст выводится как есть.
/// </summary>
public abstract class UserPageModel : PageModel
{
    /// <summary>Тексты на языке текущего запроса.</summary>
    protected Texts L => HttpContext.RequestServices.GetRequiredService<Texts>();

    /// <summary>Перед любым обработчиком переводит ошибки биндинга в ключи пакета (см. <see cref="LocalizeBindingErrors"/>).</summary>
    public override async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        LocalizeBindingErrors();
        await next();
    }

    /// <summary>
    /// Однократное сообщение после редиректа (Post/Redirect/Get). В TempData["Flash"] во всём приложении хранится
    /// готовый текст (админка пишет русский, здесь — перевод ключа), поэтому макет выводит его без перевода.
    /// </summary>
    protected void Flash(string key) => TempData["Flash"] = L[key];

    /// <summary>
    /// Ошибка сервиса в форму: ключ пакета, если сервис его задал (<see cref="AdminException.Key"/>),
    /// иначе русский текст сообщения — лучше, чем ничего, пока для ошибки нет ключа.
    /// </summary>
    protected void AddError(AdminException ex) => ModelState.AddModelError("", ex.Key ?? ex.Message);

    /// <summary>
    /// Ошибки Identity (смена/сброс пароля): нарушения политики паролей уже переведены валидатором (коды Password*),
    /// остальные описания Identity — английские, вместо них общий текст.
    /// </summary>
    protected void AddIdentityErrors(IEnumerable<Microsoft.AspNetCore.Identity.IdentityError> errors, Func<string, string?>? map = null)
    {
        foreach (var error in errors)
            ModelState.AddModelError("", map?.Invoke(error.Code)
                ?? (error.Code.StartsWith("Password", StringComparison.Ordinal) ? error.Description : "error.generic"));
    }

    /// <summary>
    /// Адрес «домой» после входа или смены пароля без returnUrl: администраторам и аудиторам — админка,
    /// остальным — личный кабинет (иначе обычный пользователь попадал на /Admin и получал «Доступ запрещён»).
    /// Права проверяются той же политикой, что и доступ к папке /Admin.
    /// </summary>
    public static async Task<string> HomeAsync(HttpContext http, ClaimsPrincipal user) =>
        (await http.RequestServices.GetRequiredService<IAuthorizationService>().AuthorizeAsync(user, AdminPolicies.UiView)).Succeeded
            ? "/Admin" : "/Account";

    // Ошибки биндинга («The value 'x' is not valid…») и неявного [Required] у ненулевых строк MVC формирует
    // по-английски. Ключи пакета (сообщения атрибутов валидации) оставляем, остальное заменяем ключами.
    private void LocalizeBindingErrors()
    {
        if (ModelState.IsValid) return;
        var localization = HttpContext.RequestServices.GetRequiredService<LocalizationService>();
        foreach (var (_, entry) in ModelState)
        {
            if (entry.Errors.Count == 0) continue;
            var messages = entry.Errors.Select(e => e.ErrorMessage).ToList();
            entry.Errors.Clear();
            foreach (var message in messages)
                entry.Errors.Add(localization.Get(LocalizationService.DefaultCulture, message) is not null ? message
                    : string.IsNullOrEmpty(entry.AttemptedValue) ? "validation.required" : "validation.invalidValue");
        }
    }
}
