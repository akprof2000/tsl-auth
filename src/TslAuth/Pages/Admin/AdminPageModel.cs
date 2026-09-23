using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Infrastructure;
using TslAuth.Services;

namespace TslAuth.Pages.Admin;

/// <summary>
/// Базовая модель страниц админки: просмотр доступен ролям administrator и auditor,
/// любые изменения (POST) — только при разрешении "manage".
/// Доступ к папке /Admin на чтение задаётся конвенцией AuthorizeFolder с политикой <see cref="AdminPolicies.UiView"/>;
/// там же подключены MustChangePasswordFilter (временный пароль → смена) и AdminPageAuditFilter (аудит действий).
/// </summary>
public abstract class AdminPageModel : PageModel
{
    /// <summary>Есть ли у текущего пользователя право изменять данные (используется в представлениях, чтобы скрыть кнопки).</summary>
    public bool CanManage { get; private set; }

    /// <summary>
    /// Централизованная проверка права на изменения: любой POST без политики UiManage отклоняется
    /// ещё до вызова обработчика, поэтому в самих OnPost* проверка не нужна.
    /// </summary>
    public override async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var authorization = HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
        CanManage = (await authorization.AuthorizeAsync(User, AdminPolicies.UiManage)).Succeeded;

        if (HttpMethods.IsPost(Request.Method) && !CanManage)
        {
            context.Result = Forbid();
            return;
        }

        await next();
    }

    /// <summary>Однократное сообщение, которое покажет макет после редиректа (Post/Redirect/Get).</summary>
    protected void Flash(string message) => TempData["Flash"] = message;

    /// <summary>Выполняет действие, превращая AdminException в ошибку формы.</summary>
    protected async Task<bool> TryAsync(Func<Task> action)
    {
        try
        {
            await action();
            return true;
        }
        catch (AdminException ex)
        {
            ModelState.AddModelError("", ex.Message);
            return false;
        }
    }

    /// <summary>Разбивает текст из textarea на элементы (разделители — перевод строки, запятая, пробел).</summary>
    protected static List<string> Lines(string? text) =>
        (text ?? "").Split(['\n', '\r', ',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
}
