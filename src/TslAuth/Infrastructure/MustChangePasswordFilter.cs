using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using TslAuth.Data;

namespace TslAuth.Infrastructure;

/// <summary>
/// Пока временный пароль не сменён, админка недоступна — перенаправляем на смену пароля.
/// Навешивается на папку /Admin в ServiceSetup; флаг читается из БД на каждый запрос (не из cookie),
/// поэтому действует сразу после сброса пароля администратором.
/// </summary>
public sealed class MustChangePasswordFilter : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var http = context.HttpContext;
        if (http.User.Identity?.IsAuthenticated == true)
        {
            var users = http.RequestServices.GetRequiredService<UserManager<AppUser>>();
            if (await users.GetUserAsync(http.User) is { MustChangePassword: true })
            {
                context.Result = new RedirectToPageResult("/Account/ChangePassword",
                    new { returnUrl = http.Request.PathBase + http.Request.Path + http.Request.QueryString });
                return;
            }
        }

        await next();
    }
}
