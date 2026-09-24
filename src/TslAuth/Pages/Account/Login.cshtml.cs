using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Страница входа по логину и паролю (cookie-сессия Identity). Доступна анонимно, с rate limiting
/// (политика LoginPolicy для папки /Account). Сюда же OIDC-авторизация перенаправляет пользователя
/// с returnUrl = /connect/authorize?...; по нему определяется приложение для брендинга и самостоятельной регистрации.
/// Использует SignInManager (проверка пароля и lockout), UserService, BrandingService, ApplicationService,
/// SettingsService (политика срока действия пароля), AuditService и WebhookService.
/// </summary>
public sealed class LoginModel(
    SignInManager<AppUser> signIn,
    UserService userService,
    BrandingService branding,
    ApplicationService apps,
    WebhookService webhooks,
    AuditService audit,
    SettingsService settings) : UserPageModel
{
    public bool RegistrationEnabled { get; private set; }
    private string? _clientId;

    /// <summary>
    /// Выполняется перед любым обработчиком (GET и POST): по ReturnUrl определяет клиентское приложение,
    /// чтобы показать его брендинг, ссылку на регистрацию и указать ClientId в аудите.
    /// </summary>
    public override async Task OnPageHandlerExecutionAsync(Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutingContext context,
        Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutionDelegate next)
    {
        var app = await branding.ResolveFromReturnUrlAsync(ReturnUrl);
        _clientId = app?.ClientId;
        RegistrationEnabled = app is not null && await apps.IsSelfRegistrationEnabledAsync(app.ClientId);
        await base.OnPageHandlerExecutionAsync(context, next);
    }

    [BindProperty, Required(ErrorMessage = "validation.required")]
    public string Login { get; set; } = "";

    [BindProperty, Required(ErrorMessage = "validation.required"), DataType(DataType.Password)]
    public string Password { get; set; } = "";

    [BindProperty]
    public bool RememberMe { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? Error { get; private set; }

    public void OnGet() { }

    /// <summary>Проверяет учётные данные, пишет аудит и выполняет вход либо отправляет на обязательную смену пароля.</summary>
    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid) return Page();
        try
        {
            return await SignInAsync();
        }
        catch (AdminException ex)
        {
            // Ошибка сервиса (например, учётная запись отключена) — на языке пользователя, если у неё есть ключ.
            AddError(ex);
            return Page();
        }
    }

    private async Task<IActionResult> SignInAsync()
    {

        var user = await userService.FindByLoginAsync(Login.Trim());
        // Для неизвестного и отключённого пользователя — одна и та же ошибка, что и для неверного пароля:
        // по ответу нельзя узнать, существует ли логин (причина фиксируется только в аудите).
        if (user is not { IsActive: true })
        {
            await audit.WriteAsync(AuditTypes.LoginFailed, false, AuditSeverity.Info, _clientId, user?.Id,
                new { login = Login, reason = user is null ? "unknown_user" : "inactive", channel = "web" }, "anonymous");
            Error = "login.error.invalid";
            return Page();
        }

        // lockoutOnFailure: неудачные попытки считаются, после порога учётная запись временно блокируется (защита от перебора).
        var result = await signIn.PasswordSignInAsync(user, Password, RememberMe, lockoutOnFailure: true);
        if (result.IsLockedOut)
        {
            await audit.WriteAsync(AuditTypes.LockedOut, false, AuditSeverity.Warning, _clientId, user.Id,
                new { channel = "web" }, $"user:{user.Id}", user.UserName);
            await webhooks.PublishAsync(WebhookEvents.UserLockedOut,
                $"🔒 Учётная запись {user.UserName} заблокирована после неудачных попыток входа (IP {HttpContext.Connection.RemoteIpAddress}).",
                new { userId = user.Id, userName = user.UserName, ip = HttpContext.Connection.RemoteIpAddress?.ToString() });
            Error = "login.error.locked";
            return Page();
        }
        if (!result.Succeeded)
        {
            await audit.WriteAsync(AuditTypes.LoginFailed, false, AuditSeverity.Info, _clientId, user.Id,
                new { reason = "bad_password", failedCount = user.AccessFailedCount, channel = "web" }, $"user:{user.Id}", user.UserName);
            Error = "login.error.invalid";
            return Page();
        }

        // Истёк срок действия пароля по политике — требуем смену так же, как для временного.
        // Отслеживаемую сущность не меняем: запись идёт точечным UPDATE (без конфликтов при параллельных входах).
        var mustChange = user.MustChangePassword || Security.AppUserManager.IsPasswordExpired(user, (await settings.GetAsync()).Passwords);
        await userService.RecordLoginAsync(user.Id, mustChange);
        await audit.WriteAsync(AuditTypes.LoginSucceeded, true, AuditSeverity.Info, _clientId, user.Id,
            new { channel = "web", mustChangePassword = mustChange }, $"user:{user.Id}", user.UserName);

        // Только локальный returnUrl — защита от open redirect на чужой сайт. Без него — «домой» по правам:
        // User этого запроса ещё анонимный, поэтому права проверяются по principal только что вошедшего пользователя.
        // При обязательной смене пароля returnUrl передаётся дальше, чтобы после смены продолжить исходный сценарий (например, OIDC).
        var returnUrl = Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : await HomeAsync(HttpContext, await signIn.CreateUserPrincipalAsync(user));
        return mustChange
            ? RedirectToPage("/Account/ChangePassword", new { returnUrl })
            : LocalRedirect(returnUrl);
    }
}
