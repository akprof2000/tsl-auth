using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Security;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Второй шаг входа (решение В-9 ЧТЗ): пароль уже проверен на /Account/Login, роли пользователя требуют второй
/// фактор. Пользователь определяется по временной cookie Identity (TwoFactorUserId), а не по полям формы.
/// Каналы: код на почту (кнопка «Отправить») и код в мессенджере (пользователь пишет боту /code).
/// Неверные коды считаются в общий счётчик неудачных попыток — после порога учётная запись блокируется.
/// Страница анонимная, с тем же rate limiting, что и /Account/Login.
/// </summary>
public sealed class LoginTwoFactorModel(
    SignInManager<AppUser> signIn,
    UserService userService,
    IEmailSender email,
    AuditService audit,
    SettingsService settings) : UserPageModel
{
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool RememberMe { get; set; }

    /// <summary>Выбранный канал: email-code или messenger-code (<see cref="TwoFactorProviders"/>).</summary>
    [BindProperty(SupportsGet = true)]
    public string? Provider { get; set; }

    [BindProperty, Required(ErrorMessage = "validation.required")]
    public string Code { get; set; } = "";

    /// <summary>Каналы, доступные пользователю (есть email / привязан мессенджер).</summary>
    public IList<string> Providers { get; private set; } = [];

    public string? Error { get; private set; }
    public string? Info { get; private set; }

    public async Task<IActionResult> OnGetAsync() =>
        await LoadAsync() is null ? RedirectToLogin() : Page();

    /// <summary>Отправляет код на email учётной записи. Для мессенджера отправка не нужна: код выдаёт бот по /code.</summary>
    public async Task<IActionResult> OnPostSendAsync(CancellationToken ct)
    {
        ModelState.Remove(nameof(Code));
        var user = await LoadAsync();
        if (user is null) return RedirectToLogin();
        Provider = TwoFactorProviders.Email;
        if (!Providers.Contains(TwoFactorProviders.Email)) return Page();

        try
        {
            var code = await signIn.UserManager.GenerateTwoFactorTokenAsync(user, TwoFactorProviders.Email);
            await email.SendAsync(user.Email!, L["login.2fa.emailSubject"],
                $"<p>{System.Net.WebUtility.HtmlEncode(L.Get("login.2fa.emailBody", code))}</p>", ct);
            await audit.WriteAsync(AuditTypes.TwoFactorCodeSent, true, AuditSeverity.Info, null, user.Id,
                new { channel = "email" }, $"user:{user.Id}", user.UserName);
            Info = L.Get("login.2fa.sentEmail", MaskEmail(user.Email!));
        }
        catch (AdminException ex)
        {
            // Почта не настроена или SMTP недоступен — показываем причину, код не отправлен.
            AddError(ex);
        }
        return Page();
    }

    /// <summary>
    /// Проверяет код и завершает вход: TwoFactorSignInAsync выпускает cookie с claim amr=mfa
    /// (его AuthorizationController передаёт в токены), затем — те же шаги, что после входа по паролю.
    /// </summary>
    public async Task<IActionResult> OnPostVerifyAsync()
    {
        var user = await LoadAsync();
        if (user is null) return RedirectToLogin();
        if (!ModelState.IsValid) return Page();
        if (Provider is null || !Providers.Contains(Provider))
        {
            Error = "login.2fa.error.invalid";
            return Page();
        }

        // rememberClient: false — «запомнить это устройство» не предусмотрено, код нужен при каждом входе.
        var result = await signIn.TwoFactorSignInAsync(Provider, Code.Replace(" ", "").Trim(), RememberMe, rememberClient: false);
        if (!result.Succeeded)
        {
            await audit.WriteAsync(result.IsLockedOut ? AuditTypes.LockedOut : AuditTypes.TwoFactorFailed, false,
                result.IsLockedOut ? AuditSeverity.Warning : AuditSeverity.Info, null, user.Id,
                new { channel = Provider, reason = result.IsLockedOut ? "locked_out" : "bad_code" }, $"user:{user.Id}", user.UserName);
            // Блокировку не раскрываем отдельным текстом — как и на странице входа.
            Error = "login.2fa.error.invalid";
            return Page();
        }

        var mustChange = user.MustChangePassword || AppUserManager.IsPasswordExpired(user, (await settings.GetAsync()).Passwords);
        await userService.RecordLoginAsync(user.Id, mustChange);
        await audit.WriteAsync(AuditTypes.LoginSucceeded, true, AuditSeverity.Info, null, user.Id,
            new { channel = "web", secondFactor = Provider, mustChangePassword = mustChange }, $"user:{user.Id}", user.UserName);

        // Только локальный returnUrl — защита от open redirect (как на /Account/Login).
        var returnUrl = Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : await HomeAsync(HttpContext, await signIn.CreateUserPrincipalAsync(user));
        return mustChange
            ? RedirectToPage("/Account/ChangePassword", new { returnUrl })
            : LocalRedirect(returnUrl);
    }

    /// <summary>Пользователь из временной cookie второго шага и доступные ему каналы; null — cookie нет или истекла.</summary>
    private async Task<AppUser?> LoadAsync()
    {
        var user = await signIn.GetTwoFactorAuthenticationUserAsync();
        if (user is not { IsActive: true }) return null;
        Providers = await signIn.UserManager.GetValidTwoFactorProvidersAsync(user);
        if (Provider is null || !Providers.Contains(Provider)) Provider = Providers.FirstOrDefault();
        return user;
    }

    private IActionResult RedirectToLogin()
    {
        TempData["Flash"] = L["login.2fa.error.session"];
        return RedirectToPage("/Account/Login", new { returnUrl = ReturnUrl });
    }

    /// <summary>Маска адреса для сообщения «код отправлен на …»: полный email на странице не показывается.</summary>
    internal static string MaskEmail(string email)
    {
        var at = email.IndexOf('@');
        if (at <= 1) return "***" + (at >= 0 ? email[at..] : "");
        return email[0] + new string('*', Math.Min(at - 1, 5)) + email[at..];
    }
}
