using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Запрос ссылки для сброса пароля по e-mail. Доступна анонимно (rate limiting папки /Account).
/// Работает только при настроенной отправке почты (<see cref="IEmailSender"/>).
/// Использует UserService (генерация и отправка ссылки) и AuditService.
/// </summary>
public sealed class ForgotPasswordModel(UserService users, IEmailSender email, AuditService audit) : UserPageModel
{
    [BindProperty, Required(ErrorMessage = "validation.required")]
    public string Login { get; set; } = "";

    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    public bool Sent { get; private set; }
    public bool EmailAvailable => email.IsConfigured;

    public void OnGet() { }

    /// <summary>Отправляет письмо со ссылкой сброса, если пользователь найден; ответ всегда одинаковый.</summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        if (!ModelState.IsValid || !EmailAvailable) return Page();

        try
        {
            await users.RequestPasswordResetAsync(Login, ct);
        }
        catch (AdminException ex)
        {
            AddError(ex);
            return Page();
        }
        await audit.WriteAsync(AuditTypes.PasswordResetRequested, true, Data.AuditSeverity.Info, details: new { login = Login });
        // Одинаковый ответ независимо от того, существует ли пользователь (защита от перечисления логинов).
        Sent = true;
        return Page();
    }
}
