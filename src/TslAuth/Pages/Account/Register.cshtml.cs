using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Account;

/// <summary>
/// Самостоятельная регистрация в приложении (client_id из returnUrl) с запросом ролей.
/// Доступна анонимно, но только если у приложения из returnUrl включена самостоятельная регистрация.
/// Запрошенные роли не выдаются сразу — создаются заявки на доступ, которые одобряет администратор.
/// Использует BrandingService, ApplicationService, AccessRequestService, UserManager, SignInManager и AuditService.
/// </summary>
public sealed class RegisterModel(
    BrandingService branding,
    ApplicationService apps,
    AccessRequestService requests,
    UserManager<AppUser> users,
    SignInManager<AppUser> signIn,
    AuditService audit) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    [BindProperty, Required(ErrorMessage = "validation.required")] public string UserName { get; set; } = "";
    [BindProperty, EmailAddress(ErrorMessage = "validation.email")] public string? Email { get; set; }
    [BindProperty] public string? DisplayName { get; set; }
    [BindProperty, Required(ErrorMessage = "validation.required"), DataType(DataType.Password)] public string Password { get; set; } = "";
    [BindProperty, DataType(DataType.Password), Compare(nameof(Password), ErrorMessage = "password.mismatch")]
    public string Confirm { get; set; } = "";
    [BindProperty] public List<string> Roles { get; set; } = [];
    [BindProperty] public string? Comment { get; set; }

    public LoginContext? App { get; private set; }
    public bool Enabled { get; private set; }
    public List<RequestableRole> Requestable { get; private set; } = [];
    public bool Done { get; private set; }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    /// <summary>Создаёт пользователя и заявки на роли, затем сразу выполняет вход.</summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        // Разрешение на регистрацию перепроверяется на POST — нельзя обойти, отправив форму напрямую.
        await LoadAsync(ct);
        if (!Enabled || !ModelState.IsValid) return Page();

        try
        {
            var id = await requests.RegisterAsync(App!.ClientId,
                new RegistrationInput(UserName, Email, DisplayName, Password, ParseRoles(Roles), Comment), ct);
            // Сессионная (не persistent) cookie: пользователь сразу залогинен и может продолжить OIDC-сценарий.
            await signIn.SignInAsync((await users.FindByIdAsync(id.ToString()))!, isPersistent: false);
            await audit.WriteAsync(AuditTypes.Registered, true, Data.AuditSeverity.Info, App!.ClientId, id,
                new { userName = UserName, requestedRoles = Roles }, $"user:{id}", UserName);
            Done = true;
        }
        catch (AdminException ex)
        {
            ModelState.AddModelError("", ex.Message);
        }

        return Page();
    }

    /// <summary>Значения чекбоксов — "client_id|роль".</summary>
    public static List<RoleRef> ParseRoles(IEnumerable<string> keys) =>
        keys.Select(k => k.Split('|', 2)).Where(p => p.Length == 2).Select(p => new RoleRef(p[0], p[1])).ToList();

    /// <summary>Определяет приложение по returnUrl, проверяет, включена ли регистрация, и загружает доступные для запроса роли.</summary>
    private async Task LoadAsync(CancellationToken ct)
    {
        ViewData["ReturnUrl"] = ReturnUrl;
        App = await branding.ResolveFromReturnUrlAsync(ReturnUrl, ct);
        Enabled = App is not null && await apps.IsSelfRegistrationEnabledAsync(App.ClientId, ct);
        if (Enabled) Requestable = await requests.ListRequestableRolesAsync(App!.ClientId, ct);
    }
}
