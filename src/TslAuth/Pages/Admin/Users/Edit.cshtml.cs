using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Users;

/// <summary>
/// Создание (Id пуст) и редактирование пользователя: профиль, активность, роли; первичная установка пароля
/// (приглашение / временный пароль / заданный пароль), временный пароль, приглашение, сброс по e-mail,
/// разблокировка, отзыв сессий и персональных токенов, удаление.
/// Просмотр — политика UiView, изменения — UiManage. Использует UserService, SessionService, AccountLinks,
/// AuthDbContext (список ролей) и PatService.
/// </summary>
public sealed class EditModel(UserService users, SessionService sessions, AccountLinks links, AuthDbContext db, PatService pats) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public Guid? Id { get; set; }

    [BindProperty] public string UserName { get; set; } = "";
    [BindProperty] public string? Email { get; set; }
    [BindProperty] public string? DisplayName { get; set; }
    [BindProperty] public bool IsActive { get; set; } = true;
    [BindProperty] public List<string> Roles { get; set; } = [];

    /// <summary>Способ первичной установки пароля для нового пользователя.</summary>
    [BindProperty] public string Onboarding { get; set; } = "invite";
    [BindProperty] public string? Password { get; set; }

    public bool IsNew => Id is null;
    public UserDto? Current { get; private set; }
    public List<RoleRef> AllRoles { get; private set; } = [];
    public List<SessionDto> Sessions { get; private set; } = [];
    public List<PatDto> Tokens { get; private set; } = [];
    public bool EmailConfigured => links.EmailConfigured;

    // Одноразово показываемые после действия значения: TempData живёт до первого чтения после редиректа,
    // поэтому пароль/ссылка видны администратору один раз и не попадают в URL.
    public string? OneTimePassword => TempData["OneTimePassword"] as string;
    public string? InviteLink => TempData["InviteLink"] as string;

    /// <summary>Загружает пользователя (с сессиями и токенами) в форму или показывает пустую форму создания.</summary>
    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!IsNew)
        {
            if (!await LoadAsync(ct)) return NotFound();
            UserName = Current!.UserName;
            Email = Current.Email;
            DisplayName = Current.DisplayName;
            IsActive = Current.IsActive;
            Roles = Current.Roles.Select(Apps.EditModel.RoleKey).ToList();
        }

        LoadRoles();
        return Page();
    }

    /// <summary>Создаёт или обновляет пользователя; для нового — выполняет выбранный способ онбординга.</summary>
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        UserDto? saved = null;
        var ok = await TryAsync(async () =>
        {
            var roles = Roles.Select(Apps.EditModel.ParseRole).ToList();
            if (IsNew)
            {
                // "temporary" — сгенерированный пароль, который нужно сменить при первом входе;
                // "password" — пароль задаёт администратор; "invite" (по умолчанию) — без пароля, пользователь задаст его по ссылке.
                var password = Onboarding switch
                {
                    "temporary" => PasswordGenerator(),
                    "password" => Password ?? throw new AdminException("Укажите пароль."),
                    _ => null
                };
                saved = await users.CreateAsync(new UserInput(UserName, Email, DisplayName, IsActive, password,
                    MustChangePassword: Onboarding == "temporary", Roles: roles), ct);

                if (Onboarding == "temporary") TempData["OneTimePassword"] = password;
                if (Onboarding == "invite") await InviteAsync(saved.Id, ct);
            }
            else
            {
                // Пароль при обновлении не меняется — для этого отдельные действия (временный пароль, сброс, приглашение).
                saved = await users.UpdateAsync(Id!.Value, new UserInput(UserName, Email, DisplayName, IsActive, Roles: roles), ct);
            }
        });

        if (!ok)
        {
            if (!IsNew) await LoadAsync(ct);
            LoadRoles();
            return Page();
        }

        // InviteAsync уже мог записать своё сообщение (отправлено ли письмо) — не перезатираем его.
        if (TempData.Peek("Flash") is null) Flash(IsNew ? "Пользователь создан." : "Изменения сохранены.");
        return RedirectToPage(new { id = saved!.Id });
    }

    /// <summary>Генерирует временный пароль (показывается один раз); сервис завершает все сессии пользователя.</summary>
    public async Task<IActionResult> OnPostTemporaryPasswordAsync(CancellationToken ct) =>
        await RunAsync(async () => TempData["OneTimePassword"] = await users.SetTemporaryPasswordAsync(Id!.Value, ct),
            "Выдан временный пароль. Все сессии пользователя завершены.", ct);

    /// <summary>Повторно выпускает приглашение (сообщение формирует сам InviteAsync).</summary>
    public async Task<IActionResult> OnPostInviteAsync(CancellationToken ct) =>
        await RunAsync(() => InviteAsync(Id!.Value, ct), null, ct);

    /// <summary>Отправляет пользователю письмо со ссылкой для сброса пароля.</summary>
    public async Task<IActionResult> OnPostResetEmailAsync(CancellationToken ct) =>
        await RunAsync(() => users.SendPasswordResetAsync(Id!.Value, ct), "Ссылка для сброса пароля отправлена на email.", ct);

    /// <summary>Снимает блокировку после неудачных попыток входа.</summary>
    public async Task<IActionResult> OnPostUnlockAsync(CancellationToken ct) =>
        await RunAsync(() => users.UnlockAsync(Id!.Value), "Пользователь разблокирован.", ct);

    /// <summary>Отзывает все OIDC-сессии пользователя (refresh-токены перестают действовать).</summary>
    public async Task<IActionResult> OnPostRevokeSessionsAsync(CancellationToken ct) =>
        await RunAsync(() => sessions.RevokeBySubjectAsync(Id!.Value.ToString(), ct), "Все сессии пользователя отозваны.", ct);

    /// <summary>Отзывает персональный токен пользователя (владелец проверяется по Id).</summary>
    public async Task<IActionResult> OnPostRevokeTokenAsync(Guid tokenId, CancellationToken ct) =>
        await RunAsync(() => pats.RevokeAsync(tokenId, Id!.Value, ct), "Персональный токен отозван.", ct);

    /// <summary>Удаляет пользователя и возвращает к списку.</summary>
    public async Task<IActionResult> OnPostDeleteAsync(CancellationToken ct)
    {
        if (!await TryAsync(() => users.DeleteAsync(Id!.Value, ct))) return await OnGetAsync(ct);
        Flash("Пользователь удалён.");
        return RedirectToPage("Index");
    }

    /// <summary>
    /// Выпускает ссылку-приглашение и пытается отправить её письмом. Ссылка показывается администратору
    /// в любом случае — если почта не настроена или не сработала, её можно передать вручную.
    /// </summary>
    private async Task InviteAsync(Guid id, CancellationToken ct)
    {
        var result = await users.InviteAsync(id, sendEmail: true, ct);
        TempData["InviteLink"] = result.Link;
        Flash(result.EmailSent
            ? "Приглашение отправлено на email. Ссылка также показана ниже."
            : $"Письмо не отправлено ({result.EmailError}). Передайте пользователю ссылку-приглашение вручную.");
    }

    /// <summary>Общий шаблон действий над существующим пользователем: выполнить, flash (если задан), редирект (PRG).</summary>
    private async Task<IActionResult> RunAsync(Func<Task> action, string? message, CancellationToken ct)
    {
        if (!await TryAsync(action)) return await OnGetAsync(ct);
        if (message is not null) Flash(message);
        return RedirectToPage(new { id = Id });
    }

    /// <summary>Загружает пользователя, его активные сессии и персональные токены; false — пользователь не найден.</summary>
    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        Current = await users.GetAsync(Id!.Value, ct);
        if (Current is null) return false;
        Sessions = await sessions.ListAsync(Id.Value.ToString(), ct: ct);
        Tokens = await pats.ListAsync(Id.Value, ct);
        return true;
    }

    private void LoadRoles() =>
        AllRoles = db.AccessRoles.OrderBy(r => r.ClientId).ThenBy(r => r.Name).Select(r => new RoleRef(r.ClientId, r.Name)).ToList();

    private static string PasswordGenerator() => Infrastructure.PasswordGenerator.Generate();
}
