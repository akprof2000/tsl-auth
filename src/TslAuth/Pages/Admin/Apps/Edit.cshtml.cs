using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Apps;

/// <summary>
/// Создание (ClientId пуст) и редактирование приложения — OIDC-клиента: тип, redirect URI, grant types, scopes,
/// сервисные роли (для client_credentials), флаги самоуправления/саморегистрации и сроки жизни токенов;
/// перевыпуск секрета, отключение и удаление; политика подчинённых клиентов и список подчинённых владельца.
/// Подчинённый клиент показывается только для чтения (его настройки задаёт владелец через App API).
/// Просмотр — политика UiView, изменения — UiManage.
/// Использует ApplicationService, ManagedClientService, AccessService, AuthDbContext, TokenLifetimeService и SettingsService.
/// </summary>
public sealed class EditModel(ApplicationService apps, ManagedClientService managed, AccessService access, AuthDbContext db,
    TokenLifetimeService lifetimes, SettingsService settings) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public string? ClientId { get; set; }

    [BindProperty] public string NewClientId { get; set; } = "";
    [BindProperty] public string? DisplayName { get; set; }
    [BindProperty] public string ClientType { get; set; } = "confidential";
    [BindProperty] public string? RedirectUris { get; set; }
    [BindProperty] public string? PostLogoutRedirectUris { get; set; }
    [BindProperty] public List<string> GrantTypes { get; set; } = [];
    [BindProperty] public List<string> Scopes { get; set; } = [];
    [BindProperty] public List<string> ServiceRoles { get; set; } = [];
    [BindProperty] public bool SelfManagement { get; set; }
    [BindProperty] public bool SelfRegistration { get; set; }
    [BindProperty] public int? AccessTokenMinutes { get; set; }
    [BindProperty] public int? RefreshTokenDays { get; set; }
    [BindProperty] public int? ExchangeTokenMinutes { get; set; }
    /// <summary>Глобальные сроки жизни токенов — подсказка, что будет действовать, если поле приложения пустое.</summary>
    public TokenPolicy GlobalTokens { get; private set; } = new();

    // ---------- Политика подчинённых клиентов (только администратор) ----------
    [BindProperty] public bool PolicyEnabled { get; set; }
    [BindProperty] public string? PolicyPrefix { get; set; }
    [BindProperty] public List<string> PolicyRoles { get; set; } = [];
    [BindProperty] public List<string> PolicyAuthMethods { get; set; } = [ManagedClientsPolicy.PrivateKeyJwt];
    [BindProperty] public int PolicyMaxClients { get; set; } = 200;
    [BindProperty] public int PolicyAccessTokenLifetime { get; set; } = 5;
    [BindProperty] public bool PolicyRequireDelegation { get; set; } = true;
    [BindProperty] public string PolicyManagePermission { get; set; } = "agents.manage";
    [BindProperty] public int PolicyInactiveDays { get; set; }

    public bool IsNew => string.IsNullOrEmpty(ClientId);
    public bool IsSystem { get; private set; }

    /// <summary>Владелец, если это подчинённый клиент; такой клиент в админке только читается, отключается и удаляется.</summary>
    public string? Owner { get; private set; }
    public bool Disabled { get; private set; }
    public bool IsManaged => Owner is not null;
    public ManagedClientsPolicy? Policy { get; private set; }
    public List<ManagedClientDto> ManagedClients { get; private set; } = [];
    public List<string> AvailableScopes { get; private set; } = [];
    public List<RoleOption> AllRoles { get; private set; } = [];

    /// <summary>Роли этого приложения — белый список политики подчинённых.</summary>
    public List<RoleOption> OwnRoles => AllRoles.Where(r => r.ClientId == ClientId).ToList();

    /// <summary>Секрет показывается один раз — сразу после создания/перевыпуска.</summary>
    public string? Secret => TempData["Secret"] as string;

    /// <summary>Загружает приложение для редактирования или заполняет значения по умолчанию для нового.</summary>
    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!IsNew)
        {
            var app = await apps.GetAsync(ClientId!, ct);
            if (app is null) return NotFound();
            Fill(app);
            ServiceRoles = (await access.GetAssignmentsAsync(SubjectType.Client, ClientId!, ct)).Select(RoleKey).ToList();
            var lt = await lifetimes.GetForAppAsync(ClientId!);
            (AccessTokenMinutes, RefreshTokenDays, ExchangeTokenMinutes) = (lt.AccessTokenMinutes, lt.RefreshTokenDays, lt.ExchangeTokenMinutes);
        }
        else
        {
            // Типовой веб-клиент по умолчанию: authorization code + refresh token и первые стандартные scopes.
            GrantTypes = [AppGrantTypes.AuthorizationCode, AppGrantTypes.RefreshToken];
            Scopes = [.. ApplicationService.StandardScopes.Take(2)];
        }

        await LoadListsAsync(ct);
        return Page();
    }

    /// <summary>Создаёт или обновляет приложение вместе со сроками жизни токенов и сервисными ролями.</summary>
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        var input = new ApplicationInput(IsNew ? NewClientId : ClientId!, DisplayName, ClientType,
            Lines(RedirectUris), Lines(PostLogoutRedirectUris), GrantTypes, Scopes, SelfManagement, SelfRegistration);

        ApplicationSecretResult? result = null;
        var ok = await TryAsync(async () =>
        {
            result = IsNew ? await apps.CreateAsync(input, ct: ct) : await apps.UpdateAsync(ClientId!, input, ct);

            await lifetimes.SetForAppAsync(result.Application.ClientId,
                new AppTokenLifetimes(AccessTokenMinutes, RefreshTokenDays, ExchangeTokenMinutes), ct);
            var roles = ServiceRoles.Select(ParseRole).ToList();
            // Сервисные роли (роли самого клиента) имеют смысл для client_credentials; для остальных
            // приложений назначения трогаем, только если роли выбраны явно.
            if (result.Application.GrantTypes.Contains(AppGrantTypes.ClientCredentials) || roles.Count > 0)
                await access.SetAssignmentsAsync(SubjectType.Client, result.Application.ClientId, roles, ct);
        });

        if (!ok)
        {
            await LoadListsAsync(ct);
            return Page();
        }

        // Секрет передаётся через TempData на одну загрузку страницы после редиректа (показ один раз), в БД хранится только хэш.
        if (result!.ClientSecret is not null) TempData["Secret"] = result.ClientSecret;
        Flash(IsNew ? "Приложение зарегистрировано." : "Изменения сохранены.");
        return RedirectToPage(new { clientId = result.Application.ClientId });
    }

    /// <summary>Сохраняет или снимает политику подчинённых клиентов этого приложения.</summary>
    public async Task<IActionResult> OnPostPolicyAsync(CancellationToken ct)
    {
        var policy = PolicyEnabled
            ? new ManagedClientsPolicy(PolicyPrefix ?? "", PolicyRoles, [AppGrantTypes.ClientCredentials], PolicyAuthMethods,
                PolicyMaxClients, PolicyAccessTokenLifetime, PolicyRequireDelegation, PolicyManagePermission, PolicyInactiveDays)
            : null;
        if (!await TryAsync(() => managed.SetPolicyAsync(ClientId!, policy, ct)))
            return await OnGetAsync(ct);
        Flash(PolicyEnabled ? "Политика подчинённых клиентов сохранена." : "Подчинённые клиенты выключены.");
        return RedirectToPage(new { clientId = ClientId });
    }

    /// <summary>Отключает или включает клиента: само приложение (target пуст) или его подчинённого.</summary>
    public async Task<IActionResult> OnPostToggleAsync(string? target, bool disabled, CancellationToken ct)
    {
        var ok = await TryAsync(async () =>
        {
            if (string.IsNullOrEmpty(target) || target == ClientId) await apps.SetDisabledAsync(ClientId!, disabled, ct);
            else await managed.SetDisabledAsync(ClientId!, target, disabled, ct: ct);
        });
        if (!ok) return await OnGetAsync(ct);
        Flash(disabled ? $"Клиент {target ?? ClientId} отключён, его токены отозваны." : $"Клиент {target ?? ClientId} включён.");
        return RedirectToPage(new { clientId = ClientId });
    }

    /// <summary>Удаляет подчинённого клиента этого приложения с отзывом его токенов.</summary>
    public async Task<IActionResult> OnPostDeleteManagedAsync(string target, CancellationToken ct)
    {
        if (!await TryAsync(() => managed.DeleteAsync(ClientId!, target, ct: ct)))
            return await OnGetAsync(ct);
        Flash($"Подчинённый клиент {target} удалён, его токены отозваны.");
        return RedirectToPage(new { clientId = ClientId });
    }

    /// <summary>Перевыпускает client_secret (старый сразу перестаёт действовать); новый показывается один раз.</summary>
    public async Task<IActionResult> OnPostSecretAsync(CancellationToken ct)
    {
        if (!await TryAsync(async () => TempData["Secret"] = await apps.RegenerateSecretAsync(ClientId!, ct)))
            return await OnGetAsync(ct);
        Flash("Секрет перевыпущен. Старый секрет больше не действует.");
        return RedirectToPage(new { clientId = ClientId });
    }

    /// <summary>Удаляет приложение вместе с его сессиями.</summary>
    public async Task<IActionResult> OnPostDeleteAsync(CancellationToken ct)
    {
        if (!await TryAsync(() => apps.DeleteAsync(ClientId!, ct)))
            return await OnGetAsync(ct);
        Flash($"Приложение {ClientId} удалено, его сессии отозваны.");
        return RedirectToPage("Index");
    }

    /// <summary>Переносит данные приложения в свойства формы (URI — по одному на строку).</summary>
    private void Fill(ApplicationDto app)
    {
        DisplayName = app.DisplayName;
        ClientType = app.ClientType;
        RedirectUris = string.Join("\n", app.RedirectUris);
        PostLogoutRedirectUris = string.Join("\n", app.PostLogoutRedirectUris);
        GrantTypes = app.GrantTypes;
        Scopes = app.Scopes;
        IsSystem = app.IsSystem;
        SelfManagement = app.SelfManagement;
        SelfRegistration = app.SelfRegistration;
        Owner = app.Owner;
        Disabled = app.Disabled;
        Policy = app.ManagedClients;
        if (Policy is not null)
        {
            PolicyEnabled = true;
            PolicyPrefix = Policy.Prefix;
            PolicyRoles = Policy.Roles ?? [];
            PolicyAuthMethods = Policy.AuthMethods ?? [ManagedClientsPolicy.PrivateKeyJwt];
            PolicyMaxClients = Policy.MaxClients;
            PolicyAccessTokenLifetime = Policy.AccessTokenLifetime;
            PolicyRequireDelegation = Policy.RequireDelegation;
            PolicyManagePermission = Policy.ManagePermission;
            PolicyInactiveDays = Policy.InactiveDays;
        }
    }

    /// <summary>
    /// Справочники для формы (доступные scopes, все роли, глобальные сроки токенов). Вызывается и при
    /// повторном показе формы с ошибкой, поэтому не перезаписывает введённые пользователем значения.
    /// </summary>
    private async Task LoadListsAsync(CancellationToken ct)
    {
        GlobalTokens = (await settings.GetAsync(ct)).Tokens;
        // Scope App API управляется флагом «Самоуправление», а не вручную.
        AvailableScopes = (await apps.ListAvailableScopesAsync(ct)).Where(s => s != SystemApp.AppApiScope).ToList();
        AllRoles = db.AccessRoles.OrderBy(r => r.ClientId).ThenBy(r => r.Name)
            .Select(r => new RoleOption(r.ClientId, r.Name, r.DisplayName)).ToList();
        if (!IsNew && await apps.GetAsync(ClientId!, ct) is { } current)
        {
            IsSystem = current.IsSystem;
            Owner = current.Owner;
            Disabled = current.Disabled;
            Policy = current.ManagedClients;
            if (Owner is null) ManagedClients = await managed.ListAsync(ClientId!, ct);
        }
    }

    /// <summary>Значение чекбокса роли: "client_id|role" ('|' не допускается в именах).</summary>
    public static string RoleKey(RoleRef role) => $"{role.ClientId}|{role.Role}";

    /// <summary>Обратное к <see cref="RoleKey"/>: разбирает "client_id|role"; некорректное значение — ошибка формы.</summary>
    public static RoleRef ParseRole(string value)
    {
        var index = value.IndexOf('|');
        return index > 0 ? new RoleRef(value[..index], value[(index + 1)..]) : throw new AdminException($"Некорректная роль: {value}");
    }
}
