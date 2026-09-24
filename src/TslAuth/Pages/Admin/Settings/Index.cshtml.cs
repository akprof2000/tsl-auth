using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Settings;

/// <summary>
/// Настройки времени выполнения (хранятся в БД, применяются без перезапуска): сроки хранения аудита/событий/токенов
/// (в т.ч. по типам событий аудита), политики паролей, токенов, PAT и сброса пароля через бота; ручной запуск очистки.
/// Просмотр — политика UiView, изменения — UiManage. Использует SettingsService, AuditService (список типов),
/// UserManager (автор изменений) и IServiceScopeFactory (для разового запуска TokenPruningService).
/// </summary>
public sealed class IndexModel(SettingsService settings, AuditService audit, UserManager<AppUser> users,
    IServiceScopeFactory scopes) : AdminPageModel
{
    [BindProperty] public int AuditRetentionDays { get; set; }
    [BindProperty] public bool AuditLogTokenRefresh { get; set; }
    [BindProperty] public int EventsRetentionDays { get; set; }
    [BindProperty] public int TokensRetentionHours { get; set; }

    /// <summary>Сроки по типам: тип/префикс → дни (пустое значение — общий срок).</summary>
    [BindProperty] public Dictionary<string, int?> Retention { get; set; } = [];
    [BindProperty] public string? NewType { get; set; }
    [BindProperty] public int? NewDays { get; set; }

    [BindProperty] public PasswordPolicy Passwords { get; set; } = new();
    [BindProperty] public TokenPolicy Tokens { get; set; } = new();
    [BindProperty] public PatPolicy Pats { get; set; } = new();
    [BindProperty] public BotResetPolicy Bot { get; set; } = new();

    public List<string> Types { get; private set; } = [];
    public DateTime? UpdatedAt { get; private set; }
    public string? UpdatedBy { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        var s = await settings.GetAsync(ct);
        (AuditRetentionDays, AuditLogTokenRefresh, EventsRetentionDays, TokensRetentionHours) =
            (s.AuditRetentionDays, s.AuditLogTokenRefresh, s.EventsRetentionDays, s.TokensRetentionHours);
        (Passwords, Tokens, Pats, Bot) = (s.Passwords, s.Tokens, s.Pats, s.BotReset);
        var rules = s.EffectiveRetentionByType;
        await LoadTypesAsync(rules.Keys, ct);
        Retention = Types.ToDictionary(t => t, t => rules.TryGetValue(t, out var d) ? d : (int?)null);
    }

    /// <summary>
    /// Строки таблицы сроков: все встречавшиеся в аудите типы плюс типы/префиксы, для которых заданы правила;
    /// заодно — кто и когда менял настройки. Значения полей формы не трогает.
    /// </summary>
    private async Task LoadTypesAsync(IEnumerable<string> ruleTypes, CancellationToken ct)
    {
        Types = (await audit.ListTypesAsync(ct)).Union(ruleTypes).Order().ToList();
        (UpdatedAt, UpdatedBy) = await settings.GetMetadataAsync(ct);
    }

    /// <summary>Сохраняет настройки; другие экземпляры сервиса подхватывают их из БД по таймеру.</summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        // Пустые поля — «общий срок», поэтому в правила попадают только заполненные значения (+ новая строка, если задана).
        var rules = Retention.Where(r => r.Value is not null).ToDictionary(r => r.Key, r => r.Value!.Value);
        if (!string.IsNullOrWhiteSpace(NewType) && NewDays is { } days) rules[NewType.Trim()] = days;

        var ok = await TryAsync(() => settings.SetAsync(
            new RuntimeSettings(AuditRetentionDays, AuditLogTokenRefresh, EventsRetentionDays, TokensRetentionHours, rules,
                Passwords, Pats, Tokens, Bot),
            $"user:{users.GetUserName(User)}", ct));
        if (!ok)
        {
            // Все введённые значения (политики, сроки, новое правило) остаются в форме — из БД только справочные данные.
            await LoadTypesAsync(Retention.Keys, ct);
            return Page();
        }

        Flash("Настройки сохранены. Остальные экземпляры применят их в течение 30 секунд.");
        return RedirectToPage();
    }

    /// <summary>Немедленно запускает фоновую очистку (просроченные токены, старые записи аудита и событий) и показывает итог.</summary>
    public async Task<IActionResult> OnPostMaintenanceAsync(CancellationToken ct)
    {
        var result = await TokenPruningService.RunOnceAsync(scopes, ct);
        Flash($"Очистка выполнена: {System.Text.Json.JsonSerializer.Serialize(result)}");
        return RedirectToPage();
    }
}
