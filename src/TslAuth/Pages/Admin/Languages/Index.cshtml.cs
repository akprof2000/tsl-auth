using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Localization;

namespace TslAuth.Pages.Admin.Languages;

/// <summary>
/// Языковые пакеты интерфейса: список (включая отключённые), редактирование JSON-пакета или загрузка файла,
/// скачивание шаблона для переводчика, удаление пакета из БД.
/// Просмотр — политика UiView, изменения — UiManage. Использует LocalizationService и UserManager (автор изменений).
/// </summary>
public sealed class IndexModel(LocalizationService localization, UserManager<AppUser> users) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public string? Culture { get; set; }
    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Json { get; set; }
    [BindProperty] public bool IsEnabled { get; set; } = true;
    [BindProperty] public IFormFile? Upload { get; set; }

    public IReadOnlyList<LanguageInfo> Items { get; private set; } = [];

    // Форматированный JSON без экранирования кириллицы — чтобы пакет было удобно читать и править вручную.
    private static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>Список языков; при выбранной культуре — её пакет (или шаблон для нового языка) в редакторе.</summary>
    public async Task OnGetAsync()
    {
        Items = await localization.ListAsync(includeDisabled: true);
        if (Culture is null) return;
        var pack = await localization.GetPackAsync(Culture);
        Name = pack?.Name;
        IsEnabled = pack?.IsEnabled ?? true;
        // Для нового языка — шаблон со всеми ключами (из встроенного пакета этого языка, если он есть, иначе русский).
        Json = pack?.Json ?? JsonSerializer.Serialize(LocalizationService.Template(Culture), Pretty);
    }

    /// <summary>Шаблон пакета со всеми ключами — отдать переводчику.</summary>
    public IActionResult OnGetTemplate(string? from) =>
        File(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(LocalizationService.Template(from ?? "ru"), Pretty)),
            "application/json", $"tsl-auth-lang-{from ?? "ru"}.json");

    /// <summary>Сохраняет пакет; валидацию JSON и ключей выполняет LocalizationService.</summary>
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        // Загруженный файл имеет приоритет над текстом из редактора.
        if (Upload is { Length: > 0 })
        {
            using var reader = new StreamReader(Upload.OpenReadStream());
            Json = await reader.ReadToEndAsync(ct);
        }

        if (!await TryAsync(() => localization.SavePackAsync(Culture ?? "", Name ?? "", Json ?? "", IsEnabled,
                $"user:{users.GetUserName(User)}", ct)))
        {
            Items = await localization.ListAsync(includeDisabled: true);
            return Page();
        }

        Flash($"Языковой пакет {Culture} сохранён.");
        return RedirectToPage(new { culture = Culture });
    }

    /// <summary>Удаляет пакет из БД; для встроенных языков снова начинают действовать встроенные строки.</summary>
    public async Task<IActionResult> OnPostDeleteAsync(CancellationToken ct)
    {
        // Ошибку (например, пакета в БД нет — встроенный язык удалять нечего) показываем, а не рапортуем об успехе.
        if (!await TryAsync(() => localization.DeletePackAsync(Culture ?? "", ct)))
        {
            await OnGetAsync();
            return Page();
        }
        Flash($"Пакет {Culture} удалён из БД (встроенный язык при этом остаётся).");
        return RedirectToPage(new { culture = (string?)null });
    }
}
