using Microsoft.AspNetCore.Mvc;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Apps;

/// <summary>
/// Матрица доступа приложения: разрешения (столбцы) × роли (строки).
/// Здесь же добавляются/удаляются роли и разрешения и отмечается, какие роли можно запрашивать самостоятельно.
/// Просмотр — политика UiView, изменения — UiManage. Использует ApplicationService и AccessService.
/// </summary>
public sealed class MatrixModel(ApplicationService apps, AccessService access) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public string ClientId { get; set; } = "";

    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Description { get; set; }

    /// <summary>Отмеченные ячейки в формате "роль|разрешение".</summary>
    [BindProperty] public List<string> Cells { get; set; } = [];

    public ApplicationDto App { get; private set; } = null!;
    public MatrixDto Matrix { get; private set; } = null!;

    public async Task<IActionResult> OnGetAsync(CancellationToken ct) => await LoadAsync(ct) ? Page() : NotFound();

    public async Task<IActionResult> OnPostAddPermissionAsync(CancellationToken ct) =>
        await RunAsync(() => access.AddPermissionAsync(ClientId, Name ?? "", Description, ct), $"Разрешение {Name} добавлено.", ct);

    public async Task<IActionResult> OnPostAddRoleAsync(CancellationToken ct) =>
        await RunAsync(() => access.AddRoleAsync(ClientId, Name ?? "", Description, null, ct), $"Роль {Name} добавлена.", ct);

    public async Task<IActionResult> OnPostDeletePermissionAsync(CancellationToken ct) =>
        await RunAsync(() => access.DeletePermissionAsync(ClientId, Name ?? "", ct), $"Разрешение {Name} удалено.", ct);

    public async Task<IActionResult> OnPostDeleteRoleAsync(CancellationToken ct) =>
        await RunAsync(() => access.DeleteRoleAsync(ClientId, Name ?? "", ct), $"Роль {Name} удалена.", ct);

    /// <summary>Включает/выключает возможность запрашивать роль (при регистрации и через «Запрос доступа»).</summary>
    public async Task<IActionResult> OnPostRequestableAsync(bool value, CancellationToken ct) =>
        await RunAsync(() => access.SetRoleRequestableAsync(ClientId, Name ?? "", value, ct),
            value ? $"Роль {Name} можно запрашивать." : $"Роль {Name} больше нельзя запрашивать.", ct);

    /// <summary>Сохраняет матрицу целиком: неотмеченные ячейки означают отсутствие разрешения у роли.</summary>
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        // Ячейки "роль|разрешение" → словарь роль → список разрешений.
        var matrix = Cells.Select(c => c.Split('|', 2)).Where(p => p.Length == 2)
            .GroupBy(p => p[0]).ToDictionary(g => g.Key, g => g.Select(p => p[1]).ToList());
        return await RunAsync(() => access.SetMatrixAsync(ClientId, matrix, ct),
            "Матрица сохранена. Изменения попадут в токены при следующем входе или обновлении токена.", ct);
    }

    /// <summary>
    /// Общий шаблон POST-обработчиков: проверить, что приложение существует, выполнить действие,
    /// при ошибке показать страницу с сообщением, при успехе — flash и редирект (PRG).
    /// </summary>
    private async Task<IActionResult> RunAsync(Func<Task> action, string message, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return NotFound();
        if (!await TryAsync(action)) return Page();
        Flash(message);
        return RedirectToPage(new { clientId = ClientId });
    }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        var app = await apps.GetAsync(ClientId, ct);
        if (app is null) return false;
        App = app;
        Matrix = await access.GetMatrixAsync(ClientId, ct);
        return true;
    }
}
