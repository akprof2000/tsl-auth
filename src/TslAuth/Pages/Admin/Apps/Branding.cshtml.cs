using Microsoft.AspNetCore.Mvc;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Apps;

/// <summary>
/// Оформление страницы входа для конкретного приложения: заголовок, тексты, цвета, логотип, язык по умолчанию.
/// Просмотр — политика UiView, сохранение — UiManage. Использует ApplicationService и BrandingService.
/// </summary>
public sealed class BrandingModel(ApplicationService apps, BrandingService branding) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public string ClientId { get; set; } = "";

    [BindProperty] public string? Title { get; set; }
    [BindProperty] public string? WelcomeText { get; set; }
    [BindProperty] public string? AccentColor { get; set; }
    [BindProperty] public string? BackgroundColor { get; set; }
    [BindProperty] public string? CardColor { get; set; }
    [BindProperty] public string? TextColor { get; set; }
    // Отметки «задать цвет»: без отметки значение <input type="color"> игнорируется (оно всегда непустое).
    [BindProperty] public bool SetAccentColor { get; set; }
    [BindProperty] public bool SetBackgroundColor { get; set; }
    [BindProperty] public bool SetCardColor { get; set; }
    [BindProperty] public bool SetTextColor { get; set; }
    [BindProperty] public string? FooterText { get; set; }
    [BindProperty] public string? DefaultLanguage { get; set; }
    [BindProperty] public IFormFile? Logo { get; set; }
    [BindProperty] public bool RemoveLogo { get; set; }

    public string? CurrentLogo { get; private set; }
    public string? DisplayName { get; private set; }

    /// <summary>Как увидит страницу пользователь: вход с returnUrl авторизации этого приложения.</summary>
    public string PreviewUrl => "/Account/Login?ReturnUrl=" + Uri.EscapeDataString($"/connect/authorize?client_id={ClientId}");

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        var b = await LoadAsync(ct);
        if (b is null) return NotFound();
        (Title, WelcomeText, FooterText, DefaultLanguage) = (b.Title, b.WelcomeText, b.FooterText, b.DefaultLanguage);
        (SetAccentColor, SetBackgroundColor, SetCardColor, SetTextColor) =
            (b.AccentColor is not null, b.BackgroundColor is not null, b.CardColor is not null, b.TextColor is not null);
        // Незаданный цвет показываем стандартным цветом темы — чтобы при отметке «задать» не получить чёрный.
        (AccentColor, BackgroundColor, CardColor, TextColor) =
            (b.AccentColor ?? "#2458d6", b.BackgroundColor ?? "#f5f6f8", b.CardColor ?? "#ffffff", b.TextColor ?? "#1d2330");
        return Page();
    }

    /// <summary>Сохраняет оформление; при ошибке валидации показывает форму заново с введёнными значениями.</summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var ok = await TryAsync(async () =>
        {
            // Логотип: без нового файла сохраняем текущий (или удаляем, если отмечено «удалить»).
            var current = await branding.GetAsync(ClientId, ct);
            var logo = RemoveLogo ? null : current.LogoDataUri;
            if (Logo is { Length: > 0 })
            {
                // Логотип хранится в БД как data: URI; тип и размер проверяет BrandingService.ToDataUri.
                using var stream = new MemoryStream();
                await Logo.CopyToAsync(stream, ct);
                logo = BrandingService.ToDataUri(Logo.ContentType, stream.ToArray());
            }

            await branding.SetAsync(ClientId, new LoginBranding(Title, WelcomeText, logo,
                SetAccentColor ? AccentColor : null, SetBackgroundColor ? BackgroundColor : null,
                SetCardColor ? CardColor : null, SetTextColor ? TextColor : null, FooterText, DefaultLanguage), ct);
        });

        if (!ok)
        {
            // Перечитываем только справочные данные (название, текущий логотип) — введённое администратором остаётся в форме.
            return await LoadAsync(ct) is null ? NotFound() : Page();
        }
        Flash("Оформление страницы входа сохранено.");
        return RedirectToPage(new { clientId = ClientId });
    }

    /// <summary>Название приложения и текущий логотип для страницы; null — приложение не найдено.</summary>
    private async Task<LoginBranding?> LoadAsync(CancellationToken ct)
    {
        var app = await apps.GetAsync(ClientId, ct);
        if (app is null) return null;
        DisplayName = app.DisplayName;
        var b = await branding.GetAsync(ClientId, ct);
        CurrentLogo = b.LogoDataUri;
        return b;
    }
}
