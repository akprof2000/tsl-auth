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
        var app = await apps.GetAsync(ClientId, ct);
        if (app is null) return NotFound();
        DisplayName = app.DisplayName;

        var b = await branding.GetAsync(ClientId, ct);
        (Title, WelcomeText, CurrentLogo, AccentColor, BackgroundColor, CardColor, TextColor, FooterText, DefaultLanguage) =
            (b.Title, b.WelcomeText, b.LogoDataUri, b.AccentColor, b.BackgroundColor, b.CardColor, b.TextColor, b.FooterText, b.DefaultLanguage);
        return Page();
    }

    /// <summary>Сохраняет оформление; при ошибке валидации показывает форму заново.</summary>
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

            await branding.SetAsync(ClientId, new LoginBranding(Title, WelcomeText, logo, AccentColor, BackgroundColor,
                CardColor, TextColor, FooterText, DefaultLanguage), ct);
        });

        if (!ok) return await OnGetAsync(ct);
        Flash("Оформление страницы входа сохранено.");
        return RedirectToPage(new { clientId = ClientId });
    }
}
