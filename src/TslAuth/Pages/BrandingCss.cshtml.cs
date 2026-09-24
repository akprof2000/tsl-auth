using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Services;

namespace TslAuth.Pages;

/// <summary>
/// Цвета оформления страницы входа приложения — отдельной таблицей стилей <c>/branding.css?client_id=...</c>.
/// Раньше они вставлялись в макет inline-блоком &lt;style&gt;, из-за чего CSP требовал 'unsafe-inline' в style-src;
/// файл с того же origin разрешён политикой 'self'. Доступна анонимно (страница входа), использует BrandingService.
/// </summary>
[AllowAnonymous, IgnoreAntiforgeryToken]
public sealed class BrandingCssModel(BrandingService branding) : PageModel
{
    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "client_id")] string? clientId, CancellationToken ct)
    {
        var brand = string.IsNullOrEmpty(clientId) ? null : (await branding.ResolveAsync(clientId, ct))?.Branding;
        // Адрес в макете содержит версию (хеш цветов), поэтому кэш браузера не мешает увидеть изменения сразу.
        Response.Headers.CacheControl = "public, max-age=3600";
        return Content(brand is null ? "" : Build(brand), "text/css; charset=utf-8");
    }

    /// <summary>Есть ли у оформления цвета (иначе таблица стилей не подключается).</summary>
    public static bool HasColors(LoginBranding b) =>
        b.AccentColor is not null || b.BackgroundColor is not null || b.CardColor is not null || b.TextColor is not null;

    /// <summary>Адрес таблицы стилей для макета: client_id и короткий хеш содержимого (сброс кэша при изменении).</summary>
    public static string Href(string clientId, LoginBranding b) =>
        $"/branding.css?client_id={Uri.EscapeDataString(clientId)}&v={Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Build(b))))[..12]}";

    // Цвета уже провалидированы BrandingService (#RRGGBB при записи и при чтении), поэтому подставляются как есть.
    // Переменные переопределяют и тёмную тему: правило :root ниже по каскаду, чем @media в site.css.
    private static string Build(LoginBranding b)
    {
        var css = new StringBuilder(":root {");
        if (b.AccentColor is not null) css.Append($" --accent: {b.AccentColor}; --accent-text: #fff;");
        if (b.BackgroundColor is not null) css.Append($" --bg: {b.BackgroundColor};");
        if (b.CardColor is not null) css.Append($" --surface: {b.CardColor};");
        if (b.TextColor is not null) css.Append($" --text: {b.TextColor};");
        return css.Append(" }\n").ToString();
    }
}
