using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TslAuth.Localization;

namespace TslAuth.Pages;

/// <summary>
/// Страница ошибки для UseExceptionHandler("/Error"). Обработчик исключений повторяет запрос с исходным методом,
/// поэтому страница отвечает и на POST — без проверки antiforgery (иначе упавшая форма получила бы 400 вместо
/// страницы ошибки). Ответ не кэшируется. Язык — только из уже выбранного LanguageMiddleware значения, cookie
/// или Accept-Language: пакеты из БД не читаются, тексты (ru/en) заданы в разметке.
/// </summary>
[AllowAnonymous, IgnoreAntiforgeryToken]
public sealed class ErrorModel : PageModel
{
    public string RequestId { get; private set; } = "";
    public bool English { get; private set; }

    public void OnGet() => Prepare();

    public void OnPost() => Prepare();

    private void Prepare()
    {
        Response.Headers.CacheControl = "no-store";
        RequestId = System.Diagnostics.Activity.Current?.Id ?? HttpContext.TraceIdentifier;
        English = ResolveLanguage() == "en";
    }

    private string ResolveLanguage()
    {
        static string? Known(string? value) =>
            value is null ? null
            : value.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? "en"
            : value.StartsWith("ru", StringComparison.OrdinalIgnoreCase) ? "ru"
            : null;

        if (Known(HttpContext.Items[Texts.ItemKey] as string) is { } chosen) return chosen;
        if (Known(Request.Cookies[LanguageMiddleware.CookieName]) is { } cookie) return cookie;
        foreach (var lang in Request.GetTypedHeaders().AcceptLanguage.OrderByDescending(l => l.Quality ?? 1))
            if (Known(lang.Value.ToString()) is { } accepted) return accepted;
        return LocalizationService.DefaultCulture;
    }
}
