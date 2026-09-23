using Microsoft.AspNetCore.Html;
using TslAuth.Services;

namespace TslAuth.Localization;

/// <summary>
/// Тексты интерфейса на языке текущего запроса. Язык выбирается middleware (см. <see cref="LanguageMiddleware"/>)
/// и лежит в HttpContext.Items. В представлениях доступен как <c>L["ключ"]</c>.
/// </summary>
public sealed class Texts(LocalizationService localization, IHttpContextAccessor http)
{
    public const string ItemKey = "tsl.culture";

    public string Culture => http.HttpContext?.Items[ItemKey] as string ?? LocalizationService.DefaultCulture;

    public string this[string key] => Get(key);

    /// <summary>Строка по ключу с подстановкой аргументов string.Format; если перевода нет — возвращается сам ключ.</summary>
    public string Get(string key, params object?[] args)
    {
        var text = localization.Get(Culture, key) ?? key;
        return args.Length == 0 ? text : string.Format(text, args);
    }

    /// <summary>Строка с HTML-разметкой из пакета (например, тексты писем). Аргументы должны быть уже экранированы.</summary>
    public IHtmlContent Html(string key, params object?[] args) => new HtmlString(Get(key, args));

    /// <summary>Человекочитаемое описание требований политики паролей (подсказка на формах смены пароля).</summary>
    public string PasswordPolicy(PasswordPolicy p)
    {
        var parts = new List<string> { Get("policy.minLength", p.MinLength) };
        if (p.RequireLowercase) parts.Add(Get("policy.lower"));
        if (p.RequireUppercase) parts.Add(Get("policy.upper"));
        if (p.RequireDigit) parts.Add(Get("policy.digit"));
        if (p.RequireSymbol) parts.Add(Get("policy.symbol"));
        if (p.MinUniqueChars > 1) parts.Add(Get("policy.unique", p.MinUniqueChars));
        if (p.HistoryCount > 0) parts.Add(Get("policy.history", p.HistoryCount));
        return string.Join(", ", parts) + ".";
    }

    public Task<IReadOnlyList<LanguageInfo>> LanguagesAsync() => localization.ListAsync();
}

/// <summary>
/// Выбор языка: ?lang= (запоминается в cookie) → cookie → язык по умолчанию приложения (из оформления входа)
/// → Accept-Language браузера → ru.
/// Заодно прогревает кэш LocalizationService, чтобы синхронный <see cref="Texts.Get"/> в представлениях не ходил в БД.
/// </summary>
public sealed class LanguageMiddleware(RequestDelegate next, LocalizationService localization)
{
    public const string CookieName = "tsl_lang";

    public async Task InvokeAsync(HttpContext context, BrandingService branding)
    {
        await localization.EnsureLoadedAsync();
        var culture = await ResolveAsync(context, branding);
        context.Items[Texts.ItemKey] = culture;
        await next(context);
    }

    private async Task<string> ResolveAsync(HttpContext context, BrandingService branding)
    {
        // Принимаем только доступные языки — в cookie и Items не попадёт произвольное значение из запроса.
        var requested = context.Request.Query["lang"].ToString();
        if (requested.Length > 0 && await localization.IsAvailableAsync(requested))
        {
            context.Response.Cookies.Append(CookieName, requested, new CookieOptions
            {
                HttpOnly = true, SameSite = SameSiteMode.Lax, IsEssential = true, MaxAge = TimeSpan.FromDays(365),
                Secure = context.Request.IsHttps
            });
            return requested;
        }

        if (context.Request.Cookies.TryGetValue(CookieName, out var cookie) && await localization.IsAvailableAsync(cookie))
            return cookie;

        // Язык по умолчанию приложения — только для страниц входа (returnUrl с client_id).
        var returnUrl = context.Request.Query["ReturnUrl"].ToString();
        if (returnUrl.Length > 0 && context.Request.Path.StartsWithSegments("/Account") &&
            await branding.ResolveFromReturnUrlAsync(returnUrl) is { Branding.DefaultLanguage: { } appLang } &&
            await localization.IsAvailableAsync(appLang))
            return appLang;

        foreach (var lang in context.Request.GetTypedHeaders().AcceptLanguage.OrderByDescending(l => l.Quality ?? 1))
        {
            var value = lang.Value.ToString();
            if (await localization.IsAvailableAsync(value)) return value;
            var dash = value.IndexOf('-');
            if (dash > 0 && await localization.IsAvailableAsync(value[..dash])) return value[..dash];
        }

        return LocalizationService.DefaultCulture;
    }
}
