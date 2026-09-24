using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;

namespace TslAuth.Services;

/// <summary>Оформление страницы входа для конкретного приложения (хранится в свойствах клиента OpenIddict).</summary>
/// <param name="LogoDataUri">Логотип как data URI (png/jpeg/webp, до 256 КБ) — работает без внешних ресурсов.</param>
public sealed record LoginBranding(
    string? Title = null,
    string? WelcomeText = null,
    string? LogoDataUri = null,
    string? AccentColor = null,
    string? BackgroundColor = null,
    string? CardColor = null,
    string? TextColor = null,
    string? FooterText = null,
    string? DefaultLanguage = null)
{
    /// <summary>Ничего не настроено — используется стандартное оформление (свойство в клиенте удаляется).</summary>
    public bool IsEmpty => this == new LoginBranding();
}

/// <summary>Контекст страницы входа: какое приложение запрашивает вход и как его оформить.</summary>
public sealed record LoginContext(string ClientId, string? DisplayName, LoginBranding Branding);

/// <summary>
/// Хранение и валидация брендинга страниц входа. Данные лежат JSON-объектом в Properties клиента OpenIddict,
/// поэтому отдельная таблица не нужна и настройки удаляются вместе с приложением.
/// Используется страницами Account/Login, Register, RequestAccess, общим _Layout, /branding.css (цвета),
/// Admin/Apps/Branding, LanguageMiddleware (язык по умолчанию), а также Admin API и App API
/// (приложение может само настроить своё оформление).
/// </summary>
public sealed partial class BrandingService(IOpenIddictApplicationManager applications)
{
    private const string Property = "tsl_branding";
    public const int MaxLogoBytes = 256 * 1024;

    // Сервис scoped (один экземпляр на запрос): страницу входа за один запрос разбирают LanguageMiddleware,
    // модель страницы и _Layout — кэш не даёт трижды ходить в БД за одним и тем же клиентом.
    private readonly Dictionary<string, LoginContext?> _resolved = new(StringComparer.Ordinal);

    [GeneratedRegex("^#[0-9a-fA-F]{6}$")]
    private static partial Regex Color();

    [GeneratedRegex("^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$")]
    private static partial Regex Logo();

    [GeneratedRegex("^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})*$")]
    private static partial Regex Language();

    /// <summary>Брендинг приложения; если не настроен — пустой объект.</summary>
    public async Task<LoginBranding> GetAsync(string clientId, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        return await ReadAsync(app, ct);
    }

    private async Task<LoginBranding> ReadAsync(object app, CancellationToken ct)
    {
        var properties = await applications.GetPropertiesAsync(app, ct);
        if (!properties.TryGetValue(Property, out var json) || json.ValueKind != JsonValueKind.Object) return new LoginBranding();
        try
        {
            // Значения выводятся на публичной странице и в CSS — перепроверяем их и при чтении: свойство клиента
            // могло быть записано в обход SetAsync (старая версия, ручная правка БД, импорт).
            return Sanitize(json.Deserialize<LoginBranding>() ?? new LoginBranding());
        }
        catch (JsonException)
        {
            return new LoginBranding();
        }
    }

    /// <summary>Валидирует и сохраняет брендинг; возвращает нормализованную версию.</summary>
    public async Task<LoginBranding> SetAsync(string clientId, LoginBranding branding, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        branding = Validate(branding);
        _resolved.Clear();

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, app, ct);
        if (branding.IsEmpty) descriptor.Properties.Remove(Property);
        else descriptor.Properties[Property] = JsonSerializer.SerializeToElement(branding);
        await applications.UpdateAsync(app, descriptor, ct);
        return branding;
    }

    /// <summary>Определяет приложение по returnUrl вида /connect/authorize?client_id=...</summary>
    public async Task<LoginContext?> ResolveFromReturnUrlAsync(string? returnUrl, CancellationToken ct = default)
    {
        // returnUrl приходит от пользователя: берём из него только client_id и проверяем, что такой клиент есть.
        var clientId = ClientIdFromReturnUrl(returnUrl);
        return clientId is null ? null : await ResolveAsync(clientId, ct);
    }

    /// <summary>Контекст входа для приложения; null — такого клиента нет (ошибкой не считается: страница входа общая).</summary>
    public async Task<LoginContext?> ResolveAsync(string clientId, CancellationToken ct = default)
    {
        if (_resolved.TryGetValue(clientId, out var cached)) return cached;

        var app = await applications.FindByClientIdAsync(clientId, ct);
        var context = app is null ? null
            : new LoginContext(clientId, await applications.GetDisplayNameAsync(app, ct), await ReadAsync(app, ct));
        _resolved[clientId] = context;
        return context;
    }

    /// <summary>client_id из query-строки returnUrl (/connect/authorize?client_id=...) без проверки существования клиента.</summary>
    public static string? ClientIdFromReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) return null;
        var queryIndex = returnUrl.IndexOf('?');
        if (queryIndex < 0) return null;
        var query = QueryHelpers.ParseQuery(returnUrl[queryIndex..]);
        return query.TryGetValue("client_id", out var values) && !string.IsNullOrEmpty(values.ToString()) ? values.ToString() : null;
    }

    /// <summary>
    /// Мягкая проверка при чтении: некорректные значения не ломают страницу входа, а отбрасываются
    /// (цвет — только #RRGGBB, логотип — только data URI картинки, тексты обрезаются по лимитам).
    /// </summary>
    private static LoginBranding Sanitize(LoginBranding b)
    {
        static string? ColorOrNull(string? v) => v is not null && Color().IsMatch(v) ? v : null;
        static string? Cut(string? v, int max) => string.IsNullOrWhiteSpace(v) ? null : v.Length > max ? v[..max] : v;
        var logo = b.LogoDataUri is { } l && Logo().IsMatch(l) && l.Length <= MaxLogoBytes * 4 / 3 + 64 ? l : null;
        var lang = b.DefaultLanguage is { } d && Language().IsMatch(d) ? d : null;
        return new LoginBranding(Cut(b.Title, 100), Cut(b.WelcomeText, 500), logo,
            ColorOrNull(b.AccentColor), ColorOrNull(b.BackgroundColor), ColorOrNull(b.CardColor), ColorOrNull(b.TextColor),
            Cut(b.FooterText, 200), lang);
    }

    /// <summary>Превращает загруженный файл логотипа в data URI, проверяя размер и тип.</summary>
    public static string ToDataUri(string contentType, byte[] content)
    {
        if (content.Length > MaxLogoBytes) throw new AdminException("Логотип больше 256 КБ.");
        if (contentType is not ("image/png" or "image/jpeg" or "image/webp"))
            throw new AdminException("Логотип должен быть PNG, JPEG или WEBP.");
        return $"data:{contentType};base64,{Convert.ToBase64String(content)}";
    }

    // Строгая валидация важна: значения выводятся на публичной странице входа (в т.ч. в CSS),
    // поэтому цвета — только #RRGGBB, логотип — только base64 data URI картинки (без SVG со скриптами).
    private static LoginBranding Validate(LoginBranding b)
    {
        static string? Text(string? value, int max, string what)
        {
            value = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
            if (value?.Length > max) throw new AdminException($"{what}: не длиннее {max} символов.");
            return value;
        }

        string? ColorValue(string? value, string what)
        {
            value = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
            if (value is not null && !Color().IsMatch(value)) throw new AdminException($"{what}: цвет в формате #RRGGBB.");
            return value;
        }

        // Base64 увеличивает размер в 4/3 раза; +64 — запас на префикс "data:image/...;base64,".
        var logo = string.IsNullOrWhiteSpace(b.LogoDataUri) ? null : b.LogoDataUri.Trim();
        if (logo is not null && (!Logo().IsMatch(logo) || logo.Length > MaxLogoBytes * 4 / 3 + 64))
            throw new AdminException("Логотип: data URI PNG/JPEG/WEBP (base64) до 256 КБ.");

        return new LoginBranding(
            Text(b.Title, 100, "Заголовок"),
            Text(b.WelcomeText, 500, "Текст приветствия"),
            logo,
            ColorValue(b.AccentColor, "Акцентный цвет"),
            ColorValue(b.BackgroundColor, "Цвет фона"),
            ColorValue(b.CardColor, "Цвет карточки"),
            ColorValue(b.TextColor, "Цвет текста"),
            Text(b.FooterText, 200, "Подпись"),
            string.IsNullOrWhiteSpace(b.DefaultLanguage) ? null
                : Language().IsMatch(b.DefaultLanguage.Trim())
                    ? b.DefaultLanguage.Trim() : throw new AdminException("Язык по умолчанию: код вида ru, en, kk."));
    }
}
