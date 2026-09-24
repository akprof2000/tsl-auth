using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TslAuth.Pages.Account;

/// <summary>
/// Подтверждение выхода по запросу OIDC end_session (/connect/logout), пришедшему без id_token_hint.
/// Без подсказки нельзя убедиться, что выход инициировало приложение пользователя, а не сторонняя страница
/// (logout-CSRF: картинка или ссылка на /connect/logout разлогинивала бы пользователя везде). Форма отправляет
/// исходные параметры запроса (post_logout_redirect_uri, state, client_id…) POST-ом с antiforgery-токеном
/// обратно на /connect/logout, где AuthorizationController проверяет токен и выполняет выход.
/// </summary>
public sealed class EndSessionModel : PageModel
{
    // Какие параметры end_session переносятся в форму: только протокольные, без antiforgery и мусора.
    private static readonly HashSet<string> Allowed =
        new(StringComparer.Ordinal) { "client_id", "post_logout_redirect_uri", "state", "ui_locales", "logout_hint" };

    public List<(string Name, string Value)> Parameters { get; } = [];

    public void OnGet()
    {
        foreach (var (name, values) in Request.Query)
            if (Allowed.Contains(name))
                foreach (var value in values)
                    if (value is not null) Parameters.Add((name, value));
    }
}
