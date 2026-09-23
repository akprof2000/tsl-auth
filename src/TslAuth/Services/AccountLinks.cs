using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using TslAuth.Data;
using TslAuth.Options;

namespace TslAuth.Services;

/// <summary>
/// Токены приглашений живут дольше, чем токены сброса пароля, поэтому у них свой провайдер.
/// Все такие токены привязаны к security stamp: после установки пароля ссылка перестаёт работать (одноразовая).
/// </summary>
public sealed class InviteTokenProvider(
    IDataProtectionProvider dataProtectionProvider,
    IOptions<InviteTokenProviderOptions> options,
    ILogger<DataProtectorTokenProvider<AppUser>> logger)
    : DataProtectorTokenProvider<AppUser>(dataProtectionProvider, options, logger)
{
    public const string ProviderName = "Invite";
    public const string Purpose = "Invite";
}

/// <summary>Настройки провайдера приглашений: отдельное имя и срок жизни 7 дней (регистрируется в ServiceSetup).</summary>
public sealed class InviteTokenProviderOptions : DataProtectionTokenProviderOptions
{
    public InviteTokenProviderOptions()
    {
        Name = InviteTokenProvider.ProviderName;
        TokenLifespan = TimeSpan.FromDays(7);
    }
}

/// <summary>
/// Формирование ссылок на страницы аккаунта и отправка писем.
/// Используется <see cref="UserService"/> (приглашения, сброс пароля), страницами Account/AcceptInvite
/// и Admin/Users/Edit. Токены в ссылках — одноразовые токены ASP.NET Core Identity.
/// </summary>
public sealed class AccountLinks(
    UserManager<AppUser> users,
    IEmailSender email,
    IOptions<AuthServerOptions> server,
    IHttpContextAccessor http,
    Localization.Texts L)
{
    public bool EmailConfigured => email.IsConfigured;

    /// <summary>Ссылка на установку пароля по приглашению (Account/AcceptInvite), действует 7 дней.</summary>
    public async Task<string> CreateInviteLinkAsync(AppUser user)
    {
        var token = await users.GenerateUserTokenAsync(user, InviteTokenProvider.ProviderName, InviteTokenProvider.Purpose);
        return BuildUrl("/Account/AcceptInvite", user.Id, token);
    }

    public Task<bool> ValidateInviteAsync(AppUser user, string token) =>
        users.VerifyUserTokenAsync(user, InviteTokenProvider.ProviderName, InviteTokenProvider.Purpose, token);

    /// <summary>Ссылка на сброс пароля (Account/ResetPassword) со стандартным токеном Identity.</summary>
    public async Task<string> CreatePasswordResetLinkAsync(AppUser user)
    {
        var token = await users.GeneratePasswordResetTokenAsync(user);
        return BuildUrl("/Account/ResetPassword", user.Id, token);
    }

    public async Task SendInviteAsync(AppUser user, string link, CancellationToken ct = default)
    {
        var address = user.Email ?? throw new AdminException("У пользователя не указан email.");
        // Все подставляемые в HTML значения экранируются: логин/имя задаются пользователем.
        await email.SendAsync(address, L["email.invite.subject"], L.Get("email.invite.body",
            user.DisplayName is null ? "" : ", " + WebUtility.HtmlEncode(user.DisplayName),
            WebUtility.HtmlEncode(user.UserName), WebUtility.HtmlEncode(link)), ct);
    }

    public async Task SendPasswordResetAsync(AppUser user, string link, CancellationToken ct = default)
    {
        var address = user.Email ?? throw new AdminException("У пользователя не указан email.");
        await email.SendAsync(address, L["email.reset.subject"], L.Get("email.reset.body",
            WebUtility.HtmlEncode(user.UserName), WebUtility.HtmlEncode(link)), ct);
    }

    private string BuildUrl(string path, Guid userId, string token)
    {
        // Предпочитаем настроенный Issuer: за reverse proxy Host запроса может быть внутренним адресом.
        // Хост запроса — лишь запасной вариант, когда Issuer не задан.
        var baseUrl = server.Value.Issuer?.TrimEnd('/');
        if (string.IsNullOrEmpty(baseUrl) && http.HttpContext?.Request is { } request)
            baseUrl = $"{request.Scheme}://{request.Host}{request.PathBase}";

        return QueryHelpers.AddQueryString(baseUrl + path, new Dictionary<string, string?>
        {
            ["uid"] = userId.ToString(),
            ["token"] = token
        });
    }
}
