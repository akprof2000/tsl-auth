using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using TslAuth.Data;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Controllers;

/// <summary>
/// Конечные точки OAuth 2.0 / OpenID Connect (протокольную часть обрабатывает OpenIddict).
/// OpenIddict работает в режиме passthrough: он сам разбирает и валидирует запрос (client_id/secret,
/// redirect_uri, PKCE, подпись и срок кодов/refresh-токенов), а сюда передаёт управление, чтобы
/// приложение решило, КОГО аутентифицировать и какие claims положить в токен. Набор claims
/// (роли и разрешения из матрицы доступа, audience) строит <see cref="TokenPrincipalFactory"/>;
/// итоговый SignIn снова уходит в OpenIddict, который выпускает и подписывает токены.
/// Поддерживаемые гранты: authorization_code (+refresh_token), client_credentials, password,
/// token exchange (RFC 8693) и собственный грант обмена PAT на JWT.
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
public sealed class AuthorizationController(
    IOpenIddictApplicationManager applications,
    IOpenIddictAuthorizationManager authorizations,
    UserManager<AppUser> users,
    SignInManager<AppUser> signIn,
    UserService userService,
    WebhookService webhooks,
    AuditService audit,
    SettingsService settings,
    TokenLifetimeService lifetimes,
    PatService pats,
    TokenPrincipalFactory principals) : Controller
{
    private const string Scheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    /// <summary>Выдача токена + запись в журнал безопасности.</summary>
    private async Task<IActionResult> IssueAsync(ClaimsIdentity identity, string grant, string clientId, Guid? userId, string? actorName,
        object? extra = null)
    {
        // Обновления токенов очень частые — их аудит отключаемый, чтобы не раздувать журнал.
        if (grant != GrantTypes.RefreshToken || (await settings.GetAsync()).AuditLogTokenRefresh)
        {
            var subject = identity.GetClaim(Claims.Subject);
            await audit.WriteAsync(grant == GrantTypes.TokenExchange ? AuditTypes.TokenExchanged : AuditTypes.TokenIssued, true,
                AuditSeverity.Info, clientId, userId, new { grant, scopes = identity.GetScopes(), audiences = identity.GetResources(), extra },
                userId is null ? $"client:{subject}" : $"user:{subject}", actorName);
        }
        // Сроки жизни задаются на уровне конкретного principal: переопределения приложения не могут
        // превышать глобальные, а для token exchange и PAT действуют отдельные (обычно более короткие) лимиты.
        await lifetimes.ApplyAsync(identity, clientId, HttpContext.GetOpenIddictServerRequest(),
            grant == GrantTypes.TokenExchange ? TokenLifetimeService.Kind.Exchange
            : grant == PatGrantType ? TokenLifetimeService.Kind.Pat : TokenLifetimeService.Kind.Regular);
        return SignIn(new ClaimsPrincipal(identity), Scheme);
    }

    /// <summary>Нестандартный grant_type для обмена персонального токена (tslpat_…) на короткоживущий JWT.</summary>
    public const string PatGrantType = "urn:tsl:grant-type:pat";

    /// <summary>
    /// Authorization endpoint (первый шаг authorization code flow): проверяет вход пользователя
    /// по cookie Identity и выдаёт код авторизации, который клиент затем обменяет на /connect/token.
    /// </summary>
    [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("Запрос OpenID Connect не найден.");

        // Пользователь определяется по cookie веб-входа (страница /Account/Login), а не по токену.
        var cookie = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var user = cookie.Succeeded ? await users.GetUserAsync(cookie.Principal) : null;

        // OIDC max_age: если вход был давнее, чем требует клиент, — нужна повторная аутентификация.
        var expired = request.MaxAge is { } maxAge && cookie.Properties?.IssuedUtc is { } issued &&
                      DateTimeOffset.UtcNow - issued > TimeSpan.FromSeconds(maxAge);

        if (user is not { IsActive: true } || expired || request.HasPromptValue(PromptValues.Login))
        {
            // prompt=none (тихое продление в iframe/SPA) запрещает показывать UI — отвечаем ошибкой по спецификации.
            if (request.HasPromptValue(PromptValues.None))
                return Error(Errors.LoginRequired, "Пользователь не аутентифицирован.");

            // После входа вернёмся сюда же, но без prompt=login, чтобы не зациклиться.
            var parameters = (Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                .Where(p => p.Key != Parameters.Prompt).ToList();

            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
            }, IdentityConstants.ApplicationScheme);
        }

        // Временный пароль: токены не выдаются, пока пользователь его не сменит; затем вернётся в этот же запрос.
        if (user.MustChangePassword)
        {
            if (request.HasPromptValue(PromptValues.None))
                return Error(Errors.InteractionRequired, "Требуется смена временного пароля.");
            return RedirectToPage("/Account/ChangePassword",
                new { returnUrl = Request.PathBase + Request.Path + Request.QueryString });
        }

        var application = await applications.FindByClientIdAsync(request.ClientId!)
                          ?? throw new InvalidOperationException("Приложение не найдено.");
        var applicationId = await applications.GetIdAsync(application);

        // Согласие (consent) не запрашивается: доступ определяется ролями в матрице, а не выбором пользователя.
        var identity = await principals.CreateForUserAsync(user, request.ClientId!, request.GetScopes());

        // Постоянная авторизация пользователь+клиент — это "сессия", видимая в админке.
        // Существующая переиспользуется, чтобы повторные входы не плодили записи; её отзыв
        // инвалидирует все refresh-токены, выпущенные в рамках этой сессии.
        object? authorization = null;
        await foreach (var existing in authorizations.FindAsync(user.Id.ToString(), applicationId, Statuses.Valid,
                           AuthorizationTypes.Permanent, identity.GetScopes()))
        {
            authorization = existing;
            break;
        }

        authorization ??= await authorizations.CreateAsync(identity, user.Id.ToString(), applicationId!,
            AuthorizationTypes.Permanent, identity.GetScopes());
        identity.SetAuthorizationId(await authorizations.GetIdAsync(authorization));

        // На этом шаге OpenIddict выпускает не токены, а одноразовый код; claims сохраняются внутри него.
        return await IssueAsync(identity, "authorization_code(authorize)", request.ClientId!, user.Id, user.UserName);
    }

    /// <summary>
    /// Token endpoint: выдаёт токены по всем поддерживаемым грантам. Аутентификация клиента
    /// (client_secret) уже выполнена OpenIddict; защищён rate limiting от перебора.
    /// </summary>
    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting(Infrastructure.SecurityMiddleware.TokenPolicy)]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("Запрос OpenID Connect не найден.");

        // Resource Owner Password (устаревший грант для доверенных клиентов): проверяем пароль сами,
        // с тем же учётом блокировки (lockout) и аудитом, что и при входе через веб-форму.
        if (request.IsPasswordGrantType())
        {
            var user = string.IsNullOrEmpty(request.Username) ? null : await userService.FindByLoginAsync(request.Username);
            // Одинаковое сообщение для «нет пользователя» и «неверный пароль» — не раскрываем существование логинов.
            if (user is not { IsActive: true })
            {
                await audit.WriteAsync(AuditTypes.LoginFailed, false, AuditSeverity.Info, request.ClientId, user?.Id,
                    new { login = request.Username, reason = user is null ? "unknown_user" : "inactive", channel = "password_grant" }, "anonymous");
                return Error(Errors.InvalidGrant, "Неверное имя пользователя или пароль.");
            }

            var check = await signIn.CheckPasswordSignInAsync(user, request.Password ?? "", lockoutOnFailure: true);
            if (check.IsLockedOut)
                await audit.WriteAsync(AuditTypes.LockedOut, false, AuditSeverity.Warning, request.ClientId, user.Id,
                    new { channel = "password_grant" }, $"user:{user.Id}", user.UserName);
            if (!check.Succeeded && !check.IsLockedOut)
                await audit.WriteAsync(AuditTypes.LoginFailed, false, AuditSeverity.Info, request.ClientId, user.Id,
                    new { reason = "bad_password", channel = "password_grant" }, $"user:{user.Id}", user.UserName);
            if (check.IsLockedOut)
                await webhooks.PublishAsync(WebhookEvents.UserLockedOut,
                    $"🔒 Учётная запись {user.UserName} заблокирована (password grant, клиент {request.ClientId}).",
                    new { userId = user.Id, userName = user.UserName, clientId = request.ClientId });
            if (!check.Succeeded)
                return Error(Errors.InvalidGrant, check.IsLockedOut
                    ? "Учётная запись временно заблокирована из-за неудачных попыток входа."
                    : "Неверное имя пользователя или пароль.");

            // Сменить пароль в password grant нельзя (нет UI) — просроченный пароль помечаем
            // «требует смены» и отправляем пользователя в веб-интерфейс.
            var expired = Security.AppUserManager.IsPasswordExpired(user, (await settings.GetAsync()).Passwords);
            if (expired) await userService.RecordLoginAsync(user.Id, mustChangePassword: true);
            if (user.MustChangePassword || expired)
                return Error(Errors.InvalidGrant, "Используется временный или просроченный пароль: смените его через веб-интерфейс (/Account/ChangePassword).");

            await userService.RecordLoginAsync(user.Id, mustChangePassword: false);

            var identity = await principals.CreateForUserAsync(user, request.ClientId!, request.GetScopes());
            // Ad-hoc авторизация: привязывает выданный refresh-токен к записи, которую можно отозвать из админки.
            var application = await applications.FindByClientIdAsync(request.ClientId!);
            var authorization = await authorizations.CreateAsync(identity, user.Id.ToString(),
                (await applications.GetIdAsync(application!))!, AuthorizationTypes.AdHoc, identity.GetScopes());
            identity.SetAuthorizationId(await authorizations.GetIdAsync(authorization));

            await audit.WriteAsync(AuditTypes.LoginSucceeded, true, AuditSeverity.Info, request.ClientId, user.Id,
                new { channel = "password_grant" }, $"user:{user.Id}", user.UserName);
            return await IssueAsync(identity, GrantTypes.Password, request.ClientId!, user.Id, user.UserName);
        }

        // Client credentials: сервис-к-сервису без пользователя. Субъект токена — сам клиент;
        // его права берутся из ролей сервисной учётной записи (SubjectType.Client) в матрицах приложений.
        if (request.IsClientCredentialsGrantType())
        {
            var application = await applications.FindByClientIdAsync(request.ClientId!)
                              ?? throw new InvalidOperationException("Приложение не найдено.");
            var identity = await principals.CreateForClientAsync(request.ClientId!,
                await applications.GetDisplayNameAsync(application), request.GetScopes());
            return await IssueAsync(identity, GrantTypes.ClientCredentials, request.ClientId!, null, request.ClientId);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Код/refresh-токен уже проверены OpenIddict (подпись, срок, статус в БД).
            // Для refresh включена ротация с «окном повторного использования» (RefreshTokenReuseLeewaySeconds):
            // старый refresh-токен ещё короткое время принимается, чтобы параллельные запросы клиента
            // или повтор после сетевого сбоя не приводили к разлогину. Повтор вне окна OpenIddict
            // считает кражей и отзывает всю цепочку токенов авторизации.
            var principal = (await HttpContext.AuthenticateAsync(Scheme)).Principal;
            if (principal is null)
                return Error(Errors.InvalidGrant, "Токен недействителен.");

            // Principal пересобирается заново, а не копируется из старого токена: так в новый токен попадают
            // актуальные роли/разрешения, а заблокированный с тех пор пользователь токен не получит.
            ClaimsIdentity identity;
            if (principal.GetClaim(CustomClaims.SubjectType) == "client")
            {
                identity = await principals.CreateForClientAsync(principal.GetClaim(Claims.Subject)!, null,
                    principal.GetScopes(), request.ClientId);
            }
            else
            {
                var user = await users.FindByIdAsync(principal.GetClaim(Claims.Subject) ?? "");
                if (user is not { IsActive: true })
                    return Error(Errors.InvalidGrant, "Пользователь не найден или заблокирован.");

                identity = await principals.CreateForUserAsync(user, request.ClientId!, principal.GetScopes());
            }

            // Сохраняем привязку к той же авторизации (сессии), чтобы её отзыв продолжал действовать.
            identity.SetAuthorizationId(principal.GetAuthorizationId());
            Guid? uid = Guid.TryParse(identity.GetClaim(Claims.Subject), out var g) && identity.GetClaim(CustomClaims.SubjectType) == "user" ? g : null;
            return await IssueAsync(identity, request.GrantType!, request.ClientId!, uid, identity.GetClaim(Claims.PreferredUsername));
        }

        if (request.IsTokenExchangeGrantType())
        {
            // RFC 8693: сервис A предъявляет токен пользователя (subject_token), полученный им как ресурсом,
            // и получает токен того же пользователя для сервиса B (scope=B). Подпись, срок и отзыв
            // subject_token уже проверены OpenIddict.
            var subject = (await HttpContext.AuthenticateAsync(Scheme)).Principal;
            if (subject is null)
                return Error(Errors.InvalidGrant, "subject_token недействителен.");

            // Обменивать можно только токен, адресованный самому клиенту (защита от повторного использования чужих токенов).
            if (!subject.GetAudiences().Contains(request.ClientId!))
                return Error(Errors.InvalidGrant, "subject_token выдан не для этого клиента (aud не содержит client_id).");

            ClaimsIdentity identity;
            if (subject.GetClaim(CustomClaims.SubjectType) == "client")
            {
                identity = await principals.CreateForClientAsync(subject.GetClaim(Claims.Subject)!, null,
                    request.GetScopes(), request.ClientId);
            }
            else
            {
                var user = await users.FindByIdAsync(subject.GetClaim(Claims.Subject) ?? "");
                if (user is not { IsActive: true, MustChangePassword: false })
                    return Error(Errors.InvalidGrant, "Пользователь не найден или заблокирован.");

                identity = await principals.CreateForUserAsync(user, request.ClientId!, request.GetScopes());
            }

            // Claim act (RFC 8693) фиксирует цепочку делегирования: кто действует от имени пользователя
            // (с учётом предыдущего актора при многошаговом обмене).
            TokenPrincipalFactory.AddActor(identity, request.ClientId!, subject.GetClaim(CustomClaims.Actor));
            Guid? xid = Guid.TryParse(identity.GetClaim(Claims.Subject), out var xg) && identity.GetClaim(CustomClaims.SubjectType) == "user" ? xg : null;
            return await IssueAsync(identity, GrantTypes.TokenExchange, request.ClientId!, xid, identity.GetClaim(Claims.PreferredUsername),
                new { actor = request.ClientId, previousActor = subject.GetClaim(CustomClaims.Actor) });
        }

        if (request.GrantType == PatGrantType)
        {
            // Персональный токен доступа (tslpat_…) → короткоживущий JWT с текущими правами владельца.
            // PatService сравнивает SHA-256 предъявленного токена с хранимым хешем (сам токен в БД не хранится),
            // проверяет срок/отзыв и фиксирует время и IP последнего использования.
            var validated = await pats.ValidateAsync((string?)request.GetParameter("token"), HttpContext.Connection.RemoteIpAddress?.ToString());
            if (validated is not { } pat)
            {
                await audit.WriteAsync("pat.rejected", false, AuditSeverity.Warning, PatService.PatClientId);
                return Error(Errors.InvalidGrant, "Персональный токен недействителен, истёк или отозван.");
            }

            var audiences = pat.Token.Audiences.Split(",", StringSplitOptions.RemoveEmptyEntries);
            var identity = await principals.CreateForUserAsync(pat.User, PatService.PatClientId, [.. audiences], audiences: audiences);
            identity.SetClaim("pat_id", pat.Token.Id.ToString());
            // Только access token (без id/refresh): security stamp не должен утечь наружу ни в один токен.
            identity.SetDestinations(c => c.Type == "AspNet.Identity.SecurityStamp" ? [] : [Destinations.AccessToken]);
            return await IssueAsync(identity, PatGrantType, PatService.PatClientId, pat.User.Id, pat.User.UserName,
                new { tokenId = pat.Token.Id, tokenName = pat.Token.Name });
        }

        return Error(Errors.UnsupportedGrantType, "Тип гранта не поддерживается.");
    }

    /// <summary>OIDC UserInfo: claims профиля по access token; состав зависит от выданных scope (profile, email).</summary>
    [Authorize(AuthenticationSchemes = Scheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> UserInfo()
    {
        var user = await users.FindByIdAsync(User.GetClaim(Claims.Subject) ?? "");
        if (user is not { IsActive: true })
            return Challenge(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Пользователь не найден или заблокирован."
            }), Scheme);

        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id.ToString()
        };

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.DisplayName ?? user.UserName;
            claims[Claims.PreferredUsername] = user.UserName;
        }

        if (User.HasScope(Scopes.Email) && user.Email is not null)
        {
            claims[Claims.Email] = user.Email;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        return Ok(claims);
    }

    /// <summary>
    /// OIDC end_session: гасит cookie веб-входа и через OpenIddict перенаправляет на
    /// post_logout_redirect_uri клиента (или на главную, если он не передан).
    /// </summary>
    [HttpGet("~/connect/logout"), HttpPost("~/connect/logout"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        if (User.Identity?.IsAuthenticated == true)
            await audit.WriteAsync(AuditTypes.Logout, true, AuditSeverity.Info, HttpContext.GetOpenIddictServerRequest()?.ClientId,
                Guid.TryParse(users.GetUserId(User), out var lid) ? lid : null);
        await signIn.SignOutAsync();
        return SignOut(new AuthenticationProperties { RedirectUri = "/" }, Scheme);
    }

    // Forbid со схемой OpenIddict превращается в стандартный OAuth-ответ {error, error_description}.
    private ForbidResult Error(string error, string description) =>
        Forbid(new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        }), Scheme);
}
