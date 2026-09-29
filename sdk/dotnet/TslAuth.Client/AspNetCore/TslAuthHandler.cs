using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TslAuth.Client.AspNetCore;

/// <summary>Константы схемы аутентификации TSL Auth.</summary>
public static class TslAuthDefaults
{
    /// <summary>Имя схемы аутентификации.</summary>
    public const string AuthenticationScheme = "TslAuth";
    /// <summary>Realm в заголовке <c>WWW-Authenticate</c>.</summary>
    public const string Realm = "tsl-auth";
    /// <summary>Ключ <c>HttpContext.Items</c> с кодом отказа аутентификации (§2).</summary>
    public const string ItemErrorCode = "TslAuth.ErrorCode";
    /// <summary>Ключ <c>HttpContext.Items</c> с кодом отказа авторизации (§5).</summary>
    public const string ItemForbidCode = "TslAuth.ForbidCode";
    /// <summary>Ключ <c>HttpContext.Items</c> с описанием отказа авторизации («что требовалось»).</summary>
    public const string ItemForbidDescription = "TslAuth.ForbidDescription";
}

/// <summary>Параметры схемы; сама конфигурация SDK — в <see cref="TslAuthOptions"/> (DI).</summary>
public sealed class TslAuthSchemeOptions : AuthenticationSchemeOptions
{
}

/// <summary>
/// Схема <c>TslAuth</c>: Bearer из заголовка <c>Authorization</c>, проверка через <see cref="TslAuthVerifier"/>,
/// ответы 401/403 строго по §5 контракта (JSON-тело и <c>WWW-Authenticate</c>).
/// </summary>
public sealed class TslAuthHandler : AuthenticationHandler<TslAuthSchemeOptions>
{
    private readonly TslAuthVerifier _verifier;

    /// <summary>Создаётся DI.</summary>
    public TslAuthHandler(IOptionsMonitor<TslAuthSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, TslAuthVerifier verifier)
        : base(options, logger, encoder)
    {
        _verifier = verifier;
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var principal = await _verifier.VerifyAuthorizationHeaderAsync(Request.Headers.Authorization.ToString(), Context.RequestAborted)
                .ConfigureAwait(false);
            Context.Features.Set(principal);
            var user = principal.ToClaimsPrincipal(Scheme.Name);
            return AuthenticateResult.Success(new AuthenticationTicket(user, Scheme.Name));
        }
        catch (TslAuthException ex)
        {
            Context.Items[TslAuthDefaults.ItemErrorCode] = ex.Code;
            // Нет токена — NoResult (другие схемы могут сработать); испорченный токен — отказ. Оба дают 401 через Challenge.
            return ex.Code == TslAuthErrorCodes.Missing ? AuthenticateResult.NoResult() : AuthenticateResult.Fail(ex);
        }
    }

    /// <inheritdoc />
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var code = Context.Items.TryGetValue(TslAuthDefaults.ItemErrorCode, out var c) && c is string s ? s : TslAuthErrorCodes.Missing;
        return WriteAsync(Context, StatusCodes.Status401Unauthorized, "invalid_token", code);
    }

    /// <inheritdoc />
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        var code = Context.Items.TryGetValue(TslAuthDefaults.ItemForbidCode, out var c) && c is string s ? s : "insufficient_permissions";
        var description = Context.Items.TryGetValue(TslAuthDefaults.ItemForbidDescription, out var d) && d is string ds ? ds : "forbidden";
        return WriteAsync(Context, StatusCodes.Status403Forbidden, code, description);
    }

    /// <summary>Пишет ответ по RFC 6750: заголовок <c>WWW-Authenticate</c> и JSON-тело.</summary>
    internal static async Task WriteAsync(HttpContext context, int status, string error, string description)
    {
        var response = context.Response;
        if (response.HasStarted) return;
        response.StatusCode = status;
        response.Headers.WWWAuthenticate =
            $"Bearer realm=\"{TslAuthDefaults.Realm}\", error=\"{error}\", error_description=\"{Escape(description)}\"";
        response.ContentType = "application/json; charset=utf-8";
        await response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(new { error, error_description = description }))
            .ConfigureAwait(false);
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
