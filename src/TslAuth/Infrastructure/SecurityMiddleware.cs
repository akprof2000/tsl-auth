using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace TslAuth.Infrastructure;

/// <summary>
/// Настройки секции "Security" (лимиты частоты запросов). Лимиты считаются в памяти каждого экземпляра,
/// поэтому в кластере фактический лимит на IP = значение × число экземпляров.
/// </summary>
public sealed class SecurityOptions
{
    public const string Section = "Security";

    /// <summary>Лимит запросов к /connect/token с одного IP в минуту (на экземпляр).</summary>
    public int TokenRequestsPerMinute { get; set; } = 600;

    /// <summary>Лимит попыток входа/сброса пароля с одного IP в минуту (на экземпляр).</summary>
    public int LoginAttemptsPerMinute { get; set; } = 30;
}

/// <summary>
/// Защитные механизмы уровня HTTP: rate limiting (политики token/login), HSTS и заголовки безопасности (CSP и др.).
/// Регистрация — из ServiceSetup (AddTslSecurity), подключение в конвейер — из Program.cs (UseSecurityHeaders).
/// </summary>
public static class SecurityMiddleware
{
    public const string TokenPolicy = "token";

    /// <summary>
    /// SHA-256 inline-скрипта автоотправки формы OpenIddict (response_mode=form_post).
    /// Хеш привязан к разметке, которую генерирует OpenIddict: при обновлении пакета, если скрипт изменится,
    /// браузер заблокирует автоотправку — хеш нужно пересчитать.
    /// </summary>
    private const string FormPostScriptHash = "sha256-j7OoGArf6XW6YY4cAyS3riSSvrJRqpSi1fOF9vQ5SrI=";
    public const string LoginPolicy = "login";

    /// <summary>Регистрирует политики ограничения частоты запросов и HSTS.</summary>
    public static void AddTslSecurity(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection(SecurityOptions.Section).Get<SecurityOptions>() ?? new SecurityOptions();

        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.AddPolicy(TokenPolicy, ctx => PerIp(ctx, options.TokenRequestsPerMinute));
            // Ограничиваем только POST (попытки ввода пароля), показ страниц входа не лимитируется.
            o.AddPolicy(LoginPolicy, ctx => HttpMethods.IsPost(ctx.Request.Method)
                ? PerIp(ctx, options.LoginAttemptsPerMinute)
                : RateLimitPartition.GetNoLimiter("get"));
        });

        services.AddHsts(o => o.MaxAge = TimeSpan.FromDays(365));
    }

    // Партиция по IP клиента; за балансировщиком корректный IP даёт только включённый TrustForwardedHeaders.
    private static RateLimitPartition<string> PerIp(HttpContext ctx, int permitsPerMinute) =>
        RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = permitsPerMinute, Window = TimeSpan.FromMinutes(1) });

    /// <summary>Заголовки безопасности: запрет фреймов, строгий CSP (все ресурсы только свои), no-referrer и т.д.</summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        // OnStarting: заголовки выставляются прямо перед отправкой ответа и перекрывают то, что задали обработчики ниже.
        context.Response.OnStarting(() =>
        {
            var h = context.Response.Headers;
            h["X-Content-Type-Options"] = "nosniff";
            h["X-Frame-Options"] = "DENY";
            h["Referrer-Policy"] = "no-referrer";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
            // form-action не ограничиваем: после входа форма OIDC уходит на redirect_uri клиента.
            // Справочник API (Scalar) использует inline-конфигурацию — для него разрешён inline-скрипт; все ресурсы — локальные.
            h["Content-Security-Policy"] = context.Request.Path.StartsWithSegments(ApiDocs.ReferencePath)
                ? "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                  "connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'"
                : context.Request.Path.StartsWithSegments("/connect")
                    // response_mode=form_post: OpenIddict отдаёт форму с фиксированным скриптом автоотправки —
                    // разрешён только он (по хешу), а не любые inline-скрипты.
                    ? "default-src 'self'; script-src 'self' '" + FormPostScriptHash + "'; style-src 'self' 'unsafe-inline'; " +
                      "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
                    : "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                      "object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
            // Ответы с токенами и данными API не должны оседать в кэшах браузера/прокси.
            if (context.Request.Path.StartsWithSegments("/connect") || context.Request.Path.StartsWithSegments("/api"))
                h.CacheControl = "no-store";
            h.Remove("Server");
            return Task.CompletedTask;
        });
        await next();
    });
}
