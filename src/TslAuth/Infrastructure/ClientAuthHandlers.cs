using System.Threading.RateLimiting;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using TslAuth.Data;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace TslAuth.Infrastructure;

/// <summary>
/// Дополнительные правила входа клиента по ключу (<c>private_key_jwt</c>, RFC 7523) поверх встроенных проверок
/// OpenIddict (подпись по JWKS клиента, iss/sub/aud/exp): только ES256, срок assertion ≤ 5 минут, одноразовый
/// <c>jti</c> — вставка в таблицу ClientAssertionJtis, общую для всех узлов кластера (повтор — 0 вставленных строк).
/// Клиенту уходит только <c>invalid_client</c>; причина — в аудит (Warning) и метрику
/// <c>tsl_auth.client_assertion.rejected{reason}</c>. Встраивается после встроенных проверок assertion, перед ValidateClientId.
/// Работает для всех эндпоинтов с аутентификацией клиента: token, introspection, revocation.
/// </summary>
public sealed class ClientAssertionPolicyHandler(AuthDbContext db, AuditService audit, TslAuthMetrics metrics)
    : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    /// <summary>Предел длины jti: ключ «client_id:jti» должен уместиться в столбец (400) на любой СУБД одинаково.</summary>
    public const int MaxJtiLength = 255;

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseScopedHandler<ClientAssertionPolicyHandler>()
            .SetOrder(OpenIddictServerHandlers.ValidateClientId.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        // Встроенные обработчики уже проверили подпись и обязательные claims; без principal делать нечего.
        if (context.IsRejected || context.ClientAssertionPrincipal is null || string.IsNullOrEmpty(context.ClientAssertion)) return;

        var clientId = context.ClientAssertionPrincipal.GetClaim(Claims.Subject) ?? context.ClientId ?? "";
        var reason = ClientAssertionRules.Check(context.ClientAssertion, out var token);
        if (reason is null && token is not null && token.Id.Length > MaxJtiLength) reason = "jti_too_long";
        if (reason is null && token is not null)
        {
            // jti одноразовый: вставка по первичному ключу «client_id:jti», при конфликте — ничего (0 строк) → повтор.
            // Без отслеживания EF и без исключения: прочие ошибки БД остаются ошибками, а не «повтором».
            var key = $"{clientId}:{token.Id}";
            var expires = DateTime.SpecifyKind(token.ValidTo, DateTimeKind.Utc);
            var inserted = await db.Database.ExecuteSqlInterpolatedAsync(
                $"INSERT INTO \"ClientAssertionJtis\" (\"Jti\", \"ClientId\", \"ExpiresAt\") VALUES ({key}, {clientId}, {expires}) ON CONFLICT DO NOTHING",
                context.CancellationToken);
            if (inserted == 0) reason = "jti_replay";
        }
        if (reason is null) return;

        metrics.ClientAssertionRejected(reason);
        await audit.WriteAsync(AuditTypes.TokenRejected, false, AuditSeverity.Warning, clientId,
            details: new { endpoint = context.EndpointType.ToString(), reason, kid = token?.Kid, jti = Shorten(token?.Id), alg = token?.Alg });
        context.Reject(Errors.InvalidClient, ClientAuthErrorHandler.AssertionInvalid);
    }

    private static string? Shorten(string? value) => value is { Length: > 100 } ? value[..100] + "…" : value;
}

/// <summary>
/// Предварительная проверка assertion до встроенной валидации OpenIddict: временные claims (<c>iat</c>, <c>nbf</c>,
/// <c>exp</c>) должны быть числами в диапазоне дат .NET. OpenIddict 7.7 сам вызывает DateTimeOffset.FromUnixTimeSeconds
/// и на значении в миллисекундах падает исключением (HTTP 500) — здесь такой assertion отклоняется как invalid_client.
/// </summary>
public sealed class ClientAssertionPrecheckHandler(AuditService audit, TslAuthMetrics metrics)
    : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    private static readonly long MaxUnixSeconds = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseScopedHandler<ClientAssertionPrecheckHandler>()
            .SetOrder(OpenIddictServerHandlers.ValidateClientAssertion.Descriptor.Order - 100)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        if (context.IsRejected || string.IsNullOrEmpty(context.ClientAssertion)) return;
        // Payload читается напрямую (IdentityModel числа вне диапазона дат молча «зажимает», а OpenIddict — нет).
        var parts = context.ClientAssertion.Split('.');
        if (parts.Length < 2) return; // разбор и отказ сделает сама OpenIddict
        System.Text.Json.JsonDocument payload;
        try
        {
            payload = System.Text.Json.JsonDocument.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(parts[1]));
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or System.Text.Json.JsonException)
        {
            return;
        }
        using (payload)
        {
            if (payload.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object) return;
            foreach (var claim in (string[])["iat", "nbf", "exp"])
            {
                // Нечисловой claim отвергнет сама OpenIddict (ID2171); здесь — только числа вне диапазона дат.
                if (!payload.RootElement.TryGetProperty(claim, out var value) || value.ValueKind != System.Text.Json.JsonValueKind.Number) continue;
                if (value.TryGetDouble(out var seconds) && seconds >= 0 && seconds <= MaxUnixSeconds) continue;
                metrics.ClientAssertionRejected("time_claim_invalid");
                await audit.WriteAsync(AuditTypes.TokenRejected, false, AuditSeverity.Warning, context.ClientId,
                    details: new { endpoint = context.EndpointType.ToString(), reason = "time_claim_invalid", claim });
                context.Reject(Errors.InvalidClient, ClientAuthErrorHandler.AssertionInvalid);
                return;
            }
        }
    }
}

/// <summary>
/// Метаданные discovery для входа по ключу: <c>token_endpoint_auth_signing_alg_values_supported: ["ES256"]</c>
/// и гарантия, что <c>token_endpoint_auth_methods_supported</c> содержит <c>private_key_jwt</c>.
/// </summary>
public sealed class ClientAssertionMetadataHandler : IOpenIddictServerHandler<HandleConfigurationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
            .UseSingletonHandler<ClientAssertionMetadataHandler>()
            .SetOrder(OpenIddictServerHandlers.Discovery.AttachClientAuthenticationMethods.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(HandleConfigurationRequestContext context)
    {
        context.TokenEndpointAuthenticationMethods.Add(ClientAuthenticationMethods.PrivateKeyJwt);
        context.Metadata["token_endpoint_auth_signing_alg_values_supported"] = new OpenIddictParameter(System.Collections.Immutable.ImmutableArray.Create<string?>("ES256"));
        return default;
    }
}

/// <summary>
/// Отключённый клиент (свойство <c>tsl_disabled</c>) не получает токены и коды авторизации: <c>invalid_client</c>
/// на токен-эндпоинте (после аутентификации клиента) и на authorize. Проверка по БД на каждый запрос. Такой отказ
/// не считается попыткой подбора (<see cref="ClientAuthErrorHandler.NotCounted"/>): отключённый агент может
/// продолжать опрашивать сервис, это не атака.
/// </summary>
public sealed class DisabledClientHandler(ApplicationService apps)
    : IOpenIddictServerHandler<ValidateTokenRequestContext>, IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor TokenDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseScopedHandler<DisabledClientHandler>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateAuthentication.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor AuthorizationDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<DisabledClientHandler>()
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateAuthentication.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        if (!context.IsRejected && context.ClientId is { } clientId && await apps.IsDisabledAsync(clientId, context.CancellationToken))
        {
            context.Transaction.Properties[ClientAuthErrorHandler.NotCounted] = true;
            context.Reject(Errors.InvalidClient, "Приложение отключено.");
        }
    }

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        if (!context.IsRejected && context.ClientId is { } clientId && await apps.IsDisabledAsync(clientId, context.CancellationToken))
            context.Reject(Errors.InvalidClient, "Приложение отключено.");
    }
}

/// <summary>
/// Предел отказов аутентификации клиента: после N ошибок <c>invalid_client</c> за минуту пара «client_id + IP»
/// блокируется на минуту (подбор секрета или ключа). Ключ включает IP, чтобы посторонний не мог, подставляя чужой
/// client_id, заблокировать настоящего клиента с другого адреса. Считается в памяти каждого узла (как остальные
/// лимиты); отказы фиксирует <see cref="ClientAuthErrorHandler"/>, проверку делает <see cref="ClientFailureLimitHandler"/>.
/// </summary>
public sealed class ClientFailureLimiter(int failuresPerMinute, TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Dictionary<string, Window> _windows = new(StringComparer.Ordinal);
    private readonly Lock _sync = new();

    /// <summary>Порог отказов в минуту; 0 — предел выключен.</summary>
    public int FailuresPerMinute { get; } = failuresPerMinute;

    /// <summary>Ключ счётчика: client_id и адрес клиента.</summary>
    public static string Key(string clientId, string? ip) => $"{clientId}|{ip ?? "unknown"}";

    /// <summary>Заблокирован ли ключ сейчас.</summary>
    public bool IsBlocked(string key)
    {
        if (FailuresPerMinute <= 0) return false;
        lock (_sync) return _windows.TryGetValue(key, out var w) && w.BlockedUntil > _time.GetUtcNow();
    }

    /// <summary>Учитывает отказ; при достижении порога блокирует на минуту. Возвращает true, если блокировка наступила именно сейчас.</summary>
    public bool RecordFailure(string key)
    {
        if (FailuresPerMinute <= 0) return false;
        var now = _time.GetUtcNow();
        lock (_sync)
        {
            _windows.TryGetValue(key, out var w);
            if (w is not null && w.BlockedUntil > now) return false;
            var fresh = w is null || now - w.Start >= TimeSpan.FromMinutes(1);
            var count = fresh ? 1 : w!.Count + 1;
            var blocked = count >= FailuresPerMinute;
            _windows[key] = blocked
                ? new Window(now, 0, now.AddMinutes(1))
                : new Window(fresh ? now : w!.Start, count, DateTimeOffset.MinValue);

            // Редкая уборка старых окон, чтобы словарь не рос от одноразовых client_id.
            if (_windows.Count > 10_000)
                foreach (var (k, old) in _windows.ToList())
                    if (now - old.Start > TimeSpan.FromMinutes(5) && old.BlockedUntil < now) _windows.Remove(k);
            return blocked;
        }
    }

    private sealed record Window(DateTimeOffset Start, int Count, DateTimeOffset BlockedUntil);
}

/// <summary>
/// Отклоняет запросы заблокированного клиента (token, introspection, revocation) — сразу после аутентификации
/// клиента, когда client_id известен и в том случае, когда он выведен из assertion (RFC 7523 позволяет его не передавать).
/// </summary>
public sealed class ClientFailureLimitHandler(ClientFailureLimiter limiter, TslAuthMetrics metrics, IHttpContextAccessor http)
    : IOpenIddictServerHandler<ValidateTokenRequestContext>, IOpenIddictServerHandler<ValidateIntrospectionRequestContext>,
      IOpenIddictServerHandler<ValidateRevocationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor TokenDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<ClientFailureLimitHandler>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateAuthentication.Descriptor.Order + 400)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor IntrospectionDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateIntrospectionRequestContext>()
            .UseSingletonHandler<ClientFailureLimitHandler>()
            .SetOrder(OpenIddictServerHandlers.Introspection.ValidateAuthentication.Descriptor.Order + 400)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor RevocationDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
            .UseSingletonHandler<ClientFailureLimitHandler>()
            .SetOrder(OpenIddictServerHandlers.Revocation.ValidateAuthentication.Descriptor.Order + 400)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context) => Check(context);
    public ValueTask HandleAsync(ValidateIntrospectionRequestContext context) => Check(context);
    public ValueTask HandleAsync(ValidateRevocationRequestContext context) => Check(context);

    private ValueTask Check(BaseValidatingClientContext context)
    {
        if (!context.IsRejected && context.ClientId is { Length: > 0 } clientId &&
            limiter.IsBlocked(ClientFailureLimiter.Key(clientId, http.HttpContext?.Connection.RemoteIpAddress?.ToString())))
        {
            metrics.ClientAssertionRejected("client_blocked");
            context.Transaction.Properties[ClientAuthErrorHandler.NotCounted] = true;
            context.Reject(Errors.InvalidClient, "Слишком много неудачных попыток входа клиента: повторите через минуту.");
        }
        return default;
    }
}

/// <summary>
/// Общая обработка ошибок аутентификации клиента на token, introspection и revocation (событие ProcessError OpenIddict,
/// до того как ошибка попадёт в ответ):
/// <list type="bullet">
/// <item>отказы встроенных проверок assertion (<c>invalid_token</c> — подпись, aud, срок; <c>invalid_request</c> — нет
/// обязательного claim; <c>invalid_grant</c> — iss/sub не совпадают с client_id) превращаются в <c>invalid_client</c> без
/// подробностей (постановка 3.3), а причина уходит в журнал (Warning) и метрику;</item>
/// <item>каждый <c>invalid_client</c> (кроме отключённого клиента и уже действующей блокировки) учитывается в
/// <see cref="ClientFailureLimiter"/>; наступившая блокировка — запись Warning в журнал.</item>
/// </list>
/// Подбор ключа или секрета поэтому одинаково ограничен на всех трёх эндпоинтах.
/// </summary>
public sealed class ClientAuthErrorHandler(AuditService audit, TslAuthMetrics metrics, ClientFailureLimiter limiter,
    IHttpContextAccessor http) : IOpenIddictServerHandler<ProcessErrorContext>
{
    /// <summary>Свойство транзакции: отказ не считается попыткой подбора (отключённый клиент, действующая блокировка).</summary>
    public const string NotCounted = "tsl:client_auth_not_counted";

    /// <summary>Единственное описание ошибки, которое видит клиент при отказе assertion.</summary>
    public const string AssertionInvalid = "The client assertion is invalid.";

    // Коды OpenIddict для отказов проверок assertion: ID2171 — claim неверного формата, ID2172 — нет обязательного
    // claim, ID2173 — iss/sub не совпадают с ожидаемыми (client_id).
    private static readonly string[] AssertionErrorIds = ["ID2171", "ID2172", "ID2173"];

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
            .UseScopedHandler<ClientAuthErrorHandler>()
            .SetOrder(OpenIddictServerHandlers.AttachErrorParameters.Descriptor.Order - 1_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessErrorContext context)
    {
        if (context.EndpointType is not (OpenIddictServerEndpointType.Token or OpenIddictServerEndpointType.Introspection
            or OpenIddictServerEndpointType.Revocation)) return;
        var clientId = context.Request?.ClientId;

        if (!string.IsNullOrEmpty(context.Request?.ClientAssertion) && context.Error != Errors.InvalidClient &&
            (context.Error == Errors.InvalidToken || AssertionErrorIds.Any(id => context.ErrorUri?.EndsWith(id, StringComparison.Ordinal) == true)))
        {
            metrics.ClientAssertionRejected("server_validation");
            await audit.WriteAsync(AuditTypes.TokenRejected, false, AuditSeverity.Warning, clientId, details: new
            {
                endpoint = context.EndpointType.ToString(), reason = "server_validation", error = context.Error,
                description = context.ErrorDescription
            });
            context.Error = Errors.InvalidClient;
            context.ErrorDescription = AssertionInvalid;
            context.ErrorUri = null;
        }

        if (context.Error != Errors.InvalidClient || string.IsNullOrEmpty(clientId) ||
            context.Transaction.Properties.ContainsKey(NotCounted)) return;
        if (limiter.RecordFailure(ClientFailureLimiter.Key(clientId, http.HttpContext?.Connection.RemoteIpAddress?.ToString())))
            await audit.WriteAsync(AuditTypes.TokenRejected, false, AuditSeverity.Warning, clientId,
                details: new { reason = "client_blocked", failuresPerMinute = limiter.FailuresPerMinute });
    }
}

/// <summary>
/// Предел изменений подчинённых клиентов на владельца (30 в минуту по умолчанию). Фильтр группы
/// /api/app/clients: лимитер middleware здесь не подходит — владелец известен только после проверки токена.
/// </summary>
public sealed class ManagedClientRateLimiter(int changesPerMinute) : IDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter = PartitionedRateLimiter.Create<string, string>(owner =>
        RateLimitPartition.GetFixedWindowLimiter(owner, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, changesPerMinute), Window = TimeSpan.FromMinutes(1)
        }));

    /// <summary>Пытается получить разрешение на изменение для владельца.</summary>
    public ValueTask<RateLimitLease> AcquireAsync(string owner, CancellationToken ct) => _limiter.AcquireAsync(owner, 1, ct);

    public void Dispose() => _limiter.Dispose();
}
