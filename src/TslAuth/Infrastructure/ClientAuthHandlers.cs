using System.Collections.Concurrent;
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
/// <c>jti</c> — вставка в таблицу ClientAssertionJtis по первичному ключу, общая для всех узлов кластера.
/// Клиенту уходит только <c>invalid_client</c>; причина — в аудит (Warning) и метрику
/// <c>tsl_auth.client_assertion.rejected{reason}</c>. Встраивается после ValidateClientAssertionAudience, до ValidateClientId.
/// </summary>
public sealed class ClientAssertionPolicyHandler(AuthDbContext db, AuditService audit, TslAuthMetrics metrics)
    : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
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

        var clientId = context.ClientAssertionPrincipal.GetClaim(Claims.Subject) ?? context.ClientId;
        var reason = ClientAssertionRules.Check(context.ClientAssertion, out var token);
        if (reason is null && token is not null)
        {
            // jti одноразовый: первичный ключ «client_id:jti» — повтор даёт ошибку уникальности на любом узле.
            var entry = new ClientAssertionJti { Jti = $"{clientId}:{token.Id}", ClientId = clientId ?? "", ExpiresAt = token.ValidTo };
            db.ClientAssertionJtis.Add(entry);
            try
            {
                await db.SaveChangesAsync(context.CancellationToken);
            }
            catch (DbUpdateException)
            {
                // DbContext общий с менеджерами OpenIddict в этом же запросе: неудачную вставку нужно снять с учёта.
                db.Entry(entry).State = EntityState.Detached;
                reason = "jti_replay";
            }
        }
        if (reason is null) return;

        metrics.ClientAssertionRejected(reason);
        await audit.WriteAsync(AuditTypes.TokenRejected, false, AuditSeverity.Warning, clientId,
            details: new { endpoint = "client_assertion", reason, kid = token?.Kid, jti = token?.Id, alg = token?.Alg });
        context.Reject(Errors.InvalidClient, "The client assertion is invalid.");
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
/// на токен-эндпоинте (после аутентификации клиента) и на authorize. Проверка по БД на каждый запрос.
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
            context.Reject(Errors.InvalidClient, "Приложение отключено.");
    }

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        if (!context.IsRejected && context.ClientId is { } clientId && await apps.IsDisabledAsync(clientId, context.CancellationToken))
            context.Reject(Errors.InvalidClient, "Приложение отключено.");
    }
}

/// <summary>
/// Предел отказов аутентификации клиента по <c>client_id</c> на токен-эндпоинте: после N ошибок
/// <c>invalid_client</c> за минуту клиент блокируется на минуту (подбор секрета или ключа). Считается в памяти
/// каждого узла (как остальные лимиты); отказы фиксирует <see cref="TokenErrorAuditHandler"/>.
/// </summary>
public sealed class ClientFailureLimiter(int failuresPerMinute, TimeProvider? time = null)
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, Window> _windows = new(StringComparer.Ordinal);

    /// <summary>Порог отказов в минуту; 0 — предел выключен.</summary>
    public int FailuresPerMinute { get; } = failuresPerMinute;

    /// <summary>Заблокирован ли клиент сейчас.</summary>
    public bool IsBlocked(string clientId) =>
        FailuresPerMinute > 0 && _windows.TryGetValue(clientId, out var w) && w.BlockedUntil > _time.GetUtcNow();

    /// <summary>Учитывает отказ; при достижении порога блокирует клиента на минуту. Возвращает true, если блокировка только что наступила.</summary>
    public bool RecordFailure(string clientId)
    {
        if (FailuresPerMinute <= 0) return false;
        var now = _time.GetUtcNow();
        var blocked = false;
        _windows.AddOrUpdate(clientId, _ => new Window(now, 1, DateTimeOffset.MinValue), (_, w) =>
        {
            if (w.BlockedUntil > now) return w;
            var (start, count) = now - w.Start >= TimeSpan.FromMinutes(1) ? (now, 1) : (w.Start, w.Count + 1);
            if (count < FailuresPerMinute) return new Window(start, count, DateTimeOffset.MinValue);
            blocked = true;
            return new Window(now, 0, now.AddMinutes(1));
        });
        // Редкая уборка старых окон, чтобы словарь не рос от одноразовых client_id.
        if (_windows.Count > 10_000)
            foreach (var (key, w) in _windows)
                if (now - w.Start > TimeSpan.FromMinutes(5) && w.BlockedUntil < now) _windows.TryRemove(key, out _);
        return blocked;
    }

    private sealed record Window(DateTimeOffset Start, int Count, DateTimeOffset BlockedUntil);
}

/// <summary>Отклоняет запросы токена заблокированного клиента ещё до проверки его учётных данных.</summary>
public sealed class ClientFailureLimitHandler(ClientFailureLimiter limiter, TslAuthMetrics metrics)
    : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<ClientFailureLimitHandler>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateAuthentication.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        if (!context.IsRejected && context.ClientId is { } clientId && limiter.IsBlocked(clientId))
        {
            metrics.ClientAssertionRejected("client_blocked");
            context.Reject(Errors.InvalidClient, "Слишком много неудачных попыток входа клиента: повторите через минуту.");
        }
        return default;
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

/// <summary>
/// Встроенные проверки assertion OpenIddict (aud, exp, подпись) отвечают <c>invalid_token</c> с подробностями.
/// Наружу уходит только <c>invalid_client</c> без деталей (постановка 3.3); подробная причина — в аудит (Warning)
/// и метрику. Работает до <see cref="TokenErrorAuditHandler"/>, чтобы отказ считался и в блокировку client_id.
/// </summary>
public sealed class ClientAssertionErrorNormalizer(AuditService audit, TslAuthMetrics metrics)
    : IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>()
            .UseScopedHandler<ClientAssertionErrorNormalizer>()
            .SetOrder(TokenErrorAuditHandler.Descriptor.Order - 1_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyTokenResponseContext context)
    {
        if (context.Response.Error is not Errors.InvalidToken || string.IsNullOrEmpty(context.Request?.ClientAssertion)) return;
        metrics.ClientAssertionRejected("server_validation");
        await audit.WriteAsync(AuditTypes.TokenRejected, false, AuditSeverity.Warning, context.Request?.ClientId, details: new
        {
            endpoint = "client_assertion", reason = "server_validation", description = context.Response.ErrorDescription
        });
        context.Response.Error = Errors.InvalidClient;
        context.Response.ErrorDescription = "The client assertion is invalid.";
        context.Response.ErrorUri = null;
    }
}
