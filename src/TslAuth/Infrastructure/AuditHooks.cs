using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Mvc.Filters;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using TslAuth.Data;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace TslAuth.Infrastructure;

/// <summary>
/// Аудит всех изменяющих запросов Admin API / App API: кто, какой маршрут, результат.
/// Подключается к группам маршрутов в AdminApi, AppApi и EventsApi; запись идёт через AuditService
/// (буферизованная пакетная запись в фоне, запрос не ждёт БД).
/// </summary>
public sealed class ApiAuditFilter(string type) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        // Чтения не аудируются — только изменения.
        if (HttpMethods.IsGet(http.Request.Method)) return await next(context);

        object? result = null;
        Exception? error = null;
        try
        {
            result = await next(context);
            return result;
        }
        catch (Exception ex)
        {
            error = ex;
            throw;
        }
        finally
        {
            // Пишем и при исключении. Ошибки бизнес-логики (AdminException: 400/404/409) и некорректные запросы —
            // со своим кодом и уровнем Info: иначе каждая опечатка в API попадала бы в журнал как сбой (500)
            // с немедленным security.alert. Warning и алерт — только для настоящих сбоев (5xx).
            // Для App API приложение — это сам вызывающий клиент (sub токена), для Admin API — clientId из маршрута.
            var status = error switch
            {
                null => (result as IStatusCodeHttpResult)?.StatusCode ?? http.Response.StatusCode,
                AdminException admin => admin.StatusCode,
                BadHttpRequestException bad => bad.StatusCode,
                _ => StatusCodes.Status500InternalServerError
            };
            var clientId = type == AuditTypes.AppApiChange ? http.User.GetClaim(Claims.Subject)
                : http.Request.RouteValues.TryGetValue("clientId", out var c) ? c?.ToString() : null;
            Guid? userId = http.Request.RouteValues.TryGetValue("id", out var id) && Guid.TryParse(id?.ToString(), out var g) ? g : null;
            await http.RequestServices.GetRequiredService<AuditService>().WriteAsync(type, status < 400,
                status >= 500 ? AuditSeverity.Warning : AuditSeverity.Info, clientId, userId,
                new { method = http.Request.Method, path = http.Request.Path.Value, status });
        }
    }
}

/// <summary>
/// Аудит POST-действий в веб-админке (все изменения через интерфейс).
/// Навешивается на папку /Admin конвенцией Razor Pages в ServiceSetup.
/// </summary>
public sealed class AdminPageAuditFilter : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var executed = await next();
        var http = context.HttpContext;
        if (!HttpMethods.IsPost(http.Request.Method)) return;

        // Ошибки валидации формы тоже считаются неуспешной попыткой изменения (текст ошибок — в details).
        var failed = executed.Exception is not null || !context.ModelState.IsValid || http.Response.StatusCode >= 400;
        var query = http.Request.Query;
        Guid? userId = Guid.TryParse(query["id"], out var g) ? g : null;
        await http.RequestServices.GetRequiredService<AuditService>().WriteAsync(AuditTypes.AdminChange, !failed,
            AuditSeverity.Info, query["clientId"].ToString() is { Length: > 0 } c ? c : null, userId,
            new
            {
                page = context.ActionDescriptor.ViewEnginePath,
                handler = context.HandlerMethod?.Name,
                errors = context.ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToArray()
            });
    }
}

/// <summary>
/// Попытки доступа без прав (403) к админке и API — событие безопасности.
/// Заменяет стандартный обработчик результата авторизации (регистрация в ServiceSetup), затем делегирует ему.
/// </summary>
public sealed class AuditingAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _default = new();

    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult result)
    {
        if (result.Forbidden)
        {
            await context.RequestServices.GetRequiredService<AuditService>().WriteAsync(AuditTypes.AccessDenied, false,
                AuditSeverity.Warning, details: new { method = context.Request.Method, path = context.Request.Path.Value });
        }
        await _default.HandleAsync(next, context, policy, result);
    }
}

/// <summary>
/// Ошибки token-эндпоинта, которые OpenIddict отклоняет до нашего контроллера
/// (неверный секрет клиента, недопустимый grant/scope, отозванный refresh-токен и т.п.).
/// Встраивается в конвейер OpenIddict через <see cref="Descriptor"/> (AddEventHandler в ServiceSetup).
/// </summary>
public sealed class TokenErrorAuditHandler(AuditService audit, TslAuthMetrics metrics) : IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    // Самый ранний порядок: обработчик должен увидеть ответ до того, как встроенные обработчики его отправят.
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>()
            .UseScopedHandler<TokenErrorAuditHandler>()
            .SetOrder(int.MinValue + 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyTokenResponseContext context)
    {
        if (string.IsNullOrEmpty(context.Response.Error)) return;
        metrics.TokenRejected(context.Request?.GrantType, context.Response.Error, context.Request?.ClientId);

        // Неверные учётные данные клиента — повод насторожиться (подбор секрета).
        var severity = context.Response.Error is Errors.InvalidClient ? AuditSeverity.Warning : AuditSeverity.Info;
        await audit.WriteAsync(AuditTypes.TokenRejected, false, severity, context.Request?.ClientId, details: new
        {
            grantType = context.Request?.GrantType,
            error = context.Response.Error,
            description = context.Response.ErrorDescription
        });
    }
}

/// <summary>
/// Отказы introspection и revocation (прежде всего invalid_client — подбор секрета клиента): эти эндпоинты
/// обрабатывает сам OpenIddict без нашего контроллера, поэтому ошибки перехватываются в его конвейере.
/// </summary>
public sealed class IntrospectionErrorAuditHandler(AuditService audit) : IOpenIddictServerHandler<ApplyIntrospectionResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyIntrospectionResponseContext>()
            .UseScopedHandler<IntrospectionErrorAuditHandler>()
            .SetOrder(int.MinValue + 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyIntrospectionResponseContext context) =>
        EndpointErrorAudit.WriteAsync(audit, "introspect", context.Request?.ClientId, context.Response);
}

/// <summary>Отказы revocation — см. <see cref="IntrospectionErrorAuditHandler"/>.</summary>
public sealed class RevocationErrorAuditHandler(AuditService audit) : IOpenIddictServerHandler<ApplyRevocationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyRevocationResponseContext>()
            .UseScopedHandler<RevocationErrorAuditHandler>()
            .SetOrder(int.MinValue + 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyRevocationResponseContext context) =>
        EndpointErrorAudit.WriteAsync(audit, "revoke", context.Request?.ClientId, context.Response);
}

internal static class EndpointErrorAudit
{
    public static async ValueTask WriteAsync(AuditService audit, string endpoint, string? clientId, OpenIddictResponse response)
    {
        if (string.IsNullOrEmpty(response.Error)) return;
        var severity = response.Error is Errors.InvalidClient ? AuditSeverity.Warning : AuditSeverity.Info;
        await audit.WriteAsync(AuditTypes.TokenRejected, false, severity, clientId, details: new
        {
            endpoint,
            error = response.Error,
            description = response.ErrorDescription
        });
    }
}
