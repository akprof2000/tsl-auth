using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace TslAuth.Client.AspNetCore;

/// <summary>Подключение TSL Auth к ASP.NET Core. Дальше достаточно стандартных <c>UseAuthentication</c>/<c>UseAuthorization</c>.</summary>
public static class TslAuthServiceCollectionExtensions
{
    /// <summary>Настройки из переменных окружения <c>TSL_AUTH_*</c>.</summary>
    public static IServiceCollection AddTslAuth(this IServiceCollection services) =>
        services.AddTslAuth(TslAuthOptions.FromEnvironment());

    /// <summary>Настройки из окружения, затем явная донастройка (явные значения имеют приоритет).</summary>
    public static IServiceCollection AddTslAuth(this IServiceCollection services, Action<TslAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var options = TslAuthOptions.FromEnvironment();
        configure(options);
        return services.AddTslAuth(options);
    }

    /// <summary>Настройки из секции <c>TslAuth</c> конфигурации; переменные окружения <c>TSL_AUTH_*</c> имеют приоритет.</summary>
    public static IServiceCollection AddTslAuth(this IServiceCollection services, IConfiguration configuration, string sectionName = "TslAuth", bool environmentOverrides = true)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var section = configuration.GetSection(sectionName);
        return services.AddTslAuth(TslAuthOptions.FromConfiguration(section, environmentOverrides));
    }

    /// <summary>Регистрирует готовые настройки, verifier, клиент токенов, схему <c>TslAuth</c> и обработчики авторизации.</summary>
    public static IServiceCollection AddTslAuth(this IServiceCollection services, TslAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        options.RequireIssuer();

        services.TryAddSingleton(options);
        services.TryAddSingleton<TslAuthVerifier>();
        services.TryAddSingleton<TokenClient>();

        // Схема по умолчанию — TslAuth, если приложение не задало другую (cookie и т. п.).
        services.AddAuthentication(o =>
            {
                if (string.IsNullOrEmpty(o.DefaultScheme)) o.DefaultScheme = TslAuthDefaults.AuthenticationScheme;
            })
            .AddScheme<TslAuthSchemeOptions, TslAuthHandler>(TslAuthDefaults.AuthenticationScheme, "TSL Auth", null);

        services.AddAuthorization();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, TslRequirementHandler>());
        // AddAuthorization уже зарегистрировал стандартный обработчик результата — заменяем своим (он делегирует стандартному).
        services.Replace(ServiceDescriptor.Singleton<IAuthorizationMiddlewareResultHandler, TslAuthorizationResultHandler>());
        return services;
    }
}

/// <summary>Требования TSL Auth для endpoint'ов (Minimal API, контроллеры через <c>MapControllers()</c>, группы).</summary>
public static class TslAuthEndpointExtensions
{
    /// <summary>Только аутентификация схемой <c>TslAuth</c>.</summary>
    public static TBuilder RequireTslAuth<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization(Policy());

    /// <summary>Разрешение этого API (короткая форма, например <c>orders.read</c>); 403 <c>insufficient_permissions</c>.</summary>
    public static TBuilder RequireTslPermission<TBuilder>(this TBuilder builder, string permission) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization(Policy(new TslPermissionRequirement(permission)));

    /// <summary>Хотя бы одно из разрешений; 403 <c>insufficient_permissions</c>.</summary>
    public static TBuilder RequireTslAnyPermission<TBuilder>(this TBuilder builder, params string[] permissions) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization(Policy(new TslPermissionRequirement(permissions)));

    /// <summary>Роль этого API; 403 <c>insufficient_role</c>.</summary>
    public static TBuilder RequireTslRole<TBuilder>(this TBuilder builder, string role) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization(Policy(new TslRoleRequirement(role)));

    /// <summary>Двухфакторный вход; 403 <c>mfa_required</c>.</summary>
    public static TBuilder RequireTslMfa<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization(Policy(new TslMfaRequirement()));

    /// <summary>Тип субъекта <c>user</c>/<c>client</c>; 403 <c>subject_type_not_allowed</c>.</summary>
    public static TBuilder RequireTslSubjectType<TBuilder>(this TBuilder builder, string subjectType) where TBuilder : IEndpointConventionBuilder =>
        builder.RequireAuthorization(Policy(new TslSubjectTypeRequirement(subjectType)));

    /// <summary>Политика на схеме <c>TslAuth</c> с указанными требованиями (для <c>AddPolicy</c> и атрибутов).</summary>
    public static AuthorizationPolicy Policy(params IAuthorizationRequirement[] requirements)
    {
        var b = new AuthorizationPolicyBuilder(TslAuthDefaults.AuthenticationScheme).RequireAuthenticatedUser();
        foreach (var r in requirements) b.AddRequirements(r);
        return b.Build();
    }
}

/// <summary>Доступ к principal TSL Auth из обработчика запроса.</summary>
public static class TslAuthHttpContextExtensions
{
    /// <summary>Principal текущего запроса или <c>null</c>, если токен не проверен.</summary>
    public static TslPrincipal? GetTslPrincipal(this HttpContext context) => context.Features.Get<TslPrincipal>();
}
