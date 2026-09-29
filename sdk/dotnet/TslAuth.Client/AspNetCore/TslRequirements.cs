using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace TslAuth.Client.AspNetCore;

/// <summary>Требование к principal TSL Auth (docs/client-contract.md §5): код отказа и «что требовалось».</summary>
public abstract class TslRequirement : IAuthorizationRequirement
{
    /// <summary>Код 403 (<c>insufficient_permissions</c>, <c>insufficient_role</c>, <c>mfa_required</c>, <c>subject_type_not_allowed</c>).</summary>
    public abstract string Code { get; }

    /// <summary>Описание для <c>error_description</c>: что требовалось (с префиксом audience для прав и ролей).</summary>
    public abstract string Describe(string? audience);

    /// <summary>Выполнено ли требование.</summary>
    public abstract bool IsSatisfied(TslPrincipal principal);
}

/// <summary>Хотя бы одно из разрешений этого API.</summary>
public sealed class TslPermissionRequirement : TslRequirement
{
    /// <summary>Создаёт требование по списку разрешений (достаточно одного).</summary>
    public TslPermissionRequirement(params string[] permissions)
    {
        if (permissions is null || permissions.Length == 0) throw new ArgumentException("Нужно хотя бы одно разрешение.", nameof(permissions));
        Permissions = permissions;
    }

    /// <summary>Разрешения без префикса audience.</summary>
    public IReadOnlyList<string> Permissions { get; }
    /// <inheritdoc />
    public override string Code => "insufficient_permissions";
    /// <inheritdoc />
    public override string Describe(string? audience) => string.Join(' ', Permissions.Select(p => Prefix(audience, p)));
    /// <inheritdoc />
    public override bool IsSatisfied(TslPrincipal principal) => Permissions.Any(principal.HasPermission);

    internal static string Prefix(string? audience, string value) => string.IsNullOrEmpty(audience) ? value : audience + ":" + value;
}

/// <summary>Роль этого API.</summary>
public sealed class TslRoleRequirement : TslRequirement
{
    /// <summary>Создаёт требование роли.</summary>
    public TslRoleRequirement(string role) => Role = role ?? throw new ArgumentNullException(nameof(role));

    /// <summary>Роль без префикса audience.</summary>
    public string Role { get; }
    /// <inheritdoc />
    public override string Code => "insufficient_role";
    /// <inheritdoc />
    public override string Describe(string? audience) => TslPermissionRequirement.Prefix(audience, Role);
    /// <inheritdoc />
    public override bool IsSatisfied(TslPrincipal principal) => principal.HasRole(Role);
}

/// <summary>Двухфакторный вход (<c>amr</c> содержит <c>mfa</c>).</summary>
public sealed class TslMfaRequirement : TslRequirement
{
    /// <inheritdoc />
    public override string Code => "mfa_required";
    /// <inheritdoc />
    public override string Describe(string? audience) => "mfa";
    /// <inheritdoc />
    public override bool IsSatisfied(TslPrincipal principal) => principal.IsMfa;
}

/// <summary>Тип субъекта: <c>user</c> или <c>client</c>.</summary>
public sealed class TslSubjectTypeRequirement : TslRequirement
{
    /// <summary>Создаёт требование типа субъекта.</summary>
    public TslSubjectTypeRequirement(string subjectType) => SubjectType = subjectType ?? throw new ArgumentNullException(nameof(subjectType));

    /// <summary>Требуемый тип.</summary>
    public string SubjectType { get; }
    /// <inheritdoc />
    public override string Code => "subject_type_not_allowed";
    /// <inheritdoc />
    public override string Describe(string? audience) => SubjectType;
    /// <inheritdoc />
    public override bool IsSatisfied(TslPrincipal principal) => principal.SubjectType == SubjectType;
}

/// <summary>Проверяет все <see cref="TslRequirement"/> по principal из <c>HttpContext.Features</c>.</summary>
public sealed class TslRequirementHandler : IAuthorizationHandler
{
    /// <inheritdoc />
    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        var principal = (context.Resource as HttpContext)?.GetTslPrincipal();
        foreach (var requirement in context.PendingRequirements.OfType<TslRequirement>().ToList())
        {
            if (principal is not null && requirement.IsSatisfied(principal))
                context.Succeed(requirement);
            else
                context.Fail(new AuthorizationFailureReason(this, requirement.Code));
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Перед стандартной обработкой 403 запоминает в <c>HttpContext.Items</c>, какое требование TSL не выполнено,
/// чтобы <see cref="TslAuthHandler"/> записал код и описание по §5.
/// </summary>
public sealed class TslAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _default = new();
    private readonly TslAuthOptions _options;

    /// <summary>Создаётся DI.</summary>
    public TslAuthorizationResultHandler(TslAuthOptions options) => _options = options;

    /// <inheritdoc />
    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Forbidden)
        {
            var failed = authorizeResult.AuthorizationFailure?.FailedRequirements.OfType<TslRequirement>().FirstOrDefault()
                         ?? policy.Requirements.OfType<TslRequirement>().FirstOrDefault(r =>
                             context.GetTslPrincipal() is { } p && !r.IsSatisfied(p));
            if (failed is not null)
            {
                context.Items[TslAuthDefaults.ItemForbidCode] = failed.Code;
                context.Items[TslAuthDefaults.ItemForbidDescription] = failed.Describe(_options.Audience);
            }
        }
        return _default.HandleAsync(next, context, policy, authorizeResult);
    }
}
