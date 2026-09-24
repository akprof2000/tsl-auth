using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using TslAuth.Data;
using TslAuth.Infrastructure;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Api;

/// <summary>
/// API для бота мессенджера (client_credentials, scope tsl-auth-admin, роль reset-bot в системном приложении).
/// Бот передаёт provider + externalId отправителя; действует только для привязанных пользователей.
/// Маршруты /api/bot защищены политиками по разрешениям системного приложения: токен клиента (sub_type=client)
/// с password_reset (привязка и сброс), user_lock (блокировка) или password_force (смена пароля).
/// Привязки хранятся в <see cref="ExternalIdentity"/>, бизнес-логика — в BotService.
/// </summary>
public static class BotApi
{
    public const string Policy = "bot-password-reset";
    public const string LockPolicy = "bot-user-lock";
    public const string ForcePasswordPolicy = "bot-password-force";

    /// <summary>Регистрирует политики авторизации Bot API.</summary>
    public static void AddBotPolicy(AuthorizationOptions options)
    {
        options.AddPolicy(Policy, p => Client(p).AddRequirements(new AdminPermissionRequirement(SystemApp.PasswordResetPermission)));
        options.AddPolicy(LockPolicy, p => Client(p).AddRequirements(new AdminPermissionRequirement(SystemApp.UserLockPermission)));
        options.AddPolicy(ForcePasswordPolicy, p => Client(p).AddRequirements(new AdminPermissionRequirement(SystemApp.PasswordForcePermission)));
    }

    private static AuthorizationPolicyBuilder Client(AuthorizationPolicyBuilder p) => p
        .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireClaim(CustomClaims.SubjectType, "client");

    /// <summary>Регистрирует маршруты /api/bot/*.</summary>
    public static void MapBotApi(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/bot").WithTags("Bot")
            .AddEndpointFilter(ApiErrors.Handle);
        var bot = group.MapGroup("").RequireAuthorization(Policy);

        // Пользователь прислал боту "/link КОД" (код получен в личном кабинете /Account/Messenger).
        bot.MapPost("/link", (ClaimsPrincipal me, BotLinkInput input, BotService s, CancellationToken ct) =>
            s.LinkAsync(Client(me), input, ct));
        // /unlink — отвязать отправителя; /whois — узнать, к какой учётной записи он привязан.
        bot.MapPost("/unlink", async (ClaimsPrincipal me, BotUserRef user, BotService s, CancellationToken ct) =>
            Results.Ok(new { unlinked = await s.UnlinkAsync(Client(me), user, ct) }));
        bot.MapPost("/whois", async (BotUserRef user, BotService s, CancellationToken ct) =>
            await s.WhoIsAsync(user, ct) is { } name ? Results.Ok(new { linked = true, userName = name }) : Results.Ok(new { linked = false }));

        // Пользователь прислал боту "/reset": вернуть одноразовую ссылку (или временный пароль — по настройке).
        bot.MapPost("/password-reset", (ClaimsPrincipal me, BotUserRef user, BotService s, CancellationToken ct) =>
            s.ResetPasswordAsync(Client(me), user, ct));

        // Команды над учётной записью: target пустой — своя учётка, иначе логин/email другого пользователя
        // (нужно разрешение user_lock / password_force у самого отправителя, например роль security-officer).
        group.MapPost("/lock", (ClaimsPrincipal me, BotTargetInput input, BotService s, CancellationToken ct) =>
            s.LockAsync(Client(me), input, ct)).RequireAuthorization(LockPolicy);
        group.MapPost("/unlock", (ClaimsPrincipal me, BotTargetInput input, BotService s, CancellationToken ct) =>
            s.UnlockAsync(Client(me), input, ct)).RequireAuthorization(LockPolicy);
        group.MapPost("/force-password-change", (ClaimsPrincipal me, BotTargetInput input, BotService s, CancellationToken ct) =>
            s.ForcePasswordChangeAsync(Client(me), input, ct)).RequireAuthorization(ForcePasswordPolicy);
    }

    private static string Client(ClaimsPrincipal me) => me.GetClaim(Claims.Subject)!;
}
