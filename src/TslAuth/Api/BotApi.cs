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
/// Группа /api/bot защищена политикой <see cref="Policy"/>: токен клиента (sub_type=client) с разрешением
/// сброса пароля в матрице системного приложения. Привязки хранятся в <see cref="ExternalIdentity"/>,
/// бизнес-логика — в BotService.
/// </summary>
public static class BotApi
{
    public const string Policy = "bot-password-reset";

    /// <summary>Регистрирует политику авторизации Bot API.</summary>
    public static void AddBotPolicy(AuthorizationOptions options) =>
        options.AddPolicy(Policy, p => p
            .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireClaim(CustomClaims.SubjectType, "client")
            .AddRequirements(new AdminPermissionRequirement(SystemApp.PasswordResetPermission)));

    /// <summary>Регистрирует маршруты /api/bot/*.</summary>
    public static void MapBotApi(this IEndpointRouteBuilder endpoints)
    {
        var bot = endpoints.MapGroup("/api/bot").RequireAuthorization(Policy).WithTags("Bot")
            .AddEndpointFilter(async (ctx, next) =>
            {
                try { return await next(ctx); }
                catch (AdminException ex) { return Results.Problem(detail: ex.Message, statusCode: ex.StatusCode); }
            });

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
    }

    private static string Client(ClaimsPrincipal me) => me.GetClaim(Claims.Subject)!;
}
