using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;

namespace TslAuth.Security;

// Двухфакторный вход (решение В-9 ЧТЗ): после пароля пользователь вводит одноразовый код, полученный на почту
// или в мессенджер через бота. Коды — TOTP ASP.NET Core Identity по security stamp пользователя: сервис их
// не хранит; код действует несколько минут (шаг 3 минуты с допуском) и перестаёт действовать при смене
// security stamp (смена пароля, отключение). Какие роли требуют второй фактор, задаёт администратор
// (флаг AccessRole.RequiresTwoFactor); проверку «нужен ли второй фактор» выполняет AppUserManager.

/// <summary>Имена провайдеров второго фактора (они же — значения поля выбора канала на странице входа).</summary>
public static class TwoFactorProviders
{
    /// <summary>Код на email учётной записи.</summary>
    public const string Email = "email-code";

    /// <summary>Код в мессенджер: пользователь отправляет боту команду /code, бот получает код по Bot API.</summary>
    public const string Messenger = "messenger-code";

    /// <summary>Все каналы в порядке показа на странице входа.</summary>
    public static readonly string[] All = [Email, Messenger];
}

/// <summary>
/// Код на почту. Доступен, если у учётной записи указан email (подтверждение адреса не требуется: адрес задаёт
/// администратор или пользователь при регистрации). Модификатор включает имя провайдера, поэтому код почты
/// не подходит для мессенджера и наоборот.
/// </summary>
public sealed class EmailCodeProvider : TotpSecurityStampBasedTokenProvider<AppUser>
{
    public override async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user) =>
        !string.IsNullOrWhiteSpace(await manager.GetEmailAsync(user));

    public override async Task<string> GetUserModifierAsync(string purpose, UserManager<AppUser> manager, AppUser user) =>
        $"{TwoFactorProviders.Email}:{purpose}:{await manager.GetUserIdAsync(user)}";
}

/// <summary>
/// Код в мессенджер. Доступен, если к учётной записи привязан хотя бы один мессенджер (ExternalIdentity,
/// привязка через личный кабинет и команду боту /link). Сервис не отправляет сообщение сам: бот запрашивает
/// код по Bot API от имени привязанного отправителя (BotService.TwoFactorCodeAsync).
/// </summary>
public sealed class MessengerCodeProvider(AuthDbContext db) : TotpSecurityStampBasedTokenProvider<AppUser>
{
    public override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user) =>
        db.ExternalIdentities.AsNoTracking().AnyAsync(e => e.UserId == user.Id);

    public override async Task<string> GetUserModifierAsync(string purpose, UserManager<AppUser> manager, AppUser user) =>
        $"{TwoFactorProviders.Messenger}:{purpose}:{await manager.GetUserIdAsync(user)}";
}
