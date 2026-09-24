using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Security;

/// <summary>
/// Проверка пароля по политике из БД (длина, классы символов, уникальные символы, история).
/// Регистрируется в Identity (ServiceSetup) вместо встроенных проверок — политику меняют в админке без перезапуска.
/// </summary>
public sealed class PolicyPasswordValidator(SettingsService settings, AuthDbContext db, IPasswordHasher<AppUser> hasher,
    Localization.Texts L)
    : IPasswordValidator<AppUser>
{
    public async Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user, string? password)
    {
        var p = (await settings.GetAsync()).Passwords;
        password ??= "";
        var errors = new List<IdentityError>();
        void Fail(string code, string text) => errors.Add(new IdentityError { Code = code, Description = text });

        if (password.Length < p.MinLength) Fail("PasswordTooShort", L.Get("policy.error.tooShort", p.MinLength));
        if (p.RequireLowercase && !password.Any(char.IsLower)) Fail("PasswordRequiresLower", L["policy.error.lower"]);
        if (p.RequireUppercase && !password.Any(char.IsUpper)) Fail("PasswordRequiresUpper", L["policy.error.upper"]);
        if (p.RequireDigit && !password.Any(char.IsDigit)) Fail("PasswordRequiresDigit", L["policy.error.digit"]);
        if (p.RequireSymbol && password.All(char.IsLetterOrDigit)) Fail("PasswordRequiresNonAlphanumeric", L["policy.error.symbol"]);
        if (password.Distinct().Count() < p.MinUniqueChars)
            Fail("PasswordRequiresUniqueChars", L.Get("policy.error.unique", p.MinUniqueChars));
        if (user.UserName is { Length: > 2 } name && password.Contains(name, StringComparison.OrdinalIgnoreCase))
            Fail("PasswordContainsUserName", L["policy.error.userName"]);

        // История хранит хеши (с солью), поэтому сравнение — через проверку хеша, а не равенством строк.
        // Текущий пароль тоже считается «использованным». Для нового пользователя истории ещё нет.
        if (p.HistoryCount > 0 && user.Id != Guid.Empty)
        {
            var recent = await db.PasswordHistory.AsNoTracking().Where(h => h.UserId == user.Id)
                .OrderByDescending(h => h.CreatedAt).Take(p.HistoryCount).Select(h => h.PasswordHash).ToListAsync();
            if (user.PasswordHash is not null) recent.Add(user.PasswordHash);
            if (recent.Any(h => hasher.VerifyHashedPassword(user, h, password) != PasswordVerificationResult.Failed))
                Fail("PasswordReused", L.Get("policy.error.reused", p.HistoryCount));
        }

        return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed([.. errors]);
    }
}

/// <summary>
/// UserManager с учётом политики: при каждой смене пароля сохраняет историю и дату смены.
/// Все пути (смена, сброс, приглашение, админ) проходят через UpdatePasswordHash.
/// </summary>
public sealed class AppUserManager(
    IUserStore<AppUser> store,
    IOptions<IdentityOptions> optionsAccessor,
    IPasswordHasher<AppUser> passwordHasher,
    IEnumerable<IUserValidator<AppUser>> userValidators,
    IEnumerable<IPasswordValidator<AppUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errors,
    IServiceProvider services,
    ILogger<UserManager<AppUser>> logger,
    AuthDbContext db)
    : UserManager<AppUser>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer,
        errors, services, logger)
{
    protected override async Task<IdentityResult> UpdatePasswordHash(AppUser user, string newPassword, bool validatePassword)
    {
        var previousHash = user.PasswordHash;
        // Запись истории добавляется в тот же DbContext и сохраняется вместе с пользователем, когда UserManager обновит его в хранилище.
        var result = await base.UpdatePasswordHash(user, newPassword, validatePassword);
        if (result.Succeeded && newPassword is not null)
        {
            if (previousHash is not null)
                db.PasswordHistory.Add(new PasswordHistoryEntry { UserId = user.Id, PasswordHash = previousHash });
            user.PasswordChangedAt = DateTime.UtcNow;
        }
        return result;
    }

    /// <summary>
    /// Поиск по email без исключения при дубликатах: стандартный UserStore делает SingleOrDefault и падает (500),
    /// если адрес встречается дважды — такое возможно в БД старых версий, где уникальность email не проверялась.
    /// Неоднозначный адрес трактуется как «не найден»: вход по логину и администрирование продолжают работать.
    /// </summary>
    public override async Task<AppUser?> FindByEmailAsync(string email)
    {
        ArgumentNullException.ThrowIfNull(email);
        var normalized = NormalizeEmail(email);
        var matches = await Users.Where(u => u.NormalizedEmail == normalized).Take(2).ToListAsync();
        if (matches.Count > 1)
            Logger.LogWarning("Email встречается у нескольких учётных записей — поиск по нему отключён до устранения дубликатов.");
        return matches.Count == 1 ? matches[0] : null;
    }

    /// <summary>Истёк ли срок действия пароля по политике (0 — бессрочно).</summary>
    public static bool IsPasswordExpired(AppUser user, PasswordPolicy policy) =>
        policy.MaxAgeDays > 0 && user.PasswordHash is not null &&
        (user.PasswordChangedAt ?? user.CreatedAt) < DateTime.UtcNow.AddDays(-policy.MaxAgeDays);
}
