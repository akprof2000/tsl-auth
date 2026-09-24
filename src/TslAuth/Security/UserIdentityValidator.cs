using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Security;

/// <summary>
/// Дополнительные правила учётной записи поверх стандартного UserValidator Identity (уникальный логин, допустимые символы):
/// <list type="bullet">
/// <item>email уникален — иначе поиск по email неоднозначен, а самостоятельная регистрация с чужим адресом
///   ломала бы вход и сброс пароля владельца адреса;</item>
/// <item>логин с «@» допустим, только если совпадает с собственным email пользователя — иначе можно «занять» чужой адрес
///   как логин: вход и «забыли пароль» ищут сначала по логину и нашли бы атакующего.</item>
/// </list>
/// Проверка выполняется Identity при каждом CreateAsync/UpdateAsync — все пути создания пользователей (админка, API,
/// App API, саморегистрация, приглашения) проходят через неё.
/// </summary>
public sealed class UserIdentityValidator(AuthDbContext db) : IUserValidator<AppUser>
{
    public const string DuplicateEmailCode = "DuplicateEmail";
    public const string UserNameLooksLikeEmailCode = "UserNameLooksLikeEmail";

    public async Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
    {
        var errors = new List<IdentityError>();

        if (user.UserName is { } userName && userName.Contains('@')
            && !string.Equals(userName, user.Email, StringComparison.OrdinalIgnoreCase))
            errors.Add(new IdentityError
            {
                Code = UserNameLooksLikeEmailCode,
                Description = "Логин с символом «@» должен совпадать с email этой учётной записи."
            });

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            // NormalizedEmail хранится HMAC-индексом: EF применяет тот же конвертер к параметру, сравнение идёт по индексу.
            var normalized = manager.NormalizeEmail(user.Email);
            if (await db.Users.AnyAsync(u => u.NormalizedEmail == normalized && u.Id != user.Id))
                errors.Add(new IdentityError { Code = DuplicateEmailCode, Description = "Этот email уже используется другой учётной записью." });
        }

        return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed([.. errors]);
    }
}

/// <summary>Ошибки Identity → <see cref="AdminException"/> с ключом локализации для пользовательских страниц.</summary>
public static class IdentityErrors
{
    // Код ошибки Identity → ключ языкового пакета. Ошибки политики паролей локализует PolicyPasswordValidator.
    private static readonly Dictionary<string, string> Keys = new()
    {
        ["DuplicateUserName"] = "error.userNameTaken",
        ["InvalidUserName"] = "error.userNameInvalid",
        [UserIdentityValidator.UserNameLooksLikeEmailCode] = "error.userNameInvalid",
        [UserIdentityValidator.DuplicateEmailCode] = "error.emailTaken",
        ["DuplicateEmail"] = "error.emailTaken",
        ["InvalidEmail"] = "error.emailInvalid"
    };

    /// <summary>Бросает <see cref="AdminException"/> (400), если операция Identity не удалась.</summary>
    public static void ThrowIfFailed(IdentityResult result)
    {
        if (result.Succeeded) return;
        var key = result.Errors.Select(e => Keys.GetValueOrDefault(e.Code)).FirstOrDefault(k => k is not null);
        throw new AdminException(string.Join(" ", result.Errors.Select(e => e.Description))) { Key = key };
    }
}
