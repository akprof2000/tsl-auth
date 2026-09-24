using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;
using TslAuth.Security;
using TslAuth.Infrastructure;

namespace TslAuth.Services;

/// <summary>Пользователь для админки и Admin API (с ролями во всех приложениях).</summary>
public sealed record UserDto(
    Guid Id,
    string UserName,
    string? Email,
    string? DisplayName,
    bool IsActive,
    bool IsLockedOut,
    bool HasPassword,
    bool MustChangePassword,
    DateTime CreatedAt,
    DateTime? LastLoginAt,
    List<RoleRef> Roles);

/// <summary>Данные для создания/изменения пользователя. <c>Roles = null</c> — роли не трогать.</summary>
/// <param name="Password">Пароль. Если не задан — пользователь активируется по приглашению.</param>
/// <param name="MustChangePassword">Пароль временный: при первом входе потребуется сменить.</param>
public sealed record UserInput(
    string UserName,
    string? Email,
    string? DisplayName,
    bool IsActive = true,
    string? Password = null,
    bool MustChangePassword = false,
    List<RoleRef>? Roles = null);

/// <summary>
/// Результат приглашения: ссылка возвращается всегда, чтобы администратор мог передать её вручную,
/// если письмо не ушло (EmailError — причина).
/// </summary>
public sealed record InviteResult(string Link, bool EmailSent, string? EmailError);

/// <summary>Страница списка и общее количество элементов.</summary>
public sealed record PagedResult<T>(List<T> Items, int Total);

/// <summary>
/// Управление учётными записями поверх ASP.NET Core Identity: создание, изменение, пароли, приглашения,
/// блокировка, удаление. Следит за побочными эффектами — отзыв сессий, снятие ролей, вебхуки.
/// Используется Admin API, страницами Admin/Users и Account/*, AuthorizationController (отметка входа),
/// StartupInitializer (первый администратор), а также AccessRequestService, AppSelfService и BotService.
/// </summary>
public sealed class UserService(
    AuthDbContext db,
    UserManager<AppUser> users,
    AccessService access,
    SessionService sessions,
    AccountLinks links,
    WebhookService webhooks,
    ILogger<UserService> logger)
{
    /// <summary>
    /// Логин и email хранятся зашифрованными, поэтому поиск — только точное совпадение
    /// (через HMAC-индекс), без поиска по подстроке.
    /// </summary>
    public async Task<PagedResult<UserDto>> ListAsync(string? search, int skip = 0, int take = 50, CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(search))
        {
            var found = await FindByLoginAsync(search.Trim());
            return found is null
                ? new PagedResult<UserDto>([], 0)
                : new PagedResult<UserDto>([await ToDtoAsync(found, ct)], 1);
        }

        var total = await db.Users.CountAsync(ct);
        var page = await db.Users.AsNoTracking().OrderBy(u => u.CreatedAt).Skip(Math.Max(skip, 0)).Take(Math.Clamp(take, 1, 500)).ToListAsync(ct);
        // Роли всей страницы — одним запросом, а не по запросу на пользователя.
        var roles = await access.GetAssignmentsAsync(SubjectType.User, page.Select(u => u.Id.ToString()).ToList(), ct: ct);
        return new PagedResult<UserDto>(page.Select(u => ToDto(u, roles.GetValueOrDefault(u.Id.ToString()) ?? [])).ToList(), total);
    }

    /// <summary>
    /// Поиск по логину, а если строка похожа на email — и по email. UserManager нормализует значение,
    /// а конвертер EF превращает его в blind index, так что поиск идёт по индексу без расшифровки.
    /// </summary>
    public async Task<AppUser?> FindByLoginAsync(string login) =>
        await users.FindByNameAsync(login) ?? (login.Contains('@') ? await users.FindByEmailAsync(login) : null);

    public async Task<UserDto?> GetAsync(Guid id, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(id.ToString());
        return user is null ? null : await ToDtoAsync(user, ct);
    }

    /// <summary>Создаёт пользователя (с паролем или без — тогда он активируется по приглашению) и назначает роли.</summary>
    public async Task<UserDto> CreateAsync(UserInput input, CancellationToken ct = default)
    {
        // MustChangePassword имеет смысл только при заданном пароле: без пароля пользователь сам задаст его по приглашению.
        var user = new AppUser
        {
            UserName = input.UserName?.Trim(),
            Email = Normalize(input.Email),
            DisplayName = Normalize(input.DisplayName),
            IsActive = input.IsActive,
            EmailConfirmed = false,
            LockoutEnabled = true,
            MustChangePassword = input.MustChangePassword && !string.IsNullOrWhiteSpace(input.Password)
        };

        Check(string.IsNullOrWhiteSpace(input.Password)
            ? await users.CreateAsync(user)
            : await users.CreateAsync(user, input.Password));

        if (input.Roles is not null)
            await access.SetAssignmentsAsync(SubjectType.User, user.Id.ToString(), input.Roles, ct);

        await webhooks.PublishAsync(WebhookEvents.UserCreated, $"➕ Создан пользователь {user.UserName}.",
            new { userId = user.Id, userName = user.UserName }, ct);
        return (await GetAsync(user.Id, ct))!;
    }

    /// <summary>Изменяет профиль, статус, (опционально) пароль и роли; при отключении — разлогинивает пользователя везде.</summary>
    public async Task<UserDto> UpdateAsync(Guid id, UserInput input, CancellationToken ct = default)
    {
        var user = await Require(id);

        user.UserName = input.UserName?.Trim();
        // Новый email не подтверждён: подтверждение прежнего адреса на него не распространяется.
        if (!string.Equals(user.Email, Normalize(input.Email), StringComparison.OrdinalIgnoreCase)) user.EmailConfirmed = false;
        user.Email = Normalize(input.Email);
        user.DisplayName = Normalize(input.DisplayName);
        var deactivated = user.IsActive && !input.IsActive;
        user.IsActive = input.IsActive;
        Check(await users.UpdateAsync(user));

        if (!string.IsNullOrWhiteSpace(input.Password))
            await SetPasswordAsync(id, input.Password, input.MustChangePassword, ct);

        if (input.Roles is not null)
            await access.SetAssignmentsAsync(SubjectType.User, user.Id.ToString(), input.Roles, ct);

        if (deactivated)
        {
            // Смена security stamp инвалидирует cookie админки, отзыв — refresh-токены.
            await users.UpdateSecurityStampAsync(user);
            await sessions.RevokeBySubjectAsync(user.Id.ToString(), ct);
        }

        return (await GetAsync(id, ct))!;
    }

    /// <summary>Администратор задаёт пароль. Все сессии пользователя отзываются.</summary>
    public async Task SetPasswordAsync(Guid id, string password, bool mustChange = false, CancellationToken ct = default)
    {
        var user = await Require(id);
        // Через reset-токен, а не Remove+AddPassword: одна операция, и валидаторы политики паролей применяются так же.
        var token = await users.GeneratePasswordResetTokenAsync(user);
        Check(await users.ResetPasswordAsync(user, token, password));

        // Заодно снимаем блокировку — иначе пользователь не сможет войти с новым паролем до её истечения.
        user.MustChangePassword = mustChange;
        user.LockoutEnd = null;
        user.AccessFailedCount = 0;
        Check(await users.UpdateAsync(user));
        await sessions.RevokeBySubjectAsync(user.Id.ToString(), ct);
    }

    /// <summary>Выдаёт одноразовый (временный) пароль, который нужно сменить при первом входе.</summary>
    public async Task<string> SetTemporaryPasswordAsync(Guid id, CancellationToken ct = default)
    {
        var password = PasswordGenerator.Generate();
        await SetPasswordAsync(id, password, mustChange: true, ct);
        return password;
    }

    /// <summary>Создаёт ссылку-приглашение (одноразовую) и, если возможно, отправляет её на email.</summary>
    public async Task<InviteResult> InviteAsync(Guid id, bool sendEmail = true, CancellationToken ct = default)
    {
        var user = await Require(id);
        var link = await links.CreateInviteLinkAsync(user);

        // Сбой почты не считается ошибкой операции: ссылка уже создана и возвращается администратору.
        if (!sendEmail) return new InviteResult(link, false, null);
        if (user.Email is null) return new InviteResult(link, false, "У пользователя не указан email.");
        if (!links.EmailConfigured) return new InviteResult(link, false, "SMTP не настроен.");

        try
        {
            await links.SendInviteAsync(user, link, ct);
            return new InviteResult(link, true, null);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Не удалось отправить приглашение пользователю {UserId}.", id);
            return new InviteResult(link, false, ex.Message);
        }
    }

    /// <summary>Принимает приглашение: проверяет токен и устанавливает пароль. false — ссылка недействительна.</summary>
    public async Task<bool> AcceptInviteAsync(Guid id, string token, string password)
    {
        var user = await users.FindByIdAsync(id.ToString());
        // Отключённый администратором пользователь не должен «оживать» по старой ссылке приглашения.
        if (user is not { IsActive: true } || !await links.ValidateInviteAsync(user, token)) return false;

        // Пароль может уже быть (повторное приглашение существующему пользователю) — тогда перезаписываем его.
        Check(await users.HasPasswordAsync(user)
            ? await users.ResetPasswordAsync(user, await users.GeneratePasswordResetTokenAsync(user), password)
            : await users.AddPasswordAsync(user, password));

        // Смена пароля меняет security stamp — ссылка приглашения становится недействительной.
        // Письмо со ссылкой пришло на этот адрес, значит, email подтверждён.
        user.EmailConfirmed = user.Email is not null;
        user.MustChangePassword = false;
        Check(await users.UpdateAsync(user));
        return true;
    }

    // Хеш-«пустышка» того же формата (PBKDF2), что у настоящих паролей.
    private static readonly Lazy<string> DummyHash =
        new(() => new PasswordHasher<AppUser>().HashPassword(new AppUser(), Guid.NewGuid().ToString()));

    /// <summary>
    /// Проверка пароля «вхолостую» для неизвестного/отключённого логина: время ответа совпадает с проверкой
    /// настоящего пароля (PBKDF2), и по таймингу нельзя узнать, существует ли учётная запись.
    /// </summary>
    public void SimulatePasswordCheck(string? password) =>
        users.PasswordHasher.VerifyHashedPassword(new AppUser(), DummyHash.Value, password ?? "");

    /// <summary>
    /// Что писать в журнал о введённом логине при неудачном входе: в поле логина нередко вводят пароль,
    /// поэтому сырой ввод не сохраняется — только первые символы и длина.
    /// </summary>
    public static string MaskLogin(string? login) =>
        string.IsNullOrEmpty(login) ? "" : $"{login[..Math.Min(2, login.Length)]}… ({login.Length})";

    /// <summary>Администратор отправляет пользователю ссылку для сброса пароля.</summary>
    public async Task SendPasswordResetAsync(Guid id, CancellationToken ct = default)
    {
        var user = await Require(id);
        await links.SendPasswordResetAsync(user, await links.CreatePasswordResetLinkAsync(user), ct);
    }

    /// <summary>
    /// Самостоятельное восстановление пароля. Ничего не сообщает о существовании пользователя,
    /// ошибки отправки только логируются.
    /// </summary>
    public async Task RequestPasswordResetAsync(string login, CancellationToken ct = default)
    {
        var user = await FindByLoginAsync(login.Trim());
        // Молча выходим: одинаковый ответ для существующих и несуществующих логинов защищает от перебора учётных записей.
        if (user is not { IsActive: true, Email: not null }) return;

        // Письмо — в фоне: синхронная отправка по SMTP только для существующих выдавала бы их по времени ответа.
        links.QueuePasswordReset(user, await links.CreatePasswordResetLinkAsync(user), logger);
    }

    /// <summary>
    /// Завершает сброс пароля по ссылке: устанавливает пароль, снимает блокировку и отзывает все сессии
    /// (если пароль сбрасывают из-за компрометации, злоумышленник теряет доступ).
    /// </summary>
    public async Task<IdentityResult> CompletePasswordResetAsync(Guid id, string token, string password, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(id.ToString());
        if (user is null) return IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Ссылка недействительна." });
        // Сброс пароля не включает отключённую учётную запись (и не должен давать ей новый пароль).
        if (!user.IsActive)
            return IdentityResult.Failed(new IdentityError { Code = "AccountDisabled", Description = "Учётная запись отключена." });

        var result = await users.ResetPasswordAsync(user, token, password);
        if (!result.Succeeded) return result;

        user.MustChangePassword = false;
        user.EmailConfirmed = user.Email is not null;
        user.LockoutEnd = null;
        user.AccessFailedCount = 0;
        await users.UpdateAsync(user);
        await sessions.RevokeBySubjectAsync(user.Id.ToString(), ct);
        return result;
    }

    /// <summary>
    /// Отметка успешного входа точечным UPDATE (без проверки ConcurrencyStamp): одновременные входы одного
    /// пользователя с разных устройств/сервисов не должны конфликтовать между собой.
    /// </summary>
    public Task RecordLoginAsync(Guid id, bool mustChangePassword, CancellationToken ct = default) =>
        mustChangePassword
            ? db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(u => u.LastLoginAt, DateTime.UtcNow).SetProperty(u => u.MustChangePassword, true), ct)
            : db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.LastLoginAt, DateTime.UtcNow), ct);

    /// <summary>
    /// Включает/отключает учётную запись. Отключение — как в <see cref="UpdateAsync"/>: security stamp меняется
    /// (cookie админки перестаёт действовать), все сессии и refresh-токены отзываются. Включение заодно снимает
    /// блокировку за неверные пароли. Возвращает false, если состояние уже было таким.
    /// </summary>
    public async Task<bool> SetActiveAsync(Guid id, bool active, CancellationToken ct = default)
    {
        var user = await Require(id);
        if (user.IsActive == active) return false;
        user.IsActive = active;
        if (active)
        {
            user.LockoutEnd = null;
            user.AccessFailedCount = 0;
        }
        Check(await users.UpdateAsync(user));
        if (!active)
        {
            await users.UpdateSecurityStampAsync(user);
            await sessions.RevokeBySubjectAsync(user.Id.ToString(), ct);
        }
        return true;
    }

    /// <summary>
    /// Требует сменить пароль при следующем входе и отзывает все сессии: текущий пароль остаётся,
    /// но воспользоваться им можно только один раз — для установки нового.
    /// </summary>
    public async Task RequirePasswordChangeAsync(Guid id, CancellationToken ct = default)
    {
        var user = await Require(id);
        user.MustChangePassword = true;
        Check(await users.UpdateAsync(user));
        await users.UpdateSecurityStampAsync(user);
        await sessions.RevokeBySubjectAsync(user.Id.ToString(), ct);
    }

    /// <summary>Снимает блокировку после неудачных попыток входа и сбрасывает счётчик.</summary>
    public async Task UnlockAsync(Guid id)
    {
        var user = await Require(id);
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
    }

    /// <summary>Удаляет пользователя: сначала отзывает токены и снимает роли, затем удаляет учётную запись.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        var user = await Require(id);
        // Назначения ролей хранят SubjectId строкой (без FK на пользователя), поэтому удаляются явно.
        await sessions.RevokeBySubjectAsync(user.Id.ToString(), ct);
        await access.RemoveSubjectAsync(SubjectType.User, user.Id.ToString(), ct);
        Check(await users.DeleteAsync(user));
        await webhooks.PublishAsync(WebhookEvents.UserDeleted, $"➖ Удалён пользователь {user.UserName}.",
            new { userId = user.Id, userName = user.UserName }, ct);
    }

    private async Task<AppUser> Require(Guid id) =>
        await users.FindByIdAsync(id.ToString()) ?? throw AdminException.NotFound("Пользователь");

    private async Task<UserDto> ToDtoAsync(AppUser user, CancellationToken ct) =>
        ToDto(user, await access.GetAssignmentsAsync(SubjectType.User, user.Id.ToString(), ct));

    private static UserDto ToDto(AppUser user, List<RoleRef> roles) => new(
        user.Id,
        user.UserName!,
        user.Email,
        user.DisplayName,
        user.IsActive,
        user.LockoutEnd > DateTimeOffset.UtcNow,
        user.PasswordHash is not null,
        user.MustChangePassword,
        user.CreatedAt,
        user.LastLoginAt,
        roles);

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    // Ошибки Identity (валидация логина/пароля) превращаются в AdminException → 400 с понятным текстом и ключом локализации.
    private static void Check(IdentityResult result) => IdentityErrors.ThrowIfFailed(result);
}
