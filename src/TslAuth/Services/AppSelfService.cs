using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;
using TslAuth.Security;

namespace TslAuth.Services;

/// <summary>Пользователь глазами приложения: только роли этого приложения и признак «создан этим приложением».</summary>
public sealed record AppUserDto(
    Guid Id,
    string UserName,
    string? Email,
    string? DisplayName,
    bool IsActive,
    bool HasPassword,
    bool MustChangePassword,
    bool CreatedByThisApp,
    List<string> Roles);

/// <summary>Входные данные App API для создания/изменения пользователя.</summary>
/// <param name="Roles">Имена ролей этого приложения.</param>
/// <param name="Invite">Создать без пароля и сразу выслать приглашение.</param>
public sealed record AppUserInput(
    string UserName,
    string? Email,
    string? DisplayName,
    string? Password = null,
    bool MustChangePassword = false,
    bool Invite = false,
    List<string>? Roles = null);

/// <summary>Привязка существующего пользователя к приложению по логину или email с выдачей ролей.</summary>
public sealed record AppUserLinkInput(string Login, List<string> Roles);

/// <summary>Результат удаления через App API: учётная запись удалена целиком или только отвязана от приложения.</summary>
public sealed record AppUserDeleteResult(bool Deleted, bool Unlinked);

/// <summary>
/// App API: приложение управляет только своим "срезом" — своими ролями, матрицей и назначениями.
/// Пользователи общие для всех приложений, поэтому:
///   • видны только пользователи, созданные этим приложением или имеющие его роли;
///   • роли других приложений не видны и не изменяются;
///   • удаление — это отвязка от приложения; учётная запись удаляется полностью, только если
///     её создало это приложение и у неё нет ролей в других приложениях.
/// Вызывается из Api/AppApi.cs; clientId всегда берётся из аутентифицированного клиента, а не из запроса.
/// </summary>
public sealed class AppSelfService(
    AuthDbContext db,
    AccessService access,
    UserService users,
    UserManager<AppUser> userManager,
    SessionService sessions)
{
    /// <summary>Пользователи, связанные с приложением (созданные им или имеющие его роли).</summary>
    public async Task<List<AppUserDto>> ListUsersAsync(string clientId, CancellationToken ct = default)
    {
        var ids = (await RelatedUserIdsAsync(clientId, ct)).ToList();
        var list = await db.Users.AsNoTracking().Where(u => ids.Contains(u.Id)).OrderBy(u => u.CreatedAt).ToListAsync(ct);
        var result = new List<AppUserDto>(list.Count);
        foreach (var user in list) result.Add(await ToDtoAsync(clientId, user, ct));
        return result;
    }

    public async Task<AppUserDto> GetUserAsync(string clientId, Guid id, CancellationToken ct = default) =>
        await ToDtoAsync(clientId, await RequireRelatedAsync(clientId, id, ct), ct);

    /// <summary>
    /// Создаёт пользователя от имени приложения. Без пароля и без приглашения генерируется временный пароль
    /// (возвращается один раз, пользователь обязан сменить его при входе).
    /// </summary>
    public async Task<(AppUserDto User, InviteResult? Invite, string? TemporaryPassword)> CreateUserAsync(
        string clientId, AppUserInput input, CancellationToken ct = default)
    {
        // Роли проверяем до создания, чтобы ошибка в ролях не оставила «осиротевшую» учётную запись.
        var roles = await ValidateRolesAsync(clientId, input.Roles, ct);

        string? temporary = null;
        var password = input.Password;
        if (!input.Invite && string.IsNullOrWhiteSpace(password))
            password = temporary = Infrastructure.PasswordGenerator.Generate();

        var created = await users.CreateAsync(new UserInput(input.UserName, input.Email, input.DisplayName, true,
            input.Invite ? null : password, input.MustChangePassword || temporary is not null), ct);

        // Отметка владельца даёт приложению право менять профиль/пароль и удалять учётную запись.
        var entity = await db.Users.FirstAsync(u => u.Id == created.Id, ct);
        entity.CreatedByClientId = clientId;
        await db.SaveChangesAsync(ct);

        await SetUserRolesAsync(clientId, created.Id, roles, ct);
        var invite = input.Invite ? await users.InviteAsync(created.Id, true, ct) : null;
        return (await GetUserAsync(clientId, created.Id, ct), invite, temporary);
    }

    /// <summary>Выдать роли этого приложения уже существующему пользователю (по точному логину или email).</summary>
    public async Task<AppUserDto> LinkUserAsync(string clientId, AppUserLinkInput input, CancellationToken ct = default)
    {
        var roles = await ValidateRolesAsync(clientId, input.Roles, ct);
        if (roles.Count == 0) throw new AdminException("Укажите хотя бы одну роль приложения.");

        var user = await users.FindByLoginAsync(input.Login.Trim()) ?? throw AdminException.NotFound("Пользователь");
        await SetUserRolesAsync(clientId, user.Id, roles, ct);
        return await GetUserAsync(clientId, user.Id, ct);
    }

    /// <summary>Меняет профиль (только для «своих» пользователей) и, если передано, роли приложения.</summary>
    public async Task<AppUserDto> UpdateUserAsync(string clientId, Guid id, AppUserInput input, CancellationToken ct = default)
    {
        var user = await RequireOwnedAsync(clientId, id, ct);
        user.UserName = input.UserName.Trim();
        user.Email = string.IsNullOrWhiteSpace(input.Email) ? null : input.Email.Trim();
        user.DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? null : input.DisplayName.Trim();
        var result = await userManager.UpdateAsync(user);
        IdentityErrors.ThrowIfFailed(result);

        if (input.Roles is not null)
            await SetUserRolesAsync(clientId, id, await ValidateRolesAsync(clientId, input.Roles, ct), ct);
        return await GetUserAsync(clientId, id, ct);
    }

    /// <summary>Заменяет роли пользователя в этом приложении; роли в других приложениях не затрагиваются.</summary>
    public async Task<AppUserDto> SetUserRolesAsync(string clientId, Guid id, List<string> roleNames, CancellationToken ct = default)
    {
        var roles = await ValidateRolesAsync(clientId, roleNames, ct);
        var current = await access.GetAssignmentsAsync(SubjectType.User, id.ToString(), ct);
        // Сохраняем чужие роли как есть и заменяем только свою часть.
        var merged = current.Where(r => r.ClientId != clientId).Concat(roles.Select(r => new RoleRef(clientId, r)));
        await access.SetAssignmentsAsync(SubjectType.User, id.ToString(), merged, ct);
        return await GetUserAsync(clientId, id, ct);
    }

    /// <summary>Удаляет пользователя или только отвязывает его от приложения (см. правила в описании класса).</summary>
    public async Task<AppUserDeleteResult> DeleteUserAsync(string clientId, Guid id, CancellationToken ct = default)
    {
        var user = await RequireRelatedAsync(clientId, id, ct);
        var assignments = await access.GetAssignmentsAsync(SubjectType.User, id.ToString(), ct);
        var foreignRoles = assignments.Any(r => r.ClientId != clientId);

        if (user.CreatedByClientId == clientId && !foreignRoles)
        {
            await users.DeleteAsync(id, ct);
            return new AppUserDeleteResult(Deleted: true, Unlinked: true);
        }

        await access.SetAssignmentsAsync(SubjectType.User, id.ToString(), assignments.Where(r => r.ClientId != clientId), ct);
        // Отзываем токены пользователя в этом приложении, иначе он сохранит доступ до истечения refresh-токена.
        await sessions.RevokeBySubjectAndClientAsync(id.ToString(), clientId, ct);
        return new AppUserDeleteResult(Deleted: false, Unlinked: true);
    }

    /// <summary>Выдаёт «своему» пользователю новый временный пароль (со сменой при следующем входе).</summary>
    public async Task<string> SetTemporaryPasswordAsync(string clientId, Guid id, CancellationToken ct = default)
    {
        await RequireOwnedAsync(clientId, id, ct);
        return await users.SetTemporaryPasswordAsync(id, ct);
    }

    /// <summary>Создаёт ссылку-приглашение для «своего» пользователя и при необходимости отправляет её письмом.</summary>
    public async Task<InviteResult> InviteAsync(string clientId, Guid id, bool sendEmail, CancellationToken ct = default)
    {
        await RequireOwnedAsync(clientId, id, ct);
        return await users.InviteAsync(id, sendEmail, ct);
    }

    // Идентификаторы сравниваются в памяти: формат Guid в тексте различается между SQLite и PostgreSQL.
    private async Task<HashSet<Guid>> RelatedUserIdsAsync(string clientId, CancellationToken ct)
    {
        var withRoles = await db.AccessRoleAssignments
            .Where(a => a.SubjectType == SubjectType.User && a.Role.ClientId == clientId)
            .Select(a => a.SubjectId).ToListAsync(ct);
        var created = await db.Users.Where(u => u.CreatedByClientId == clientId).Select(u => u.Id).ToListAsync(ct);

        var result = created.ToHashSet();
        foreach (var id in withRoles)
            if (Guid.TryParse(id, out var guid)) result.Add(guid);
        return result;
    }

    private async Task<AppUser> RequireRelatedAsync(string clientId, Guid id, CancellationToken ct)
    {
        var related = (await RelatedUserIdsAsync(clientId, ct)).Contains(id);
        // 404, а не 403: приложение не должно узнавать о существовании чужих пользователей.
        return related ? (await userManager.FindByIdAsync(id.ToString()))! : throw AdminException.NotFound("Пользователь");
    }

    /// <summary>Изменять профиль/пароль можно только пользователям, созданным этим приложением.</summary>
    private async Task<AppUser> RequireOwnedAsync(string clientId, Guid id, CancellationToken ct)
    {
        var user = await RequireRelatedAsync(clientId, id, ct);
        if (user.CreatedByClientId != clientId)
            throw new AdminException("Пользователь создан не этим приложением: доступно только управление ролями.", StatusCodes.Status403Forbidden);
        return user;
    }

    // Приложение может оперировать только ролями, объявленными в нём самом.
    private async Task<List<string>> ValidateRolesAsync(string clientId, List<string>? roles, CancellationToken ct)
    {
        var wanted = (roles ?? []).Distinct().ToList();
        var existing = await db.AccessRoles.Where(r => r.ClientId == clientId && wanted.Contains(r.Name)).Select(r => r.Name).ToListAsync(ct);
        var missing = wanted.Except(existing).ToList();
        if (missing.Count > 0) throw AdminException.NotFound($"Роли {string.Join(", ", missing)}");
        return wanted;
    }

    private async Task<AppUserDto> ToDtoAsync(string clientId, AppUser user, CancellationToken ct) => new(
        user.Id, user.UserName!, user.Email, user.DisplayName, user.IsActive, user.PasswordHash is not null,
        user.MustChangePassword, user.CreatedByClientId == clientId,
        (await access.GetAssignmentsAsync(SubjectType.User, user.Id.ToString(), ct))
            .Where(r => r.ClientId == clientId).Select(r => r.Role).ToList());
}
