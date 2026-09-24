using Microsoft.EntityFrameworkCore;
using TslAuth.Data;

namespace TslAuth.Services;

/// <summary>Разрешение приложения (атомарное право, например <c>orders.read</c>).</summary>
public sealed record PermissionDto(string Name, string? Description);

/// <summary>
/// Роль приложения со списком входящих в неё разрешений; <c>IsRequestable</c> — роль можно запросить через заявку.
/// <c>Name</c> — техническое имя (в токенах и API), <c>DisplayName</c> — название для пользователей.
/// </summary>
public sealed record RoleDto(string Name, string? Description, List<string> Permissions, bool IsRequestable = false,
    string? DisplayName = null);

/// <summary>Матрица «роль × разрешение» одного приложения (страница Admin/Apps/Matrix и Admin API).</summary>
public sealed record MatrixDto(string ClientId, List<PermissionDto> Permissions, List<RoleDto> Roles);

/// <summary>Итоговые роли и разрешения субъекта в одном приложении — попадают в claims токена.</summary>
public sealed record AppGrant(IReadOnlyCollection<string> Roles, IReadOnlyCollection<string> Permissions);

/// <summary>
/// RBAC: разрешения и роли приложений, матрица роль×разрешение, назначения ролей субъектам.
/// Используется Admin API, App API, страницами Admin/Apps, проверкой прав администраторов
/// (AdminAuthorization) и <see cref="TokenPrincipalFactory"/> при выпуске токенов.
/// </summary>
public sealed class AccessService(AuthDbContext db)
{
    /// <summary>Возвращает все разрешения и роли приложения вместе с их связями.</summary>
    public async Task<MatrixDto> GetMatrixAsync(string clientId, CancellationToken ct = default)
    {
        var permissions = await db.AccessPermissions.AsNoTracking()
            .Where(p => p.ClientId == clientId).OrderBy(p => p.Name)
            .Select(p => new PermissionDto(p.Name, p.Description)).ToListAsync(ct);

        var roles = await db.AccessRoles.AsNoTracking()
            .Where(r => r.ClientId == clientId).OrderBy(r => r.Name)
            .Select(r => new RoleDto(r.Name, r.Description,
                r.Permissions.Select(x => x.Permission.Name).OrderBy(n => n).ToList(), r.IsRequestable, r.DisplayName))
            .ToListAsync(ct);

        return new MatrixDto(clientId, permissions, roles);
    }

    public async Task<PermissionDto> AddPermissionAsync(string clientId, string name, string? description, CancellationToken ct = default)
    {
        name = Names.Validate(name, "Имя разрешения");
        if (await db.AccessPermissions.AnyAsync(p => p.ClientId == clientId && p.Name == name, ct))
            throw AdminException.Conflict($"Разрешение '{name}' уже существует.");

        db.AccessPermissions.Add(new AccessPermission { ClientId = clientId, Name = name, Description = description });
        await db.SaveChangesAsync(ct);
        return new PermissionDto(name, description);
    }

    public async Task DeletePermissionAsync(string clientId, string name, CancellationToken ct = default)
    {
        var permission = await db.AccessPermissions.FirstOrDefaultAsync(p => p.ClientId == clientId && p.Name == name, ct)
                         ?? throw AdminException.NotFound($"Разрешение '{name}'");
        GuardSystem(clientId);
        db.AccessPermissions.Remove(permission);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Создаёт роль. <paramref name="name"/> — техническое имя (строчные латинские, без пробелов, уникально в приложении),
    /// <paramref name="displayName"/> — название для пользователей на языке установки (может повторяться).
    /// </summary>
    public async Task<RoleDto> AddRoleAsync(string clientId, string name, string? description,
        IEnumerable<string>? permissions = null, CancellationToken ct = default, bool requestable = false, string? displayName = null)
    {
        name = Names.ValidateRole(name);
        displayName = Names.DisplayName(displayName);
        if (await db.AccessRoles.AnyAsync(r => r.ClientId == clientId && r.Name == name, ct))
            throw AdminException.Conflict($"Роль '{name}' уже существует в этом приложении.");

        if (description is { Length: > 500 }) throw new AdminException("Описание роли: не более 500 символов.");
        // Роль и её разрешения — одной транзакцией: неизвестное разрешение не должно оставлять созданную роль
        // (повторный запрос получил бы 409 «уже существует»).
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            db.AccessRoles.Add(new AccessRole
            {
                ClientId = clientId, Name = name, DisplayName = displayName, Description = description, IsRequestable = requestable
            });
            await db.SaveChangesAsync(ct);
            if (permissions is not null)
                await SetRolePermissionsAsync(clientId, name, permissions, ct);
            await tx.CommitAsync(ct);
        }

        return (await GetMatrixAsync(clientId, ct)).Roles.First(r => r.Name == name);
    }

    public async Task DeleteRoleAsync(string clientId, string name, CancellationToken ct = default)
    {
        var role = await db.AccessRoles.FirstOrDefaultAsync(r => r.ClientId == clientId && r.Name == name, ct)
                   ?? throw AdminException.NotFound($"Роль '{name}'");
        GuardSystem(clientId);
        db.AccessRoles.Remove(role);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Меняет название роли для пользователей и описание. Техническое имя не меняется: на него ссылаются
    /// выданные токены и код приложений.
    /// </summary>
    /// <param name="system">Вызов из StartupInitializer: только он может менять описание встроенных ролей администрирования.</param>
    public async Task<RoleDto> UpdateRoleAsync(string clientId, string name, string? displayName, string? description,
        CancellationToken ct = default, bool system = false)
    {
        if (!system) GuardSystem(clientId, "изменить");
        displayName = Names.DisplayName(displayName);
        description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        var affected = await db.AccessRoles.Where(r => r.ClientId == clientId && r.Name == name)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.DisplayName, displayName).SetProperty(r => r.Description, description), ct);
        if (affected == 0) throw AdminException.NotFound($"Роль '{name}'");
        return (await GetMatrixAsync(clientId, ct)).Roles.First(r => r.Name == name);
    }

    /// <summary>Помечает роль как доступную (или недоступную) для запроса через заявку.</summary>
    public async Task SetRoleRequestableAsync(string clientId, string roleName, bool requestable, CancellationToken ct = default)
    {
        // Иначе прямым POST можно было сделать роль administrator «запрашиваемой» при самостоятельной регистрации.
        GuardSystem(clientId, "сделать запрашиваемыми");
        // Точечный UPDATE без загрузки сущности; 0 затронутых строк = роли нет.
        var affected = await db.AccessRoles.Where(r => r.ClientId == clientId && r.Name == roleName)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.IsRequestable, requestable), ct);
        if (affected == 0) throw AdminException.NotFound($"Роль '{roleName}'");
    }

    /// <summary>Заменяет набор разрешений роли указанным (все разрешения должны существовать в том же приложении).</summary>
    public async Task SetRolePermissionsAsync(string clientId, string roleName, IEnumerable<string> permissions, CancellationToken ct = default)
    {
        var role = await db.AccessRoles.Include(r => r.Permissions)
                       .FirstOrDefaultAsync(r => r.ClientId == clientId && r.Name == roleName, ct)
                   ?? throw AdminException.NotFound($"Роль '{roleName}'");

        var wanted = permissions.Distinct().ToList();
        var found = await db.AccessPermissions
            .Where(p => p.ClientId == clientId && wanted.Contains(p.Name))
            .ToDictionaryAsync(p => p.Id, p => p.Name, ct);

        var missing = wanted.Except(found.Values).ToList();
        if (missing.Count > 0)
            throw AdminException.NotFound($"Разрешения {string.Join(", ", missing)}");

        // Диф вместо «удалить всё и добавить заново»: неизменённые связи не трогаем.
        role.Permissions.RemoveAll(x => !found.ContainsKey(x.PermissionId));
        foreach (var id in found.Keys.Where(id => role.Permissions.All(x => x.PermissionId != id)))
            role.Permissions.Add(new AccessRolePermission { RoleId = role.Id, PermissionId = id });

        await db.SaveChangesAsync(ct);
    }

    /// <summary>Полностью задаёт матрицу: для каждой роли — список её разрешений.</summary>
    public async Task SetMatrixAsync(string clientId, IDictionary<string, List<string>> matrix, CancellationToken ct = default)
    {
        // Одна транзакция: либо вся матрица применяется, либо (при ошибке в любой роли) ничего.
        // Роли, отсутствующие в словаре, получают пустой набор разрешений.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var roles = await db.AccessRoles.Where(r => r.ClientId == clientId).Select(r => r.Name).ToListAsync(ct);
        foreach (var role in roles)
            await SetRolePermissionsAsync(clientId, role, matrix.TryGetValue(role, out var p) ? p : [], ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>Роли, назначенные субъекту (пользователю или клиенту-сервису) во всех приложениях.</summary>
    public async Task<List<RoleRef>> GetAssignmentsAsync(SubjectType type, string subjectId, CancellationToken ct = default) =>
        await db.AccessRoleAssignments.AsNoTracking()
            .Where(a => a.SubjectType == type && a.SubjectId == subjectId)
            .OrderBy(a => a.Role.ClientId).ThenBy(a => a.Role.Name)
            .Select(a => new RoleRef(a.Role.ClientId, a.Role.Name))
            .ToListAsync(ct);

    /// <summary>Полностью заменяет набор ролей субъекта; неизвестная роль — ошибка, изменений не будет.</summary>
    public async Task SetAssignmentsAsync(SubjectType type, string subjectId, IEnumerable<RoleRef> roles, CancellationToken ct = default)
    {
        // Сначала резолвим все роли в Id, и только потом меняем БД — чтобы не применить набор частично.
        var wanted = roles.Distinct().ToList();
        var clientIds = wanted.Select(r => r.ClientId).Distinct().ToList();
        var candidates = await db.AccessRoles.Where(r => clientIds.Contains(r.ClientId)).ToListAsync(ct);

        var roleIds = new HashSet<Guid>();
        foreach (var r in wanted)
        {
            var role = candidates.FirstOrDefault(c => c.ClientId == r.ClientId && c.Name == r.Role)
                       ?? throw AdminException.NotFound($"Роль '{r}'");
            roleIds.Add(role.Id);
        }

        var current = await db.AccessRoleAssignments
            .Where(a => a.SubjectType == type && a.SubjectId == subjectId).ToListAsync(ct);

        db.AccessRoleAssignments.RemoveRange(current.Where(a => !roleIds.Contains(a.RoleId)));
        foreach (var id in roleIds.Where(id => current.All(a => a.RoleId != id)))
            db.AccessRoleAssignments.Add(new AccessRoleAssignment { RoleId = id, SubjectType = type, SubjectId = subjectId });

        await db.SaveChangesAsync(ct);
    }

    /// <summary>Добавляет одну роль к уже назначенным (идемпотентно); используется при одобрении заявки.</summary>
    public async Task AssignAsync(SubjectType type, string subjectId, RoleRef role, CancellationToken ct = default)
    {
        var current = await GetAssignmentsAsync(type, subjectId, ct);
        if (!current.Contains(role))
            await SetAssignmentsAsync(type, subjectId, current.Append(role), ct);
    }

    /// <summary>Роли и разрешения субъекта в указанных приложениях (для формирования токена).</summary>
    public async Task<Dictionary<string, AppGrant>> GetGrantsAsync(SubjectType type, string subjectId,
        IEnumerable<string> clientIds, CancellationToken ct = default)
    {
        var ids = clientIds.Distinct().ToList();
        var rows = await db.AccessRoleAssignments.AsNoTracking()
            .Where(a => a.SubjectType == type && a.SubjectId == subjectId && ids.Contains(a.Role.ClientId))
            .Select(a => new
            {
                a.Role.ClientId,
                Role = a.Role.Name,
                Permissions = a.Role.Permissions.Select(p => p.Permission.Name).ToList()
            })
            .ToListAsync(ct);

        // Несколько ролей могут давать одно и то же разрешение — объединяем и сортируем для стабильного токена.
        return rows.GroupBy(r => r.ClientId).ToDictionary(
            g => g.Key,
            g => new AppGrant(
                g.Select(r => r.Role).Distinct().Order().ToList(),
                g.SelectMany(r => r.Permissions).Distinct().Order().ToList()));
    }

    /// <summary>Проверяет, есть ли у субъекта разрешение в приложении (через любую из его ролей).</summary>
    public async Task<bool> HasPermissionAsync(SubjectType type, string subjectId, string clientId, string permission,
        CancellationToken ct = default)
    {
        // Отключённый пользователь теряет все права сразу, даже если его роли ещё назначены.
        if (type == SubjectType.User)
        {
            if (!Guid.TryParse(subjectId, out var userId) ||
                !await db.Users.AnyAsync(u => u.Id == userId && u.IsActive, ct))
                return false;
        }

        return await db.AccessRoleAssignments.AnyAsync(a =>
            a.SubjectType == type && a.SubjectId == subjectId && a.Role.ClientId == clientId &&
            a.Role.Permissions.Any(p => p.Permission.Name == permission), ct);
    }

    /// <summary>Удаляет всю RBAC-конфигурацию приложения и назначения ролей самому приложению как субъекту.</summary>
    public async Task RemoveApplicationAsync(string clientId, CancellationToken ct = default)
    {
        // Связи роль-разрешение и назначения ролей удаляются каскадом на уровне БД.
        await db.AccessRoles.Where(r => r.ClientId == clientId).ExecuteDeleteAsync(ct);
        await db.AccessPermissions.Where(p => p.ClientId == clientId).ExecuteDeleteAsync(ct);
        await RemoveSubjectAsync(SubjectType.Client, clientId, ct);
    }

    /// <summary>Снимает все роли с субъекта (при удалении пользователя или клиента).</summary>
    public Task RemoveSubjectAsync(SubjectType type, string subjectId, CancellationToken ct = default) =>
        db.AccessRoleAssignments.Where(a => a.SubjectType == type && a.SubjectId == subjectId).ExecuteDeleteAsync(ct);

    private static void GuardSystem(string clientId, string action = "удалить")
    {
        if (clientId == SystemApp.ClientId)
            throw new AdminException($"Встроенные роли и разрешения администрирования нельзя {action}.", StatusCodes.Status403Forbidden);
    }
}
