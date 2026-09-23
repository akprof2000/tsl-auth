using System.Net;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;

namespace TslAuth.Services;

/// <summary>Заявка на роль в «плоском» виде для API и страниц (Status — строка в нижнем регистре: pending/approved/rejected).</summary>
public sealed record AccessRequestDto(
    Guid Id,
    Guid UserId,
    string? UserName,
    string? Email,
    string ClientId,
    string Role,
    string Status,
    string? Comment,
    DateTime CreatedAt,
    DateTime? DecidedAt,
    string? DecidedBy,
    string? DecisionComment);

/// <summary>Роль, которую можно запросить: <see cref="ClientId"/> — приложение, которому она принадлежит.</summary>
public sealed record RequestableRole(string ClientId, string Name, string? Description)
{
    public string Key => $"{ClientId}|{Name}";
}

/// <summary>Данные формы самостоятельной регистрации (страница Account/Register): учётная запись + запрашиваемые роли.</summary>
public sealed record RegistrationInput(
    string UserName,
    string? Email,
    string? DisplayName,
    string Password,
    List<RoleRef>? Roles,
    string? Comment);

/// <summary>
/// Самостоятельная регистрация и заявки на роли. Пользователь запрашивает только роли,
/// помеченные как «можно запросить»; назначаются они только после одобрения.
/// Вызывается страницами Account/Register, Account/RequestAccess, Admin/Requests, а также Admin API и App API
/// (приложение может само рассматривать заявки на свои роли). О событиях сообщает через вебхуки и email.
/// </summary>
public sealed class AccessRequestService(
    AuthDbContext db,
    AccessService access,
    UserService users,
    ApplicationService apps,
    IEmailSender email,
    OpenIddict.Abstractions.IOpenIddictApplicationManager oidcApps,
    WebhookService webhooks,
    ILogger<AccessRequestService> logger)
{
    /// <summary>
    /// Приложения, роли которых можно запросить, находясь в клиенте <paramref name="clientId"/>:
    /// сам клиент + API, на scope которых у него есть разрешение (SPA обычно сама ролей не имеет — они у её API).
    /// </summary>
    public async Task<List<string>> RelatedAppsAsync(string clientId, CancellationToken ct = default)
    {
        var result = new List<string> { clientId };
        if (await oidcApps.FindByClientIdAsync(clientId, ct) is { } app)
            foreach (var p in await oidcApps.GetPermissionsAsync(app, ct))
                if (p.StartsWith(OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.Ordinal))
                    result.Add(p[OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope.Length..]);
        return result.Distinct().ToList();
    }

    /// <summary>Роли, которые пользователь может запросить из клиента <paramref name="clientId"/>.</summary>
    public async Task<List<RequestableRole>> ListRequestableRolesAsync(string clientId, CancellationToken ct = default)
    {
        var apps = await RelatedAppsAsync(clientId, ct);
        return await db.AccessRoles.AsNoTracking().Where(r => apps.Contains(r.ClientId) && r.IsRequestable)
            .OrderBy(r => r.ClientId).ThenBy(r => r.Name)
            .Select(r => new RequestableRole(r.ClientId, r.Name, r.Description)).ToListAsync(ct);
    }

    /// <summary>Самостоятельная регистрация пользователя в приложении и (опционально) создание заявок на роли.</summary>
    public async Task<Guid> RegisterAsync(string clientId, RegistrationInput input, CancellationToken ct = default)
    {
        if (!await apps.IsSelfRegistrationEnabledAsync(clientId, ct))
            throw new AdminException("Самостоятельная регистрация для этого приложения отключена.", StatusCodes.Status403Forbidden);

        // Роли проверяем до создания учётной записи, чтобы не оставлять «полу-зарегистрированных» пользователей.
        await ResolveRequestableAsync(clientId, input.Roles, ct);

        var user = await users.CreateAsync(new UserInput(input.UserName, input.Email, input.DisplayName, true, input.Password), ct);
        // Запоминаем приложение-«владельца»: AppSelfService разрешает ему управлять такими пользователями.
        var entity = await db.Users.FirstAsync(u => u.Id == user.Id, ct);
        entity.CreatedByClientId = clientId;
        await db.SaveChangesAsync(ct);

        await webhooks.PublishAsync(WebhookEvents.UserRegistered,
            $"👤 Новая регистрация: {user.UserName} ({user.Email ?? "без email"}) в приложении {clientId}.",
            new { userId = user.Id, userName = user.UserName, email = user.Email, clientId }, ct);

        if (input.Roles is { Count: > 0 })
            await CreateAsync(user.Id, clientId, input.Roles, input.Comment, ct);
        return user.Id;
    }

    /// <summary>Создаёт заявки на роли; уже назначенные и уже ожидающие рассмотрения роли пропускаются.</summary>
    /// <param name="clientId">Приложение, из которого пришёл пользователь (определяет, какие роли можно запросить).</param>
    public async Task<List<AccessRequestDto>> CreateAsync(Guid userId, string clientId, List<RoleRef> roles, string? comment,
        CancellationToken ct = default)
    {
        var resolved = await ResolveRequestableAsync(clientId, roles, ct);
        // Не плодим дубликаты: повторная отправка формы не должна создавать вторую pending-заявку.
        var assigned = (await access.GetAssignmentsAsync(SubjectType.User, userId.ToString(), ct)).ToHashSet();
        var pending = await db.AccessRequests
            .Where(r => r.UserId == userId && r.Status == AccessRequestStatus.Pending)
            .Select(r => r.RoleId).ToListAsync(ct);

        var created = new List<Guid>();
        foreach (var role in resolved.Where(r => !assigned.Contains(new RoleRef(r.ClientId, r.Name)) && !pending.Contains(r.Id)))
        {
            var request = new AccessRequest
            {
                UserId = userId,
                RoleId = role.Id,
                Comment = string.IsNullOrWhiteSpace(comment) ? null : comment.Trim()[..Math.Min(comment.Trim().Length, 1000)]
            };
            db.AccessRequests.Add(request);
            created.Add(request.Id);
        }

        await db.SaveChangesAsync(ct);
        var result = await QueryAsync(db.AccessRequests.Where(r => created.Contains(r.Id)), ct);
        foreach (var r in result)
            await webhooks.PublishAsync(WebhookEvents.AccessRequestCreated,
                $"📝 {r.UserName} запрашивает роль «{r.Role}» в приложении {r.ClientId}." + (r.Comment is null ? "" : $" Комментарий: {r.Comment}"),
                r, ct);
        return result;
    }

    /// <summary>Список заявок с фильтрами по статусу, приложению и пользователю (не более 1000 последних).</summary>
    public Task<List<AccessRequestDto>> ListAsync(AccessRequestStatus? status, string? clientId = null, Guid? userId = null,
        CancellationToken ct = default)
    {
        var query = db.AccessRequests.AsQueryable();
        if (status is not null) query = query.Where(r => r.Status == status);
        if (clientId is not null) query = query.Where(r => r.Role.ClientId == clientId);
        if (userId is not null) query = query.Where(r => r.UserId == userId);
        return QueryAsync(query, ct);
    }

    /// <summary>Число заявок, ожидающих решения (бейдж в меню админки).</summary>
    public Task<int> CountPendingAsync(CancellationToken ct = default) =>
        db.AccessRequests.CountAsync(r => r.Status == AccessRequestStatus.Pending, ct);

    /// <summary>Одобряет или отклоняет заявку; при одобрении назначает роль, затем шлёт вебхук и письмо.</summary>
    /// <param name="restrictToClientId">Для App API: приложение решает только заявки на свои роли.</param>
    public async Task<AccessRequestDto> DecideAsync(Guid id, bool approve, string decidedBy, string? comment,
        string? restrictToClientId = null, CancellationToken ct = default)
    {
        // Чужая заявка для App API выглядит как несуществующая (404), чтобы не раскрывать её наличие.
        var request = await db.AccessRequests.Include(r => r.Role).FirstOrDefaultAsync(r => r.Id == id, ct);
        if (request is null || (restrictToClientId is not null && request.Role.ClientId != restrictToClientId))
            throw AdminException.NotFound("Заявка");
        if (request.Status != AccessRequestStatus.Pending)
            throw AdminException.Conflict("Заявка уже рассмотрена.");

        request.Status = approve ? AccessRequestStatus.Approved : AccessRequestStatus.Rejected;
        request.DecidedAt = DateTime.UtcNow;
        request.DecidedBy = decidedBy;
        request.DecisionComment = string.IsNullOrWhiteSpace(comment) ? null : comment.Trim();
        await db.SaveChangesAsync(ct);

        if (approve)
            await access.AssignAsync(SubjectType.User, request.UserId.ToString(), new RoleRef(request.Role.ClientId, request.Role.Name), ct);

        var dto = (await QueryAsync(db.AccessRequests.Where(r => r.Id == id), ct)).Single();
        await webhooks.PublishAsync(approve ? WebhookEvents.AccessRequestApproved : WebhookEvents.AccessRequestRejected,
            $"{(approve ? "✅" : "⛔")} Заявка {dto.UserName} на роль «{dto.Role}» в {dto.ClientId} {(approve ? "одобрена" : "отклонена")} ({decidedBy}).",
            dto, ct);
        await NotifyAsync(dto, ct);
        return dto;
    }

    // Сверяет запрошенные роли с белым списком (IsRequestable + связанные приложения):
    // без этой проверки через форму можно было бы запросить любую роль, включая админскую.
    private async Task<List<AccessRole>> ResolveRequestableAsync(string clientId, List<RoleRef>? roles, CancellationToken ct)
    {
        var wanted = (roles ?? []).Distinct().ToList();
        var apps = await RelatedAppsAsync(clientId, ct);
        var candidates = await db.AccessRoles.Where(r => apps.Contains(r.ClientId) && r.IsRequestable).ToListAsync(ct);
        var found = candidates.Where(r => wanted.Contains(new RoleRef(r.ClientId, r.Name))).ToList();
        var missing = wanted.Where(w => found.All(f => f.ClientId != w.ClientId || f.Name != w.Role)).Select(w => w.ToString()).ToList();
        if (missing.Count > 0)
            throw new AdminException($"Эти роли нельзя запросить: {string.Join(", ", missing)}.");
        return found;
    }

    private async Task<List<AccessRequestDto>> QueryAsync(IQueryable<AccessRequest> query, CancellationToken ct)
    {
        var rows = await query.AsNoTracking().OrderByDescending(r => r.CreatedAt)
            .Select(r => new { r, r.Role.ClientId, RoleName = r.Role.Name }).Take(1000).ToListAsync(ct);
        // Имена/email подтягиваем отдельным запросом: у AccessRequest нет навигации на пользователя.
        var userIds = rows.Select(x => x.r.UserId).Distinct().ToList();
        var people = await db.Users.AsNoTracking().Where(u => userIds.Contains(u.Id))
            .Select(u => new { u.Id, u.UserName, u.Email }).ToDictionaryAsync(u => u.Id, ct);

        return rows.Select(x => new AccessRequestDto(x.r.Id, x.r.UserId, people.GetValueOrDefault(x.r.UserId)?.UserName,
            people.GetValueOrDefault(x.r.UserId)?.Email, x.ClientId, x.RoleName, x.r.Status.ToString().ToLowerInvariant(),
            x.r.Comment, x.r.CreatedAt, x.r.DecidedAt, x.r.DecidedBy, x.r.DecisionComment)).ToList();
    }

    private async Task NotifyAsync(AccessRequestDto request, CancellationToken ct)
    {
        if (!email.IsConfigured || request.Email is null) return;
        var decision = request.Status == "approved" ? "одобрена" : "отклонена";
        try
        {
            await email.SendAsync(request.Email, $"Заявка на доступ {decision}", $"""
                <p>Ваша заявка на роль <b>{WebUtility.HtmlEncode(request.Role)}</b> в приложении
                   <b>{WebUtility.HtmlEncode(request.ClientId)}</b> {decision}.</p>
                {(request.DecisionComment is null ? "" : $"<p>Комментарий: {WebUtility.HtmlEncode(request.DecisionComment)}</p>")}
                """, ct);
        }
        catch (Exception ex)
        {
            // Решение уже сохранено — сбой почты не должен откатывать его или ронять запрос.
            logger.LogWarning(ex, "Не удалось отправить уведомление о заявке {RequestId}.", request.Id);
        }
    }
}
