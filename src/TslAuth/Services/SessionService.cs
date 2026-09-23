using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using TslAuth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Services;

/// <summary>Активная сессия (авторизация OpenIddict) с числом действующих токенов и временем последней выдачи.</summary>
public sealed record SessionDto(
    Guid Id,
    string? Subject,
    string? UserName,
    string? ClientId,
    string? Type,
    DateTime? CreatedAt,
    DateTime? LastTokenIssuedAt,
    int ActiveTokens);

/// <summary>
/// Сессии = авторизации OpenIddict. Хранятся в БД вместе с refresh-токенами, поэтому
/// переживают перезапуск любого экземпляра. Отзыв авторизации отзывает все её токены.
/// Используется страницами Admin/Sessions, Admin/Users/Edit, Admin/Index, Admin API, а также
/// ApplicationService/AppSelfService/UserService при удалении приложения, отвязке или блокировке пользователя.
/// Все изменения — массовые ExecuteUpdate прямо в БД, минуя менеджеры OpenIddict: быстро и без загрузки сущностей.
/// </summary>
public sealed class SessionService(AuthDbContext db)
{
    private IQueryable<OpenIddictEntityFrameworkCoreAuthorization<Guid>> Authorizations =>
        db.Set<OpenIddictEntityFrameworkCoreAuthorization<Guid>>();

    private IQueryable<OpenIddictEntityFrameworkCoreToken<Guid>> Tokens =>
        db.Set<OpenIddictEntityFrameworkCoreToken<Guid>>();

    /// <summary>Действующие сессии (есть хотя бы один неистёкший токен), новые первыми.</summary>
    public async Task<List<SessionDto>> ListAsync(string? subject = null, string? clientId = null, int take = 200,
        CancellationToken ct = default)
    {
        // Авторизация может оставаться Valid, когда все её токены уже истекли, — такие «мёртвые» сессии не показываем.
        var now = DateTime.UtcNow;
        var query = Authorizations.AsNoTracking().Where(a => a.Status == Statuses.Valid);
        if (!string.IsNullOrEmpty(subject)) query = query.Where(a => a.Subject == subject);
        if (!string.IsNullOrEmpty(clientId)) query = query.Where(a => a.Application!.ClientId == clientId);

        var rows = await query
            .Select(a => new
            {
                a.Id,
                a.Subject,
                a.Application!.ClientId,
                a.Type,
                a.CreationDate,
                Tokens = a.Tokens.Where(t => t.Status == Statuses.Valid && (t.ExpirationDate == null || t.ExpirationDate > now))
                    .Select(t => t.CreationDate)
            })
            .Where(a => a.Tokens.Any())
            .OrderByDescending(a => a.CreationDate)
            .Take(take)
            .Select(a => new { a.Id, a.Subject, a.ClientId, a.Type, a.CreationDate, Last = a.Tokens.Max(), Count = a.Tokens.Count() })
            .ToListAsync(ct);

        // Subject у клиентских сессий (client_credentials) — client_id, не Guid; для них имени пользователя не будет.
        var userIds = rows.Select(r => Guid.TryParse(r.Subject, out var id) ? id : Guid.Empty).Distinct().ToList();
        var names = await db.Users.AsNoTracking().Where(u => userIds.Contains(u.Id))
            .Select(u => new { u.Id, u.UserName }).ToDictionaryAsync(u => u.Id.ToString(), u => u.UserName, ct);

        return rows.Select(r => new SessionDto(r.Id, r.Subject, r.Subject is null ? null : names.GetValueOrDefault(r.Subject),
            r.ClientId, r.Type, r.CreationDate, r.Last, r.Count)).ToList();
    }

    /// <summary>Отзывает одну сессию и все её токены (refresh-токены перестают работать сразу).</summary>
    public async Task RevokeAsync(Guid authorizationId, CancellationToken ct = default)
    {
        var affected = await Authorizations.Where(a => a.Id == authorizationId)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, Statuses.Revoked), ct);
        if (affected == 0) throw AdminException.NotFound("Сессия");

        await Tokens.Where(t => t.Authorization!.Id == authorizationId && t.Status != Statuses.Revoked)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Status, Statuses.Revoked), ct);
    }

    /// <summary>Отзывает все сессии и токены субъекта («выйти везде»); возвращает число отозванных сессий.</summary>
    public async Task<int> RevokeBySubjectAsync(string subject, CancellationToken ct = default)
    {
        // Токены отзываем по Subject, а не через авторизации: у части токенов (например, client_credentials) авторизации нет.
        var count = await Authorizations.Where(a => a.Subject == subject && a.Status == Statuses.Valid)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, Statuses.Revoked), ct);
        await Tokens.Where(t => t.Subject == subject && t.Status != Statuses.Revoked)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Status, Statuses.Revoked), ct);
        return count;
    }

    /// <summary>Отзывает сессии субъекта только в указанном приложении.</summary>
    public async Task RevokeBySubjectAndClientAsync(string subject, string clientId, CancellationToken ct = default)
    {
        await Authorizations.Where(a => a.Subject == subject && a.Application!.ClientId == clientId && a.Status == Statuses.Valid)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, Statuses.Revoked), ct);
        await Tokens.Where(t => t.Subject == subject && t.Application!.ClientId == clientId && t.Status != Statuses.Revoked)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Status, Statuses.Revoked), ct);
    }

    /// <summary>Отзывает все сессии и токены приложения (перед его удалением).</summary>
    public async Task RevokeByClientAsync(string clientId, CancellationToken ct = default)
    {
        await Authorizations.Where(a => a.Application!.ClientId == clientId && a.Status == Statuses.Valid)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, Statuses.Revoked), ct);
        await Tokens.Where(t => t.Application!.ClientId == clientId && t.Status != Statuses.Revoked)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Status, Statuses.Revoked), ct);
    }

    /// <summary>Число активных сессий (для дашборда админки).</summary>
    public Task<int> CountActiveAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return Authorizations.CountAsync(a => a.Status == Statuses.Valid &&
            a.Tokens.Any(t => t.Status == Statuses.Valid && (t.ExpirationDate == null || t.ExpirationDate > now)), ct);
    }
}
