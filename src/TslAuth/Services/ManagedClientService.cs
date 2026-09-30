using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using TslAuth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Services;

/// <summary>Подчинённый клиент в ответах API: без секретов и координат ключей.</summary>
public sealed record ManagedClientDto(
    string ClientId,
    string? DisplayName,
    string Owner,
    bool Disabled,
    List<string> Roles,
    List<ManagedClientKeyDto> Keys,
    bool HasSecret,
    DateTime? CreatedAt,
    DateTime? LastTokenIssuedAt);

/// <summary>
/// Создание подчинённого: <c>ClientId</c> целиком (с префиксом) или <c>ClientIdSuffix</c> (без префикса);
/// пусто — сервис сгенерирует случайный суффикс. <c>Jwks</c> — открытые ключи EC P-256; <c>RequestSecret</c> —
/// выдать секрет (если политика разрешает <c>client_secret</c>).
/// </summary>
public sealed record ManagedClientInput(string? ClientId = null, string? ClientIdSuffix = null, string? DisplayName = null,
    List<string>? Roles = null, JsonElement? Jwks = null, bool RequestSecret = false);

/// <summary>Результат создания: секрет заполнен только если он выдан (показывается один раз).</summary>
public sealed record ManagedClientCreated(ManagedClientDto Client, string? ClientSecret);

/// <summary>Замена ключей подчинённого: до двух открытых ключей EC P-256.</summary>
public sealed record ManagedClientKeysInput(JsonElement Jwks);

/// <summary>
/// Подчинённые клиенты (managed clients): приложение-владелец через App API заводит сервисных клиентов
/// в рамках политики <see cref="ManagedClientsPolicy"/>, которую задал администратор. Подчинённый — обычный
/// confidential-клиент OpenIddict со свойством <c>tsl_owner</c>, потоком client_credentials и scope владельца;
/// входит по ключу (<c>private_key_jwt</c>) или секрету. Чужой или не подчинённый клиент — всегда 404.
/// Каждое действие пишется в журнал безопасности с ClientId владельца (виден в /api/app/audit).
/// Используется App API (/api/app/clients), Admin API, страницами Admin/Apps и TokenPruningService.
/// </summary>
public sealed class ManagedClientService(
    IOpenIddictApplicationManager applications,
    ApplicationService apps,
    AccessService access,
    AuditService audit,
    AuthDbContext db)
{
    /// <summary>Политика владельца или null, если подчинённые клиенты не включены.</summary>
    public async Task<ManagedClientsPolicy?> GetPolicyAsync(string owner, CancellationToken ct = default)
    {
        if (await applications.FindByClientIdAsync(owner, ct) is not { } app) return null;
        return ManagedClientsPolicy.From(await applications.GetPropertiesAsync(app, ct));
    }

    /// <summary>
    /// Задаёт (или снимает — null) политику подчинённых. Только администратор. Владелец должен быть confidential
    /// с самоуправлением (App API), роли белого списка — существовать в его матрице.
    /// </summary>
    public async Task<ManagedClientsPolicy?> SetPolicyAsync(string owner, ManagedClientsPolicy? policy, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(owner, ct) ?? throw AdminException.NotFound($"Приложение '{owner}'");
        var properties = await applications.GetPropertiesAsync(app, ct);
        if (properties.ContainsKey(ApplicationService.OwnerProperty))
            throw new AdminException("Подчинённый клиент не может иметь собственных подчинённых.");
        if (owner == SystemApp.ClientId) throw new AdminException("У системного приложения не бывает подчинённых клиентов.");

        if (policy is not null)
        {
            policy = policy.Normalize();
            var dto = (await apps.GetAsync(owner, ct))!;
            if (dto.ClientType != ClientTypes.Confidential || !dto.SelfManagement)
                throw new AdminException("Подчинённые клиенты доступны confidential-приложению с включённым самоуправлением (App API).");
            var matrix = await access.GetMatrixAsync(owner, ct);
            var missing = (policy.Roles ?? []).Except(matrix.Roles.Select(r => r.Name)).ToList();
            if (missing.Count > 0)
                throw new AdminException($"Ролей нет в матрице приложения {owner}: {string.Join(", ", missing)}.");
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, app, ct);
        if (policy is null) descriptor.Properties.Remove(ApplicationService.ManagedClientsProperty);
        else descriptor.Properties[ApplicationService.ManagedClientsProperty] = JsonSerializer.SerializeToElement(policy);
        await applications.UpdateAsync(app, descriptor, ct);

        await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Info, owner,
            details: new { action = policy is null ? "policy_removed" : "policy_set", policy });
        return policy;
    }

    /// <summary>Список подчинённых владельца (без секретов и ключей — только отпечатки).</summary>
    public async Task<List<ManagedClientDto>> ListAsync(string owner, CancellationToken ct = default)
    {
        var result = new List<ManagedClientDto>();
        foreach (var clientId in await apps.ListManagedClientIdsAsync(owner, ct))
        {
            if (await applications.FindByClientIdAsync(clientId, ct) is { } app)
                result.Add(await ToDtoAsync(app, owner, ct));
        }
        return result.OrderBy(c => c.ClientId).ToList();
    }

    /// <summary>Карточка подчинённого; чужой или не подчинённый клиент — 404.</summary>
    public async Task<ManagedClientDto> GetAsync(string owner, string clientId, CancellationToken ct = default) =>
        await ToDtoAsync(await FindManagedAsync(owner, clientId, ct), owner, ct);

    /// <summary>
    /// Создаёт подчинённого: client_id с префиксом политики, роли из белого списка, ключи и/или секрет.
    /// Дескриптор минимален: confidential, только client_credentials, scope владельца, без redirect URI.
    /// </summary>
    public async Task<ManagedClientCreated> CreateAsync(string owner, ManagedClientInput input, string? via = null,
        CancellationToken ct = default)
    {
        var policy = await RequirePolicyAsync(owner, ct);

        var clientId = input.ClientId is { Length: > 0 }
            ? policy.ValidateClientId(input.ClientId)
            : policy.ValidateClientId(policy.Prefix + (string.IsNullOrWhiteSpace(input.ClientIdSuffix)
                ? Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6))
                : input.ClientIdSuffix.Trim()));
        if (await applications.FindByClientIdAsync(clientId, ct) is not null)
            throw AdminException.Conflict($"Клиент '{clientId}' уже существует.");

        var roles = policy.ValidateRoles(input.Roles);
        var jwks = input.Jwks is { ValueKind: not (JsonValueKind.Null or JsonValueKind.Undefined) } j ? ManagedClientKeys.Parse(j) : null;
        if (jwks is not null && !policy.AllowsKeys) throw new AdminException("Политика не разрешает вход по ключу (private_key_jwt).");
        if (input.RequestSecret && !policy.AllowsSecret) throw new AdminException("Политика не разрешает вход по секрету (client_secret).");
        if (jwks is null && !input.RequestSecret) throw new AdminException("Укажите открытые ключи (jwks) или запросите секрет (requestSecret).");

        var existing = await apps.ListManagedClientIdsAsync(owner, ct);
        if (existing.Count >= policy.MaxClients)
            throw new AdminException($"Достигнут предел подчинённых клиентов ({policy.MaxClients}).");

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? clientId : input.DisplayName.Trim(),
            ClientType = ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            JsonWebKeySet = jwks
        };
        descriptor.Permissions.Add(Permissions.Endpoints.Token);
        descriptor.Permissions.Add(Permissions.Endpoints.Revocation);
        descriptor.Permissions.Add(Permissions.Endpoints.Introspection);
        descriptor.Permissions.Add(Permissions.Prefixes.GrantType + AppGrantTypes.ClientCredentials);
        descriptor.Permissions.Add(Permissions.Prefixes.Scope + owner);
        descriptor.Properties[ApplicationService.OwnerProperty] = JsonSerializer.SerializeToElement(owner);
        descriptor.Properties[ApplicationService.CreatedAtProperty] = JsonSerializer.SerializeToElement(DateTime.UtcNow);
        string? secret = null;
        if (input.RequestSecret) descriptor.ClientSecret = secret = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

        await applications.CreateAsync(descriptor, ct);
        await access.SetAssignmentsAsync(SubjectType.Client, clientId, roles.Select(r => new RoleRef(owner, r)), ct);

        await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Info, owner, details: new
        {
            action = "created", clientId, roles, keys = ManagedClientKeys.Describe(jwks).Select(k => k.Kid), secret = secret is not null, via
        });
        return new ManagedClientCreated(await GetAsync(owner, clientId, ct), secret);
    }

    /// <summary>Заменяет открытые ключи подчинённого (до двух — для плавной смены по kid).</summary>
    public async Task<ManagedClientDto> SetKeysAsync(string owner, string clientId, JsonElement jwks, string? via = null,
        CancellationToken ct = default)
    {
        var policy = await RequirePolicyAsync(owner, ct);
        if (!policy.AllowsKeys) throw new AdminException("Политика не разрешает вход по ключу (private_key_jwt).");
        var app = await FindManagedAsync(owner, clientId, ct);
        var set = ManagedClientKeys.Parse(jwks);

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, app, ct);
        descriptor.JsonWebKeySet = set;
        await applications.UpdateAsync(app, descriptor, ct);

        await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Info, owner,
            details: new { action = "keys_changed", clientId, keys = ManagedClientKeys.Describe(set).Select(k => k.Kid), via });
        return await GetAsync(owner, clientId, ct);
    }

    /// <summary>Отключает/включает подчинённого (отключение отзывает его токены).</summary>
    public async Task<ManagedClientDto> SetDisabledAsync(string owner, string clientId, bool disabled, string? via = null,
        CancellationToken ct = default)
    {
        await FindManagedAsync(owner, clientId, ct);
        var changed = await apps.SetDisabledAsync(clientId, disabled, ct);
        if (changed)
            await audit.WriteAsync(AuditTypes.ManagedClientChange, true, disabled ? AuditSeverity.Warning : AuditSeverity.Info, owner,
                details: new { action = disabled ? "disabled" : "enabled", clientId, via });
        return await GetAsync(owner, clientId, ct);
    }

    /// <summary>Выдаёт новый секрет (старый перестаёт действовать); только если политика разрешает client_secret.</summary>
    public async Task<string> NewSecretAsync(string owner, string clientId, string? via = null, CancellationToken ct = default)
    {
        var policy = await RequirePolicyAsync(owner, ct);
        if (!policy.AllowsSecret) throw new AdminException("Политика не разрешает вход по секрету (client_secret).");
        var app = await FindManagedAsync(owner, clientId, ct);
        var secret = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        await applications.UpdateAsync(app, secret, ct);
        await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Info, owner,
            details: new { action = "secret_issued", clientId, via });
        return secret;
    }

    /// <summary>Удаляет подчинённого с отзывом его токенов.</summary>
    public async Task DeleteAsync(string owner, string clientId, string? via = null, CancellationToken ct = default)
    {
        await FindManagedAsync(owner, clientId, ct);
        await apps.DeleteAsync(clientId, ct);
        await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Info, owner,
            details: new { action = "deleted", clientId, via });
    }

    /// <summary>
    /// Защита от обхода через Admin API: роли подчинённого — только роли владельца из белого списка политики.
    /// Для обычных приложений ничего не проверяет.
    /// </summary>
    public async Task EnsureServiceRolesAllowedAsync(string clientId, IEnumerable<RoleRef> roles, CancellationToken ct = default)
    {
        var dto = await apps.GetAsync(clientId, ct);
        if (dto?.Owner is not { } owner) return;
        var policy = await GetPolicyAsync(owner, ct);
        var list = roles.ToList();
        if (list.Any(r => r.ClientId != owner))
            throw new AdminException($"Подчинённому клиенту можно выдавать только роли владельца {owner}.");
        (policy ?? new ManagedClientsPolicy(owner)).ValidateRoles(list.Select(r => r.Role));
    }

    /// <summary>
    /// Автоотключение подчинённых без токенов дольше <c>InactiveDays</c> политики владельца (обслуживание БД).
    /// Отсчёт — от последнего выданного токена или от создания клиента. Возвращает отключённых (владелец, клиент).
    /// </summary>
    public async Task<List<(string Owner, string ClientId)>> DisableInactiveAsync(CancellationToken ct = default)
    {
        var result = new List<(string, string)>();
        var policies = new Dictionary<string, ManagedClientsPolicy?>();
        foreach (var (owner, clientId) in await apps.ListManagedClientsAsync(ct))
        {
            if (!policies.TryGetValue(owner, out var policy)) policies[owner] = policy = await GetPolicyAsync(owner, ct);
            if (policy is not { InactiveDays: > 0 }) continue;
            var dto = await GetAsync(owner, clientId, ct);
            if (dto.Disabled) continue;
            var last = dto.LastTokenIssuedAt ?? dto.CreatedAt ?? DateTime.UtcNow;
            if (last > DateTime.UtcNow.AddDays(-policy.InactiveDays)) continue;
            if (await apps.SetDisabledAsync(clientId, true, ct))
            {
                await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Warning, owner,
                    details: new { action = "disabled_inactive", clientId, days = policy.InactiveDays }, actor: "system", actorName: "обслуживание");
                result.Add((owner, clientId));
            }
        }
        return result;
    }

    private async Task<ManagedClientsPolicy> RequirePolicyAsync(string owner, CancellationToken ct) =>
        await GetPolicyAsync(owner, ct) ?? throw new AdminException("Подчинённые клиенты для приложения не включены администратором.");

    /// <summary>Клиент, подчинённый именно этому владельцу; иначе 404 (не раскрываем существование чужих клиентов).</summary>
    private async Task<object> FindManagedAsync(string owner, string clientId, CancellationToken ct)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct);
        if (app is null || ApplicationService.OwnerOf(await applications.GetPropertiesAsync(app, ct)) != owner)
            throw AdminException.NotFound($"Подчинённый клиент '{clientId}'");
        return app;
    }

    private async Task<ManagedClientDto> ToDtoAsync(object app, string owner, CancellationToken ct)
    {
        var clientId = (await applications.GetClientIdAsync(app, ct))!;
        var properties = await applications.GetPropertiesAsync(app, ct);
        var roles = (await access.GetAssignmentsAsync(SubjectType.Client, clientId, ct))
            .Where(r => r.ClientId == owner).Select(r => r.Role).ToList();
        var jwks = await applications.GetJsonWebKeySetAsync(app, ct);
        var lastToken = await db.Set<OpenIddictEntityFrameworkCoreToken<Guid>>().AsNoTracking()
            .Where(t => t.Application!.ClientId == clientId).MaxAsync(t => t.CreationDate, ct);
        var createdAt = properties.TryGetValue(ApplicationService.CreatedAtProperty, out var c) && c.TryGetDateTime(out var created)
            ? created : (DateTime?)null;
        return new ManagedClientDto(clientId, await applications.GetDisplayNameAsync(app, ct), owner,
            ApplicationService.IsDisabled(properties), roles, ManagedClientKeys.Describe(jwks),
            await db.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>().AsNoTracking()
                .AnyAsync(a => a.ClientId == clientId && a.ClientSecret != null, ct), createdAt, lastToken);
    }
}
