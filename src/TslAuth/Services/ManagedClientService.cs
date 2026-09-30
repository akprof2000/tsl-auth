using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
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
/// Каждое действие пишется в журнал безопасности с ClientId владельца (виден в /api/app/audit); отключение и
/// удаление журналирует <see cref="ApplicationService"/> — чтобы запись была и при действии администратора.
/// Списки строятся тремя запросами (приложения, роли, активность) независимо от числа подчинённых.
/// Используется App API (/api/app/clients), Admin API, страницами Admin/Apps, AuthorizationController и TokenPruningService.
/// </summary>
public sealed class ManagedClientService(
    IOpenIddictApplicationManager applications,
    ApplicationService apps,
    AccessService access,
    AuditService audit,
    AuthDbContext db)
{
    // Проверка предела maxClients и вставка должны идти друг за другом: без блокировки два параллельных создания
    // видели бы одно и то же число и оба проходили. Блокировка на владельца в пределах узла; между узлами
    // гонку сужает лимит изменений App API (30 в минуту на владельца).
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> CreateLocks = new(StringComparer.Ordinal);

    // Когда узел последний раз записал отметку активности клиента: предел неактивности считается в днях, поэтому
    // запись в БД не чаще раза в минуту на клиента — иначе каждый токен давал бы лишнюю запись (в SQLite они
    // выстраиваются в очередь и поднимают задержку выдачи под нагрузкой).
    private static readonly ConcurrentDictionary<string, DateTime> ActivityWritten = new(StringComparer.Ordinal);
    private static readonly TimeSpan ActivityResolution = TimeSpan.FromMinutes(1);

    /// <summary>Политика владельца или null, если подчинённые клиенты не включены.</summary>
    public async Task<ManagedClientsPolicy?> GetPolicyAsync(string owner, CancellationToken ct = default)
    {
        if (await applications.FindByClientIdAsync(owner, ct) is not { } app) return null;
        return ManagedClientsPolicy.From(await applications.GetPropertiesAsync(app, ct));
    }

    /// <summary>
    /// Задаёт (или снимает — null) политику подчинённых. Только администратор. Владелец должен быть confidential
    /// с самоуправлением (App API), роли белого списка — существовать в его матрице. Снять политику можно только
    /// у владельца без подчинённых: иначе они продолжали бы работать без срока токена из политики и без управления.
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
        else if ((await ApplicationService.ReadManagedClientsAsync(db, owner, ct)).Count > 0)
        {
            throw new AdminException("У приложения есть подчинённые клиенты: сначала удалите их, затем снимайте политику.");
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
    public async Task<List<ManagedClientDto>> ListAsync(string owner, CancellationToken ct = default) =>
        await ToDtosAsync(owner, await ApplicationService.ReadManagedClientsAsync(db, owner, ct), ct);

    /// <summary>Карточка подчинённого; чужой или не подчинённый клиент — 404.</summary>
    public async Task<ManagedClientDto> GetAsync(string owner, string clientId, CancellationToken ct = default)
    {
        var row = (await ApplicationService.ReadManagedClientsAsync(db, owner, ct)).FirstOrDefault(r => r.ClientId == clientId)
                  ?? throw AdminException.NotFound($"Подчинённый клиент '{clientId}'");
        return (await ToDtosAsync(owner, [row], ct))[0];
    }

    /// <summary>
    /// Создаёт подчинённого: client_id с префиксом политики, роли из белого списка, ключи и/или секрет.
    /// Дескриптор минимален: confidential, только client_credentials, scope владельца, без redirect URI.
    /// Клиент и его роли создаются одной транзакцией: при ошибке назначения ролей клиента не остаётся.
    /// </summary>
    public async Task<ManagedClientCreated> CreateAsync(string owner, ManagedClientInput input, string? via = null,
        CancellationToken ct = default)
    {
        var policy = await RequirePolicyAsync(owner, ct);

        // Суффикс — 8 шестнадцатеричных знаков: столько места Normalize оставляет после самого длинного префикса.
        var clientId = input.ClientId is { Length: > 0 }
            ? policy.ValidateClientId(input.ClientId)
            : policy.ValidateClientId(policy.Prefix + (string.IsNullOrWhiteSpace(input.ClientIdSuffix)
                ? Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4))
                : input.ClientIdSuffix.Trim()));

        var roles = policy.ValidateRoles(input.Roles);
        // Роль могла быть удалена из матрицы после сохранения политики — проверяем до создания клиента.
        var matrixRoles = (await access.GetMatrixAsync(owner, ct)).Roles.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
        var absent = roles.Where(r => !matrixRoles.Contains(r)).ToList();
        if (absent.Count > 0) throw new AdminException($"Ролей нет в матрице приложения {owner}: {string.Join(", ", absent)}.");

        var jwks = input.Jwks is { ValueKind: not (JsonValueKind.Null or JsonValueKind.Undefined) } j ? ManagedClientKeys.Parse(j) : null;
        if (jwks is not null && !policy.AllowsKeys) throw new AdminException("Политика не разрешает вход по ключу (private_key_jwt).");
        if (input.RequestSecret && !policy.AllowsSecret) throw new AdminException("Политика не разрешает вход по секрету (client_secret).");
        if (jwks is null && !input.RequestSecret) throw new AdminException("Укажите открытые ключи (jwks) или запросите секрет (requestSecret).");

        var gate = CreateLocks.GetOrAdd(owner, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        string? secret = null;
        try
        {
            if (await applications.FindByClientIdAsync(clientId, ct) is not null)
                throw AdminException.Conflict($"Клиент '{clientId}' уже существует.");
            if ((await ApplicationService.ReadManagedClientsAsync(db, owner, ct)).Count >= policy.MaxClients)
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
            if (input.RequestSecret) descriptor.ClientSecret = secret = ApplicationService.GenerateSecret();

            try
            {
                await db.InTransactionAsync(async () =>
                {
                    await applications.CreateAsync(descriptor, ct);
                    await access.SetAssignmentsAsync(SubjectType.Client, clientId, roles.Select(r => new RoleRef(owner, r)), ct);
                }, ct);
            }
            catch (DbUpdateException)
            {
                // Параллельный запрос (другой узел) успел занять тот же client_id — уникальный индекс OpenIddict.
                throw AdminException.Conflict($"Клиент '{clientId}' уже существует.");
            }
        }
        finally
        {
            gate.Release();
        }

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

    /// <summary>Отключает/включает подчинённого (отключение отзывает его токены; запись в журнал делает ApplicationService).</summary>
    public async Task<ManagedClientDto> SetDisabledAsync(string owner, string clientId, bool disabled, string? via = null,
        CancellationToken ct = default)
    {
        await FindManagedAsync(owner, clientId, ct);
        await apps.SetDisabledAsync(clientId, disabled, ct, via);
        return await GetAsync(owner, clientId, ct);
    }

    /// <summary>Выдаёт новый секрет (старый перестаёт действовать); только если политика разрешает client_secret.</summary>
    public async Task<string> NewSecretAsync(string owner, string clientId, string? via = null, CancellationToken ct = default)
    {
        var policy = await RequirePolicyAsync(owner, ct);
        if (!policy.AllowsSecret) throw new AdminException("Политика не разрешает вход по секрету (client_secret).");
        var app = await FindManagedAsync(owner, clientId, ct);
        var secret = ApplicationService.GenerateSecret();
        await applications.UpdateAsync(app, secret, ct);
        await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Info, owner,
            details: new { action = "secret_issued", clientId, via });
        return secret;
    }

    /// <summary>Удаляет подчинённого с отзывом его токенов (запись в журнал делает ApplicationService).</summary>
    public async Task DeleteAsync(string owner, string clientId, string? via = null, CancellationToken ct = default)
    {
        await FindManagedAsync(owner, clientId, ct);
        await apps.DeleteAsync(clientId, ct, via);
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
    /// Отмечает выдачу токена подчинённому клиенту (для предела неактивности; с точностью до минуты). Обычные клиенты не отмечаются.
    /// Вставка-или-обновление одним запросом — одинаково для SQLite и PostgreSQL.
    /// </summary>
    public async Task RecordTokenIssuedAsync(string clientId, CancellationToken ct = default)
    {
        if (await applications.FindByClientIdAsync(clientId, ct) is not { } app ||
            ApplicationService.OwnerOf(await applications.GetPropertiesAsync(app, ct)) is null) return;
        var now = DateTime.UtcNow;
        if (ActivityWritten.TryGetValue(clientId, out var written) && now - written < ActivityResolution) return;
        ActivityWritten[clientId] = now;
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO \"ClientActivities\" (\"ClientId\", \"LastTokenIssuedAt\") VALUES ({clientId}, {now}) ON CONFLICT (\"ClientId\") DO UPDATE SET \"LastTokenIssuedAt\" = excluded.\"LastTokenIssuedAt\"",
            ct);
    }

    /// <summary>
    /// Автоотключение подчинённых без токенов дольше <c>InactiveDays</c> политики владельца (обслуживание БД).
    /// Отсчёт — от последнего выданного токена (таблица ClientActivities) или от создания клиента.
    /// Возвращает отключённых (владелец, клиент).
    /// </summary>
    public async Task<List<(string Owner, string ClientId)>> DisableInactiveAsync(CancellationToken ct = default)
    {
        var result = new List<(string, string)>();
        var rows = (await ApplicationService.ReadManagedClientsAsync(db, null, ct)).Where(r => !r.Disabled).ToList();
        if (rows.Count == 0) return result;
        var activity = await LastTokensAsync(rows.Select(r => r.ClientId).ToList(), ct);
        var policies = new Dictionary<string, ManagedClientsPolicy?>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (!policies.TryGetValue(row.Owner, out var policy)) policies[row.Owner] = policy = await GetPolicyAsync(row.Owner, ct);
            if (policy is not { InactiveDays: > 0 }) continue;
            var last = activity.TryGetValue(row.ClientId, out var at) ? at : row.CreatedAt;
            if (last is null || last > DateTime.UtcNow.AddDays(-policy.InactiveDays)) continue;
            if (await apps.SetDisabledAsync(row.ClientId, true, ct, via: null, reason: $"inactive {policy.InactiveDays} days"))
                result.Add((row.Owner, row.ClientId));
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

    /// <summary>Время последнего выданного токена по клиентам — одним запросом.</summary>
    private async Task<Dictionary<string, DateTime?>> LastTokensAsync(List<string> clientIds, CancellationToken ct) =>
        await db.ClientActivities.AsNoTracking().Where(a => clientIds.Contains(a.ClientId))
            .ToDictionaryAsync(a => a.ClientId, a => (DateTime?)DateTime.SpecifyKind(a.LastTokenIssuedAt, DateTimeKind.Utc), ct);

    /// <summary>DTO по строкам таблицы приложений: роли и активность — по одному запросу на весь список.</summary>
    private async Task<List<ManagedClientDto>> ToDtosAsync(string owner, List<ManagedClientRow> rows, CancellationToken ct)
    {
        if (rows.Count == 0) return [];
        var ids = rows.Select(r => r.ClientId).ToList();
        var roles = await access.GetAssignmentsAsync(SubjectType.Client, ids, owner, ct);
        var activity = await LastTokensAsync(ids, ct);
        return rows.OrderBy(r => r.ClientId, StringComparer.Ordinal).Select(r => new ManagedClientDto(
            r.ClientId, r.DisplayName, owner, r.Disabled,
            roles.TryGetValue(r.ClientId, out var list) ? list.Select(x => x.Role).ToList() : [],
            ManagedClientKeys.Describe(string.IsNullOrEmpty(r.JsonWebKeySet) ? null : new JsonWebKeySet(r.JsonWebKeySet)),
            r.HasSecret, r.CreatedAt, activity.GetValueOrDefault(r.ClientId))).ToList();
    }
}
