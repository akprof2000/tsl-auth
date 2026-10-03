using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using TslAuth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Services;

/// <summary>Поддерживаемые grant types OAuth2 (значения, которые можно разрешить клиенту в настройках приложения).</summary>
public static class AppGrantTypes
{
    public const string AuthorizationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string Password = "password";
    public const string RefreshToken = "refresh_token";

    /// <summary>RFC 8693 — обмен токена пользователя на токен для другого приложения.</summary>
    public const string TokenExchange = GrantTypes.TokenExchange;

    /// <summary>
    /// Сервис-робот: обменять токен подключения, который выписал ему пользователь (PAT с привязкой к сервису), на JWT
    /// с правами этого пользователя. Короткий алиас в Admin API — <c>connection_token</c>.
    /// </summary>
    public const string ConnectionToken = PatService.GrantType;

    public static readonly string[] All = [AuthorizationCode, ClientCredentials, Password, RefreshToken, TokenExchange, ConnectionToken];

    /// <summary>Короткое имя grant type для UI и Admin API (полные URN длинные).</summary>
    public static string ShortName(string grant) => grant switch
    {
        TokenExchange => "token_exchange",
        ConnectionToken => "connection_token",
        _ => grant
    };
}

/// <summary>Приложение (клиент OpenIddict) в удобном для UI/API виде: grant types и scopes извлечены из permissions.</summary>
public sealed record ApplicationDto(
    string ClientId,
    string? DisplayName,
    string ClientType,
    List<string> RedirectUris,
    List<string> PostLogoutRedirectUris,
    List<string> GrantTypes,
    List<string> Scopes,
    bool IsSystem,
    bool SelfManagement,
    bool SelfRegistration,
    string? Owner = null,
    bool Disabled = false,
    ManagedClientsPolicy? ManagedClients = null);

/// <summary>Входные данные для создания/изменения приложения (Admin API и страница Admin/Apps/Edit).</summary>
/// <param name="SelfManagement">
/// Разрешить приложению через App API (/api/app) управлять своими пользователями, ролями и матрицей.
/// Требует confidential-клиента; client_credentials и scope tsl-auth-app добавляются автоматически.
/// </param>
/// <param name="SelfRegistration">На странице входа приложения доступна самостоятельная регистрация с запросом ролей.</param>
/// <remarks>
/// В <see cref="ApplicationDto"/> дополнительно: <c>Owner</c> — владелец подчинённого клиента (свойство <c>tsl_owner</c>),
/// <c>Disabled</c> — клиент отключён (<c>tsl_disabled</c>), <c>ManagedClients</c> — политика подчинённых (<c>tsl_managed_clients</c>).
/// </remarks>
public sealed record ApplicationInput(
    string ClientId,
    string? DisplayName,
    string ClientType,
    List<string>? RedirectUris,
    List<string>? PostLogoutRedirectUris,
    List<string>? GrantTypes,
    List<string>? Scopes,
    bool SelfManagement = false,
    bool SelfRegistration = false);

/// <summary>Подчинённый клиент, прочитанный одним запросом из таблицы приложений (см. <see cref="ApplicationService.ReadManagedClientsAsync"/>).</summary>
public sealed record ManagedClientRow(string Owner, string ClientId, string? DisplayName, bool Disabled, DateTime? CreatedAt,
    bool HasSecret, string? JsonWebKeySet);

/// <summary>Результат создания/изменения: <c>ClientSecret</c> заполнен только когда секрет сгенерирован сейчас (показывается один раз).</summary>
public sealed record ApplicationSecretResult(ApplicationDto Application, string? ClientSecret);

/// <summary>
/// Регистрация клиентов OAuth2/OIDC (обёртка над хранилищем OpenIddict).
/// Переводит «человеческие» настройки (тип клиента, grant types, scopes) в permissions/requirements OpenIddict,
/// для каждого приложения заводит одноимённый scope-ресурс, при удалении чистит сессии и RBAC.
/// Используется Admin API, App API, страницами Admin/Apps и StartupInitializer (системное приложение).
/// Доп. флаги (системное, App API, саморегистрация) хранятся в Properties приложения OpenIddict.
/// </summary>
public sealed class ApplicationService(
    IOpenIddictApplicationManager applications,
    IOpenIddictScopeManager scopes,
    AccessService access,
    SessionService sessions,
    WebhookService webhooks,
    AuditService audit,
    AuthDbContext db)
{
    private const string SystemProperty = "tsl_system";
    private const string SelfManagementProperty = "tsl_self_management";
    private const string SelfRegistrationProperty = "tsl_self_registration";

    /// <summary>Политика подчинённых клиентов (JSON <see cref="ManagedClientsPolicy"/>); задаёт только администратор.</summary>
    public const string ManagedClientsProperty = "tsl_managed_clients";

    /// <summary>client_id владельца у подчинённого клиента.</summary>
    public const string OwnerProperty = "tsl_owner";

    /// <summary>Клиент отключён: токены не выдаются, выданные отозваны.</summary>
    public const string DisabledProperty = "tsl_disabled";

    /// <summary>Время создания подчинённого клиента (для предела неактивности).</summary>
    public const string CreatedAtProperty = "tsl_created_at";

    /// <summary>Стандартные scope OIDC, которые можно разрешать клиентам в дополнение к scope приложений.</summary>
    public static readonly string[] StandardScopes = [Scopes.Profile, Scopes.Email, Scopes.Roles];

    /// <summary>Все приложения; системное — первым.</summary>
    public async Task<List<ApplicationDto>> ListAsync(CancellationToken ct = default)
    {
        var result = new List<ApplicationDto>();
        await foreach (var app in applications.ListAsync(null, null, ct))
            result.Add(await ToDtoAsync(app, ct));
        return result.OrderBy(a => a.IsSystem ? 0 : 1).ThenBy(a => a.ClientId).ToList();
    }

    public async Task<ApplicationDto?> GetAsync(string clientId, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct);
        return app is null ? null : await ToDtoAsync(app, ct);
    }

    /// <summary>Все scope, доступные для назначения клиентам (стандартные + scope зарегистрированных приложений).</summary>
    public async Task<List<string>> ListAvailableScopesAsync(CancellationToken ct = default)
    {
        var result = new List<string>(StandardScopes);
        await foreach (var scope in scopes.ListAsync(null, null, ct))
            if (await scopes.GetNameAsync(scope, ct) is { } name && !result.Contains(name))
                result.Add(name);
        return result;
    }

    /// <summary>
    /// Регистрирует приложение. Для confidential-клиента генерирует секрет (или использует переданный —
    /// так StartupInitializer задаёт секрет из конфигурации).
    /// </summary>
    public async Task<ApplicationSecretResult> CreateAsync(ApplicationInput input, bool isSystem = false, string? secret = null,
        CancellationToken ct = default)
    {
        var clientId = Names.Validate(input.ClientId, "client_id");
        if (await applications.FindByClientIdAsync(clientId, ct) is not null)
            throw AdminException.Conflict($"Приложение '{clientId}' уже существует.");

        var descriptor = new OpenIddictApplicationDescriptor { ClientId = clientId };
        if (isSystem) descriptor.Properties[SystemProperty] = JsonSerializer.SerializeToElement(true);

        var confidential = Apply(descriptor, input);
        if (confidential) descriptor.ClientSecret = secret ??= GenerateSecret();
        else secret = null;

        // OpenIddict сохраняет только хэш секрета — открытое значение возвращаем вызывающему единственный раз.
        await applications.CreateAsync(descriptor, ct);

        // Каждое приложение одновременно является ресурсом (API): scope = client_id, audience = client_id.
        if (await scopes.FindByNameAsync(clientId, ct) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = clientId,
                DisplayName = input.DisplayName ?? clientId,
                Resources = { clientId }
            }, ct);
        }

        await webhooks.PublishAsync(WebhookEvents.ApplicationCreated, $"🧩 Зарегистрировано приложение {clientId}.",
            new { clientId, displayName = input.DisplayName }, ct);
        return new ApplicationSecretResult((await GetAsync(clientId, ct))!, secret);
    }

    /// <summary>Изменяет настройки приложения; client_id неизменяем. Системное приложение защищено от изменений.</summary>
    public async Task<ApplicationSecretResult> UpdateAsync(string clientId, ApplicationInput input, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        var properties = await applications.GetPropertiesAsync(app, ct);
        if (IsSystem(properties))
            throw new AdminException("Настройки системного приложения изменить нельзя.");
        // Подчинённый клиент нельзя «расширить» через Admin API (другие потоки, чужие scope, redirect URI):
        // его настройки определяет политика владельца; администратору доступны отключение и удаление.
        if (OwnerOf(properties) is { } owner)
            throw new AdminException($"Клиент подчинён приложению {owner}: настройки задаёт владелец через App API, " +
                                     "администратору доступны отключение, включение и удаление.");

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, app, ct);
        var wasConfidential = descriptor.ClientType == ClientTypes.Confidential;

        var confidential = Apply(descriptor, input with { ClientId = clientId });
        // Секрет генерируется только при переходе public → confidential; существующий секрет не трогаем,
        // а при переходе в public — удаляем, чтобы старый секрет не продолжал работать.
        string? secret = null;
        if (confidential && !wasConfidential) descriptor.ClientSecret = secret = GenerateSecret();
        if (!confidential) descriptor.ClientSecret = null;

        await applications.UpdateAsync(app, descriptor, ct);

        // Синхронизируем отображаемое имя scope-ресурса с именем приложения.
        var scope = await scopes.FindByNameAsync(clientId, ct);
        if (scope is not null && input.DisplayName is not null)
        {
            var scopeDescriptor = new OpenIddictScopeDescriptor();
            await scopes.PopulateAsync(scopeDescriptor, scope, ct);
            scopeDescriptor.DisplayName = input.DisplayName;
            await scopes.UpdateAsync(scope, scopeDescriptor, ct);
        }

        return new ApplicationSecretResult((await GetAsync(clientId, ct))!, secret);
    }

    /// <summary>Генерирует новый секрет confidential-клиента; старый перестаёт действовать сразу.</summary>
    public async Task<string> RegenerateSecretAsync(string clientId, CancellationToken ct = default)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        if (!await applications.HasClientTypeAsync(app, ClientTypes.Confidential, ct))
            throw new AdminException("Секрет есть только у confidential-клиентов.");
        // Секрет подчинённого выдаётся владельцем по политике (она может запрещать вход по секрету).
        if (OwnerOf(await applications.GetPropertiesAsync(app, ct)) is { } owner)
            throw new AdminException($"Секрет подчинённого клиента выдаёт владелец {owner} через App API.");

        var secret = GenerateSecret();
        await applications.UpdateAsync(app, secret, ct);
        return secret;
    }

    /// <summary>
    /// Удаляет приложение вместе с его токенами/сессиями, scope-ресурсом и RBAC-конфигурацией; у владельца — вместе
    /// со всеми подчинёнными клиентами, в одной транзакции. Удаление подчинённого пишется в журнал владельца.
    /// </summary>
    /// <param name="via">Через какое приложение действовал пользователь (делегированный токен App API) — для журнала.</param>
    public async Task DeleteAsync(string clientId, CancellationToken ct = default, string? via = null)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        var properties = await applications.GetPropertiesAsync(app, ct);
        if (IsSystem(properties))
            throw new AdminException("Системное приложение нельзя удалить.");
        var owner = OwnerOf(properties);

        // Подчинённые клиенты без владельца бессмысленны и стали бы «ничьими» — удаляются вместе с ним. Подчинённый
        // своих подчинённых иметь не может (SetPolicyAsync это запрещает), поэтому поиск нужен только у владельца.
        var victims = new List<(object App, string ClientId, string? Owner)>();
        if (owner is null)
            foreach (var row in await ReadManagedClientsAsync(db, clientId, ct))
                if (await applications.FindByClientIdAsync(row.ClientId, ct) is { } child)
                    victims.Add((child, row.ClientId, clientId));
        victims.Add((app, clientId, owner));

        // Одна транзакция на владельца и всех подчинённых: сбой на середине не должен оставлять «полуудалённое»
        // приложение (клиента без scope, матрицу без клиента, владельца без части агентов). Менеджеры OpenIddict
        // работают через тот же DbContext и попадают в неё.
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            foreach (var victim in victims)
                await DeleteOneAsync(victim.App, victim.ClientId, ct);
            await tx.CommitAsync(ct);
        }

        foreach (var victim in victims)
        {
            if (victim.Owner is { } childOwner)
                await audit.WriteAsync(AuditTypes.ManagedClientChange, true, AuditSeverity.Info, childOwner,
                    details: new { action = "deleted", clientId = victim.ClientId, via, cascade = victim.ClientId != clientId });
            await webhooks.PublishAsync(WebhookEvents.ApplicationDeleted, $"🗑 Удалено приложение {victim.ClientId}.",
                new { clientId = victim.ClientId, owner = victim.Owner }, ct);
        }
    }

    /// <summary>Удаление одного приложения внутри транзакции вызывающего кода.</summary>
    private async Task DeleteOneAsync(object app, string clientId, CancellationToken ct)
    {
        // Сначала отзываем выданные токены, пока приложение ещё существует и связи с ним можно найти.
        await sessions.RevokeByClientAsync(clientId, ct);
        await applications.DeleteAsync(app, ct);
        if (await scopes.FindByNameAsync(clientId, ct) is { } scope)
            await scopes.DeleteAsync(scope, ct);
        await access.RemoveApplicationAsync(clientId, ct);
        // Владение пользователями и привязки мессенджеров, сделанные ботом этого приложения, снимаются:
        // иначе новое приложение с тем же client_id унаследовало бы управление чужими учётными записями.
        await db.Users.Where(u => u.CreatedByClientId == clientId)
            .ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedByClientId, (string?)null), ct);
        await db.ExternalIdentities.Where(e => e.LinkedByClientId == clientId).ExecuteDeleteAsync(ct);
        await db.ClientActivities.Where(a => a.ClientId == clientId).ExecuteDeleteAsync(ct);
        // Токены подключения, выписанные пользователями этому сервису-роботу, отзываются: иначе новое приложение
        // с тем же client_id получило бы права этих пользователей.
        var now = DateTime.UtcNow;
        await db.PersonalAccessTokens.Where(t => t.ClientId == clientId && t.RevokedAt == null)
            .ExecuteUpdateAsync(t => t.SetProperty(x => x.RevokedAt, (DateTime?)now), ct);
    }

    /// <summary>
    /// Отключает или включает клиента (свойство <c>tsl_disabled</c>). Отключённый не получает токены; при отключении
    /// его сессии и токены отзываются (introspection → active=false). Публикует application.disabled / .enabled.
    /// </summary>
    /// <param name="via">Через какое приложение действовал пользователь (делегированный токен App API) — для журнала.</param>
    /// <param name="reason">Причина (например, автоотключение по неактивности) — для журнала.</param>
    /// <returns>false, если состояние уже было таким.</returns>
    public async Task<bool> SetDisabledAsync(string clientId, bool disabled, CancellationToken ct = default, string? via = null,
        string? reason = null)
    {
        var app = await applications.FindByClientIdAsync(clientId, ct) ?? throw AdminException.NotFound($"Приложение '{clientId}'");
        var properties = await applications.GetPropertiesAsync(app, ct);
        if (IsSystem(properties)) throw new AdminException("Системное приложение нельзя отключить.");
        if (IsDisabled(properties) == disabled) return false;

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, app, ct);
        if (disabled) descriptor.Properties[DisabledProperty] = JsonSerializer.SerializeToElement(true);
        else descriptor.Properties.Remove(DisabledProperty);
        await applications.UpdateAsync(app, descriptor, ct);
        if (disabled) await sessions.RevokeByClientAsync(clientId, ct);

        var owner = OwnerOf(properties);
        // Отключение подчинённого — кем бы оно ни было сделано (администратор, владелец, обслуживание) — видно
        // владельцу в его журнале (/api/app/audit): ClientId записи — владелец.
        if (owner is not null)
            await audit.WriteAsync(AuditTypes.ManagedClientChange, true, disabled ? AuditSeverity.Warning : AuditSeverity.Info, owner,
                details: new { action = disabled ? "disabled" : "enabled", clientId, via, reason });
        await webhooks.PublishAsync(disabled ? WebhookEvents.ApplicationDisabled : WebhookEvents.ApplicationEnabled,
            disabled ? $"⛔ Клиент {clientId} отключён, его токены отозваны." : $"✅ Клиент {clientId} включён.",
            new { clientId, owner }, ct);
        return true;
    }

    /// <summary>Отключён ли клиент (проверка на токен-эндпоинте и authorize).</summary>
    public async Task<bool> IsDisabledAsync(string clientId, CancellationToken ct = default) =>
        await applications.FindByClientIdAsync(clientId, ct) is { } app && IsDisabled(await applications.GetPropertiesAsync(app, ct));

    /// <summary>client_id подчинённых клиентов владельца.</summary>
    public async Task<List<string>> ListManagedClientIdsAsync(string owner, CancellationToken ct = default) =>
        (await ReadManagedClientsAsync(db, owner, ct)).Select(m => m.ClientId).ToList();

    /// <summary>Все подчинённые клиенты (владелец, client_id).</summary>
    public async Task<List<(string Owner, string ClientId)>> ListManagedClientsAsync(CancellationToken ct = default) =>
        (await ReadManagedClientsAsync(db, null, ct)).Select(m => (m.Owner, m.ClientId)).ToList();

    /// <summary>
    /// Подчинённые клиенты одним запросом (владельца или все, <paramref name="owner"/> = null): client_id, название,
    /// состояние, дата создания, наличие секрета и JWKS. Свойства хранятся JSON-строкой в колонке Properties:
    /// предварительный фильтр по подстроке отсекает прочие приложения в БД, точное совпадение владельца — после разбора.
    /// Используется списками и проверками ManagedClientService, удалением владельца и метриками.
    /// </summary>
    public static async Task<List<ManagedClientRow>> ReadManagedClientsAsync(AuthDbContext db, string? owner, CancellationToken ct)
    {
        var query = db.Set<OpenIddictEntityFrameworkCoreApplication<Guid>>().AsNoTracking()
            .Where(a => a.Properties != null && a.Properties.Contains(OwnerProperty) && a.ClientId != null);
        if (owner is not null) query = query.Where(a => a.Properties!.Contains(owner));
        var rows = await query
            .Select(a => new { a.ClientId, a.DisplayName, a.Properties, a.JsonWebKeySet, HasSecret = a.ClientSecret != null })
            .ToListAsync(ct);

        var result = new List<ManagedClientRow>();
        foreach (var row in rows)
        {
            using var json = JsonDocument.Parse(row.Properties!);
            var root = json.RootElement;
            if (!root.TryGetProperty(OwnerProperty, out var o) || o.ValueKind != JsonValueKind.String) continue;
            var rowOwner = o.GetString()!;
            if (owner is not null && rowOwner != owner) continue;
            DateTime? created = root.TryGetProperty(CreatedAtProperty, out var c) && c.ValueKind == JsonValueKind.String &&
                                c.TryGetDateTime(out var d) ? DateTime.SpecifyKind(d.ToUniversalTime(), DateTimeKind.Utc) : null;
            var disabled = root.TryGetProperty(DisabledProperty, out var dis) && dis.ValueKind == JsonValueKind.True;
            result.Add(new ManagedClientRow(rowOwner, row.ClientId!, row.DisplayName, disabled, created, row.HasSecret, row.JsonWebKeySet));
        }
        return result;
    }

    /// <summary>Владелец подчинённого клиента из свойств; null — обычное приложение.</summary>
    public static string? OwnerOf(IReadOnlyDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(OwnerProperty, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static bool IsDisabled(IReadOnlyDictionary<string, JsonElement> properties) => Flag(properties, DisabledProperty);

    /// <summary>Переносит входные настройки в дескриптор OpenIddict (permissions, requirements, URI, флаги) с валидацией.</summary>
    /// <returns>true, если клиент confidential.</returns>
    private static bool Apply(OpenIddictApplicationDescriptor d, ApplicationInput input)
    {
        var confidential = (input.ClientType ?? "").Trim().ToLowerInvariant() switch
        {
            ClientTypes.Confidential => true,
            ClientTypes.Public => false,
            _ => throw new AdminException("ClientType должен быть 'public' или 'confidential'.")
        };

        // "token_exchange" и "connection_token" — короткие алиасы полных URN.
        // openid и offline_access не хранятся как permissions: OpenIddict обрабатывает их особым образом.
        var grants = (input.GrantTypes ?? []).Select(g => g.Trim()).Where(g => g.Length > 0)
            .Select(g => g switch { "token_exchange" => AppGrantTypes.TokenExchange, "connection_token" => AppGrantTypes.ConnectionToken, _ => g })
            .Distinct().ToList();
        var scopes = (input.Scopes ?? []).Select(s => s.Trim())
            .Where(s => s.Length > 0 && s != Scopes.OpenId && s != Scopes.OfflineAccess).Distinct().ToList();

        if (input.SelfManagement)
        {
            if (!confidential) throw new AdminException("Самоуправление (App API) доступно только confidential-клиентам.");
            if (!grants.Contains(AppGrantTypes.ClientCredentials)) grants.Add(AppGrantTypes.ClientCredentials);
            if (!scopes.Contains(SystemApp.AppApiScope)) scopes.Add(SystemApp.AppApiScope);
        }
        else
        {
            // Без флага доступ к App API не выдаётся, даже если scope передали вручную.
            scopes.Remove(SystemApp.AppApiScope);
        }

        var unknown = grants.Except(AppGrantTypes.All).ToList();
        if (unknown.Count > 0) throw new AdminException($"Неизвестные grant types: {string.Join(", ", unknown)}.");
        // Public-клиент не может хранить секрет, поэтому не должен получать токены «от своего имени».
        // Робот тоже: токен подключения обменивает только сам сервис со своим секретом или ключом.
        if (!confidential && (grants.Contains(AppGrantTypes.ClientCredentials) || grants.Contains(AppGrantTypes.TokenExchange) ||
                              grants.Contains(AppGrantTypes.ConnectionToken)))
            throw new AdminException("client_credentials, token exchange и токены подключения доступны только confidential-клиентам.");

        if (input.SelfManagement) d.Properties[SelfManagementProperty] = JsonSerializer.SerializeToElement(true);
        else d.Properties.Remove(SelfManagementProperty);
        if (input.SelfRegistration) d.Properties[SelfRegistrationProperty] = JsonSerializer.SerializeToElement(true);
        else d.Properties.Remove(SelfRegistrationProperty);

        d.DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? input.ClientId : input.DisplayName.Trim();
        d.ClientType = confidential ? ClientTypes.Confidential : ClientTypes.Public;
        // Все клиенты — доверенные (регистрирует администратор), экран согласия не показываем.
        d.ConsentType = ConsentTypes.Implicit;

        d.RedirectUris.Clear();
        foreach (var uri in ParseUris(input.RedirectUris)) d.RedirectUris.Add(uri);
        d.PostLogoutRedirectUris.Clear();
        foreach (var uri in ParseUris(input.PostLogoutRedirectUris)) d.PostLogoutRedirectUris.Add(uri);

        if (grants.Contains(AppGrantTypes.AuthorizationCode) && d.RedirectUris.Count == 0)
            throw new AdminException("Для authorization_code необходим хотя бы один Redirect URI.");

        // Permissions пересобираются с нуля по принципу минимальных прав: только то, что нужно для выбранных grant types.
        d.Permissions.Clear();
        d.Requirements.Clear();
        d.Permissions.Add(Permissions.Endpoints.Revocation);
        if (confidential) d.Permissions.Add(Permissions.Endpoints.Introspection);
        if (grants.Count > 0) d.Permissions.Add(Permissions.Endpoints.Token);

        foreach (var grant in grants)
        {
            d.Permissions.Add(Permissions.Prefixes.GrantType + grant);
            if (grant == AppGrantTypes.AuthorizationCode)
            {
                d.Permissions.Add(Permissions.Endpoints.Authorization);
                d.Permissions.Add(Permissions.Endpoints.EndSession);
                d.Permissions.Add(Permissions.ResponseTypes.Code);
                // PKCE обязателен для всех клиентов (OAuth 2.1): защищает от перехвата кода авторизации.
                d.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
            }
        }

        // Свой scope (приложение как ресурс) разрешён всегда.
        if (!string.IsNullOrEmpty(input.ClientId) && !scopes.Contains(input.ClientId)) scopes.Add(input.ClientId);
        foreach (var scope in scopes)
            d.Permissions.Add(Permissions.Prefixes.Scope + scope);

        return confidential;
    }

    /// <summary>Разбирает и проверяет redirect URI, убирая пустые значения и повторы.</summary>
    private static IEnumerable<Uri> ParseUris(IEnumerable<string>? values)
    {
        foreach (var value in (values ?? []).Select(v => v.Trim()).Where(v => v.Length > 0).Distinct())
        {
            // Фрагмент в redirect URI запрещён спецификацией OAuth2 (RFC 6749, 3.1.2).
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
                throw new AdminException($"Некорректный URI: {value}");
            yield return uri;
        }
    }

    /// <summary>Собирает DTO приложения из дескриптора OpenIddict и его свойств.</summary>
    private async Task<ApplicationDto> ToDtoAsync(object app, CancellationToken ct)
    {
        var permissions = await applications.GetPermissionsAsync(app, ct);
        var properties = await applications.GetPropertiesAsync(app, ct); // один раз: каждый вызов разбирает JSON заново
        return new ApplicationDto(
            (await applications.GetClientIdAsync(app, ct))!,
            await applications.GetDisplayNameAsync(app, ct),
            await applications.GetClientTypeAsync(app, ct) ?? ClientTypes.Public,
            (await applications.GetRedirectUrisAsync(app, ct)).ToList(),
            (await applications.GetPostLogoutRedirectUrisAsync(app, ct)).ToList(),
            permissions.Where(p => p.StartsWith(Permissions.Prefixes.GrantType, StringComparison.Ordinal))
                .Select(p => p[Permissions.Prefixes.GrantType.Length..]).ToList(),
            permissions.Where(p => p.StartsWith(Permissions.Prefixes.Scope, StringComparison.Ordinal))
                .Select(p => p[Permissions.Prefixes.Scope.Length..]).ToList(),
            IsSystem(properties),
            Flag(properties, SelfManagementProperty),
            Flag(properties, SelfRegistrationProperty),
            OwnerOf(properties),
            IsDisabled(properties),
            ManagedClientsPolicy.From(properties));
    }

    /// <summary>Включена ли для приложения самостоятельная регистрация (ссылка «Регистрация» на странице входа).</summary>
    public async Task<bool> IsSelfRegistrationEnabledAsync(string clientId, CancellationToken ct = default) =>
        await applications.FindByClientIdAsync(clientId, ct) is { } app &&
        Flag(await applications.GetPropertiesAsync(app, ct), SelfRegistrationProperty);

    /// <summary>Разрешён ли приложению доступ к App API (/api/app).</summary>
    public async Task<bool> IsSelfManagementEnabledAsync(string clientId, CancellationToken ct = default) =>
        await applications.FindByClientIdAsync(clientId, ct) is { } app &&
        Flag(await applications.GetPropertiesAsync(app, ct), SelfManagementProperty);

    private static bool IsSystem(IReadOnlyDictionary<string, JsonElement> properties) => Flag(properties, SystemProperty);

    /// <summary>Логический флаг из пользовательских свойств приложения OpenIddict.</summary>
    private static bool Flag(IReadOnlyDictionary<string, JsonElement> properties, string name) =>
        properties.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.True;

    // 256 бит криптостойкой случайности в URL-safe Base64.
    internal static string GenerateSecret() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
