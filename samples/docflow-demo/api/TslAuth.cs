// Взаимодействие с TSL Auth от имени самого приложения (client_credentials, scope tsl-auth-app):
// справочник пользователей приложения, назначение ролей, заявки на доступ, журнал.
// Приложение docflow-api зарегистрировано с флагом «Самоуправление», поэтому видит только свой срез
// пользователей и только свои роли — чужие приложения через App API недоступны.
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;

namespace Docflow.Api;

public sealed class AuthOptions
{
    /// <summary>Публичный issuer (как в токенах): http://localhost:8080/</summary>
    public string Issuer { get; set; } = "http://localhost:8080/";
    /// <summary>Адрес для обращений сервер→сервер (в Docker — http://tsl-auth:8080/). По умолчанию = Issuer.</summary>
    public string? InternalUrl { get; set; }
    public string ClientId { get; set; } = "docflow-api";
    public string ClientSecret { get; set; } = "";
    /// <summary>Public-клиент PWA (для config.js).</summary>
    public string WebClientId { get; set; } = "docflow-web";
    public string Internal => string.IsNullOrEmpty(InternalUrl) ? Issuer : InternalUrl;
}

/// <summary>Пользователь текущего запроса, извлечённый из JWT (MapInboundClaims = false — имена claims как в токене).</summary>
public sealed record CurrentUser(Guid Id, string UserName, string DisplayName, IReadOnlyList<string> Roles, IReadOnlyList<string> Permissions)
{
    public bool Has(string permission) => Permissions.Contains(permission);
    public bool InRole(string role) => Roles.Contains(role);

    public static CurrentUser From(ClaimsPrincipal p, string clientId)
    {
        var prefix = clientId + ":";
        var roles = p.FindAll("role").Select(c => c.Value).Where(v => v.StartsWith(prefix)).Select(v => v[prefix.Length..]).ToList();
        var perms = p.FindAll("permissions").Select(c => c.Value).Where(v => v.StartsWith(prefix)).Select(v => v[prefix.Length..]).ToList();
        var name = p.FindFirstValue("preferred_username") ?? p.FindFirstValue("name") ?? "?";
        return new CurrentUser(Guid.Parse(p.FindFirstValue("sub")!), name, p.FindFirstValue("name") ?? name, roles, perms);
    }
}

/// <remarks>
/// Для пользователей, которых приложение не создавало само (привязаны через /users/link), TSL Auth скрывает
/// email, isActive, hasPassword и mustChangePassword (null/false) — поэтому поля nullable, а «неактивным»
/// считается только явный isActive=false у своих пользователей.
/// </remarks>
public sealed record DirectoryUser(Guid Id, string UserName, string? Email, string? DisplayName, bool? IsActive, bool? HasPassword,
    bool? MustChangePassword, bool CreatedByThisApp, List<string> Roles)
{
    public string Display => string.IsNullOrWhiteSpace(DisplayName) ? UserName : DisplayName;

    /// <summary>Заблокирован — только если это достоверно известно (свой пользователь с isActive=false).</summary>
    public bool KnownInactive => CreatedByThisApp && IsActive == false;
}

/// <summary>
/// HTTP-клиент App API с кэшем токена приложения и справочником пользователей (обновляется раз в 30 с —
/// нужен для выбора исполнителей маршрута и адресных уведомлений «всем с ролью»).
/// </summary>
public sealed class TslAuthClient(IHttpClientFactory http, AuthOptions options, ILogger<TslAuthClient> log)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _token;
    private DateTime _tokenExpires;
    private List<DirectoryUser> _users = [];
    private DateTime _usersLoaded = DateTime.MinValue;

    public string Issuer => options.Issuer;
    public string ClientId => options.ClientId;

    /// <summary>Токен приложения: client_credentials, кэшируется до истечения (с запасом в минуту).</summary>
    private async Task<string> TokenAsync(CancellationToken ct)
    {
        if (_token is not null && DateTime.UtcNow < _tokenExpires) return _token;
        await _lock.WaitAsync(ct);
        try
        {
            if (_token is not null && DateTime.UtcNow < _tokenExpires) return _token;
            var client = http.CreateClient();
            var response = await client.PostAsync(new Uri(new Uri(options.Internal), "connect/token"), new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials", ["client_id"] = options.ClientId,
                ["client_secret"] = options.ClientSecret, ["scope"] = "tsl-auth-app"
            }), ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode) throw new TslAuthException($"Не удалось получить токен приложения: {body}", 502);
            var json = JsonDocument.Parse(body).RootElement;
            _token = json.GetProperty("access_token").GetString();
            _tokenExpires = DateTime.UtcNow.AddSeconds(json.GetProperty("expires_in").GetInt32() - 60);
            return _token!;
        }
        finally { _lock.Release(); }
    }

    /// <summary>Произвольный вызов App API; ошибки TSL Auth (ProblemDetails) пробрасываются с тем же статусом.</summary>
    public async Task<JsonElement> CallAsync(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        var client = http.CreateClient();
        using var request = new HttpRequestMessage(method, new Uri(new Uri(options.Internal), "api/app" + path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await TokenAsync(ct));
        if (body is not null) request.Content = JsonContent.Create(body, options: Json);
        using var response = await client.SendAsync(request, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            var detail = text;
            try { detail = JsonDocument.Parse(text).RootElement.TryGetProperty("detail", out var d) ? d.GetString() ?? text : text; }
            catch (JsonException) { /* не JSON — отдаём как есть */ }
            log.LogWarning("App API {Method} {Path} -> {Status}: {Detail}", method, path, (int)response.StatusCode, detail);
            throw new TslAuthException(detail, (int)response.StatusCode);
        }
        if (text.Length == 0) return default;
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    public async Task<IReadOnlyList<DirectoryUser>> UsersAsync(bool force = false, CancellationToken ct = default)
    {
        if (!force && DateTime.UtcNow - _usersLoaded < TimeSpan.FromSeconds(30)) return _users;
        try
        {
            // Список постраничный (take ≤ 500): для демо одной страницы хватает, но читаем до конца.
            var all = new List<DirectoryUser>();
            for (var skip = 0; ; skip += 500)
            {
                var page = (await CallAsync(HttpMethod.Get, $"/users?skip={skip}&take=500", ct: ct)).Deserialize<List<DirectoryUser>>(Json) ?? [];
                all.AddRange(page);
                if (page.Count < 500) break;
            }
            _users = all;
            _usersLoaded = DateTime.UtcNow;
        }
        catch (Exception ex) when (ex is TslAuthException or HttpRequestException)
        {
            // TSL Auth недоступен: работаем со старым справочником, чтобы документооборот не останавливался.
            log.LogWarning(ex, "Справочник пользователей не обновлён");
            if (_usersLoaded == DateTime.MinValue) throw;
        }
        return _users;
    }

    public void InvalidateUsers() => _usersLoaded = DateTime.MinValue;
}

public sealed class TslAuthException(string message, int status) : Exception(message)
{
    public int Status { get; } = status;
}
