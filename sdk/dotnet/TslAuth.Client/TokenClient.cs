using System.Net;
using System.Text.Json;
using TslAuth.Client.Internal;

namespace TslAuth.Client;

/// <summary>Набор токенов из ответа token endpoint (docs/client-contract.md §6).</summary>
public sealed class TokenSet
{
    internal TokenSet(JsonElement raw, DateTimeOffset now)
    {
        Raw = raw.Clone();
        AccessToken = Str(raw, "access_token") ?? "";
        RefreshToken = Str(raw, "refresh_token");
        IdToken = Str(raw, "id_token");
        Scope = Str(raw, "scope");
        TokenType = Str(raw, "token_type") ?? "Bearer";
        var expiresIn = raw.TryGetProperty("expires_in", out var e) && e.ValueKind == JsonValueKind.Number ? e.GetDouble() : 0;
        ExpiresAt = now.AddSeconds(expiresIn);
    }

    /// <summary>Access-токен.</summary>
    public string AccessToken { get; }
    /// <summary>Refresh-токен (при ротации — уже новый).</summary>
    public string? RefreshToken { get; }
    /// <summary>ID-токен (scope <c>openid</c>).</summary>
    public string? IdToken { get; }
    /// <summary>Момент истечения, вычисленный из <c>expires_in</c> при получении.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>Выданный <c>scope</c>.</summary>
    public string? Scope { get; }
    /// <summary><c>token_type</c>, обычно <c>Bearer</c>.</summary>
    public string TokenType { get; }
    /// <summary>Сырой ответ сервера.</summary>
    public JsonElement Raw { get; }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>Результат интроспекции: <see cref="Active"/> и сырые claims.</summary>
public sealed record TokenIntrospection(bool Active, JsonElement Claims);

/// <summary>Ошибка token/introspection/revocation endpoint: <c>4xx</c> с JSON <c>error</c>; сеть и <c>5xx</c> — <c>unavailable</c>.</summary>
public sealed class TokenError : Exception
{
    /// <summary>Создаёт ошибку с полями ответа OAuth2.</summary>
    public TokenError(string error, string? errorDescription, int status, Exception? inner = null)
        : base($"{error}: {errorDescription ?? "(без описания)"} (HTTP {status})", inner)
    {
        Error = error;
        ErrorDescription = errorDescription;
        Status = status;
    }

    /// <summary>Код OAuth2 (<c>invalid_grant</c>, <c>invalid_client</c>, …) или <c>unavailable</c>.</summary>
    public string Error { get; }
    /// <summary><c>error_description</c> ответа.</summary>
    public string? ErrorDescription { get; }
    /// <summary>HTTP-статус (0 при сетевой ошибке).</summary>
    public int Status { get; }
}

/// <summary>
/// Клиент token endpoint (§6): client_credentials с кэшем и single-flight, exchange, refresh, password,
/// authorization_code (PKCE), introspect, revoke. Потокобезопасен.
/// </summary>
public sealed class TokenClient
{
    private static readonly TimeSpan CacheMargin = TimeSpan.FromSeconds(30);
    private readonly TslAuthOptions _options;
    private readonly TslHttp _http;
    private readonly string _issuer;
    private readonly Dictionary<string, TokenSet> _cache = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SemaphoreSlim> _locks = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    /// <summary>Создаёт клиент; настройки должны содержать Issuer и ClientId.</summary>
    public TokenClient(TslAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _issuer = options.RequireIssuer();
        _http = new TslHttp(options);
    }

    /// <summary>Сервисный токен; кэшируется по <c>scope</c> до <c>expiresAt − 30 с</c>, параллельные вызовы делают один запрос.</summary>
    public async Task<TokenSet> ClientCredentialsAsync(IEnumerable<string>? scopes = null, CancellationToken ct = default)
    {
        var scope = Join(scopes);
        var key = scope ?? "";
        if (TryCached(key, out var cached)) return cached;

        var gate = GetLock(key);
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (TryCached(key, out cached)) return cached;
            var set = await RequestTokenAsync(Form("client_credentials", ("scope", scope)), ct).ConfigureAwait(false);
            lock (_sync) _cache[key] = set;
            return set;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Token exchange (RFC 8693) от имени пользователя; не кэшируется.</summary>
    public Task<TokenSet> ExchangeAsync(string subjectToken, IEnumerable<string>? scopes = null, CancellationToken ct = default) =>
        RequestTokenAsync(Form("urn:ietf:params:oauth:grant-type:token-exchange",
            ("subject_token", subjectToken),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("scope", Join(scopes))), ct);

    /// <summary>Обновление по refresh-токену; ответ содержит новый refresh-токен — сохраните его вместо старого.</summary>
    public Task<TokenSet> RefreshAsync(string refreshToken, IEnumerable<string>? scopes = null, CancellationToken ct = default) =>
        RequestTokenAsync(Form("refresh_token", ("refresh_token", refreshToken), ("scope", Join(scopes))), ct);

    /// <summary>Grant <c>password</c> — только для серверных приложений.</summary>
    public Task<TokenSet> PasswordAsync(string username, string password, IEnumerable<string>? scopes = null, CancellationToken ct = default) =>
        RequestTokenAsync(Form("password", ("username", username), ("password", password), ("scope", Join(scopes))), ct);

    /// <summary>Обмен authorization code с PKCE.</summary>
    public Task<TokenSet> AuthorizationCodeAsync(string code, string redirectUri, string codeVerifier, CancellationToken ct = default) =>
        RequestTokenAsync(Form("authorization_code", ("code", code), ("redirect_uri", redirectUri), ("code_verifier", codeVerifier)), ct);

    /// <summary>Интроспекция токена.</summary>
    public async Task<TokenIntrospection> IntrospectAsync(string token, CancellationToken ct = default)
    {
        var disco = await DiscoveryAsync(ct).ConfigureAwait(false);
        var endpoint = disco.IntrospectionEndpoint ?? _issuer + "/connect/introspect";
        using var doc = await PostFormAsync(endpoint, Form(null, ("token", token)), ct).ConfigureAwait(false);
        var root = doc.RootElement;
        var active = root.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.True;
        return new TokenIntrospection(active, root.Clone());
    }

    /// <summary>Отзыв access- или refresh-токена; успех — 200.</summary>
    public async Task RevokeAsync(string token, CancellationToken ct = default)
    {
        var disco = await DiscoveryAsync(ct).ConfigureAwait(false);
        var endpoint = disco.RevocationEndpoint ?? _issuer + "/connect/revoke";
        using var _ = await PostFormAsync(endpoint, Form(null, ("token", token)), ct).ConfigureAwait(false);
    }

    private async Task<TokenSet> RequestTokenAsync(Dictionary<string, string> form, CancellationToken ct)
    {
        var disco = await DiscoveryAsync(ct).ConfigureAwait(false);
        var endpoint = disco.TokenEndpoint ?? _issuer + "/connect/token";
        using var doc = await PostFormAsync(endpoint, form, ct).ConfigureAwait(false);
        return new TokenSet(doc.RootElement, _http.Now);
    }

    private async Task<Discovery> DiscoveryAsync(CancellationToken ct)
    {
        try
        {
            return await _http.GetDiscoveryAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            throw new TokenError("unavailable", "discovery недоступен", 0, ex);
        }
    }

    /// <summary>POST формы; пустой ответ (revoke) — пустой JSON-объект.</summary>
    private async Task<JsonDocument> PostFormAsync(string endpoint, Dictionary<string, string> form, CancellationToken ct)
    {
        HttpResponseMessage response;
        string body;
        try
        {
            response = await _http.Client.PostAsync(endpoint, new FormUrlEncodedContent(form), ct).ConfigureAwait(false);
            using (response)
            {
                body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                var status = (int)response.StatusCode;
                if (status >= 500)
                    throw new TokenError("unavailable", $"сервер вернул {status}", status);
                if (status >= 400)
                {
                    string error = "invalid_request", description = "";
                    try
                    {
                        using var err = JsonDocument.Parse(body);
                        error = Str(err.RootElement, "error") ?? error;
                        description = Str(err.RootElement, "error_description") ?? "";
                    }
                    catch (JsonException) { }
                    throw new TokenError(error, description, status);
                }
                if (string.IsNullOrWhiteSpace(body)) return JsonDocument.Parse("{}");
                return JsonDocument.Parse(body);
            }
        }
        catch (TokenError) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or JsonException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            throw new TokenError("unavailable", "сервис недоступен", 0, ex);
        }
    }

    private Dictionary<string, string> Form(string? grantType, params (string Name, string? Value)[] fields)
    {
        if (string.IsNullOrEmpty(_options.ClientId))
            throw new InvalidOperationException("TSL Auth: не задан ClientId (TSL_AUTH_CLIENT_ID).");
        var form = new Dictionary<string, string> { ["client_id"] = _options.ClientId };
        if (!string.IsNullOrEmpty(_options.ClientSecret)) form["client_secret"] = _options.ClientSecret;
        if (grantType is not null) form["grant_type"] = grantType;
        foreach (var (name, value) in fields)
            if (!string.IsNullOrEmpty(value)) form[name] = value;
        return form;
    }

    private bool TryCached(string key, out TokenSet set)
    {
        lock (_sync)
        {
            if (_cache.TryGetValue(key, out var found) && _http.Now < found.ExpiresAt - CacheMargin)
            {
                set = found;
                return true;
            }
        }
        set = null!;
        return false;
    }

    private SemaphoreSlim GetLock(string key)
    {
        lock (_sync)
        {
            if (!_locks.TryGetValue(key, out var gate)) _locks[key] = gate = new SemaphoreSlim(1, 1);
            return gate;
        }
    }

    private static string? Join(IEnumerable<string>? scopes)
    {
        if (scopes is null) return null;
        var s = string.Join(' ', scopes.Where(x => !string.IsNullOrWhiteSpace(x)));
        return s.Length == 0 ? null : s;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
