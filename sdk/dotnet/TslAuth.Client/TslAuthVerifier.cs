using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TslAuth.Client.Internal;

namespace TslAuth.Client;

/// <summary>
/// Проверка access-токена (docs/client-contract.md §2–§3): RS256 по JWKS с кэшем, issuer, срок, audience,
/// при <see cref="TslAuthOptions.Introspect"/> — интроспекция. Потокобезопасен, один экземпляр на приложение.
/// </summary>
public sealed class TslAuthVerifier
{
    private readonly TslAuthOptions _options;
    private readonly TslHttp _http;
    private readonly JwksCache _jwks;
    private readonly string _issuer;

    /// <summary>Создаёт verifier; настройки должны содержать <see cref="TslAuthOptions.Issuer"/>.</summary>
    public TslAuthVerifier(TslAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _issuer = options.RequireIssuer();
        _http = new TslHttp(options);
        _jwks = new JwksCache(options, _http);
    }

    /// <summary>Настройки, с которыми создан verifier.</summary>
    public TslAuthOptions Options => _options;

    /// <summary>
    /// Проверяет заголовок <c>Authorization</c>: схема <c>Bearer</c> без учёта регистра; отсутствие/пустота — <c>missing</c>.
    /// </summary>
    public Task<TslPrincipal> VerifyAuthorizationHeaderAsync(string? header, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(header))
            throw new TslAuthException(TslAuthErrorCodes.Missing, "Заголовок Authorization отсутствует.");
        var h = header.Trim();
        if (h.Length < 7 || !h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            throw new TslAuthException(TslAuthErrorCodes.Missing, "Ожидается схема Bearer.");
        var token = h.Substring(7).Trim();
        if (token.Length == 0)
            throw new TslAuthException(TslAuthErrorCodes.Missing, "Пустой Bearer-токен.");
        return VerifyAsync(token, ct);
    }

    /// <summary>Проверяет JWT и возвращает principal; при отказе — <see cref="TslAuthException"/> с кодом §2.</summary>
    public async Task<TslPrincipal> VerifyAsync(string? token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new TslAuthException(TslAuthErrorCodes.Malformed, "Пустой токен.");

        // 2. Три части, заголовок и payload — JSON в base64url.
        var parts = token.Split('.');
        if (parts.Length != 3)
            throw new TslAuthException(TslAuthErrorCodes.Malformed, "Токен должен состоять из трёх частей.");
        using var header = ParseJson(parts[0]);
        using var payload = ParseJson(parts[1]);
        if (header.RootElement.ValueKind != JsonValueKind.Object || payload.RootElement.ValueKind != JsonValueKind.Object)
            throw new TslAuthException(TslAuthErrorCodes.Malformed, "Заголовок и payload должны быть JSON-объектами.");

        // 3. Только RS256 — до любых обращений к ключам.
        if (Str(header.RootElement, "alg") != "RS256")
            throw new TslAuthException(TslAuthErrorCodes.UnsupportedAlg, "Поддерживается только alg=RS256.");

        // 4. kid обязателен.
        var kid = Str(header.RootElement, "kid");
        if (string.IsNullOrEmpty(kid))
            throw new TslAuthException(TslAuthErrorCodes.Malformed, "В заголовке нет kid.");

        // 5. Ключ из кэша JWKS.
        var key = await _jwks.GetKeyAsync(kid, ct).ConfigureAwait(false)
                  ?? throw new TslAuthException(TslAuthErrorCodes.UnknownKey, "Ключ с таким kid не найден в JWKS.");

        // 6. Подпись RSASSA-PKCS1-v1_5 / SHA-256 — до чтения claims.
        var signature = Base64Url.TryDecode(parts[2]);
        if (signature is null || signature.Length == 0)
            throw new TslAuthException(TslAuthErrorCodes.BadSignature, "Подпись не декодируется.");
        var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        using (var rsa = RSA.Create())
        {
            try
            {
                rsa.ImportParameters(key);
                if (!rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    throw new TslAuthException(TslAuthErrorCodes.BadSignature, "Подпись неверна.");
            }
            catch (CryptographicException ex)
            {
                throw new TslAuthException(TslAuthErrorCodes.BadSignature, "Подпись не проверяется.", ex);
            }
        }

        var claims = payload.RootElement;

        // 7. Issuer (без завершающего «/»).
        var iss = Str(claims, "iss");
        if (iss is null || iss.TrimEnd('/') != _issuer)
            throw new TslAuthException(TslAuthErrorCodes.BadIssuer, "iss не совпадает с настроенным issuer.");

        // 8. exp обязателен; nbf — если есть.
        var now = _options.TimeProvider.GetUtcNow().ToUnixTimeSeconds();
        var skew = (long)_options.ClockSkew.TotalSeconds;
        if (!claims.TryGetProperty("exp", out var expEl) || !TryGetSeconds(expEl, out var exp))
            throw new TslAuthException(TslAuthErrorCodes.Expired, "В токене нет exp.");
        if (now > exp + skew)
            throw new TslAuthException(TslAuthErrorCodes.Expired, "Срок действия токена истёк.");
        if (claims.TryGetProperty("nbf", out var nbfEl) && TryGetSeconds(nbfEl, out var nbf) && now < nbf - skew)
            throw new TslAuthException(TslAuthErrorCodes.NotYetValid, "Токен ещё не действует (nbf).");

        // 9. aud содержит audience этого API.
        if (!string.IsNullOrEmpty(_options.Audience) && !TslPrincipal.List(claims, "aud").Contains(_options.Audience))
            throw new TslAuthException(TslAuthErrorCodes.BadAudience, "aud не содержит audience этого API.");

        // 10. Интроспекция — мгновенный отзыв.
        if (_options.Introspect)
            await IntrospectAsync(token, ct).ConfigureAwait(false);

        return new TslPrincipal(claims, _options.Audience);
    }

    private async Task IntrospectAsync(string token, CancellationToken ct)
    {
        try
        {
            var disco = await _http.GetDiscoveryAsync(ct).ConfigureAwait(false);
            var endpoint = disco.IntrospectionEndpoint ?? _issuer + "/connect/introspect";
            var form = new Dictionary<string, string> { ["token"] = token };
            if (!string.IsNullOrEmpty(_options.ClientId)) form["client_id"] = _options.ClientId;
            if (!string.IsNullOrEmpty(_options.ClientSecret)) form["client_secret"] = _options.ClientSecret;
            using var response = await _http.Client.PostAsync(endpoint, new FormUrlEncodedContent(form), ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                throw new TslAuthException(TslAuthErrorCodes.IntrospectionUnavailable, $"Интроспекция вернула {(int)response.StatusCode}.");
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var active = doc.RootElement.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.True;
            if (!active)
                throw new TslAuthException(TslAuthErrorCodes.Revoked, "Токен отозван (active: false).");
        }
        catch (TslAuthException) { throw; }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            throw new TslAuthException(TslAuthErrorCodes.IntrospectionUnavailable, "Introspection endpoint недоступен.", ex);
        }
    }

    private static JsonDocument ParseJson(string base64Url)
    {
        var bytes = Base64Url.TryDecode(base64Url)
                    ?? throw new TslAuthException(TslAuthErrorCodes.Malformed, "Часть токена не в base64url.");
        try
        {
            return JsonDocument.Parse(bytes);
        }
        catch (JsonException ex)
        {
            throw new TslAuthException(TslAuthErrorCodes.Malformed, "Часть токена не JSON.", ex);
        }
    }

    private static bool TryGetSeconds(JsonElement e, out long seconds)
    {
        seconds = 0;
        if (e.ValueKind != JsonValueKind.Number) return false;
        if (e.TryGetInt64(out seconds)) return true;
        if (e.TryGetDouble(out var d)) { seconds = (long)d; return true; }
        return false;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
