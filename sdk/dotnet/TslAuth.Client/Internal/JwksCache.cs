using System.Security.Cryptography;
using System.Text.Json;

namespace TslAuth.Client.Internal;

/// <summary>Кэш ключей JWKS (§3): TTL, перечитывание по неизвестному kid не чаще JwksMinRefresh, single-flight.</summary>
internal sealed class JwksCache
{
    private readonly TslAuthOptions _options;
    private readonly TslHttp _http;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private Dictionary<string, RSAParameters>? _keys;
    private DateTimeOffset _loadedAt = DateTimeOffset.MinValue;   // успешная загрузка
    private DateTimeOffset _attemptedAt = DateTimeOffset.MinValue; // любая попытка (для лимита частоты)

    public JwksCache(TslAuthOptions options, TslHttp http)
    {
        _options = options;
        _http = http;
    }

    /// <summary>Параметры ключа по kid или null, если ключа нет даже после допустимого перечитывания.</summary>
    public async Task<RSAParameters?> GetKeyAsync(string kid, CancellationToken ct)
    {
        var now = _http.Now;
        var keys = _keys;
        if (keys is null || now - _loadedAt >= _options.JwksTtl)
            keys = await RefreshAsync(now, force: keys is null, ct).ConfigureAwait(false);

        if (keys is not null && keys.TryGetValue(kid, out var found)) return found;

        // Неизвестный kid — ротация на сервере? Перечитываем, но не чаще JwksMinRefresh.
        if (now - _attemptedAt >= _options.JwksMinRefresh)
        {
            keys = await RefreshAsync(now, force: false, ct).ConfigureAwait(false);
            if (keys is not null && keys.TryGetValue(kid, out found)) return found;
        }
        return null;
    }

    /// <summary>
    /// Загружает JWKS один раз на всех ожидающих: если после захвата замка обнаруживается загрузка,
    /// начатая после <paramref name="requestedAt"/>, используется её результат.
    /// При ошибке сети возвращает старый набор (если он есть).
    /// </summary>
    private async Task<Dictionary<string, RSAParameters>?> RefreshAsync(DateTimeOffset requestedAt, bool force, CancellationToken ct)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_attemptedAt >= requestedAt && _keys is not null) return _keys;
            if (!force && _keys is not null && _http.Now - _attemptedAt < _options.JwksMinRefresh && _http.Now - _loadedAt < _options.JwksTtl)
                return _keys;
            _attemptedAt = _http.Now;
            try
            {
                var uri = _options.JwksUri;
                if (string.IsNullOrWhiteSpace(uri))
                    uri = (await _http.GetDiscoveryAsync(ct).ConfigureAwait(false)).JwksUri
                          ?? throw new InvalidOperationException("discovery не содержит jwks_uri");
                using var doc = await _http.GetJsonAsync(uri, ct).ConfigureAwait(false);
                _keys = Parse(doc.RootElement);
                _loadedAt = _http.Now;
            }
            catch (Exception) when (_keys is not null)
            {
                // Ошибка сети не роняет проверку: продолжаем со старым набором.
            }
            return _keys;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Только kty=RSA с use отсутствующим или sig; ключи с некорректными n/e пропускаются.</summary>
    internal static Dictionary<string, RSAParameters> Parse(JsonElement root)
    {
        var result = new Dictionary<string, RSAParameters>(StringComparer.Ordinal);
        if (!root.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array) return result;
        foreach (var k in keys.EnumerateArray())
        {
            if (Str(k, "kty") != "RSA") continue;
            var use = Str(k, "use");
            if (use is not null && use != "sig") continue;
            var kid = Str(k, "kid");
            var n = Str(k, "n");
            var e = Str(k, "e");
            if (kid is null || n is null || e is null) continue;
            var modulus = Base64Url.TryDecode(n);
            var exponent = Base64Url.TryDecode(e);
            if (modulus is null || exponent is null || modulus.Length == 0 || exponent.Length == 0) continue;
            result[kid] = new RSAParameters { Modulus = modulus, Exponent = exponent };
        }
        return result;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

internal static class Base64Url
{
    public static byte[]? TryDecode(string s)
    {
        if (s.Length == 0) return Array.Empty<byte>();
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
            case 1: return null;
        }
        try { return Convert.FromBase64String(padded); }
        catch (FormatException) { return null; }
    }
}
