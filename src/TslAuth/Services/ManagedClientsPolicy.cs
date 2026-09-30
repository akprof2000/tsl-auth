using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace TslAuth.Services;

/// <summary>
/// Политика подчинённых клиентов приложения-владельца (свойство <c>tsl_managed_clients</c> клиента OpenIddict).
/// Задаёт её только администратор; приложение через App API может лишь заводить подчинённых в её рамках.
/// </summary>
/// <param name="Prefix">Обязательный префикс <c>client_id</c> подчинённых (например <c>import-agent-</c>).</param>
/// <param name="Roles">Белый список ролей <b>своего</b> приложения, которые можно выдавать подчинённым.</param>
/// <param name="GrantTypes">Разрешённые потоки; поддерживается только <c>client_credentials</c>.</param>
/// <param name="AuthMethods">Способы входа подчинённого: <c>private_key_jwt</c> (по умолчанию) и/или <c>client_secret</c>.</param>
/// <param name="MaxClients">Предел числа подчинённых у владельца.</param>
/// <param name="AccessTokenLifetime">Срок access-токена подчинённых, минут (не больше глобального).</param>
/// <param name="RequireDelegation">Изменения — только делегированным токеном оператора (false — тестовые стенды).</param>
/// <param name="ManagePermission">Разрешение в матрице владельца, нужное оператору для управления подчинёнными.</param>
/// <param name="InactiveDays">Автоотключение подчинённого без токенов N дней (0 — выключено).</param>
public sealed partial record ManagedClientsPolicy(
    string Prefix,
    List<string>? Roles = null,
    List<string>? GrantTypes = null,
    List<string>? AuthMethods = null,
    int MaxClients = 200,
    int AccessTokenLifetime = 5,
    bool RequireDelegation = true,
    string ManagePermission = "agents.manage",
    int InactiveDays = 0)
{
    public const string PrivateKeyJwt = "private_key_jwt";
    public const string ClientSecret = "client_secret";
    public const int MaxClientIdLength = 64;

    /// <summary>Разрешён ли вход по ключу.</summary>
    public bool AllowsKeys => (AuthMethods ?? []).Contains(PrivateKeyJwt);

    /// <summary>Разрешён ли вход по секрету.</summary>
    public bool AllowsSecret => (AuthMethods ?? []).Contains(ClientSecret);

    /// <summary>Проверяет и нормализует политику; ошибка — <see cref="AdminException"/> с текстом для администратора.</summary>
    public ManagedClientsPolicy Normalize()
    {
        var prefix = (Prefix ?? "").Trim();
        if (!ClientIdPattern().IsMatch(prefix) || prefix.Length > MaxClientIdLength - 8)
            throw new AdminException($"Префикс client_id подчинённых: строчные латинские буквы, цифры и «-», до {MaxClientIdLength - 8} символов.");

        var roles = (Roles ?? []).Select(r => r.Trim()).Where(r => r.Length > 0).Distinct().ToList();
        foreach (var role in roles) Names.ValidateRole(role);

        var grants = (GrantTypes ?? [AppGrantTypes.ClientCredentials]).Select(g => g.Trim()).Where(g => g.Length > 0).Distinct().ToList();
        if (grants.Count == 0) grants = [AppGrantTypes.ClientCredentials];
        if (grants.Any(g => g != AppGrantTypes.ClientCredentials))
            throw new AdminException("Подчинённым клиентам доступен только поток client_credentials.");

        var methods = (AuthMethods ?? [PrivateKeyJwt]).Select(m => m.Trim()).Where(m => m.Length > 0).Distinct().ToList();
        if (methods.Count == 0) methods = [PrivateKeyJwt];
        if (methods.Any(m => m is not (PrivateKeyJwt or ClientSecret)))
            throw new AdminException("Способы входа подчинённых: private_key_jwt и/или client_secret.");

        if (MaxClients is < 1 or > 10_000) throw new AdminException("Предел числа подчинённых: от 1 до 10000.");
        if (AccessTokenLifetime is < 1 or > 1440) throw new AdminException("Срок токена подчинённых: от 1 до 1440 минут.");
        if (InactiveDays is < 0 or > 3650) throw new AdminException("Предел неактивности подчинённых: от 0 (выключено) до 3650 дней.");
        var permission = Names.Validate(ManagePermission, "Разрешение управления подчинёнными");

        return this with
        {
            Prefix = prefix, Roles = roles, GrantTypes = grants, AuthMethods = methods, ManagePermission = permission
        };
    }

    /// <summary>Политика из свойств клиента OpenIddict; null — подчинённые клиенты не включены.</summary>
    public static ManagedClientsPolicy? From(IReadOnlyDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(ApplicationService.ManagedClientsProperty, out var json) && json.ValueKind == JsonValueKind.Object
            ? json.Deserialize<ManagedClientsPolicy>()
            : null;

    /// <summary>
    /// Проверяет client_id подчинённого: префикс политики, символы <c>[a-z0-9-]</c>, длина не больше 64.
    /// </summary>
    public string ValidateClientId(string? value)
    {
        value = value?.Trim() ?? "";
        if (!value.StartsWith(Prefix, StringComparison.Ordinal))
            throw new AdminException($"client_id подчинённого должен начинаться с префикса «{Prefix}».");
        if (value.Length > MaxClientIdLength || !ClientIdPattern().IsMatch(value))
            throw new AdminException($"client_id подчинённого: строчные латинские буквы, цифры и «-», до {MaxClientIdLength} символов.");
        return value;
    }

    /// <summary>Роли подчинённого должны входить в белый список политики.</summary>
    public List<string> ValidateRoles(IEnumerable<string>? roles)
    {
        var wanted = (roles ?? []).Select(r => r.Trim()).Where(r => r.Length > 0).Distinct().ToList();
        var outside = wanted.Except(Roles ?? []).ToList();
        if (outside.Count > 0)
            throw new AdminException($"Роли вне белого списка политики подчинённых: {string.Join(", ", outside)}.");
        return wanted;
    }

    [GeneratedRegex("^[a-z0-9-]+$")]
    private static partial Regex ClientIdPattern();
}

/// <summary>Открытый ключ подчинённого клиента в ответах API: только отпечаток (<c>kid</c>) и параметры кривой.</summary>
public sealed record ManagedClientKeyDto(string Kid, string Kty, string Crv);

/// <summary>
/// Разбор JWKS подчинённого клиента: принимаются только открытые ключи EC P-256 (ES256), не больше двух
/// (плавная смена ключа по <c>kid</c>); закрытая часть (<c>d</c>) отклоняется — сервис закрытых ключей не хранит.
/// <c>kid</c> всегда вычисляется сервисом как отпечаток RFC 7638, переданное значение игнорируется.
/// </summary>
public static class ManagedClientKeys
{
    public const int MaxKeys = 2;

    /// <summary>Разбирает и проверяет JWKS (<c>{"keys":[…]}</c> или один JWK); ошибки — <see cref="AdminException"/>.</summary>
    public static JsonWebKeySet Parse(JsonElement jwks)
    {
        if (jwks.ValueKind != JsonValueKind.Object) throw new AdminException("jwks: ожидается объект {\"keys\":[…]}.");
        var keys = jwks.TryGetProperty("keys", out var array) && array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().ToList()
            : [jwks];
        if (keys.Count == 0) throw new AdminException("jwks: нет ни одного ключа.");
        if (keys.Count > MaxKeys) throw new AdminException($"jwks: не больше {MaxKeys} ключей одновременно.");

        var result = new JsonWebKeySet();
        foreach (var key in keys)
        {
            if (key.ValueKind != JsonValueKind.Object) throw new AdminException("jwks: ключ должен быть объектом JWK.");
            if (Str(key, "kty") != "EC" || Str(key, "crv") != "P-256")
                throw new AdminException("jwks: поддерживаются только открытые ключи EC P-256 (ES256).");
            if (key.TryGetProperty("d", out _)) throw new AdminException("jwks: передан закрытый ключ (поле d) — нужна только открытая часть.");
            var x = Str(key, "x");
            var y = Str(key, "y");
            if (string.IsNullOrEmpty(x) || string.IsNullOrEmpty(y)) throw new AdminException("jwks: у ключа EC нет координат x/y.");
            try
            {
                if (Base64UrlEncoder.DecodeBytes(x).Length != 32 || Base64UrlEncoder.DecodeBytes(y).Length != 32)
                    throw new AdminException("jwks: координаты x/y ключа P-256 должны быть по 32 байта.");
                // Точка должна лежать на кривой — иначе ключ бесполезен, а ошибка всплывёт только при входе.
                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = Base64UrlEncoder.DecodeBytes(x), Y = Base64UrlEncoder.DecodeBytes(y) }
                });
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                throw new AdminException("jwks: некорректный открытый ключ P-256.");
            }

            var jwk = new JsonWebKey { Kty = "EC", Crv = "P-256", X = x, Y = y, Alg = SecurityAlgorithms.EcdsaSha256, Use = "sig" };
            jwk.KeyId = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
            if (result.Keys.Any(k => k.KeyId == jwk.KeyId)) throw new AdminException("jwks: ключи повторяются.");
            result.Keys.Add(jwk);
        }
        return result;
    }

    /// <summary>Отпечаток RFC 7638 для EC-ключа: base64url(SHA-256 канонического JSON {crv, kty, x, y}).</summary>
    public static string Thumbprint(string x, string y) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));

    /// <summary>Ключи для ответов API (без самих координат — отпечатка достаточно, чтобы узнать ключ).</summary>
    public static List<ManagedClientKeyDto> Describe(JsonWebKeySet? set) =>
        set is null ? [] : set.Keys.Select(k => new ManagedClientKeyDto(k.KeyId ?? Thumbprint(k.X, k.Y), k.Kty, k.Crv)).ToList();

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>
/// Требования к клиентскому assertion сверх встроенных проверок OpenIddict (подпись, iss/sub/aud/exp):
/// только ES256, срок не больше 5 минут от <c>iat</c>, обязательный <c>jti</c>. Возвращает код причины отказа
/// (для аудита и метрики) или null. Одноразовость <c>jti</c> проверяет вызывающий код по БД.
/// </summary>
public static class ClientAssertionRules
{
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Код причины отказа или null, если assertion допустим.</summary>
    public static string? Check(string assertion, out JsonWebToken? token)
    {
        token = null;
        try
        {
            token = new JsonWebToken(assertion);
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException)
        {
            return "malformed";
        }

        // Алгоритм проверяется по заголовку отдельно от ключа: none/HS*/RS* не проходят, даже если ключ клиента
        // почему-то подошёл бы (например, HS256 с открытым ключом в роли секрета).
        if (!string.Equals(token.Alg, SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal)) return "alg";
        if (string.IsNullOrEmpty(token.Id)) return "jti_missing";
        if (!token.TryGetPayloadValue<long>("iat", out var iat)) return "iat_missing";
        // Значения вне диапазона DateTimeOffset (например, миллисекунды вместо секунд) — отказ, а не исключение.
        if (iat < 0 || iat > DateTimeOffset.MaxValue.ToUnixTimeSeconds()) return "iat_invalid";
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
        if (token.ValidTo == DateTime.MinValue) return "exp_missing";
        if (token.ValidTo - issuedAt.UtcDateTime > MaxLifetime) return "lifetime";
        if (issuedAt.UtcDateTime > DateTime.UtcNow.AddMinutes(1)) return "iat_future";
        return null;
    }
}
