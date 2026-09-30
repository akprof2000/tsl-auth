using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TslAuth.Client.Internal;

/// <summary>
/// Подпись клиентского assertion (RFC 7523, <c>private_key_jwt</c>): ES256, заголовок
/// <c>typ=client-authentication+jwt</c>, <c>iss=sub=client_id</c>, <c>aud</c> — issuer сервиса (как в discovery),
/// одноразовый <c>jti</c>, срок 60 секунд.
/// </summary>
internal sealed class ClientAssertionSigner : IDisposable
{
    public const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(60);
    private readonly ECDsa _key;
    private readonly string _kid;

    private ClientAssertionSigner(ECDsa key, string kid)
    {
        _key = key;
        _kid = kid;
    }

    /// <summary>Подписант из настроек (PEM строкой или файлом); null — ключ не задан.</summary>
    public static ClientAssertionSigner? FromOptions(TslAuthOptions options)
    {
        var pem = options.ClientPrivateKeyPem;
        if (string.IsNullOrWhiteSpace(pem) && !string.IsNullOrWhiteSpace(options.ClientPrivateKeyFile))
        {
            try
            {
                pem = File.ReadAllText(options.ClientPrivateKeyFile);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException($"TSL Auth: не удалось прочитать файл ключа клиента (TSL_AUTH_CLIENT_KEY_FILE): {ex.Message}", ex);
            }
        }
        if (string.IsNullOrWhiteSpace(pem)) return null;
        var key = ClientKeys.Load(pem);
        var (x, y) = ClientKeys.Coordinates(key);
        return new ClientAssertionSigner(key, string.IsNullOrWhiteSpace(options.ClientKeyId) ? ClientKeys.Thumbprint(x, y) : options.ClientKeyId!);
    }

    /// <summary>Новый assertion с <paramref name="audience"/> = issuer сервиса.</summary>
    public string Create(string clientId, string audience, DateTimeOffset now)
    {
        var header = JsonSerializer.Serialize(new Dictionary<string, string> { ["alg"] = "ES256", ["typ"] = "client-authentication+jwt", ["kid"] = _kid });
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["iss"] = clientId, ["sub"] = clientId, ["aud"] = audience,
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["iat"] = now.ToUnixTimeSeconds(), ["nbf"] = now.ToUnixTimeSeconds(), ["exp"] = (now + Lifetime).ToUnixTimeSeconds()
        });
        var signingInput = ClientKeys.Base64Url(Encoding.UTF8.GetBytes(header)) + "." + ClientKeys.Base64Url(Encoding.UTF8.GetBytes(payload));
        // ES256 в JWS — «сырая» подпись r||s по 32 байта (IEEE P1363); именно её возвращает ECDsa.SignData по умолчанию.
        var signature = _key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return signingInput + "." + ClientKeys.Base64Url(signature);
    }

    public void Dispose() => _key.Dispose();
}
