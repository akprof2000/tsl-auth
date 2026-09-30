using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TslAuth.Client;

/// <summary>
/// Ключи клиента для входа по ключу (<c>private_key_jwt</c>, docs/client-contract.md §6): генерация закрытого ключа
/// EC P-256 в PEM, открытая часть как JWK для регистрации подчинённого клиента (<c>POST /api/app/clients</c>) и
/// отпечаток RFC 7638 (<c>kid</c>). Закрытый ключ никуда не передаётся — только подписывает assertion.
/// </summary>
public static class ClientKeys
{
    /// <summary>Новый закрытый ключ EC P-256 в формате PKCS#8 PEM.</summary>
    public static string GeneratePrivateKeyPem()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>Загружает ключ из PEM (PKCS#8 «PRIVATE KEY» или SEC1 «EC PRIVATE KEY»); кривая должна быть P-256.</summary>
    public static ECDsa Load(string pem)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        var p = ecdsa.ExportParameters(false);
        if (p.Q.X is not { Length: 32 } || p.Q.Y is not { Length: 32 })
            throw new InvalidOperationException("TSL Auth: ключ клиента должен быть EC P-256 (ES256).");
        return ecdsa;
    }

    /// <summary>Открытая часть ключа как JWK (<c>{"kty":"EC","crv":"P-256","x":…,"y":…,"kid":…}</c>).</summary>
    public static string PublicJwk(string pem)
    {
        using var ecdsa = Load(pem);
        var (x, y) = Coordinates(ecdsa);
        return JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["kty"] = "EC", ["crv"] = "P-256", ["x"] = x, ["y"] = y, ["kid"] = Thumbprint(x, y), ["alg"] = "ES256", ["use"] = "sig"
        });
    }

    /// <summary>JWKS с одним ключом — тело поля <c>jwks</c> при регистрации подчинённого клиента.</summary>
    public static string PublicJwks(string pem) => "{\"keys\":[" + PublicJwk(pem) + "]}";

    /// <summary>Отпечаток RFC 7638 — тот же <c>kid</c>, который присвоит ключу сервис.</summary>
    public static string KeyId(string pem)
    {
        using var ecdsa = Load(pem);
        var (x, y) = Coordinates(ecdsa);
        return Thumbprint(x, y);
    }

    internal static (string X, string Y) Coordinates(ECDsa ecdsa)
    {
        var p = ecdsa.ExportParameters(false);
        return (Base64Url(p.Q.X!), Base64Url(p.Q.Y!));
    }

    internal static string Thumbprint(string x, string y) =>
        Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));

    internal static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
