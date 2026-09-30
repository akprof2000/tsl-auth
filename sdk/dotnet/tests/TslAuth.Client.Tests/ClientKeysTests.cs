using System.Security.Cryptography;
using TslAuth.Client;

namespace TslAuth.Client.Tests;

/// <summary>Загрузка ключа клиента для private_key_jwt: только закрытый ключ именно P-256 (без стенда).</summary>
public class ClientKeysTests
{
    [Fact]
    public void Generated_key_loads_and_has_rfc7638_kid()
    {
        var pem = ClientKeys.GeneratePrivateKeyPem();
        using var key = ClientKeys.Load(pem);
        Assert.Equal(43, ClientKeys.KeyId(pem).Length); // base64url(SHA-256) без «=»
        Assert.Contains("\"crv\":\"P-256\"", ClientKeys.PublicJwk(pem));
    }

    [Fact]
    public void Public_key_pem_is_rejected_at_load()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ex = Assert.Throws<InvalidOperationException>(() => ClientKeys.Load(ecdsa.ExportSubjectPublicKeyInfoPem()));
        Assert.Contains("закрытого ключа", ex.Message);
    }

    [Fact]
    public void Other_256_bit_curve_is_rejected()
    {
        ECDsa other;
        try { other = ECDsa.Create(ECCurve.CreateFromFriendlyName("brainpoolP256r1")); }
        catch (Exception e) when (e is PlatformNotSupportedException or CryptographicException) { return; } // кривая недоступна в ОС
        using (other)
            Assert.Throws<InvalidOperationException>(() => ClientKeys.Load(other.ExportPkcs8PrivateKeyPem()));
    }

    [Fact]
    public void Missing_key_file_gives_clear_error()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => new TokenClient(new TslAuthOptions
        {
            Issuer = "http://localhost/", ClientId = "agent", ClientPrivateKeyFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pem")
        }));
        Assert.Contains("TSL_AUTH_CLIENT_KEY_FILE", ex.Message);
    }
}
