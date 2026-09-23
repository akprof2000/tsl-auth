using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using TslAuth.Data;

namespace TslAuth.Security;

/// <summary>
/// Ключи подписи (RSA) и шифрования (AES) токенов. Хранятся в БД в зашифрованном виде,
/// поэтому одинаковы для всех экземпляров и переживают перезапуск: выданные токены остаются валидными.
/// Singleton: заполняется StartupInitializer, читается при настройке OpenIddictServerOptions (ServiceSetup).
/// </summary>
public sealed class ServerKeyRing
{
    private const string SigningKeyId = "oidc-signing-rsa";
    private const string EncryptionKeyId = "oidc-encryption-aes";

    public RsaSecurityKey SigningKey { get; private set; } = null!;
    public SymmetricSecurityKey EncryptionKey { get; private set; } = null!;

    /// <summary>Загружает ключи из БД, при первом запуске — генерирует и сохраняет.</summary>
    public async Task LoadOrCreateAsync(AuthDbContext db, CancellationToken ct)
    {
        var signing = await GetOrCreateAsync(db, SigningKeyId, () =>
        {
            using var rsa = RSA.Create(2048);
            return Convert.ToBase64String(rsa.ExportRSAPrivateKey());
        }, ct);

        var encryption = await GetOrCreateAsync(db, EncryptionKeyId,
            () => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), ct);

        var rsaKey = RSA.Create();
        rsaKey.ImportRSAPrivateKey(Convert.FromBase64String(signing), out _);
        // kid детерминированно выводится из публичного ключа: одинаков на всех экземплярах и совпадает с JWKS.
        var modulusHash = SHA256.HashData(rsaKey.ExportParameters(false).Modulus!);

        SigningKey = new RsaSecurityKey(rsaKey) { KeyId = Base64UrlEncoder.Encode(modulusHash[..16]) };
        EncryptionKey = new SymmetricSecurityKey(Convert.FromBase64String(encryption));
    }

    private static async Task<string> GetOrCreateAsync(AuthDbContext db, string id, Func<string> factory, CancellationToken ct)
    {
        var existing = await db.KeyMaterials.AsNoTracking().FirstOrDefaultAsync(k => k.Id == id, ct);
        if (existing is not null) return existing.Value;

        // Value шифруется мастер-ключом конвертером EF. Гонку экземпляров исключает advisory-lock StartupInitializer;
        // после записи перечитываем значение из БД — источник истины одинаков для всех.
        db.KeyMaterials.Add(new KeyMaterial { Id = id, Value = factory() });
        await db.SaveChangesAsync(ct);
        return (await db.KeyMaterials.AsNoTracking().FirstAsync(k => k.Id == id, ct)).Value;
    }
}
