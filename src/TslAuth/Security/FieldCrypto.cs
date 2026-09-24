using System.Security.Cryptography;
using System.Text;

namespace TslAuth.Security;

/// <summary>
/// Шифрование данных "at rest": AES-256-GCM для персональных данных и секретов,
/// HMAC-SHA256 "слепые индексы" для полей, по которым нужен поиск на равенство.
/// Ключи выводятся (HKDF) из одного мастер-ключа, общего для всех экземпляров сервиса.
/// Статический: используется value converter'ами EF (AuthDbContext) и шифратором ключей Data Protection;
/// инициализируется в ServiceSetup ключом из <see cref="MasterKeyResolver"/>.
/// </summary>
public static class FieldCrypto
{
    // Префиксы версионируют формат: позволяют отличить зашифрованное значение от открытого
    // и в будущем сменить алгоритм без миграции старых данных.
    private const string EncryptedPrefix = "enc1:";
    private const string BlindIndexPrefix = "bi1:";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private static byte[]? _encryptionKey;
    private static byte[]? _indexKey;

    /// <summary>Выводит ключи шифрования и индекса из мастер-ключа; вызывается один раз при старте.</summary>
    public static void Initialize(byte[] masterKey)
    {
        if (masterKey.Length < 32)
            throw new InvalidOperationException("Мастер-ключ шифрования должен быть не короче 32 байт.");

        // Разные info → независимые ключи: компрометация индекса (HMAC) не раскрывает ключ шифрования.
        _encryptionKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, 32, info: "tsl-auth/field-encryption"u8.ToArray());
        _indexKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, 32, info: "tsl-auth/blind-index"u8.ToArray());
    }

    private static byte[] EncryptionKey =>
        _encryptionKey ?? throw new InvalidOperationException("FieldCrypto не инициализирован.");

    /// <summary>Шифрует строку в формат "enc1:" + base64(nonce | шифротекст | тег); null остаётся null.</summary>
    public static string? Encrypt(string? plaintext)
    {
        if (plaintext is null) return null;
        return EncryptedPrefix + Convert.ToBase64String(EncryptBytes(Encoding.UTF8.GetBytes(plaintext)));
    }

    /// <summary>Расшифровывает значение из БД; при подмене данных или чужом ключе GCM бросит CryptographicException.</summary>
    public static string? Decrypt(string? stored)
    {
        if (stored is null) return null;
        // Все версии сервиса шифруют эти поля с самого начала, незашифрованных значений быть не может.
        // Значение без префикса — признак подмены данных в БД в обход шифрования (например, подставленный email
        // для перехвата сброса пароля), поэтому не принимается как открытый текст.
        if (!stored.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
            throw new CryptographicException("Поле в БД не зашифровано: значение изменено в обход сервиса.");
        return Encoding.UTF8.GetString(DecryptBytes(Convert.FromBase64String(stored[EncryptedPrefix.Length..])));
    }

    /// <summary>AES-256-GCM: результат — nonce (12 байт) | шифротекст | тег (16 байт).</summary>
    public static byte[] EncryptBytes(ReadOnlySpan<byte> plaintext)
    {
        // Случайный nonce на каждое шифрование: повтор nonce с тем же ключом в GCM ломает стойкость.
        var buffer = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = buffer.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(EncryptionKey, TagSize);
        aes.Encrypt(nonce, plaintext, buffer.AsSpan(NonceSize, plaintext.Length), buffer.AsSpan(NonceSize + plaintext.Length));
        return buffer;
    }

    /// <summary>Обратная операция к <see cref="EncryptBytes"/>; проверяет тег целостности.</summary>
    public static byte[] DecryptBytes(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < NonceSize + TagSize)
            throw new CryptographicException("Некорректный зашифрованный блок.");

        var length = payload.Length - NonceSize - TagSize;
        var plaintext = new byte[length];
        using var aes = new AesGcm(EncryptionKey, TagSize);
        aes.Decrypt(payload[..NonceSize], payload.Slice(NonceSize, length), payload[(NonceSize + length)..], plaintext);
        return plaintext;
    }

    /// <summary>
    /// Детерминированный индекс для поиска на равенство. Идемпотентен: уже вычисленный индекс
    /// возвращается как есть (EF может повторно записать прочитанное значение при Update).
    /// HMAC с секретным ключом (а не простой хеш) не даёт подобрать значение по словарю, имея только дамп БД.
    /// </summary>
    public static string? BlindIndex(string? value)
    {
        if (value is null || value.StartsWith(BlindIndexPrefix, StringComparison.Ordinal)) return value;
        var key = _indexKey ?? throw new InvalidOperationException("FieldCrypto не инициализирован.");
        return BlindIndexPrefix + Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
    }
}
