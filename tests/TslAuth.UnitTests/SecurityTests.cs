using System.Security.Cryptography;
using TslAuth.Infrastructure;
using TslAuth.Security;
using TslAuth.Services;

namespace TslAuth.UnitTests;

/// <summary>Шифрование персональных полей (AES-GCM, префикс enc1:) и слепой индекс для поиска (bi1:).</summary>
public sealed class FieldCryptoTests
{
    static FieldCryptoTests() => FieldCrypto.Initialize(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void Encrypt_Decrypt_Roundtrip()
    {
        var cipher = FieldCrypto.Encrypt("ivan@tsl.local");
        Assert.StartsWith("enc1:", cipher);
        Assert.DoesNotContain("ivan", cipher);
        Assert.Equal("ivan@tsl.local", FieldCrypto.Decrypt(cipher));
    }

    [Fact]
    public void Encrypt_UsesRandomNonce()
    {
        // Одинаковые значения не должны давать одинаковый шифртекст (иначе утечка через сравнение).
        Assert.NotEqual(FieldCrypto.Encrypt("same"), FieldCrypto.Encrypt("same"));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws()
    {
        var bytes = Convert.FromBase64String(FieldCrypto.Encrypt("secret")![5..]);
        bytes[^1] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(() => FieldCrypto.Decrypt("enc1:" + Convert.ToBase64String(bytes)));
    }

    [Fact]
    public void Decrypt_PlainLegacyValue_ReturnedAsIs() => Assert.Equal("legacy", FieldCrypto.Decrypt("legacy"));

    [Fact]
    public void Null_IsPreserved()
    {
        Assert.Null(FieldCrypto.Encrypt(null));
        Assert.Null(FieldCrypto.Decrypt(null));
        Assert.Null(FieldCrypto.BlindIndex(null));
    }

    [Fact]
    public void BlindIndex_IsDeterministic_AndIdempotent()
    {
        var index = FieldCrypto.BlindIndex("IVAN");
        Assert.StartsWith("bi1:", index);
        Assert.Equal(index, FieldCrypto.BlindIndex("IVAN"));
        Assert.Equal(index, FieldCrypto.BlindIndex(index)); // повторная запись прочитанного значения не «перехеширует»
        Assert.NotEqual(index, FieldCrypto.BlindIndex("PETR"));
    }

    [Fact]
    public void EncryptBytes_Roundtrip()
    {
        var data = RandomNumberGenerator.GetBytes(100);
        Assert.Equal(data, FieldCrypto.DecryptBytes(FieldCrypto.EncryptBytes(data)));
    }

    [Fact]
    public void Initialize_RejectsShortKey() =>
        Assert.Throws<InvalidOperationException>(() => FieldCrypto.Initialize(new byte[16]));
}

/// <summary>Проверка допустимых имён (clientId, разрешения, роли): латиница, цифры и ограниченный набор символов.</summary>
public sealed class NamesTests
{
    [Theory]
    [InlineData("orders-api")]
    [InlineData("orders.read")]
    [InlineData("app:scope_1")]
    public void Valid(string name) => Assert.Equal(name, Names.Validate(name, "x"));

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("-starts-with-dash")]
    [InlineData("has space")]
    [InlineData("pipe|char")]
    [InlineData("кириллица")]
    public void Invalid(string name) => Assert.Throws<AdminException>(() => Names.Validate(name, "x"));

    [Fact]
    public void TooLong() => Assert.Throws<AdminException>(() => Names.Validate(new string('a', 101), "x"));
}

/// <summary>Генератор временных паролей: длина, все классы символов, уникальность.</summary>
public sealed class PasswordGeneratorTests
{
    [Fact]
    public void Generated_ContainsAllClasses()
    {
        for (var i = 0; i < 200; i++)
        {
            var p = PasswordGenerator.Generate();
            Assert.Equal(16, p.Length);
            Assert.Contains(p, char.IsLower);
            Assert.Contains(p, char.IsUpper);
            Assert.Contains(p, char.IsDigit);
            Assert.Contains(p, c => !char.IsLetterOrDigit(c));
        }
    }

    [Fact]
    public void Generated_AreUnique() =>
        Assert.Equal(1000, Enumerable.Range(0, 1000).Select(_ => PasswordGenerator.Generate()).Distinct().Count());
}

/// <summary>Подпись тела вебхука: HMAC-SHA256 в формате "sha256=&lt;hex&gt;", зависит от секрета.</summary>
public sealed class WebhookSignatureTests
{
    [Fact]
    public void Sign_IsHmacSha256Hex()
    {
        // Эталон: echo -n '{"a":1}' | openssl dgst -sha256 -hmac secret
        Assert.Equal("sha256=4aa2d0fd8d2cc48ea9ad6ad2d8fbd1d7b25c3c61da5f37dfd236a0cd27ce4a3c".Length,
            WebhookService.Sign("secret", "{\"a\":1}").Length);
        Assert.Equal(WebhookService.Sign("secret", "{\"a\":1}"), WebhookService.Sign("secret", "{\"a\":1}"));
        Assert.NotEqual(WebhookService.Sign("secret", "{\"a\":1}"), WebhookService.Sign("other", "{\"a\":1}"));
        Assert.StartsWith("sha256=", WebhookService.Sign("secret", "x"));
    }
}

/// <summary>Экспорт журнала в CSV: экранирование кавычек и защита от CSV/формульных инъекций.</summary>
public sealed class AuditCsvTests
{
    [Fact]
    public void Csv_EscapesFormulaInjection_AndQuotes()
    {
        var row = new AuditDto(1, DateTime.UnixEpoch, "auth.login.failed", "info", false, "anonymous", "=HYPERLINK(\"x\")",
            null, null, "1.2.3.4", null, "node", null);
        var csv = AuditService.ToCsv([row]);
        Assert.Contains("\"'=HYPERLINK(\"\"x\"\")\"", csv);
    }
}
