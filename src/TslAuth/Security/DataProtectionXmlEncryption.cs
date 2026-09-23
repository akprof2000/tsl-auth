using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace TslAuth.Security;

/// <summary>
/// Шифрует ключи ASP.NET Data Protection перед сохранением в БД.
/// Без него ключи (которыми защищены cookie входа и antiforgery) лежали бы в таблице открыто:
/// утечка дампа БД позволила бы подделать сессию. Подключается в ServiceSetup (XmlEncryptor).
/// </summary>
public sealed class FieldCryptoXmlEncryptor : IXmlEncryptor
{
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        var element = new XElement("encryptedKey",
            new XComment(" AES-256-GCM, TSL Auth master key "),
            new XElement("value", FieldCrypto.Encrypt(plaintextElement.ToString(SaveOptions.DisableFormatting))));
        // Тип дешифратора записывается в XML ключа — Data Protection создаст его сам при чтении.
        return new EncryptedXmlInfo(element, typeof(FieldCryptoXmlDecryptor));
    }
}

/// <summary>
/// Обратная операция к <see cref="FieldCryptoXmlEncryptor"/>. Создаётся Data Protection через конструктор
/// без параметров, поэтому ключ берёт из статического FieldCrypto (инициализирован при старте).
/// </summary>
public sealed class FieldCryptoXmlDecryptor : IXmlDecryptor
{
    public XElement Decrypt(XElement encryptedElement)
    {
        var value = (string?)encryptedElement.Element("value")
                    ?? throw new InvalidOperationException("Повреждённый ключ Data Protection.");
        return XElement.Parse(FieldCrypto.Decrypt(value)!);
    }
}
