using System.Security.Cryptography;
using TslAuth.Options;

namespace TslAuth.Security;

/// <summary>
/// Определяет мастер-ключ шифрования полей при старте (вызывается из ServiceSetup до создания DI-контейнера)
/// и передаёт его в <see cref="FieldCrypto"/>. Потеря ключа = потеря зашифрованных данных и ключей токенов.
/// </summary>
public static class MasterKeyResolver
{
    /// <summary>
    /// Порядок: Encryption:MasterKey → Encryption:MasterKeyFile → (только SQLite) автогенерация файла рядом с БД.
    /// Для PostgreSQL/кластера ключ обязан быть задан явно, иначе экземпляры не смогут читать данные друг друга.
    /// </summary>
    public static byte[] Resolve(EncryptionOptions encryption, DatabaseOptions database, string contentRoot, ILogger logger)
    {
        if (!string.IsNullOrWhiteSpace(encryption.MasterKey))
            return Decode(encryption.MasterKey, "Encryption:MasterKey");

        if (!string.IsNullOrWhiteSpace(encryption.MasterKeyFile) && File.Exists(encryption.MasterKeyFile))
            return Decode(File.ReadAllText(encryption.MasterKeyFile), encryption.MasterKeyFile);

        if (database.IsPostgres)
            throw new InvalidOperationException(
                "Для PostgreSQL необходимо задать Encryption__MasterKey (base64, 32+ байт) или Encryption__MasterKeyFile.");

        // Одиночный экземпляр на SQLite: генерируем ключ автоматически, чтобы сервис запускался «из коробки».
        // Файл кладётся рядом с БД — при резервном копировании каталога данных ключ сохраняется вместе с ней.
        var path = string.IsNullOrWhiteSpace(encryption.MasterKeyFile)
            ? Path.Combine(DataDirectory(database, contentRoot), "master.key")
            : encryption.MasterKeyFile;
        if (File.Exists(path))
            return Decode(File.ReadAllText(path), path);

        // Новый ключ — только для новой БД. Если файл БД уже есть, а ключа нет (не примонтирован том, ключ удалён),
        // новый ключ сделал бы все зашифрованные поля и ключи подписи нечитаемыми — и перезаписал бы путь к ключу.
        if (SqliteDatabaseExists(database, contentRoot))
            throw new InvalidOperationException(
                $"Файл мастер-ключа '{path}' не найден, а база данных уже существует. Без исходного ключа её данные " +
                "не расшифровать: верните master.key (том с данными) или задайте Encryption__MasterKey. Новый ключ не создаётся.");

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(path, Convert.ToBase64String(key));
        logger.LogWarning("Сгенерирован новый мастер-ключ шифрования: {Path}. Сохраните его резервную копию — без него данные не расшифровать.", path);
        return key;
    }

    // Файл SQLite уже существует и не пуст (у новой установки его ещё нет — StartupInitializer создаст его позже).
    private static bool SqliteDatabaseExists(DatabaseOptions database, string contentRoot)
    {
        var builder = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(database.ConnectionString ?? "");
        if (string.IsNullOrEmpty(builder.DataSource) || builder.DataSource == ":memory:") return false;
        var file = new FileInfo(Path.GetFullPath(builder.DataSource, contentRoot));
        return file.Exists && file.Length > 0;
    }

    // Каталог файла SQLite из строки подключения (относительные пути — от content root).
    private static string DataDirectory(DatabaseOptions database, string contentRoot)
    {
        var builder = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(database.ConnectionString ?? "");
        var dir = Path.GetDirectoryName(builder.DataSource);
        return string.IsNullOrEmpty(dir) ? contentRoot : Path.GetFullPath(dir, contentRoot);
    }

    private static byte[] Decode(string value, string source)
    {
        try
        {
            var key = Convert.FromBase64String(value.Trim());
            if (key.Length < 32) throw new FormatException();
            return key;
        }
        catch (FormatException)
        {
            throw new InvalidOperationException($"Мастер-ключ из '{source}' должен быть base64-строкой длиной не менее 32 байт.");
        }
    }
}
