using System.Text.RegularExpressions;
using Npgsql;

namespace TslAuth.Infrastructure;

/// <summary>
/// Значения по умолчанию для строки подключения PostgreSQL.
/// Npgsql по умолчанию пробует шифрование через Kerberos (GSSAPI); в distroless-образе библиотеки
/// libgssapi_krb5 нет, поэтому каждое подключение писало в лог «Cannot load library libgssapi_krb5.so.2».
/// GSS-шифрование отключается, если администратор не задал его явно; TLS (SSL Mode) работает как обычно.
/// </summary>
public static partial class PostgresConnectionString
{
    public static string Normalize(string connectionString)
    {
        if (GssSetting().IsMatch(connectionString)) return connectionString; // задано явно — не трогаем
        return new NpgsqlConnectionStringBuilder(connectionString) { GssEncryptionMode = GssEncryptionMode.Disable }.ConnectionString;
    }

    [GeneratedRegex(@"gss\s*enc", RegexOptions.IgnoreCase)]
    private static partial Regex GssSetting();
}
