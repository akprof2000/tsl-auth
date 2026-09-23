using System.Data.Common;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Npgsql;
using TslAuth.Data;

namespace TslAuth.Infrastructure;

/// <summary>
/// Перенос всех данных из встроенной SQLite в PostgreSQL (переход с одиночного режима на кластер).
/// Команда: <c>admin migrate-to-postgres --target "Host=...;Database=...;Username=...;Password=..." [--overwrite]</c>.
///
/// Как работает:
/// 1. Схема SQLite уже доведена до актуальной (StartupInitializer выполняется перед CLI), приёмник создаётся
///    и доводится до той же версии штатными миграциями.
/// 2. Приёмник должен быть пустым; <c>--overwrite</c> явно разрешает очистить его (например, если кластер
///    уже успел стартовать и создать начального администратора).
/// 3. Таблицы копируются из согласованного снимка SQLite (одна читающая транзакция) в порядке внешних ключей,
///    всё в одной транзакции PostgreSQL. Значения переносятся «как хранятся»: зашифрованные поля не
///    расшифровываются, HMAC-индексы не пересчитываются — поэтому узлы PostgreSQL должны использовать
///    ТОТ ЖЕ мастер-ключ (содержимое master.key одиночного режима).
/// 4. До фиксации транзакции для каждой таблицы сверяются число записей и SHA-256 содержимого; при любом
///    расхождении транзакция откатывается и в PostgreSQL ничего не остаётся.
/// 5. После фиксации пользователи читаются из PostgreSQL через EF (с расшифровкой) и сверяются с исходными.
/// </summary>
public static class PostgresMigration
{
    private const int BatchRows = 500;

    /// <summary>Итог по одной таблице: число записей и контрольные суммы в источнике и приёмнике.</summary>
    public sealed record TableResult(string Table, long SourceRows, long TargetRows, string SourceHash, string TargetHash)
    {
        public bool Ok => SourceRows == TargetRows && SourceHash == TargetHash;
    }

    /// <summary>Выполняет перенос. Исключение — перенос не выполнен (транзакция в PostgreSQL откатывается).</summary>
    public static async Task<IReadOnlyList<TableResult>> RunAsync(AuthDbContext source, string targetConnectionString, bool overwrite,
        ILogger logger, CancellationToken ct = default)
    {
        if (!source.Database.IsSqlite())
            throw new InvalidOperationException("Источник должен быть SQLite: команда запускается в одиночном режиме (Database__Provider=Sqlite).");

        targetConnectionString = PostgresConnectionString.Normalize(targetConnectionString);

        // --- Приёмник: создать БД при необходимости и довести схему до версии этого сервиса ---
        await StartupInitializer.EnsurePostgresDatabaseAsync(targetConnectionString, logger, ct);
        await using var target = new PostgresAuthDbContext(
            new DbContextOptionsBuilder<PostgresAuthDbContext>().UseNpgsql(targetConnectionString).Options);
        await StartupInitializer.MigrateAsync(target, logger, ct);

        var sourceMigrations = (await source.Database.GetAppliedMigrationsAsync(ct)).Select(MigrationName).ToList();
        var targetMigrations = (await target.Database.GetAppliedMigrationsAsync(ct)).Select(MigrationName).ToList();
        if (!sourceMigrations.SequenceEqual(targetMigrations))
            throw new InvalidOperationException("Версии схем SQLite и PostgreSQL не совпадают — перенос невозможен.");

        var tables = OrderByDependencies(target.Model);

        // Соединение принадлежит контексту EF — открываем, но не освобождаем сами.
        var src = (Microsoft.Data.Sqlite.SqliteConnection)source.Database.GetDbConnection();
        if (src.State != System.Data.ConnectionState.Open) await src.OpenAsync(ct);
        // Отложенная читающая транзакция: в режиме WAL она видит согласованный снимок и не блокирует запись
        // (работающий сервис не останавливается, но изменения после начала снимка не переносятся).
        IReadOnlyList<TableResult> results;
        await using (var srcTx = src.BeginTransaction(deferred: true))
            results = await CopyAsync(src, srcTx, tables, targetConnectionString, overwrite, logger, ct);
        // Транзакция источника закрыта до запросов EF ниже: SQLite не выполняет команды без неё, пока она открыта.

        // --- Проверка после фиксации: данные читаются сервисом из PostgreSQL (EF + расшифровка полей) ---
        var sourceUsers = await source.Users.AsNoTracking().Select(u => new { u.Id, u.UserName, u.Email }).OrderBy(u => u.Id).ToListAsync(ct);
        var targetUsers = await target.Users.AsNoTracking().Select(u => new { u.Id, u.UserName, u.Email }).OrderBy(u => u.Id).ToListAsync(ct);
        if (!sourceUsers.SequenceEqual(targetUsers))
            throw new InvalidOperationException("Пользователи в PostgreSQL прочитались не так, как в SQLite — проверьте мастер-ключ.");

        return results;
    }

    /// <summary>Копирование всех таблиц в одной транзакции PostgreSQL со сверкой перед фиксацией.</summary>
    private static async Task<IReadOnlyList<TableResult>> CopyAsync(DbConnection src, DbTransaction srcTx, List<Table> tables,
        string targetConnectionString, bool overwrite, ILogger logger, CancellationToken ct)
    {
        await using var dst = new NpgsqlConnection(targetConnectionString);
        await dst.OpenAsync(ct);
        await using var dstTx = await dst.BeginTransactionAsync(ct);

        // --- Приёмник должен быть пустым ---
        var nonEmpty = new List<string>();
        foreach (var t in tables)
            if (await ScalarLongAsync(dst, dstTx, $"SELECT COUNT(*) FROM {Q(t.Name)}", ct) > 0) nonEmpty.Add(t.Name);
        if (nonEmpty.Count > 0)
        {
            if (!overwrite)
                throw new InvalidOperationException(
                    $"В PostgreSQL уже есть данные (таблицы: {string.Join(", ", nonEmpty)}). " +
                    "Остановите узлы кластера и повторите с --overwrite, чтобы заменить их данными SQLite.");
            logger.LogWarning("Очистка PostgreSQL перед переносом (--overwrite): {Tables}.", string.Join(", ", nonEmpty));
            await ExecuteAsync(dst, dstTx, "TRUNCATE " + string.Join(", ", tables.Select(t => Q(t.Name))) + " CASCADE", ct);
        }

        // --- Копирование ---
        var results = new List<TableResult>();
        foreach (var t in tables)
        {
            var rows = await ReadSourceAsync(src, srcTx, t, ct);
            await InsertAsync(dst, dstTx, t, rows, ct);
            await ResetIdentityAsync(dst, dstTx, t, ct);

            // Сверка до фиксации: число записей и хеш содержимого (строки упорядочены, значения нормализованы).
            var targetRows = await ReadTargetAsync(dst, dstTx, t, ct);
            var result = new TableResult(t.Name, rows.Count, targetRows.Count, Hash(rows), Hash(targetRows));
            results.Add(result);
            logger.LogInformation("{Table}: {Rows} записей{Status}", t.Name, rows.Count, result.Ok ? "" : " — РАСХОЖДЕНИЕ");
        }

        var failed = results.Where(r => !r.Ok).ToList();
        if (failed.Count > 0)
            throw new InvalidOperationException("Данные не совпали после копирования, перенос отменён (PostgreSQL не изменён): " +
                string.Join("; ", failed.Select(f => $"{f.Table}: {f.SourceRows} → {f.TargetRows}")));

        await dstTx.CommitAsync(ct);
        return results;
    }

    // ---------- Модель: таблицы, столбцы, порядок ----------

    /// <summary>Столбец: имя и тип значения, которое хранится в PostgreSQL (после value converter'ов EF).</summary>
    private sealed record Column(string Name, Type StoreType, bool IsTimestampWithoutZone);

    private sealed record Table(string Name, List<Column> Columns, List<string> KeyColumns);

    /// <summary>Таблицы модели в порядке «сначала главные, потом зависимые» (по внешним ключам).</summary>
    private static List<Table> OrderByDependencies(IModel model)
    {
        var entities = model.GetEntityTypes().Where(e => e.GetTableName() is not null && e.GetViewName() is null && !e.IsOwned()).ToList();
        var byTable = entities.GroupBy(e => e.GetTableName()!).ToDictionary(g => g.Key, g => g.First());
        var ordered = new List<string>();
        var visiting = new HashSet<string>();

        void Visit(string table)
        {
            if (ordered.Contains(table) || !visiting.Add(table)) return; // уже добавлена или цикл (ссылка на себя)
            foreach (var fk in byTable[table].GetForeignKeys())
            {
                var principal = fk.PrincipalEntityType.GetTableName();
                if (principal is not null && principal != table && byTable.ContainsKey(principal)) Visit(principal);
            }
            ordered.Add(table);
        }

        foreach (var table in byTable.Keys.Order(StringComparer.Ordinal)) Visit(table);

        return ordered.Select(name =>
        {
            var entity = byTable[name];
            var store = StoreObjectIdentifier.Table(name, entity.GetSchema());
            var columns = entity.GetProperties()
                .Select(p =>
                {
                    var mapping = p.GetRelationalTypeMapping();
                    var type = mapping.Converter?.ProviderClrType ?? mapping.ClrType;
                    return new Column(p.GetColumnName(store)!, Nullable.GetUnderlyingType(type) ?? type,
                        mapping.StoreType.StartsWith("timestamp without", StringComparison.OrdinalIgnoreCase));
                })
                .DistinctBy(c => c.Name)
                .ToList();
            var key = entity.FindPrimaryKey()!.Properties.Select(p => p.GetColumnName(store)!).ToList();
            return new Table(name, columns, key);
        }).ToList();
    }

    // ---------- Чтение / запись ----------

    private static async Task<List<object?[]>> ReadSourceAsync(DbConnection src, DbTransaction tx, Table t, CancellationToken ct)
    {
        await using var command = src.CreateCommand();
        command.Transaction = tx;
        command.CommandText = $"SELECT {string.Join(", ", t.Columns.Select(c => Q(c.Name)))} FROM {Q(t.Name)}";
        await using var reader = await command.ExecuteReaderAsync(ct);
        var rows = new List<object?[]>();
        while (await reader.ReadAsync(ct))
        {
            var row = new object?[t.Columns.Count];
            for (var i = 0; i < row.Length; i++)
                row[i] = reader.IsDBNull(i) ? null : ConvertSqliteValue(reader.GetValue(i), t.Columns[i]);
            rows.Add(row);
        }
        return rows;
    }

    private static async Task<List<object?[]>> ReadTargetAsync(NpgsqlConnection dst, NpgsqlTransaction tx, Table t, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            $"SELECT {string.Join(", ", t.Columns.Select(c => Q(c.Name)))} FROM {Q(t.Name)}", dst, tx);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var rows = new List<object?[]>();
        while (await reader.ReadAsync(ct))
        {
            var row = new object?[t.Columns.Count];
            for (var i = 0; i < row.Length; i++) row[i] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>Вставка пачками (многострочный INSERT с параметрами).</summary>
    private static async Task InsertAsync(NpgsqlConnection dst, NpgsqlTransaction tx, Table t, List<object?[]> rows, CancellationToken ct)
    {
        var columns = string.Join(", ", t.Columns.Select(c => Q(c.Name)));
        foreach (var chunk in rows.Chunk(BatchRows))
        {
            await using var command = new NpgsqlCommand { Connection = dst, Transaction = tx };
            var values = new StringBuilder();
            var n = 0;
            foreach (var row in chunk)
            {
                values.Append(values.Length == 0 ? "(" : ", (");
                for (var i = 0; i < row.Length; i++)
                {
                    if (i > 0) values.Append(", ");
                    var name = "p" + n++;
                    values.Append('@').Append(name);
                    command.Parameters.Add(new NpgsqlParameter(name, row[i] ?? DBNull.Value));
                }
                values.Append(')');
            }
            command.CommandText = $"INSERT INTO {Q(t.Name)} ({columns}) VALUES {values}";
            await command.ExecuteNonQueryAsync(ct);
        }
    }

    /// <summary>Автоинкрементные ключи (журнал, лента событий): счётчик продолжает с максимума перенесённых значений.</summary>
    private static async Task ResetIdentityAsync(NpgsqlConnection dst, NpgsqlTransaction tx, Table t, CancellationToken ct)
    {
        if (t.KeyColumns.Count != 1) return;
        var key = t.KeyColumns[0];
        await using var find = new NpgsqlCommand("SELECT pg_get_serial_sequence(@table, @column)", dst, tx);
        find.Parameters.AddWithValue("table", Q(t.Name));
        find.Parameters.AddWithValue("column", key);
        if (await find.ExecuteScalarAsync(ct) is not string sequence) return;
        await ExecuteAsync(dst, tx,
            $"SELECT setval('{sequence.Replace("'", "''")}', COALESCE((SELECT MAX({Q(key)}) FROM {Q(t.Name)}), 1), " +
            $"(SELECT COUNT(*) > 0 FROM {Q(t.Name)}))", ct);
    }

    // ---------- Преобразование и сравнение значений ----------

    /// <summary>
    /// SQLite хранит всё как TEXT/INTEGER/REAL/BLOB; приводим к типу столбца PostgreSQL.
    /// Время: EF пишет в SQLite UTC-строки без зоны с точностью 100 нс, PostgreSQL хранит микросекунды.
    /// </summary>
    private static object ConvertSqliteValue(object value, Column column)
    {
        var type = column.StoreType;
        if (type == typeof(string)) return value as string ?? Convert.ToString(value, CultureInfo.InvariantCulture)!;
        if (type == typeof(Guid)) return value is byte[] bytes ? new Guid(bytes) : Guid.Parse((string)value);
        if (type == typeof(bool)) return Convert.ToInt64(value, CultureInfo.InvariantCulture) != 0;
        if (type == typeof(byte[])) return value;
        if (type == typeof(DateTime))
        {
            var parsed = DateTime.Parse((string)value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            parsed = new DateTime(parsed.Ticks - parsed.Ticks % 10, DateTimeKind.Utc);
            return column.IsTimestampWithoutZone ? DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified) : parsed;
        }
        if (type == typeof(DateTimeOffset))
        {
            var parsed = DateTimeOffset.Parse((string)value, CultureInfo.InvariantCulture).ToUniversalTime();
            return new DateTimeOffset(parsed.Ticks - parsed.Ticks % 10, TimeSpan.Zero);
        }
        if (type == typeof(TimeSpan)) return TimeSpan.Parse((string)value, CultureInfo.InvariantCulture);
        return Convert.ChangeType(value, type, CultureInfo.InvariantCulture);
    }

    /// <summary>SHA-256 содержимого таблицы: строки нормализуются и сортируются, порядок чтения не важен.</summary>
    private static string Hash(List<object?[]> rows)
    {
        var lines = rows.Select(r => string.Join('\u001F', r.Select(Normalize))).Order(StringComparer.Ordinal);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var line in lines) sha.AppendData(Encoding.UTF8.GetBytes(line + "\u001E"));
        return Convert.ToHexString(sha.GetHashAndReset());
    }

    private static string Normalize(object? value) => value switch
    {
        null => "␀",
        DateTime d => d.Ticks.ToString(CultureInfo.InvariantCulture),
        DateTimeOffset d => d.UtcTicks.ToString(CultureInfo.InvariantCulture),
        Guid g => g.ToString("D"),
        bool b => b ? "1" : "0",
        byte[] b => Convert.ToBase64String(b),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? ""
    };

    // ---------- Мелочи ----------

    private static string Q(string identifier) => "\"" + identifier.Replace("\"", "\"\"") + "\"";

    /// <summary>"20260923124720_InitialCreate" → "InitialCreate": метки времени миграций у провайдеров разные.</summary>
    private static string MigrationName(string id) => id[(id.IndexOf('_') + 1)..];

    private static async Task<long> ScalarLongAsync(NpgsqlConnection c, NpgsqlTransaction tx, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, c, tx);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }

    private static async Task ExecuteAsync(NpgsqlConnection c, NpgsqlTransaction tx, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, c, tx);
        await command.ExecuteNonQueryAsync(ct);
    }
}
