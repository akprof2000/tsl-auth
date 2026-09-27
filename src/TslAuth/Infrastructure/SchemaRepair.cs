using System.Data.Common;
using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Npgsql;
using TslAuth.Data;

namespace TslAuth.Infrastructure;

/// <summary>
/// Самовосстановление схемы БД при старте. Обычный путь — штатные миграции EF (<see cref="StartupInitializer.MigrateAsync"/>).
/// Если БД в состоянии, из которого миграции не ведут к рабочей схеме, схема пересобирается:
///
/// <list type="bullet">
/// <item>файл SQLite повреждён (<c>PRAGMA quick_check</c> ≠ ok или «file is not a database»);</item>
/// <item>таблицы есть, а истории миграций нет (схема создана вручную, скриптом, чужой версией);</item>
/// <item>в истории есть неизвестные миграции, не являющиеся более новыми (чужая или «ветвистая» история);</item>
/// <item>миграция упала посреди обновления;</item>
/// <item>после миграций фактическая схема не совпадает с моделью (нет таблицы или столбца —
///   «частично испорченная» БД: удалённые вручную объекты, неудачное восстановление из бэкапа).</item>
/// </list>
///
/// Пересборка: резервная копия (файл SQLite / схема PostgreSQL остаются нетронутыми) → новая пустая схема
/// штатными миграциями → перенос данных по совпадающим таблицам и столбцам с приведением типов → замена.
/// Значения переносятся «как хранятся» (зашифрованные поля не расшифровываются), поэтому нужен тот же мастер-ключ.
/// Строки, которые нельзя прочитать (повреждённые страницы) или вставить (нарушение ограничений), пропускаются
/// с записью в лог; обязательные столбцы, которых нет в старой схеме, получают нейтральные значения.
///
/// Более новая схема (все неизвестные миграции позже последней известной) — это откат образа на старую версию:
/// по умолчанию запуск останавливается, иначе старый узел кластера «откатил» бы данные новых узлов.
/// Разрешить явно: <c>Database__AllowDowngrade=true</c>. Отключить автопочинку: <c>Database__SchemaRepair=Off</c>.
/// </summary>
public static class SchemaRepair
{
    /// <summary>Итог проверки схемы (команда <c>admin db-check</c> и журнал старта).</summary>
    public sealed record Diagnosis(bool Corrupt, string? CorruptionDetails, bool HistoryMissing, bool HasTables,
        IReadOnlyList<string> Applied, IReadOnlyList<string> Pending, IReadOnlyList<string> Unknown, bool UnknownAreNewer,
        IReadOnlyList<string> SchemaProblems)
    {
        public bool Healthy => !Corrupt && !(HistoryMissing && HasTables) && Unknown.Count == 0 && SchemaProblems.Count == 0;

        public IEnumerable<string> Describe()
        {
            if (Corrupt) yield return $"файл БД повреждён: {CorruptionDetails}";
            if (HistoryMissing && HasTables) yield return "таблицы есть, но нет истории миграций (__EFMigrationsHistory)";
            if (Unknown.Count > 0)
                yield return (UnknownAreNewer ? "схема новее версии сервиса" : "неизвестная история миграций") + ": " + string.Join(", ", Unknown);
            if (Pending.Count > 0) yield return $"не применены миграции: {string.Join(", ", Pending)}";
            foreach (var p in SchemaProblems) yield return p;
        }
    }

    /// <summary>Итог переноса одной таблицы при пересборке.</summary>
    public sealed record TableCopy(string Table, long Copied, long Skipped, string? Note);

    // ====================================================================================
    // Диагностика
    // ====================================================================================

    /// <summary>Проверяет БД, ничего не меняя.</summary>
    public static async Task<Diagnosis> DiagnoseAsync(AuthDbContext db, CancellationToken ct = default)
    {
        var known = db.Database.GetMigrations().ToList();

        if (db.Database.IsSqlite())
        {
            var corruption = await SqliteCorruptionAsync(db.Database.GetConnectionString()!, ct);
            if (corruption is not null)
                return new Diagnosis(true, corruption, false, false, [], known, [], false, []);
        }

        var tables = await ExistingTablesAsync(db, ct);
        var historyExists = tables.Contains("__EFMigrationsHistory");
        var applied = historyExists ? (await db.Database.GetAppliedMigrationsAsync(ct)).ToList() : [];
        var unknown = applied.Except(known).ToList();
        var lastKnown = known.LastOrDefault() ?? "";
        var unknownNewer = unknown.Count > 0 && unknown.All(u => string.CompareOrdinal(u, lastKnown) > 0);
        var pending = known.Except(applied).ToList();
        var hasModelTables = ModelTables(db.Model).Any(t => tables.Contains(t.Name));

        // Сверка столбцов имеет смысл, когда по истории схема должна быть полной.
        var problems = pending.Count == 0 && unknown.Count == 0 && historyExists
            ? await CompareWithModelAsync(db, tables, ct)
            : [];
        return new Diagnosis(false, null, !historyExists, hasModelTables, applied, pending, unknown, unknownNewer, problems);
    }

    /// <summary>
    /// Отличия фактической схемы от модели: нет таблицы или столбца. Лишние таблицы и столбцы не считаются
    /// ошибкой (их могли добавить администраторы или будущие версии).
    /// </summary>
    public static async Task<List<string>> CompareWithModelAsync(AuthDbContext db, HashSet<string>? tables = null, CancellationToken ct = default)
    {
        tables ??= await ExistingTablesAsync(db, ct);
        var problems = new List<string>();
        foreach (var table in ModelTables(db.Model))
        {
            if (!tables.Contains(table.Name))
            {
                problems.Add($"нет таблицы {table.Name}");
                continue;
            }
            var actual = await ColumnsAsync(db, table.Name, ct);
            var missing = table.Columns.Where(c => !actual.ContainsKey(c.Name)).Select(c => c.Name).ToList();
            if (missing.Count > 0) problems.Add($"в таблице {table.Name} нет столбцов: {string.Join(", ", missing)}");
        }
        return problems;
    }

    /// <summary>null — файл цел (или его нет); иначе текст ошибки.</summary>
    private static async Task<string?> SqliteCorruptionAsync(string connectionString, CancellationToken ct)
    {
        var path = new SqliteConnectionStringBuilder(connectionString).DataSource;
        if (string.IsNullOrEmpty(path) || !File.Exists(path) || new FileInfo(path).Length == 0) return null;
        try
        {
            await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder(connectionString) { Pooling = false }.ConnectionString);
            await connection.OpenAsync(ct);
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA quick_check";
            var lines = new List<string>();
            await using (var reader = await command.ExecuteReaderAsync(ct))
                while (await reader.ReadAsync(ct)) lines.Add(reader.GetString(0));
            return lines is ["ok"] ? null : string.Join("; ", lines.Take(5));
        }
        catch (SqliteException ex)
        {
            return ex.Message;
        }
    }

    // ====================================================================================
    // Пересборка
    // ====================================================================================

    /// <summary>
    /// Пересобирает схему с переносом данных. Возвращает путь/имя резервной копии и итоги по таблицам.
    /// Вызывается при старте (под advisory-lock'ом кластера) или командой <c>admin db-repair</c>.
    /// </summary>
    public static Task<(string Backup, IReadOnlyList<TableCopy> Tables)> RebuildAsync(AuthDbContext db, ILogger logger, string reason,
        CancellationToken ct = default) =>
        db.Database.IsSqlite()
            ? RebuildSqliteAsync(db.Database.GetConnectionString()!, db.Model, logger, reason, ct)
            : RebuildPostgresAsync(db.Database.GetConnectionString()!, db.Model, logger, reason, ct);

    // ---------- SQLite ----------

    private static async Task<(string, IReadOnlyList<TableCopy>)> RebuildSqliteAsync(string connectionString, IModel model, ILogger logger,
        string reason, CancellationToken ct)
    {
        var path = Path.GetFullPath(new SqliteConnectionStringBuilder(connectionString).DataSource);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var backup = $"{path}.backup-{stamp}";
        var rebuilt = $"{path}.rebuild";
        logger.LogError("Схема БД требует пересборки ({Reason}). Резервная копия: {Backup}.", reason, backup);

        // Все соединения закрыты — файл можно копировать и заменять. WAL/SHM копируются вместе с основным файлом:
        // в них могут быть зафиксированные, но ещё не перенесённые в файл транзакции.
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            if (File.Exists(path + suffix)) File.Copy(path + suffix, backup + suffix, overwrite: true);
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            if (File.Exists(rebuilt + suffix)) File.Delete(rebuilt + suffix);

        // 1. Новая пустая БД текущей версии — штатными миграциями.
        var rebuiltCs = new SqliteConnectionStringBuilder(connectionString) { DataSource = rebuilt, Pooling = false }.ConnectionString;
        await using (var fresh = new SqliteAuthDbContext(new DbContextOptionsBuilder<SqliteAuthDbContext>().UseSqlite(rebuiltCs).Options))
            await fresh.Database.MigrateAsync(ct);

        // 2. Перенос данных из резервной копии (оригинал не читаем повторно — он мог быть повреждён сильнее).
        var results = new List<TableCopy>();
        await using (var connection = new SqliteConnection(rebuiltCs))
        {
            await connection.OpenAsync(ct);
            await ExecAsync(connection, "PRAGMA foreign_keys = OFF", ct);
            var attached = false;
            try
            {
                await using var attach = connection.CreateCommand();
                attach.CommandText = "ATTACH DATABASE $path AS old";
                attach.Parameters.AddWithValue("$path", backup);
                await attach.ExecuteNonQueryAsync(ct);
                // Проверяем, что вложенный файл вообще читается как БД.
                await ExecAsync(connection, "SELECT count(*) FROM old.sqlite_master", ct);
                attached = true;
            }
            catch (SqliteException ex)
            {
                logger.LogError("Резервную копию не удалось открыть как БД ({Message}) — данные не переносятся, " +
                                "сервис начнёт с пустой схемой; копия сохранена для ручного восстановления.", ex.Message);
            }

            if (attached)
            {
                var oldTables = await SqliteTablesAsync(connection, "old", ct);
                foreach (var table in ModelTables(model))
                {
                    if (!oldTables.Contains(table.Name)) continue;
                    results.Add(await CopySqliteTableAsync(connection, table, logger, ct));
                }
                await ExecAsync(connection, "DETACH DATABASE old", ct);
            }
            await ExecAsync(connection, "PRAGMA foreign_keys = ON", ct);
        }

        // 3. Замена: пересобранный файл становится рабочим; оригинал уже сохранён в копии.
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            if (File.Exists(path + suffix)) File.Delete(path + suffix);
        File.Move(rebuilt, path);
        LogSummary(logger, results, backup);
        return (backup, results);
    }

    private static async Task<TableCopy> CopySqliteTableAsync(SqliteConnection c, ModelTable table, ILogger logger, CancellationToken ct)
    {
        var oldColumns = await SqliteColumnsAsync(c, "old", table.Name, ct);
        var target = table.Columns;
        var names = new List<string>();
        var values = new List<string>();
        foreach (var col in target)
        {
            if (oldColumns.Contains(col.Name))
            {
                names.Add(Q(col.Name));
                values.Add(col.Required ? $"COALESCE({Q(col.Name)}, {SqliteDefault(col)})" : Q(col.Name));
            }
            else if (col.Required && !col.HasDefault)
            {
                names.Add(Q(col.Name));
                values.Add(SqliteDefault(col));
            }
        }
        if (names.Count == 0) return new TableCopy(table.Name, 0, 0, "нет общих столбцов");

        // Старые данные важнее строк, которые могли создать миграции (справочники): очищаем таблицу перед переносом.
        await ExecAsync(c, $"DELETE FROM main.{Q(table.Name)}", ct);
        var insert = $"INSERT OR IGNORE INTO main.{Q(table.Name)} ({string.Join(", ", names)}) SELECT {string.Join(", ", values)} FROM old.{Q(table.Name)}";
        try
        {
            var copied = await ExecAsync(c, insert, ct);
            var total = await ScalarAsync(c, $"SELECT count(*) FROM old.{Q(table.Name)}", ct);
            return new TableCopy(table.Name, copied, Math.Max(0, total - copied), null);
        }
        catch (SqliteException ex)
        {
            // Повреждённые страницы: копируем построчно по rowid, пропуская нечитаемые строки.
            logger.LogWarning("{Table}: массовый перенос не удался ({Message}), перенос построчно.", table.Name, ex.Message);
            return await CopySqliteRowByRowAsync(c, table, insert, ex.Message, ct);
        }
    }

    private static async Task<TableCopy> CopySqliteRowByRowAsync(SqliteConnection c, ModelTable table, string insert, string reason,
        CancellationToken ct)
    {
        List<long> rowIds = [];
        try
        {
            await using var list = c.CreateCommand();
            list.CommandText = $"SELECT rowid FROM old.{Q(table.Name)}";
            await using var reader = await list.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) rowIds.Add(reader.GetInt64(0));
        }
        catch (SqliteException)
        {
            // Даже список строк не читается целиком — берём то, что успели прочитать.
        }

        long copied = 0, skipped = 0;
        foreach (var id in rowIds)
        {
            try
            {
                await using var one = c.CreateCommand();
                one.CommandText = insert + " WHERE rowid = $id";
                one.Parameters.AddWithValue("$id", id);
                copied += await one.ExecuteNonQueryAsync(ct);
            }
            catch (SqliteException) { skipped++; }
        }
        return new TableCopy(table.Name, copied, skipped, "построчно: " + reason);
    }

    private static string SqliteDefault(ModelColumn col) => col.ClrType switch
    {
        var t when t == typeof(string) => "''",
        var t when t == typeof(Guid) => "'00000000-0000-0000-0000-000000000000'",
        var t when t == typeof(DateTime) || t == typeof(DateTimeOffset) => "'0001-01-01 00:00:00'",
        var t when t == typeof(TimeSpan) => "'00:00:00'",
        var t when t == typeof(byte[]) => "X''",
        _ => "0"
    };

    // ---------- PostgreSQL ----------

    private const string RebuildSchema = "tsl_rebuild";

    private static async Task<(string, IReadOnlyList<TableCopy>)> RebuildPostgresAsync(string connectionString, IModel model, ILogger logger,
        string reason, CancellationToken ct)
    {
        await using var c = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false }.ConnectionString);
        await c.OpenAsync(ct);
        var current = (string)(await new NpgsqlCommand("SELECT current_schema()", c).ExecuteScalarAsync(ct))!;
        var backup = $"tsl_backup_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
        logger.LogError("Схема БД требует пересборки ({Reason}). Текущая схема {Schema} сохранится как {Backup}.", reason, current, backup);

        // 1. Новая схема текущей версии — штатными миграциями (search_path направлен в неё).
        await PgExecAsync(c, $"DROP SCHEMA IF EXISTS {Q(RebuildSchema)} CASCADE; CREATE SCHEMA {Q(RebuildSchema)}", ct);
        var rebuildCs = new NpgsqlConnectionStringBuilder(connectionString) { SearchPath = RebuildSchema, Pooling = false }.ConnectionString;
        await using (var fresh = new PostgresAuthDbContext(new DbContextOptionsBuilder<PostgresAuthDbContext>().UseNpgsql(rebuildCs).Options))
            await fresh.Database.MigrateAsync(ct);

        // 2. Перенос: одна транзакция, каждая строка/таблица под savepoint — ошибка не обрывает перенос остального.
        var results = new List<TableCopy>();
        var oldTables = await PgTablesAsync(c, current, ct);
        var tables = ModelTables(model).Where(t => oldTables.Contains(t.Name)).ToList();
        await using (var tx = await c.BeginTransactionAsync(ct))
        {
            if (tables.Count > 0)
                await PgExecAsync(c, "TRUNCATE " + string.Join(", ", tables.Select(t => $"{Q(RebuildSchema)}.{Q(t.Name)}")) + " CASCADE", ct, tx);
            foreach (var table in tables)
                results.Add(await CopyPostgresTableAsync(c, tx, current, table, logger, ct));
            await tx.CommitAsync(ct);
        }

        // 3. Замена схем одной транзакцией: старая остаётся резервной копией.
        await using (var swap = await c.BeginTransactionAsync(ct))
        {
            await PgExecAsync(c, $"ALTER SCHEMA {Q(current)} RENAME TO {Q(backup)}; ALTER SCHEMA {Q(RebuildSchema)} RENAME TO {Q(current)}", ct, swap);
            await swap.CommitAsync(ct);
        }
        NpgsqlConnection.ClearAllPools();
        LogSummary(logger, results, backup);
        return (backup, results);
    }

    private static async Task<TableCopy> CopyPostgresTableAsync(NpgsqlConnection c, NpgsqlTransaction tx, string oldSchema, ModelTable table,
        ILogger logger, CancellationToken ct)
    {
        var oldColumns = await PgColumnsAsync(c, tx, oldSchema, table.Name, ct);
        var newColumns = await PgColumnsAsync(c, tx, RebuildSchema, table.Name, ct);
        var names = new List<string>();
        var values = new List<string>();
        foreach (var col in table.Columns)
        {
            if (!newColumns.TryGetValue(col.Name, out var type)) continue;
            if (oldColumns.ContainsKey(col.Name))
            {
                // Текст — универсальный мост между типами (например, text → uuid, integer → bigint).
                var cast = oldColumns[col.Name] == type ? Q(col.Name) : $"CAST(CAST({Q(col.Name)} AS text) AS {type})";
                names.Add(Q(col.Name));
                values.Add(col.Required ? $"COALESCE({cast}, {PgDefault(col, type)})" : cast);
            }
            else if (col.Required && !col.HasDefault)
            {
                names.Add(Q(col.Name));
                values.Add(PgDefault(col, type));
            }
        }
        if (names.Count == 0) return new TableCopy(table.Name, 0, 0, "нет общих столбцов");

        var insert = $"INSERT INTO {Q(RebuildSchema)}.{Q(table.Name)} ({string.Join(", ", names)}) " +
                     $"SELECT {string.Join(", ", values)} FROM {Q(oldSchema)}.{Q(table.Name)}";
        long total = await PgScalarAsync(c, tx, $"SELECT count(*) FROM {Q(oldSchema)}.{Q(table.Name)}", ct);
        await PgExecAsync(c, "SAVEPOINT t", ct, tx);
        try
        {
            var copied = await PgExecAsync(c, insert + " ON CONFLICT DO NOTHING", ct, tx);
            await PgExecAsync(c, "RELEASE SAVEPOINT t", ct, tx);
            await ResetSequencesAsync(c, tx, table, ct);
            return new TableCopy(table.Name, copied, total - copied, null);
        }
        catch (PostgresException ex)
        {
            await PgExecAsync(c, "ROLLBACK TO SAVEPOINT t", ct, tx);
            logger.LogWarning("{Table}: массовый перенос не удался ({Message}), перенос построчно.", table.Name, ex.MessageText);
        }

        // Построчно: строки, нарушающие ограничения или не приводимые к новым типам, пропускаются.
        var ctids = new List<string>();
        await using (var list = new NpgsqlCommand($"SELECT ctid::text FROM {Q(oldSchema)}.{Q(table.Name)}", c, tx))
        await using (var reader = await list.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) ctids.Add(reader.GetString(0));
        long ok = 0, skipped = 0;
        foreach (var ctid in ctids)
        {
            await PgExecAsync(c, "SAVEPOINT r", ct, tx);
            try
            {
                await using var one = new NpgsqlCommand(insert + " WHERE ctid = @ctid::tid ON CONFLICT DO NOTHING", c, tx);
                one.Parameters.AddWithValue("ctid", ctid);
                ok += await one.ExecuteNonQueryAsync(ct);
                await PgExecAsync(c, "RELEASE SAVEPOINT r", ct, tx);
            }
            catch (PostgresException)
            {
                await PgExecAsync(c, "ROLLBACK TO SAVEPOINT r", ct, tx);
                skipped++;
            }
        }
        await ResetSequencesAsync(c, tx, table, ct);
        return new TableCopy(table.Name, ok, skipped, "построчно");
    }

    /// <summary>Счётчики автоинкрементных столбцов продолжают с максимума перенесённых значений.</summary>
    private static async Task ResetSequencesAsync(NpgsqlConnection c, NpgsqlTransaction tx, ModelTable table, CancellationToken ct)
    {
        foreach (var col in table.Columns)
        {
            await using var find = new NpgsqlCommand("SELECT pg_get_serial_sequence(@t, @c)", c, tx);
            find.Parameters.AddWithValue("t", $"{Q(RebuildSchema)}.{Q(table.Name)}");
            find.Parameters.AddWithValue("c", col.Name);
            if (await find.ExecuteScalarAsync(ct) is not string sequence) continue;
            await PgExecAsync(c,
                $"SELECT setval('{sequence.Replace("'", "''")}', COALESCE((SELECT MAX({Q(col.Name)}) FROM {Q(RebuildSchema)}.{Q(table.Name)}), 1), " +
                $"(SELECT count(*) > 0 FROM {Q(RebuildSchema)}.{Q(table.Name)}))", ct, tx);
        }
    }

    private static string PgDefault(ModelColumn col, string type) => col.ClrType switch
    {
        var t when t == typeof(string) => "''",
        var t when t == typeof(bool) => "false",
        var t when t == typeof(Guid) => "'00000000-0000-0000-0000-000000000000'::uuid",
        var t when t == typeof(DateTime) || t == typeof(DateTimeOffset) => $"'0001-01-01 00:00:00'::{type}",
        var t when t == typeof(TimeSpan) => "'0'::interval",
        var t when t == typeof(byte[]) => "''::bytea",
        _ => $"0::{type}"
    };

    // ====================================================================================
    // Модель и метаданные
    // ====================================================================================

    private sealed record ModelColumn(string Name, Type ClrType, bool Required, bool HasDefault);

    private sealed record ModelTable(string Name, List<ModelColumn> Columns);

    /// <summary>Таблицы и столбцы модели EF (то, что должно быть в рабочей схеме).</summary>
    private static List<ModelTable> ModelTables(IModel model) => model.GetEntityTypes()
        .Where(e => e.GetTableName() is not null && e.GetViewName() is null)
        .GroupBy(e => e.GetTableName()!)
        .Select(g =>
        {
            var store = StoreObjectIdentifier.Table(g.Key, g.First().GetSchema());
            var columns = g.SelectMany(e => e.GetProperties())
                .Select(p =>
                {
                    var mapping = p.GetRelationalTypeMapping();
                    var type = mapping.Converter?.ProviderClrType ?? mapping.ClrType;
                    return new ModelColumn(p.GetColumnName(store)!, Nullable.GetUnderlyingType(type) ?? type,
                        !p.IsColumnNullable(store), p.GetDefaultValueSql() is not null || p.GetDefaultValue() is not null
                                                     || p.ValueGenerated != Microsoft.EntityFrameworkCore.Metadata.ValueGenerated.Never && p.IsPrimaryKey());
                })
                .DistinctBy(c => c.Name)
                .ToList();
            return new ModelTable(g.Key, columns);
        })
        .ToList()
        .Pipe(tables => OrderByDependencies(model, tables));

    /// <summary>Порядок «сначала главные таблицы, потом зависимые» — иначе в PostgreSQL строки отсекут внешние ключи.</summary>
    private static List<ModelTable> OrderByDependencies(IModel model, List<ModelTable> tables)
    {
        var principals = model.GetEntityTypes().Where(e => e.GetTableName() is not null)
            .GroupBy(e => e.GetTableName()!)
            .ToDictionary(g => g.Key, g => g.SelectMany(e => e.GetForeignKeys())
                .Select(fk => fk.PrincipalEntityType.GetTableName()).Where(t => t is not null && t != g.Key).Select(t => t!).ToHashSet());
        var byName = tables.ToDictionary(t => t.Name);
        var ordered = new List<ModelTable>();
        var visiting = new HashSet<string>();
        void Visit(string name)
        {
            if (!byName.ContainsKey(name) || ordered.Contains(byName[name]) || !visiting.Add(name)) return;
            foreach (var p in principals.GetValueOrDefault(name, [])) Visit(p);
            ordered.Add(byName[name]);
        }
        foreach (var name in byName.Keys.Order(StringComparer.Ordinal)) Visit(name);
        return ordered;
    }

    private static async Task<HashSet<string>> ExistingTablesAsync(AuthDbContext db, CancellationToken ct)
    {
        var connection = db.Database.GetDbConnection();
        var wasOpen = connection.State == System.Data.ConnectionState.Open;
        if (!wasOpen) await connection.OpenAsync(ct);
        try
        {
            return db.Database.IsSqlite()
                ? await SqliteTablesAsync((SqliteConnection)connection, "main", ct)
                : await PgTablesAsync((NpgsqlConnection)connection, null, ct);
        }
        finally
        {
            if (!wasOpen) await connection.CloseAsync();
        }
    }

    private static async Task<Dictionary<string, string>> ColumnsAsync(AuthDbContext db, string table, CancellationToken ct)
    {
        var connection = db.Database.GetDbConnection();
        var wasOpen = connection.State == System.Data.ConnectionState.Open;
        if (!wasOpen) await connection.OpenAsync(ct);
        try
        {
            if (db.Database.IsSqlite())
                return (await SqliteColumnsAsync((SqliteConnection)connection, "main", table, ct)).ToDictionary(c => c, _ => "");
            return await PgColumnsAsync((NpgsqlConnection)connection, null, null, table, ct);
        }
        finally
        {
            if (!wasOpen) await connection.CloseAsync();
        }
    }

    private static async Task<HashSet<string>> SqliteTablesAsync(SqliteConnection c, string schema, CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        await using var command = c.CreateCommand();
        command.CommandText = $"SELECT name FROM {schema}.sqlite_master WHERE type = 'table'";
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) set.Add(reader.GetString(0));
        return set;
    }

    private static async Task<HashSet<string>> SqliteColumnsAsync(SqliteConnection c, string schema, string table, CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        await using var command = c.CreateCommand();
        command.CommandText = $"SELECT name FROM pragma_table_info($t, $s)";
        command.Parameters.AddWithValue("$t", table);
        command.Parameters.AddWithValue("$s", schema);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) set.Add(reader.GetString(0));
        return set;
    }

    private static async Task<HashSet<string>> PgTablesAsync(NpgsqlConnection c, string? schema, CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        await using var command = new NpgsqlCommand(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = COALESCE(@s, current_schema()) AND table_type = 'BASE TABLE'", c);
        command.Parameters.AddWithValue("s", (object?)schema ?? DBNull.Value).NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Text;
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) set.Add(reader.GetString(0));
        return set;
    }

    /// <summary>Столбцы таблицы PostgreSQL: имя → полный тип (format_type, например "timestamp with time zone").</summary>
    private static async Task<Dictionary<string, string>> PgColumnsAsync(NpgsqlConnection c, NpgsqlTransaction? tx, string? schema, string table,
        CancellationToken ct)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        await using var command = new NpgsqlCommand("""
            SELECT a.attname, format_type(a.atttypid, a.atttypmod)
            FROM pg_attribute a
            JOIN pg_class t ON t.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = COALESCE(@s, current_schema()) AND t.relname = @t AND a.attnum > 0 AND NOT a.attisdropped
            """, c, tx);
        command.Parameters.AddWithValue("s", (object?)schema ?? DBNull.Value).NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Text;
        command.Parameters.AddWithValue("t", table);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) map[reader.GetString(0)] = reader.GetString(1);
        return map;
    }

    // ====================================================================================
    // Мелочи
    // ====================================================================================

    private static void LogSummary(ILogger logger, List<TableCopy> results, string backup)
    {
        foreach (var r in results.Where(r => r.Skipped > 0 || r.Note is not null))
            logger.LogWarning("{Table}: перенесено {Copied}, пропущено {Skipped}{Note}.", r.Table, r.Copied, r.Skipped,
                r.Note is null ? "" : $" ({r.Note})");
        logger.LogWarning("Схема БД пересобрана: перенесено {Rows} записей в {Tables} таблицах, пропущено {Skipped}. Резервная копия: {Backup}.",
            results.Sum(r => r.Copied), results.Count, results.Sum(r => r.Skipped), backup);
    }

    private static TOut Pipe<TIn, TOut>(this TIn value, Func<TIn, TOut> f) => f(value);

    private static string Q(string identifier) => "\"" + identifier.Replace("\"", "\"\"") + "\"";

    private static async Task<int> ExecAsync(SqliteConnection c, string sql, CancellationToken ct)
    {
        await using var command = c.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task<long> ScalarAsync(DbConnection c, string sql, CancellationToken ct)
    {
        await using var command = c.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }

    private static async Task<int> PgExecAsync(NpgsqlConnection c, string sql, CancellationToken ct, NpgsqlTransaction? tx = null)
    {
        await using var command = new NpgsqlCommand(sql, c, tx);
        return await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task<long> PgScalarAsync(NpgsqlConnection c, NpgsqlTransaction tx, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, c, tx);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }
}
