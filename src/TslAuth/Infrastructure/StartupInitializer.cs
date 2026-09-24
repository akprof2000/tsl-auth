using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using TslAuth.Data;
using TslAuth.Options;
using TslAuth.Security;
using TslAuth.Services;

namespace TslAuth.Infrastructure;

/// <summary>
/// Миграции, ключи и начальные данные. При нескольких экземплярах на PostgreSQL выполнение
/// сериализуется advisory-lock'ом, чтобы экземпляры не создавали данные одновременно.
/// Вызывается из Program.cs до запуска веб-сервера (и перед CLI-командами admin).
/// </summary>
public static class StartupInitializer
{
    private const long AdvisoryLockKey = 0x75_4C_41_75_74_68; // "TSLAuth"

    /// <summary>Полная инициализация: блокировка (PostgreSQL) → миграции → ключи токенов → начальные данные.</summary>
    public static async Task RunAsync(IServiceProvider services, CancellationToken ct = default)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<AuthDbContext>();
        var dbOptions = sp.GetRequiredService<IOptions<DatabaseOptions>>().Value;
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("TslAuth.Startup");

        // Блокировка держится до конца метода (await using): остальные экземпляры ждут,
        // пока первый не закончит миграции и сидинг, и затем видят уже готовую БД.
        await using var @lock = dbOptions.IsPostgres ? await AcquirePostgresLockAsync(dbOptions.ConnectionString!, logger, ct) : null;

        // SQLite не создаёт каталоги сама — готовим папку под файл БД.
        if (!dbOptions.IsPostgres)
        {
            var dataSource = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(db.Database.GetConnectionString()).DataSource;
            var directory = Path.GetDirectoryName(Path.GetFullPath(dataSource));
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        }

        await MigrateAsync(db, logger, ct);
        if (!dbOptions.IsPostgres)
        {
            // WAL: чтения не блокируются записью (важно при параллельной выдаче токенов). Режим сохраняется в файле БД.
            await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", ct);
            await db.Database.ExecuteSqlRawAsync("PRAGMA synchronous=NORMAL;", ct);
        }
        // Ключи подписи/шифрования токенов нужны OpenIddict до первого запроса (см. ServiceSetup).
        await sp.GetRequiredService<ServerKeyRing>().LoadOrCreateAsync(db, ct);
        await SeedAsync(sp, logger, ct);
    }

    /// <summary>
    /// Автоматическое обновление схемы БД до версии, с которой собран сервис.
    /// Миграции применяются последовательно, каждая в своей транзакции; повторный запуск безопасен.
    /// </summary>
    internal static async Task MigrateAsync(AuthDbContext db, ILogger logger, CancellationToken ct)
    {
        var known = db.Database.GetMigrations().ToList();
        // На пустой БД таблицы истории ещё нет — не запрашиваем её (иначе EF пишет в лог ложную ошибку).
        var history = Microsoft.EntityFrameworkCore.Infrastructure.AccessorExtensions
            .GetService<Microsoft.EntityFrameworkCore.Migrations.IHistoryRepository>(db);
        var applied = await history.ExistsAsync(ct) ? (await db.Database.GetAppliedMigrationsAsync(ct)).ToList() : [];
        var pending = known.Except(applied).ToList();
        var target = known.LastOrDefault() ?? "—";
        var current = applied.LastOrDefault() ?? "пустая БД";

        // Защита от отката образа на старую версию: схема новее, чем знает этот сервис.
        var unknown = applied.Except(known).ToList();
        if (unknown.Count > 0)
            throw new InvalidOperationException(
                $"Версия БД ({current}) новее версии сервиса ({target}). Неизвестные миграции: {string.Join(", ", unknown)}. " +
                "Запустите более новую версию сервиса.");

        if (pending.Count == 0)
        {
            logger.LogInformation("Схема БД актуальна: {Version}.", current);
            return;
        }

        logger.LogWarning("Обновление схемы БД: {Current} → {Target} (миграций: {Count}: {List}).",
            current, target, pending.Count, string.Join(", ", pending));
        await db.Database.MigrateAsync(ct);
        logger.LogInformation("Схема БД обновлена до {Target}.", target);
    }

    /// <summary>
    /// Берёт сессионный pg_advisory_lock на отдельном соединении и возвращает это соединение:
    /// пока оно открыто, другие экземпляры блокируются на том же ключе.
    /// </summary>
    private static async Task<NpgsqlConnection> AcquirePostgresLockAsync(string connectionString, ILogger logger, CancellationToken ct)
    {
        // БД может стартовать позже сервиса (docker compose) — ждём её доступности.
        for (var attempt = 1; ; attempt++)
        {
            var connection = new NpgsqlConnection(connectionString);
            try
            {
                await EnsurePostgresDatabaseAsync(connectionString, logger, ct);
                await connection.OpenAsync(ct);
                await using var command = new NpgsqlCommand("SELECT pg_advisory_lock(@key)", connection);
                command.Parameters.AddWithValue("key", AdvisoryLockKey);
                await command.ExecuteNonQueryAsync(ct);
                return connection; // блокировка снимается при закрытии соединения
            }
            catch (NpgsqlException ex) when (attempt < 30)
            {
                await connection.DisposeAsync();
                logger.LogWarning("PostgreSQL недоступен ({Message}), попытка {Attempt}/30...", ex.Message, attempt);
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
    }

    /// <summary>Создаёт базу данных, если её ещё нет (подключение к служебной БД "postgres").</summary>
    internal static async Task EnsurePostgresDatabaseAsync(string connectionString, ILogger logger, CancellationToken ct)
    {
        var target = new NpgsqlConnectionStringBuilder(connectionString);
        var databaseName = target.Database ?? throw new InvalidOperationException("В строке подключения не указан Database.");
        var maintenance = new NpgsqlConnectionStringBuilder(connectionString) { Database = "postgres", Pooling = false };

        await using var connection = new NpgsqlConnection(maintenance.ConnectionString);
        await connection.OpenAsync(ct);

        // CREATE DATABASE не поддерживает IF NOT EXISTS — сначала проверяем наличие.
        await using (var exists = new NpgsqlCommand("SELECT 1 FROM pg_database WHERE datname = @name", connection))
        {
            exists.Parameters.AddWithValue("name", databaseName);
            if (await exists.ExecuteScalarAsync(ct) is not null) return;
        }

        try
        {
            // Имя БД нельзя передать параметром — экранируем как идентификатор (удвоение кавычек).
            var quoted = "\"" + databaseName.Replace("\"", "\"\"") + "\"";
            await using var create = new NpgsqlCommand($"CREATE DATABASE {quoted} ENCODING 'UTF8'", connection);
            await create.ExecuteNonQueryAsync(ct);
            logger.LogWarning("База данных '{Database}' не найдена и была создана.", databaseName);
        }
        catch (PostgresException ex) when (ex.SqlState is PostgresErrorCodes.DuplicateDatabase or PostgresErrorCodes.UniqueViolation)
        {
            // Параллельный экземпляр успел создать её раньше — это нормально
            // (при одновременном CREATE DATABASE PostgreSQL может вернуть 23505 вместо 42P04).
            logger.LogInformation("База данных '{Database}' создана параллельным экземпляром.", databaseName);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.InsufficientPrivilege)
        {
            throw new InvalidOperationException(
                $"База '{databaseName}' не существует, а у пользователя '{target.Username}' нет права CREATEDB. " +
                "Выдайте право (ALTER ROLE ... CREATEDB) или создайте базу вручную.", ex);
        }
    }

    /// <summary>
    /// Идемпотентный сидинг: системное приложение, его scope, PAT-клиент, матрица доступа админки,
    /// первый администратор и (опционально) клиент Admin API. Создаётся только то, чего ещё нет.
    /// </summary>
    private static async Task SeedAsync(IServiceProvider sp, ILogger logger, CancellationToken ct)
    {
        var apps = sp.GetRequiredService<ApplicationService>();
        var access = sp.GetRequiredService<AccessService>();
        var db = sp.GetRequiredService<AuthDbContext>();
        var bootstrap = sp.GetRequiredService<IOptions<BootstrapOptions>>().Value;

        // 1. Системное приложение и его матрица доступа.
        if (await apps.GetAsync(SystemApp.ClientId, ct) is null)
        {
            await apps.CreateAsync(new ApplicationInput(SystemApp.ClientId, "TSL Auth — администрирование",
                "public", null, null, null, null), isSystem: true, ct: ct);
        }

        var scopes = sp.GetRequiredService<OpenIddict.Abstractions.IOpenIddictScopeManager>();
        if (await scopes.FindByNameAsync(SystemApp.AppApiScope, ct) is null)
        {
            await scopes.CreateAsync(new OpenIddict.Abstractions.OpenIddictScopeDescriptor
            {
                Name = SystemApp.AppApiScope,
                DisplayName = "TSL Auth — App API (самоуправление приложений)",
                Resources = { SystemApp.AppApiScope }
            }, ct);
        }

        // Системный public-клиент для обмена персональных токенов (PAT) на JWT.
        var oidcApps = sp.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
        if (await oidcApps.FindByClientIdAsync(PatService.PatClientId, ct) is null)
        {
            await oidcApps.CreateAsync(new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
            {
                ClientId = PatService.PatClientId,
                DisplayName = "Персональные токены доступа (PAT)",
                ClientType = OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Public,
                Permissions =
                {
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.GrantType + Controllers.AuthorizationController.PatGrantType
                },
                Properties = { ["tsl_system"] = System.Text.Json.JsonSerializer.SerializeToElement(true) }
            }, ct);
        }

        var matrix = await access.GetMatrixAsync(SystemApp.ClientId, ct);
        foreach (var (name, description) in new[]
                 {
                     (SystemApp.ViewPermission, "Просмотр приложений, пользователей и сессий"),
                     (SystemApp.ManagePermission, "Изменение приложений, матриц доступа, пользователей и сессий"),
                     (SystemApp.EventsPermission, "Лента событий (long-polling/SSE) и управление подписками-вебхуками"),
                     (SystemApp.PasswordResetPermission, "Бот: привязка мессенджера и сброс пароля пользователя"),
                     (SystemApp.UserLockPermission, "Бот: блокировка и разблокировка учётной записи по команде"),
                     (SystemApp.PasswordForcePermission, "Бот: принудительная смена пароля по команде")
                 })
        {
            if (matrix.Permissions.All(p => p.Name != name))
                await access.AddPermissionAsync(SystemApp.ClientId, name, description, ct);
        }

        // Роли системного приложения. Для существующих установок недостающие разрешения
        // добавляются к ролям при обновлении (например, "events" появилось в новой версии),
        // а пустое название для пользователей заполняется (изменённое администратором не трогается).
        foreach (var (role, displayName, description, permissions) in new[]
                 {
                     (SystemApp.AdministratorRole, "Администратор", "Полный доступ к администрированию",
                         new[] { SystemApp.ViewPermission, SystemApp.ManagePermission, SystemApp.EventsPermission }),
                     (SystemApp.AuditorRole, "Аудитор", "Только просмотр", new[] { SystemApp.ViewPermission }),
                     (SystemApp.NotifierRole, "Бот уведомлений", "Бот-уведомитель: только события", new[] { SystemApp.EventsPermission }),
                     (SystemApp.ResetBotRole, "Бот сброса пароля", "Бот сброса пароля (мессенджер)", new[] { SystemApp.PasswordResetPermission }),
                     (SystemApp.SecurityBotRole, "Бот безопасности", "Бот мессенджера: сброс пароля, блокировка, принудительная смена пароля",
                         new[] { SystemApp.PasswordResetPermission, SystemApp.UserLockPermission, SystemApp.PasswordForcePermission }),
                     (SystemApp.SecurityOfficerRole, "Офицер безопасности", "Через бота блокирует чужие учётные записи и требует смену пароля",
                         new[] { SystemApp.UserLockPermission, SystemApp.PasswordForcePermission })
                 })
        {
            var existing = matrix.Roles.FirstOrDefault(r => r.Name == role);
            if (existing is null)
            {
                await access.AddRoleAsync(SystemApp.ClientId, role, description, permissions, ct, displayName: displayName);
                continue;
            }
            if (permissions.Except(existing.Permissions).Any())
                await access.SetRolePermissionsAsync(SystemApp.ClientId, role, existing.Permissions.Union(permissions), ct);
            if (existing.DisplayName is null)
                await access.UpdateRoleAsync(SystemApp.ClientId, role, displayName, existing.Description, ct, system: true);
        }

        // 2. Первый администратор — только если в системе ещё нет ни одного.
        var hasAdmin = await db.AccessRoleAssignments.AnyAsync(a =>
            a.SubjectType == SubjectType.User && a.Role.ClientId == SystemApp.ClientId && a.Role.Name == SystemApp.AdministratorRole, ct);
        if (!hasAdmin)
        {
            string? password;
            try
            {
                password = await EnsureAdministratorAsync(sp, bootstrap.AdminUserName, bootstrap.AdminPassword, bootstrap.AdminEmail, ct);
            }
            catch (AdminException ex)
            {
                throw new InvalidOperationException(
                    $"Не удалось создать первого администратора '{bootstrap.AdminUserName}': {ex.Message} " +
                    "Проверьте Bootstrap:AdminPassword (политика паролей) или оставьте его пустым — пароль будет сгенерирован.", ex);
            }
            if (password is not null)
                logger.LogWarning(
                    "Создан администратор '{User}' с временным паролем: {Password}  — смените его после первого входа.",
                    bootstrap.AdminUserName, password);
            else
                logger.LogInformation("Создан администратор '{User}' (пароль из Bootstrap:AdminPassword).", bootstrap.AdminUserName);
        }

        // 3. Опциональный клиент для внешнего Admin API.
        if (!string.IsNullOrWhiteSpace(bootstrap.AdminApiClientId) && !string.IsNullOrWhiteSpace(bootstrap.AdminApiClientSecret) &&
            await apps.GetAsync(bootstrap.AdminApiClientId, ct) is null)
        {
            await apps.CreateAsync(new ApplicationInput(bootstrap.AdminApiClientId, "Admin API client", "confidential",
                null, null, [AppGrantTypes.ClientCredentials], [SystemApp.ClientId]), secret: bootstrap.AdminApiClientSecret, ct: ct);
            await access.AssignAsync(SubjectType.Client, bootstrap.AdminApiClientId,
                new RoleRef(SystemApp.ClientId, SystemApp.AdministratorRole), ct);
            logger.LogInformation("Создан клиент Admin API '{ClientId}'.", bootstrap.AdminApiClientId);
        }
    }

    /// <summary>
    /// Создаёт (или восстанавливает) администратора: активирует, разблокирует, задаёт пароль, назначает роль.
    /// Используется и при первом запуске, и CLI-командой восстановления доступа.
    /// </summary>
    /// <returns>Сгенерированный пароль, если он не был передан.</returns>
    public static async Task<string?> EnsureAdministratorAsync(IServiceProvider sp, string userName, string? password, string? email,
        CancellationToken ct)
    {
        var users = sp.GetRequiredService<UserService>();
        var userManager = sp.GetRequiredService<UserManager<AppUser>>();
        var access = sp.GetRequiredService<AccessService>();

        var generated = string.IsNullOrWhiteSpace(password) ? PasswordGenerator.Generate() : null;
        password = generated ?? password!;

        // Сгенерированный пароль — одноразовый: при первом входе его потребуется сменить.
        var mustChange = generated is not null;

        var existing = await users.FindByLoginAsync(userName);
        if (existing is null)
        {
            await users.CreateAsync(new UserInput(userName, email, "Administrator", true, password, mustChange), ct);
            existing = await users.FindByLoginAsync(userName) ?? throw new InvalidOperationException("Не удалось создать администратора.");
        }
        else
        {
            existing.IsActive = true;
            await userManager.UpdateAsync(existing);
            await users.SetPasswordAsync(existing.Id, password, mustChange, ct);
        }

        await access.AssignAsync(SubjectType.User, existing.Id.ToString(),
            new RoleRef(SystemApp.ClientId, SystemApp.AdministratorRole), ct);
        return generated;
    }
}

/// <summary>
/// Генератор временных паролей (первый администратор, сброс админом, App API).
/// Криптостойкий ГСЧ; алфавит без похожих символов (l/1, O/0) — пароль удобно передать вручную.
/// </summary>
public static class PasswordGenerator
{
    /// <summary>16 символов, гарантированно содержит строчную, заглавную букву, цифру и спецсимвол.</summary>
    public static string Generate()
    {
        const string lower = "abcdefghijkmnpqrstuvwxyz", upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", digits = "23456789", symbols = "!@#$%*-_";
        var all = lower + upper + digits + symbols;
        var chars = new List<char>
        {
            lower[System.Security.Cryptography.RandomNumberGenerator.GetInt32(lower.Length)],
            upper[System.Security.Cryptography.RandomNumberGenerator.GetInt32(upper.Length)],
            digits[System.Security.Cryptography.RandomNumberGenerator.GetInt32(digits.Length)],
            symbols[System.Security.Cryptography.RandomNumberGenerator.GetInt32(symbols.Length)]
        };
        // Добиваем до 16 символов и перемешиваем, чтобы обязательные классы не стояли в начале.
        while (chars.Count < 16) chars.Add(all[System.Security.Cryptography.RandomNumberGenerator.GetInt32(all.Length)]);
        return new string(chars.OrderBy(_ => System.Security.Cryptography.RandomNumberGenerator.GetInt32(int.MaxValue)).ToArray());
    }
}
