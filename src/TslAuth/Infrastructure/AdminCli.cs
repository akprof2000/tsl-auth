namespace TslAuth.Infrastructure;

/// <summary>
/// Консольные команды обслуживания, работают напрямую с БД (веб-вход не нужен):
///   dotnet /app/TslAuth.dll admin reset-password [логин] [--password P]
/// (в контейнере: docker exec -it tsl-auth dotnet /app/TslAuth.dll admin reset-password admin)
///   dotnet /app/TslAuth.dll admin migrate-to-postgres --target "Host=...;Database=..." [--overwrite]
/// Переносит все данные одиночного режима (SQLite) в PostgreSQL — см. <see cref="PostgresMigration"/>.
/// Восстанавливает доступ администратора: создаёт/активирует пользователя, разблокирует,
/// задаёт пароль (или генерирует), назначает роль administrator и отзывает его сессии.
/// Program.cs вызывает команду после StartupInitializer (схема и данные уже готовы) вместо запуска веб-сервера.
/// </summary>
public static class AdminCli
{
    /// <summary>Аргументы командной строки — служебная команда, а не запуск сервиса.</summary>
    public static bool IsCliCommand(string[] args) => args.Length > 0 && args[0] == "admin";

    /// <summary>Выполняет команду и возвращает код выхода процесса (0 — успех).</summary>
    public static async Task<int> RunAsync(IServiceProvider services, string[] args)
    {
        var command = args.Length > 1 ? args[1] : "help";
        switch (command)
        {
            case "reset-password":
            {
                var positional = args.Skip(2).TakeWhile(a => !a.StartsWith("--")).ToList();
                var userName = positional.FirstOrDefault() ?? "admin";
                var passwordIndex = Array.IndexOf(args, "--password");
                var password = passwordIndex > 0 && passwordIndex + 1 < args.Length ? args[passwordIndex + 1] : null;

                using var scope = services.CreateScope();
                try
                {
                    var generated = await StartupInitializer.EnsureAdministratorAsync(scope.ServiceProvider, userName, password, null, default);
                    Console.WriteLine($"Доступ администратора '{userName}' восстановлен.");
                    if (generated is not null) Console.WriteLine($"Новый пароль: {generated}");
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Ошибка: {ex.Message}");
                    return 1;
                }
            }

            case "migrate-to-postgres":
            {
                // Строку подключения лучше передавать переменной окружения — так пароль не попадёт в историю shell.
                var targetIndex = Array.IndexOf(args, "--target");
                var target = targetIndex > 0 && targetIndex + 1 < args.Length
                    ? args[targetIndex + 1]
                    : Environment.GetEnvironmentVariable("TARGET_DB_CONNECTION_STRING");
                if (string.IsNullOrWhiteSpace(target))
                {
                    Console.Error.WriteLine("Укажите PostgreSQL: --target \"Host=...;Database=...;Username=...;Password=...\" " +
                                            "или переменную TARGET_DB_CONNECTION_STRING.");
                    return 1;
                }

                using var scope = services.CreateScope();
                var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("TslAuth.Migration");
                try
                {
                    var db = scope.ServiceProvider.GetRequiredService<Data.AuthDbContext>();
                    var results = await PostgresMigration.RunAsync(db, target, args.Contains("--overwrite"), logger);
                    Console.WriteLine();
                    Console.WriteLine($"{"Таблица",-32} {"SQLite",10} {"PostgreSQL",10}  Содержимое");
                    foreach (var r in results)
                        Console.WriteLine($"{r.Table,-32} {r.SourceRows,10} {r.TargetRows,10}  {(r.Ok ? "совпадает" : "РАЗЛИЧАЕТСЯ")}");
                    Console.WriteLine();
                    Console.WriteLine($"Перенос завершён: {results.Count} таблиц, {results.Sum(r => r.TargetRows)} записей, все совпадают.");
                    Console.WriteLine("Дальше: запустите узлы PostgreSQL с ТЕМ ЖЕ мастер-ключом — ENCRYPTION_MASTER_KEY = содержимое");
                    Console.WriteLine("файла master.key из тома данных одиночного режима (данные перенесены зашифрованными).");
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Ошибка: {ex.Message}");
                    return 1;
                }
            }

            default:
                Console.WriteLine("""
                    Команды:
                      admin reset-password [логин] [--password <пароль>]
                          Создать/восстановить администратора: разблокировать, сменить пароль
                          (без --password будет сгенерирован), выдать роль administrator.
                      admin migrate-to-postgres [--target <строка подключения>] [--overwrite]
                          Перенести все данные из SQLite (одиночный режим) в PostgreSQL со сверкой
                          числа записей и содержимого каждой таблицы. Строку подключения можно задать
                          переменной TARGET_DB_CONNECTION_STRING. --overwrite очищает непустой приёмник.
                    """);
                return command == "help" ? 0 : 1;
        }
    }
}
