namespace TslAuth.Infrastructure;

/// <summary>
/// Консольные команды обслуживания, работают напрямую с БД (веб-вход не нужен):
///   tslauth admin reset-password [логин] [--password P]
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

            default:
                Console.WriteLine("""
                    Команды:
                      admin reset-password [логин] [--password <пароль>]
                          Создать/восстановить администратора: разблокировать, сменить пароль
                          (без --password будет сгенерирован), выдать роль administrator.
                    """);
                return command == "help" ? 0 : 1;
        }
    }
}
