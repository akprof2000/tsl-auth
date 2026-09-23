using Microsoft.EntityFrameworkCore;
using TslAuth.Data;
using TslAuth.Options;
using TslAuth.Services;
using Microsoft.Extensions.Options;

namespace TslAuth.Pages.Admin;

/// <summary>
/// Главная страница админки: сводка (число приложений, пользователей, активных сессий),
/// сведения о БД и версии схемы, статус почты и адрес издателя (issuer).
/// Доступ — политика UiView (конвенция для /Admin). Использует AuthDbContext, ApplicationService,
/// SessionService, DatabaseOptions и IEmailSender.
/// </summary>
public sealed class IndexModel(AuthDbContext db, ApplicationService apps, SessionService sessions,
    IOptions<DatabaseOptions> database, IEmailSender email) : AdminPageModel
{
    public int Applications { get; private set; }
    public int Users { get; private set; }
    public int ActiveUsers { get; private set; }
    public int Sessions { get; private set; }
    public string DatabaseProvider => database.Value.IsPostgres ? "PostgreSQL" : "SQLite (встроенная)";
    public string? SchemaVersion { get; private set; }
    public bool EmailConfigured => email.IsConfigured;
    public string Issuer { get; private set; } = "";

    public async Task OnGetAsync(CancellationToken ct)
    {
        Applications = (await apps.ListAsync(ct)).Count;
        Users = await db.Users.CountAsync(ct);
        ActiveUsers = await db.Users.CountAsync(u => u.IsActive, ct);
        Sessions = await sessions.CountActiveAsync(ct);
        // Версия схемы — имя последней применённой миграции EF Core.
        SchemaVersion = (await db.Database.GetAppliedMigrationsAsync(ct)).LastOrDefault();
        // Issuer показывается по текущему запросу — подсказка для настройки клиентов (authority).
        Issuer = $"{Request.Scheme}://{Request.Host}{Request.PathBase}";
    }
}
