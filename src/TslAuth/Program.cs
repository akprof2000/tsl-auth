using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Serilog;
using TslAuth.Api;
using TslAuth.Infrastructure;
using TslAuth.Options;

// `healthcheck` — проверка готовности для Docker HEALTHCHECK. В distroless-образе нет wget/curl и shell,
// поэтому проверку выполняет сам процесс .NET: GET /health/ready на локальном порту, код выхода 0/1.
// Выполняется до построения хоста — без подключения к БД и миграций.
if (args is ["healthcheck", ..])
    return await HealthProbe.RunAsync(args.Length > 1 ? args[1] : null);

// `admin ...` — служебные команды (восстановление доступа администратора).
var isCli = AdminCli.IsCliCommand(args);

// В режиме CLI аргументы не передаются в конфигурацию, иначе "admin ..." разбирались бы как ключи настроек.
var builder = WebApplication.CreateBuilder(isCli ? [] : args);
// appsettings.json из APPSETTINGS_PATH или из каталогов выше каталога приложения (см. ConfigFiles).
var configFiles = ConfigFiles.Attach(builder);
builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);
// Вся регистрация сервисов — в Infrastructure/ServiceSetup.cs.
builder.AddTslAuth(cli: isCli);

var app = builder.Build();
foreach (var source in configFiles)
    app.Logger.LogInformation("Настройки: {Source}.", source);

// Миграции, ключи токенов и начальные данные — до приёма запросов (в кластере — под advisory-lock).
await StartupInitializer.RunAsync(app.Services);

if (isCli)
    return await AdminCli.RunAsync(app.Services, args);

// Порядок middleware важен. Forwarded headers — первыми, чтобы схема/хост/IP клиента были верными
// для HSTS, issuer, CORS и лимитов по IP.
var server = app.Configuration.GetSection(AuthServerOptions.Section).Get<AuthServerOptions>() ?? new AuthServerOptions();
if (server.TrustForwardedHeaders)
    app.UseForwardedHeaders();
// /metrics для Prometheus — сразу после forwarded headers (проверка подсети по реальному адресу), до всего остального.
app.UseTslObservability(app.Services.GetRequiredService<ObservabilityOptions>());

if (!app.Environment.IsDevelopment())
    app.UseExceptionHandler("/Error");
if (server.RequireHttps)
    app.UseHsts();

// Заголовки безопасности и CORS — до статики, чтобы действовали на все ответы, включая preflight.
app.UseSecurityHeaders();
app.UseMiddleware<ClientCorsMiddleware>();
app.UseStaticFiles();
// Одна строка на запрос (метод, путь, код, время) — категория Serilog.AspNetCore.RequestLoggingMiddleware,
// по умолчанию Warning (только ошибки сервера); Information включается в настройках логирования при разборе проблем.
app.UseSerilogRequestLogging(o =>
{
    // Логгер хоста, а не статический Log.Logger (он не используется — см. LoggingSetup).
    o.Logger = app.Services.GetRequiredService<Serilog.ILogger>();
    o.GetLevel = (ctx, _, ex) =>
        ex is not null || ctx.Response.StatusCode >= 500 ? Serilog.Events.LogEventLevel.Warning
        : ObservabilitySetup.IsInfrastructure(ctx.Request.Path, "/metrics") ? Serilog.Events.LogEventLevel.Verbose
        : Serilog.Events.LogEventLevel.Information;
});
app.UseMiddleware<TslAuth.Localization.LanguageMiddleware>();
app.UseRouting();
// После UseRouting: политики лимитов привязаны к конкретным эндпоинтам (метаданные маршрута).
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Контроллеры — протокольные эндпоинты OIDC (/connect/*); Razor Pages — вход и админка; Map*Api — REST API.
app.MapControllers();
app.MapRazorPages();
app.MapAdminApi();
app.MapAppApi();
app.MapEventsApi();
app.MapBotApi();
app.MapTslApiDocs();

// live — процесс жив; ready — есть связь с БД (для балансировщика/оркестратора).
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready");

await app.RunAsync();
return 0;

/// <summary>Точка входа (partial — для WebApplicationFactory в интеграционных тестах).</summary>
public partial class Program;
