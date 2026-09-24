using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using TslAuth.Data;
using TslAuth.Options;
using TslAuth.Security;
using TslAuth.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Infrastructure;

/// <summary>
/// Композиция DI-контейнера всего сервиса: опции, шифрование полей, EF Core (SQLite/PostgreSQL),
/// Data Protection, Identity, OpenIddict (сервер + валидация), прикладные и фоновые сервисы, авторизация,
/// Razor Pages, документация API. Вызывается один раз из Program.cs (builder.AddTslAuth()).
/// </summary>
public static class ServiceSetup
{
    /// <summary>Регистрирует все сервисы TSL Auth в контейнере.</summary>
    /// <param name="cli">Запуск служебной команды (admin ...): веб-сервер не поднимается, Issuer не обязателен.</param>
    public static void AddTslAuth(this WebApplicationBuilder builder, bool cli = false)
    {
        var services = builder.Services;
        var config = builder.Configuration;

        services.Configure<DatabaseOptions>(config.GetSection(DatabaseOptions.Section));
        services.Configure<AuthServerOptions>(config.GetSection(AuthServerOptions.Section));
        services.Configure<BootstrapOptions>(config.GetSection(BootstrapOptions.Section));

        var database = config.GetSection(DatabaseOptions.Section).Get<DatabaseOptions>() ?? new DatabaseOptions();
        // Секреты из файлов (docker secrets: /run/secrets/...) — вместо значений в переменных окружения,
        // которые видны в docker inspect и списке процессов.
        database.ConnectionString = SecretFile.Read(database.ConnectionStringFile, "Database:ConnectionStringFile") ?? database.ConnectionString;
        services.PostConfigure<DatabaseOptions>(o =>
            o.ConnectionString = SecretFile.Read(o.ConnectionStringFile, "Database:ConnectionStringFile") ?? o.ConnectionString);
        services.PostConfigure<BootstrapOptions>(o =>
        {
            o.AdminPassword = SecretFile.Read(o.AdminPasswordFile, "Bootstrap:AdminPasswordFile") ?? o.AdminPassword;
            o.AdminApiClientSecret = SecretFile.Read(o.AdminApiClientSecretFile, "Bootstrap:AdminApiClientSecretFile") ?? o.AdminApiClientSecret;
        });
        if (database.IsPostgres && !string.IsNullOrWhiteSpace(database.ConnectionString))
            database.ConnectionString = PostgresConnectionString.Normalize(database.ConnectionString);
        // То же для IOptions<DatabaseOptions> (блокировка и создание БД в StartupInitializer).
        services.PostConfigure<DatabaseOptions>(o =>
        {
            if (o.IsPostgres && !string.IsNullOrWhiteSpace(o.ConnectionString))
                o.ConnectionString = PostgresConnectionString.Normalize(o.ConnectionString);
        });
        var encryption = config.GetSection(EncryptionOptions.Section).Get<EncryptionOptions>() ?? new EncryptionOptions();
        var server = config.GetSection(AuthServerOptions.Section).Get<AuthServerOptions>() ?? new AuthServerOptions();
        ValidateIssuer(server.Issuer, builder.Environment, cli);

        // Ключ шифрования полей нужен до первого обращения к БД.
        // FieldCrypto статический (его используют value converter'ы EF), поэтому инициализируется здесь, вне DI;
        // логгер временный — полноценный ещё не построен.
        using (var loggerFactory = LoggerFactory.Create(b => b.AddConsole()))
        {
            FieldCrypto.Initialize(MasterKeyResolver.Resolve(encryption, database, builder.Environment.ContentRootPath,
                loggerFactory.CreateLogger("TslAuth.Encryption")));
        }

        // --- База данных: встроенная SQLite или внешняя PostgreSQL ---
        if (database.IsPostgres)
        {
            if (string.IsNullOrWhiteSpace(database.ConnectionString))
                throw new InvalidOperationException("Database:ConnectionString обязателен для PostgreSQL.");
            services.AddDbContext<AuthDbContext, PostgresAuthDbContext>(o => o.UseNpgsql(database.ConnectionString));
        }
        else
        {
            var cs = string.IsNullOrWhiteSpace(database.ConnectionString) ? "Data Source=data/tsl-auth.db" : database.ConnectionString;
            services.AddDbContext<AuthDbContext, SqliteAuthDbContext>(o => o.UseSqlite(cs));
        }

        // Ключи Data Protection (cookie, antiforgery) — в общей БД, зашифрованы мастер-ключом.
        // Общие ключи и одинаковое имя приложения позволяют любому экземпляру кластера расшифровать cookie,
        // выданную другим экземпляром (не нужна «липкая» балансировка).
        services.AddDataProtection()
            .SetApplicationName("tsl-auth")
            .PersistKeysToDbContext<AuthDbContext>()
            .AddKeyManagementOptions(o => o.XmlEncryptor = new FieldCryptoXmlEncryptor());

        // --- Пользователи (ASP.NET Core Identity; пароли — PBKDF2-HMAC-SHA512, 100k итераций) ---
        // Требования к паролю задаёт политика из БД (PolicyPasswordValidator), встроенные проверки Identity отключены.
        services.AddIdentity<AppUser, IdentityRole<Guid>>(o =>
            {
                o.Password.RequiredLength = 1;
                o.Password.RequiredUniqueChars = 1;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireDigit = false;
                o.Lockout.MaxFailedAccessAttempts = 5;
                o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                o.User.RequireUniqueEmail = false;
            })
            .AddEntityFrameworkStores<AuthDbContext>()
            .AddUserManager<AppUserManager>()
            .AddPasswordValidator<PolicyPasswordValidator>()
            .AddUserValidator<UserIdentityValidator>()
            .AddDefaultTokenProviders()
            .AddTokenProvider<InviteTokenProvider>(InviteTokenProvider.ProviderName);

        // Ссылки сброса пароля — 2 часа, приглашения — 7 дней (см. InviteTokenProviderOptions).
        services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromHours(2));
        // Security stamp сверяется с БД раз в минуту: смена пароля/блокировка/отзыв сессий выкидывает из cookie-сессий быстро.
        services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.FromMinutes(1));
        services.ConfigureApplicationCookie(o =>
        {
            o.Cookie.Name = "tsl_auth";
            o.LoginPath = "/Account/Login";
            o.LogoutPath = "/Account/Logout";
            o.AccessDeniedPath = "/Account/AccessDenied";
            o.ExpireTimeSpan = TimeSpan.FromHours(8);
            o.SlidingExpiration = true;
        });

        // --- OAuth 2.0 / OpenID Connect ---
        services.AddSingleton<ServerKeyRing>();
        services.AddOpenIddict()
            .AddCore(o => o.UseEntityFrameworkCore().UseDbContext<AuthDbContext>().ReplaceDefaultEntities<Guid>())
            .AddServer(o =>
            {
                o.SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetEndSessionEndpointUris("connect/logout")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetIntrospectionEndpointUris("connect/introspect")
                    .SetRevocationEndpointUris("connect/revoke");

                // PKCE обязателен для authorization code; PAT — собственный grant обмена персонального токена на JWT.
                o.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange()
                    .AllowClientCredentialsFlow()
                    .AllowPasswordFlow()
                    .AllowRefreshTokenFlow()
                    .AllowTokenExchangeFlow()
                    .AllowCustomFlow(Controllers.AuthorizationController.PatGrantType);

                o.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Roles, Scopes.OfflineAccess);
                o.RegisterClaims(Claims.Subject, Claims.Name, Claims.PreferredUsername, Claims.Email, Claims.EmailVerified,
                    Claims.Role, CustomClaims.Permissions, CustomClaims.ResourceAccess, CustomClaims.Actor, "pat_id");

                o.SetAccessTokenLifetime(TimeSpan.FromMinutes(server.AccessTokenLifetimeMinutes))
                    .SetIdentityTokenLifetime(TimeSpan.FromMinutes(server.IdentityTokenLifetimeMinutes))
                    .SetRefreshTokenLifetime(TimeSpan.FromDays(server.RefreshTokenLifetimeDays))
                    .SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(server.AuthorizationCodeLifetimeMinutes));

                // Access token — подписанный JWT (проверяется сервисами по JWKS без обращения к нам).
                o.DisableAccessTokenEncryption();
                // Refresh token — ссылочный (случайный id, содержимое в БД): можно отозвать, переживает рестарт.
                o.UseReferenceRefreshTokens();
                o.SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(server.RefreshTokenReuseLeewaySeconds));

                if (!string.IsNullOrWhiteSpace(server.Issuer))
                    o.SetIssuer(new Uri(server.Issuer));

                // Passthrough: OpenIddict валидирует протокольный запрос, а решение (выдать/отказать) принимает AuthorizationController.
                var aspNetCore = o.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();
                if (!server.RequireHttps) aspNetCore.DisableTransportSecurityRequirement();

                o.AddEventHandler(TokenErrorAuditHandler.Descriptor);
                o.AddEventHandler(IntrospectionErrorAuditHandler.Descriptor);
                o.AddEventHandler(RevocationErrorAuditHandler.Descriptor);
            })
            .AddValidation(o =>
            {
                // Для собственного Admin API: проверка токенов локально + проверка статуса токена в БД (мгновенный отзыв).
                o.UseLocalServer();
                o.AddAudiences(SystemApp.ClientId, SystemApp.AppApiScope);
                o.EnableTokenEntryValidation();
                o.EnableAuthorizationEntryValidation();
                o.UseAspNetCore();
            });

        // Ключи подписи/шифрования загружаются из БД при старте (общие для всех экземпляров).
        // Делегат выполняется лениво — при первом обращении к опциям, т.е. уже после StartupInitializer.
        services.AddOptions<OpenIddictServerOptions>().Configure<ServerKeyRing>((o, keys) =>
        {
            o.SigningCredentials.Add(new SigningCredentials(keys.SigningKey, SecurityAlgorithms.RsaSha256));
            o.EncryptionCredentials.Add(new EncryptingCredentials(keys.EncryptionKey,
                SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
        });

        // --- Прикладные сервисы ---
        services.AddScoped<AccessService>();
        services.AddScoped<ApplicationService>();
        services.AddScoped<UserService>();
        services.AddScoped<SessionService>();
        services.AddScoped<TokenPrincipalFactory>();
        services.AddScoped<TokenLifetimeService>();
        services.AddScoped<PatService>();
        services.AddScoped<AccountLinks>();
        services.AddHttpContextAccessor();
        services.Configure<SmtpOptions>(config.GetSection(SmtpOptions.Section));
        services.AddSingleton<IEmailSender, SmtpEmailSender>();
        services.AddScoped<AppSelfService>();
        services.AddScoped<BotService>();
        services.AddScoped<BrandingService>();
        services.AddSingleton<Localization.LocalizationService>();
        services.AddScoped<Localization.Texts>();
        services.AddScoped<AccessRequestService>();
        services.AddScoped<WebhookService>();
        // AuditService — одновременно singleton-очередь и фоновый писатель пакетов: один и тот же экземпляр.
        services.AddSingleton<AuditService>();
        services.AddHostedService(sp => sp.GetRequiredService<AuditService>());
        services.AddSingleton<SettingsService>();
        services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, AuditingAuthorizationResultHandler>();
        services.AddHostedService<WebhookDispatcher>();
        // Клиент вебхуков: без редиректов (Location мог бы увести на внутренний адрес), без системного прокси
        // (иначе проверялся бы адрес прокси, а не получателя) и с проверкой адреса при каждом соединении (M6, SSRF).
        var webhookTargets = WebhookTargetPolicy.FromConfig(config);
        services.AddSingleton(webhookTargets);
        services.AddHttpClient(WebhookDispatcher.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(10))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                ConnectCallback = webhookTargets.ConnectAsync
            });
        services.AddScoped<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, AdminPermissionHandler>();
        services.AddScoped<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, Api.AppSelfHandler>();
        services.AddAuthorization(o =>
        {
            AdminPolicies.Register(o);
            Api.AppApi.AddAppApiPolicy(o);
            Api.BotApi.AddBotPolicy(o);
        });
        services.AddHostedService<TokenPruningService>();

        services.AddTslSecurity(config);
        // Introspection и revocation проверяют client_secret, но обрабатываются OpenIddict без контроллера —
        // атрибут политики на них не повесить. Глобальный лимитер по IP (тот же лимит, что у /connect/token)
        // не даёт перебирать секреты клиентов через эти эндпоинты.
        var security = config.GetSection(SecurityOptions.Section).Get<SecurityOptions>() ?? new SecurityOptions();
        services.Configure<Microsoft.AspNetCore.RateLimiting.RateLimiterOptions>(o =>
            o.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
                ctx.Request.Path.StartsWithSegments("/connect/introspect") || ctx.Request.Path.StartsWithSegments("/connect/revoke")
                    ? System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                        "client-auth:" + (ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown"),
                        _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                        {
                            PermitLimit = security.TokenRequestsPerMinute, Window = TimeSpan.FromMinutes(1)
                        })
                    : System.Threading.RateLimiting.RateLimitPartition.GetNoLimiter("none")));
        // Кириллица и другие алфавиты выводятся как есть, а не HTML-сущностями (&#x...;).
        services.Configure<Microsoft.Extensions.WebEncoders.WebEncoderOptions>(o =>
            o.TextEncoderSettings = new System.Text.Encodings.Web.TextEncoderSettings(System.Text.Unicode.UnicodeRanges.All));
        services.AddControllers();
        services.AddRazorPages(o =>
        {
            o.Conventions.AuthorizeFolder("/Admin", AdminPolicies.UiView);
            o.Conventions.AuthorizePage("/Account/ChangePassword");
            o.Conventions.AuthorizePage("/Account/Tokens");
            o.Conventions.AuthorizePage("/Account/Messenger");
            o.Conventions.AuthorizePage("/Account/RequestAccess");
            // Страницы входа/сброса пароля — под лимитом попыток с одного IP (защита от подбора).
            o.Conventions.AddFolderApplicationModelConvention("/Account",
                m => m.EndpointMetadata.Add(new Microsoft.AspNetCore.RateLimiting.EnableRateLimitingAttribute(SecurityMiddleware.LoginPolicy)));
            o.Conventions.AddFolderApplicationModelConvention("/Admin", m =>
            {
                m.Filters.Add(new MustChangePasswordFilter());
                m.Filters.Add(new AdminPageAuditFilter());
            });
            // Личный кабинет тоже недоступен, пока временный пароль не сменён: иначе знающий временный пароль
            // успел бы привязать мессенджер (альтернативный канал сброса пароля) или выпустить PAT.
            foreach (var page in new[] { "/Account/Index", "/Account/Tokens", "/Account/Messenger", "/Account/RequestAccess" })
                o.Conventions.AddPageApplicationModelConvention(page, m => m.Filters.Add(new MustChangePasswordFilter()));
        });
        services.AddTslApiDocs();
        services.AddHealthChecks().AddDbContextCheck<AuthDbContext>("database");

        if (server.TrustForwardedHeaders)
        {
            var networks = ParseKnownNetworks(server.KnownNetworks);
            services.Configure<ForwardedHeadersOptions>(o =>
            {
                // X-Forwarded-For/Proto принимаются только от прокси из известных сетей: иначе запрос напрямую на узел
                // подделал бы IP клиента (обход лимитов по IP, ложный IP в журнале) и схему (обход RequireHttps).
                // X-Forwarded-Host не принимается: публичный адрес задан Issuer, подмена хоста только расширяла бы атаки.
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                o.KnownIPNetworks.Clear();
                o.KnownProxies.Clear();
                foreach (var network in networks) o.KnownIPNetworks.Add(network);
            });
        }
    }

    /// <summary>
    /// Issuer — публичный адрес сервиса: из него строятся <c>iss</c> токенов, адреса discovery и ссылки в письмах
    /// (приглашения, сброс пароля). Без него всё это бралось бы из заголовка Host запроса, который подделывается
    /// (Host-header poisoning: письмо сброса пароля жертве со ссылкой на чужой домен). Поэтому вне Development
    /// сервис без Issuer не стартует. Служебные CLI-команды ссылок и токенов не выдают — им Issuer не нужен.
    /// </summary>
    private static void ValidateIssuer(string? issuer, IHostEnvironment environment, bool cli)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            if (cli || environment.IsDevelopment()) return;
            throw new InvalidOperationException(
                "Не задан Auth:Issuer (переменная Auth__Issuer / AUTH_ISSUER) — публичный адрес сервиса, например https://auth.corp/. " +
                "Без него ссылки в письмах и iss токенов строились бы из заголовка Host запроса, который может подделать атакующий.");
        }
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidOperationException($"Auth:Issuer должен быть абсолютным http(s)-адресом без query и фрагмента, получено: '{issuer}'.");
    }

    // Сети по умолчанию для доверенных прокси: loopback и частные диапазоны (Docker, внутренняя сеть балансировщика).
    private static readonly string[] DefaultProxyNetworks =
        ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];

    /// <summary>Разбирает Auth:KnownNetworks (CIDR через запятую/точку с запятой); ошибка формата — отказ старта.</summary>
    internal static List<System.Net.IPNetwork> ParseKnownNetworks(string? value)
    {
        var items = string.IsNullOrWhiteSpace(value)
            ? DefaultProxyNetworks
            : value.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return items.Select(item => System.Net.IPNetwork.TryParse(item, out var network)
            ? network
            : throw new InvalidOperationException($"Auth:KnownNetworks: '{item}' — не CIDR (пример: 10.0.0.0/8, 172.18.0.0/16).")).ToList();
    }
}
