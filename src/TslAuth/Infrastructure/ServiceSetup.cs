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
    public static void AddTslAuth(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var config = builder.Configuration;

        services.Configure<DatabaseOptions>(config.GetSection(DatabaseOptions.Section));
        services.Configure<AuthServerOptions>(config.GetSection(AuthServerOptions.Section));
        services.Configure<BootstrapOptions>(config.GetSection(BootstrapOptions.Section));

        var database = config.GetSection(DatabaseOptions.Section).Get<DatabaseOptions>() ?? new DatabaseOptions();
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
        services.AddHttpClient(WebhookDispatcher.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(10));
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
        });
        services.AddTslApiDocs();
        services.AddHealthChecks().AddDbContextCheck<AuthDbContext>("database");

        if (server.TrustForwardedHeaders)
        {
            services.Configure<ForwardedHeadersOptions>(o =>
            {
                // Доверяем любому прокси: включать, только если сервис недоступен напрямую, в обход балансировщика
                // (иначе клиент подделает X-Forwarded-For и обойдёт лимиты по IP).
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
                o.KnownIPNetworks.Clear();
                o.KnownProxies.Clear();
            });
        }
    }
}
