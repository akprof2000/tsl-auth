namespace TslAuth.Options;

// Классы опций, привязываемые к секциям конфигурации (appsettings.json / переменные окружения вида Section__Key).
// Читаются в ServiceSetup при построении контейнера и через IOptions<T> в сервисах.

/// <summary>Секция "Database": выбор СУБД и строка подключения.</summary>
public sealed class DatabaseOptions
{
    public const string Section = "Database";

    /// <summary>Sqlite (встроенная БД, один экземпляр) или Postgres (внешняя БД, кластер).</summary>
    public string Provider { get; set; } = "Sqlite";

    public string? ConnectionString { get; set; }

    public bool IsPostgres => Provider.Equals("Postgres", StringComparison.OrdinalIgnoreCase)
                              || Provider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Секция "Encryption": источник мастер-ключа (см. MasterKeyResolver).</summary>
public sealed class EncryptionOptions
{
    public const string Section = "Encryption";

    /// <summary>Мастер-ключ (base64, минимум 32 байта) для шифрования полей в БД.</summary>
    public string? MasterKey { get; set; }

    /// <summary>Путь к файлу с мастер-ключом (удобно для docker secrets).</summary>
    public string? MasterKeyFile { get; set; }
}

/// <summary>Секция "Auth": параметры сервера OpenIddict — issuer, HTTPS, сроки жизни токенов, работа за прокси.</summary>
public sealed class AuthServerOptions
{
    public const string Section = "Auth";

    /// <summary>Публичный адрес сервиса (iss в токенах). Обязателен при запуске нескольких экземпляров.</summary>
    public string? Issuer { get; set; }

    /// <summary>Требовать HTTPS на протокольных эндпоинтах и включать HSTS. Отключать только для разработки/TLS на прокси.</summary>
    public bool RequireHttps { get; set; } = true;

    public int AccessTokenLifetimeMinutes { get; set; } = 15;
    public int IdentityTokenLifetimeMinutes { get; set; } = 15;
    public int RefreshTokenLifetimeDays { get; set; } = 14;
    public int AuthorizationCodeLifetimeMinutes { get; set; } = 5;

    /// <summary>
    /// Окно (сек), в течение которого уже использованный refresh-токен ещё принимается — защита от сетевых повторов
    /// у клиента. 0 — строгая одноразовость.
    /// </summary>
    public int RefreshTokenReuseLeewaySeconds { get; set; } = 30;

    /// <summary>Доверять заголовкам X-Forwarded-* (сервис за балансировщиком).</summary>
    public bool TrustForwardedHeaders { get; set; }

    /// <summary>
    /// Сети (CIDR через запятую), от которых принимаются X-Forwarded-* при <see cref="TrustForwardedHeaders"/>.
    /// Пусто — loopback и частные сети (10/8, 172.16/12, 192.168/16, fc00::/7): там работают Docker-сети и балансировщик.
    /// Запрос из других адресов (например, прямо на порт узла из интернета) не сможет подменить IP клиента и схему.
    /// </summary>
    public string? KnownNetworks { get; set; }
}

/// <summary>
/// Секция "Bootstrap": начальные данные, которые StartupInitializer создаёт при первом запуске
/// (первый администратор и опциональный клиент Admin API). Существующие данные не перезаписываются.
/// </summary>
public sealed class BootstrapOptions
{
    public const string Section = "Bootstrap";

    public string AdminUserName { get; set; } = "admin";
    public string? AdminEmail { get; set; }

    /// <summary>Если не задан — будет сгенерирован и выведен в лог при первом запуске.</summary>
    public string? AdminPassword { get; set; }

    /// <summary>Опционально: клиент для внешнего Admin API (client_credentials).</summary>
    public string? AdminApiClientId { get; set; }
    public string? AdminApiClientSecret { get; set; }
}
