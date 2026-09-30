using Microsoft.Extensions.Configuration;

namespace TslAuth.Client;

/// <summary>
/// Настройки SDK (docs/client-contract.md §1). Явно заданные значения имеют приоритет над окружением,
/// если <see cref="ApplyEnvironment"/> не вызван после них.
/// </summary>
public sealed class TslAuthOptions
{
    /// <summary>Адрес сервиса, как в <c>iss</c> токена (<c>TSL_AUTH_ISSUER</c>). Обязателен.</summary>
    public string? Issuer { get; set; }

    /// <summary><c>client_id</c> этого API: токен принимается, только если <c>aud</c> его содержит (<c>TSL_AUTH_AUDIENCE</c>).</summary>
    public string? Audience { get; set; }

    /// <summary><c>client_id</c> приложения для клиента токенов и интроспекции (<c>TSL_AUTH_CLIENT_ID</c>).</summary>
    public string? ClientId { get; set; }

    /// <summary>Секрет confidential-клиента (<c>TSL_AUTH_CLIENT_SECRET</c>).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Закрытый ключ EC P-256 в PEM для входа по ключу (<c>private_key_jwt</c>, <c>TSL_AUTH_CLIENT_KEY_PEM</c>).
    /// Используется, когда секрет не задан: клиент подписывает assertion ES256 вместо передачи секрета.
    /// </summary>
    public string? ClientPrivateKeyPem { get; set; }

    /// <summary>Путь к файлу PEM с закрытым ключом (<c>TSL_AUTH_CLIENT_KEY_FILE</c>); альтернатива <see cref="ClientPrivateKeyPem"/>.</summary>
    public string? ClientPrivateKeyFile { get; set; }

    /// <summary><c>kid</c> ключа (<c>TSL_AUTH_CLIENT_KEY_ID</c>); пусто — отпечаток RFC 7638, как присваивает сервис.</summary>
    public string? ClientKeyId { get; set; }

    /// <summary>Прямой адрес JWKS в обход discovery (<c>TSL_AUTH_JWKS_URI</c>).</summary>
    public string? JwksUri { get; set; }

    /// <summary>Допуск на расхождение часов при проверке <c>exp</c>/<c>nbf</c> (<c>TSL_AUTH_CLOCK_SKEW_SECONDS</c>, 30 с).</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Срок кэша ключей и discovery (<c>TSL_AUTH_JWKS_TTL_SECONDS</c>, 600 с).</summary>
    public TimeSpan JwksTtl { get; set; } = TimeSpan.FromSeconds(600);

    /// <summary>Минимальный интервал перечитывания JWKS по неизвестному <c>kid</c> (<c>TSL_AUTH_JWKS_MIN_REFRESH_SECONDS</c>, 10 с).</summary>
    public TimeSpan JwksMinRefresh { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>После локальной проверки спрашивать introspection endpoint (<c>TSL_AUTH_INTROSPECT</c>, false).</summary>
    public bool Introspect { get; set; }

    /// <summary>Таймаут HTTP-запросов к сервису (<c>TSL_AUTH_HTTP_TIMEOUT_SECONDS</c>, 10 с).</summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Часы SDK: подменяются в тестах, по умолчанию системные.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>Свой <see cref="HttpMessageHandler"/> для обращений к сервису (прокси, тесты). По умолчанию — стандартный.</summary>
    public HttpMessageHandler? HttpMessageHandler { get; set; }

    /// <summary>Настройки только из переменных окружения <c>TSL_AUTH_*</c>.</summary>
    public static TslAuthOptions FromEnvironment() => new TslAuthOptions().ApplyEnvironment();

    /// <summary>
    /// Настройки из секции конфигурации (ключи как свойства; интервалы — <c>ClockSkewSeconds</c>, <c>JwksTtlSeconds</c>,
    /// <c>JwksMinRefreshSeconds</c>, <c>HttpTimeoutSeconds</c>). При <paramref name="environmentOverrides"/> переменные
    /// окружения <c>TSL_AUTH_*</c> имеют приоритет над секцией.
    /// </summary>
    public static TslAuthOptions FromConfiguration(IConfiguration section, bool environmentOverrides = true)
    {
        ArgumentNullException.ThrowIfNull(section);
        var o = new TslAuthOptions();
        o.Apply(key => section[key], prefix: "");
        return environmentOverrides ? o.ApplyEnvironment() : o;
    }

    /// <summary>Накладывает переменные окружения <c>TSL_AUTH_*</c> поверх текущих значений (пустые переменные игнорируются).</summary>
    public TslAuthOptions ApplyEnvironment()
    {
        Apply(key => Environment.GetEnvironmentVariable(key), prefix: "TSL_AUTH_");
        return this;
    }

    private void Apply(Func<string, string?> get, string prefix)
    {
        // Имена ключей: для окружения — TSL_AUTH_CLOCK_SKEW_SECONDS, для конфигурации — ClockSkewSeconds.
        string? Get(string env, string cfg) => prefix.Length > 0 ? Blank(get(prefix + env)) : Blank(get(cfg));

        Issuer = Get("ISSUER", "Issuer") ?? Issuer;
        Audience = Get("AUDIENCE", "Audience") ?? Audience;
        ClientId = Get("CLIENT_ID", "ClientId") ?? ClientId;
        ClientSecret = Get("CLIENT_SECRET", "ClientSecret") ?? ClientSecret;
        ClientPrivateKeyPem = Get("CLIENT_KEY_PEM", "ClientPrivateKeyPem") ?? ClientPrivateKeyPem;
        ClientPrivateKeyFile = Get("CLIENT_KEY_FILE", "ClientPrivateKeyFile") ?? ClientPrivateKeyFile;
        ClientKeyId = Get("CLIENT_KEY_ID", "ClientKeyId") ?? ClientKeyId;
        JwksUri = Get("JWKS_URI", "JwksUri") ?? JwksUri;
        ClockSkew = Seconds(Get("CLOCK_SKEW_SECONDS", "ClockSkewSeconds"), ClockSkew);
        JwksTtl = Seconds(Get("JWKS_TTL_SECONDS", "JwksTtlSeconds"), JwksTtl);
        JwksMinRefresh = Seconds(Get("JWKS_MIN_REFRESH_SECONDS", "JwksMinRefreshSeconds"), JwksMinRefresh);
        HttpTimeout = Seconds(Get("HTTP_TIMEOUT_SECONDS", "HttpTimeoutSeconds"), HttpTimeout);
        var introspect = Get("INTROSPECT", "Introspect");
        if (introspect is not null)
            Introspect = introspect.Equals("true", StringComparison.OrdinalIgnoreCase) || introspect == "1";
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static TimeSpan Seconds(string? value, TimeSpan fallback) =>
        value is not null && double.TryParse(value, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var s) && s >= 0
            ? TimeSpan.FromSeconds(s)
            : fallback;

    /// <summary>Issuer без завершающего «/», для сравнения с <c>iss</c> и построения адресов.</summary>
    internal string RequireIssuer()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
            throw new InvalidOperationException("TSL Auth: не задан Issuer (TSL_AUTH_ISSUER).");
        return Issuer.TrimEnd('/');
    }
}
