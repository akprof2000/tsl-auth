using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace Docflow.Shared;

/// <summary>Секция "OpenBao": где лежат секреты сервиса и как в хранилище войти.</summary>
public sealed class OpenBaoOptions
{
    public const string Section = "OpenBao";

    /// <summary>Адрес OpenBao, например http://openbao:8200. Пусто — OpenBao не используется.</summary>
    public string? Address { get; set; }

    /// <summary>Точка монтирования KV v2.</summary>
    public string Mount { get; set; } = "secret";

    /// <summary>Пути секретов через запятую; позже указанный перекрывает ранее указанный (например "shared,tsl-auth").</summary>
    public string Path { get; set; } = "tsl-auth";

    /// <summary>AppRole: файлы с role_id и secret_id (выдаются при развёртывании, secret_id — одноразовый или с TTL).</summary>
    public string? RoleIdFile { get; set; }
    public string? SecretIdFile { get; set; }
    public string? RoleId { get; set; }

    /// <summary>Альтернатива AppRole: файл с токеном (например, выписанный агентом OpenBao).</summary>
    public string? TokenFile { get; set; }

    /// <summary>Корневой сертификат для HTTPS-подключения к OpenBao (PEM).</summary>
    public string? CaFile { get; set; }

    /// <summary>Сколько раз повторять при недоступном или запечатанном хранилище (по 2 с) до отказа запуска.</summary>
    public int Retries { get; set; } = 30;

    public bool Enabled => !string.IsNullOrWhiteSpace(Address);
}

/// <summary>
/// OpenBao — единое хранилище секретов проектов ТСЛ (копия механизма TSL Auth: src/TslAuth/Infrastructure/OpenBaoConfiguration.cs).
/// При старте сервис входит в OpenBao (AppRole или токен), читает секреты из KV v2 и добавляет их в конфигурацию
/// последним источником: значения из хранилища перекрывают переменные окружения и appsettings.
///
/// Ключ секрета — имя настройки: <c>Encryption__MasterKey</c> (или <c>Encryption:MasterKey</c>),
/// <c>Database__ConnectionString</c>, <c>Bootstrap__AdminApiClientSecret</c>, <c>Smtp__Password</c> и т. д.
/// Поэтому любую настройку можно перенести в хранилище без изменений кода.
///
/// Секреты читаются один раз при старте: после ротации секрета перезапустите сервис (в кластере — поочерёдно).
/// Если адрес задан, а хранилище недоступно или запечатано, запуск повторяется <see cref="OpenBaoOptions.Retries"/> раз и затем
/// прерывается с ошибкой — сервис не стартует без секретов молча.
/// </summary>
public static class OpenBaoConfiguration
{
    /// <summary>Подключает секреты OpenBao к конфигурации. Возвращает описание источника для журнала или null.</summary>
    public static string? Attach(IConfigurationManager configuration, Func<int, TimeSpan>? delay = null)
    {
        var options = configuration.GetSection(OpenBaoOptions.Section).Get<OpenBaoOptions>() ?? new OpenBaoOptions();
        if (!options.Enabled) return null;

        var values = LoadAsync(options, delay ?? (_ => TimeSpan.FromSeconds(2))).GetAwaiter().GetResult();
        configuration.AddInMemoryCollection(values);
        return $"OpenBao {options.Address} ({options.Mount}: {options.Path}), ключей: {values.Count}";
    }

    /// <summary>Вход и чтение всех путей. Исключение — секреты получить не удалось.</summary>
    public static async Task<Dictionary<string, string?>> LoadAsync(OpenBaoOptions options, Func<int, TimeSpan> delay,
        CancellationToken ct = default)
    {
        using var http = CreateClient(options);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var token = await LoginAsync(http, options, ct);
                var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                foreach (var path in options.Path.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    foreach (var (key, value) in await ReadAsync(http, options.Mount, path, token, ct))
                        result[NormalizeKey(key)] = value;
                return result;
            }
            catch (OpenBaoUnavailableException ex) when (attempt < Math.Max(1, options.Retries))
            {
                Console.Error.WriteLine($"OpenBao недоступен ({ex.Message}), попытка {attempt}/{options.Retries}...");
                await Task.Delay(delay(attempt), ct);
            }
            catch (OpenBaoUnavailableException ex)
            {
                throw new InvalidOperationException($"OpenBao {options.Address}: секреты не получены — {ex.Message}", ex);
            }
        }
    }

    /// <summary>"Encryption__MasterKey" → "Encryption:MasterKey" (как у переменных окружения).</summary>
    public static string NormalizeKey(string key) => key.Replace("__", ":", StringComparison.Ordinal);

    private static HttpClient CreateClient(OpenBaoOptions options)
    {
        var handler = new HttpClientHandler();
        if (!string.IsNullOrWhiteSpace(options.CaFile))
        {
            var ca = X509Certificate2.CreateFromPem(SecretFile.Read(options.CaFile, "OpenBao:CaFile")!);
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
            {
                if (cert is null) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(cert);
            };
        }
        return new HttpClient(handler) { BaseAddress = new Uri(options.Address!.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(10) };
    }

    private static async Task<string> LoginAsync(HttpClient http, OpenBaoOptions options, CancellationToken ct)
    {
        var token = SecretFile.Read(options.TokenFile, "OpenBao:TokenFile");
        if (!string.IsNullOrEmpty(token)) return token;

        var roleId = SecretFile.Read(options.RoleIdFile, "OpenBao:RoleIdFile") ?? options.RoleId;
        var secretId = SecretFile.Read(options.SecretIdFile, "OpenBao:SecretIdFile");
        if (string.IsNullOrEmpty(roleId) || string.IsNullOrEmpty(secretId))
            throw new InvalidOperationException("OpenBao: задайте TokenFile или RoleIdFile + SecretIdFile (AppRole).");

        var response = await SendAsync(http, new HttpRequestMessage(HttpMethod.Post, "v1/auth/approle/login")
        {
            Content = JsonContent.Create(new { role_id = roleId, secret_id = secretId })
        }, ct);
        return response.GetProperty("auth").GetProperty("client_token").GetString()
               ?? throw new InvalidOperationException("OpenBao: вход по AppRole не вернул токен.");
    }

    private static async Task<List<KeyValuePair<string, string?>>> ReadAsync(HttpClient http, string mount, string path, string token,
        CancellationToken ct)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"v1/{mount.Trim('/')}/data/{path.Trim('/')}");
        request.Headers.Add("X-Vault-Token", token);
        var body = await SendAsync(http, request, ct);
        var data = body.GetProperty("data").GetProperty("data");
        return data.EnumerateObject()
            .Select(p => new KeyValuePair<string, string?>(p.Name, p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.GetRawText()))
            .ToList();
    }

    /// <summary>
    /// Запрос к API OpenBao. Сетевые ошибки, 5xx и 503 (хранилище запечатано) — временные, их повторяем;
    /// 4xx (нет прав, нет секрета, неверный secret_id) — ошибка конфигурации, запуск сразу прерывается.
    /// </summary>
    private static async Task<JsonElement> SendAsync(HttpClient http, HttpRequestMessage request, CancellationToken ct)
    {
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new OpenBaoUnavailableException(ex.Message);
        }
        using (response)
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            if ((int)response.StatusCode >= 500)
                throw new OpenBaoUnavailableException($"{(int)response.StatusCode} {Errors(text)}");
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"OpenBao: {request.Method} /{request.RequestUri} → {(int)response.StatusCode} {Errors(text)}");
            return JsonDocument.Parse(text).RootElement.Clone();
        }
    }

    private static string Errors(string body)
    {
        try
        {
            return JsonDocument.Parse(body).RootElement.TryGetProperty("errors", out var e) ? string.Join("; ", e.EnumerateArray()) : body;
        }
        catch (JsonException)
        {
            return body.Length > 200 ? body[..200] : body;
        }
    }

    private sealed class OpenBaoUnavailableException(string message) : Exception(message);
}

/// <summary>Чтение секрета из файла: пустой путь — не задано, отсутствующий файл — ошибка.</summary>
internal static class SecretFile
{
    public static string? Read(string? path, string setting)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        if (!File.Exists(path)) throw new InvalidOperationException($"{setting}: файл '{path}' не найден.");
        return File.ReadAllText(path).Trim();
    }
}
