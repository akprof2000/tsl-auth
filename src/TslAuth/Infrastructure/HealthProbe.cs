namespace TslAuth.Infrastructure;

/// <summary>
/// Проверка готовности сервиса изнутри контейнера: <c>dotnet TslAuth.dll healthcheck [url]</c>.
/// Нужна для Docker HEALTHCHECK в distroless-образе, где нет shell, wget и curl.
/// По умолчанию опрашивает http://127.0.0.1:8080/health/ready (HTTP-порт есть и при включённом HTTPS).
/// </summary>
public static class HealthProbe
{
    public static async Task<int> RunAsync(string? url)
    {
        url ??= Environment.GetEnvironmentVariable("HEALTHCHECK_URL") ?? "http://127.0.0.1:8080/health/ready";
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            using var response = await http.GetAsync(url);
            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch
        {
            // Сервис ещё стартует или не отвечает — для Docker это просто «нездоров».
            return 1;
        }
    }
}
