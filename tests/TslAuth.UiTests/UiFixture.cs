using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Playwright;

namespace TslAuth.UiTests;

/// <summary>
/// UI-автотесты работают против запущенного стенда: сервис в Docker (compose) + приложения-примеры из samples/.
/// Адреса и учётные данные можно переопределить переменными окружения.
/// Скриншоты каждого шага сохраняются в tests/artifacts/ui.
/// Фикстура один раз поднимает Playwright и Chromium (без окна; UI_HEADED=1 — с окном),
/// получает токен Admin API и готовит отдельного администратора для тестов.
/// Запуск: сначала поднять стенд (docflow-start), затем <c>dotnet test tests/TslAuth.UiTests</c>;
/// браузеры Playwright должны быть установлены заранее (playwright.ps1 install chromium).
/// </summary>
public sealed class UiFixture : IAsyncLifetime
{
    public static float TimeoutMs => float.Parse(Env("UI_TIMEOUT_MS", "15000"));
    public static string Auth => Env("UI_AUTH_URL", "http://localhost:8080");
    public static string Dotnet => Env("UI_DOTNET_URL", "http://localhost:5101");
    public static string Spa => Env("UI_SPA_URL", "http://localhost:5102");
    public static string GoApi => Env("UI_GO_URL", "http://localhost:5103");
    public static string Go => Env("UI_GO_URL", "http://localhost:5103");
    public static string Python => Env("UI_PYTHON_URL", "http://localhost:5104");
    public const string SamplePassword = "Sample-Passw0rd!";
    public const string UiAdmin = "ui-admin";
    public const string UiAdminPassword = "Ui-Adm1n-Secret!";

    public static readonly string Artifacts = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../artifacts/ui"));

    public IPlaywright Playwright { get; private set; } = null!;
    public IBrowser Browser { get; private set; } = null!;
    public HttpClient Admin { get; private set; } = null!;

    // Тексты пользовательских страниц берутся из встроенного русского пакета (браузер тестов — ru-RU):
    // проверки не ломаются при правке формулировок, а только при смене ключа.
    private static readonly Lazy<Dictionary<string, string>> RuPack = new(() => JsonSerializer.Deserialize<Dictionary<string, string>>(
        File.ReadAllText(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../src/TslAuth/Localization/Packs/ru.json"))))!);

    /// <summary>Строка русского языкового пакета по ключу; для текстов с параметрами — часть до первого «{».</summary>
    public static string Ru(string key) => RuPack.Value[key].Split('{')[0].Trim();

    private static string Env(string name, string fallback) => Environment.GetEnvironmentVariable(name) ?? fallback;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Artifacts);
        Playwright = await Microsoft.Playwright.Playwright.CreateAsync();
        Browser = await Playwright.Chromium.LaunchAsync(new() { Headless = Env("UI_HEADED", "") == "" });
        // На загруженном агенте CI (стенд в dind, соседние задания) ответы приходят дольше 5 с по умолчанию: ожидания
        // Playwright — UI_TIMEOUT_MS (по умолчанию 15 с), чтобы медленный стенд не выглядел как падение.
        Microsoft.Playwright.Assertions.SetDefaultExpectTimeout(TimeoutMs);

        // Admin API: клиент admin-cli создаётся сервисом из Bootstrap-настроек стенда.
        Admin = new HttpClient { BaseAddress = new Uri(Auth) };
        var token = await (await Admin.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials", ["client_id"] = Env("UI_ADMIN_CLIENT_ID", "admin-cli"),
            ["client_secret"] = Env("UI_ADMIN_CLIENT_SECRET", "sample-admin-cli-secret-2026"), ["scope"] = "tsl-auth-admin"
        }))).Content.ReadFromJsonAsync<JsonElement>();
        Admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.GetProperty("access_token").GetString());

        // Отдельный администратор для UI-тестов (пароль известен тестам, реальный admin не трогаем).
        await EnsureUserAsync(UiAdmin, UiAdminPassword, [new { clientId = "tsl-auth-admin", role = "administrator" }]);
    }

    /// <summary>
    /// Идемпотентно приводит пользователя к нужному состоянию: создаёт, если его нет, иначе
    /// перезаписывает роли и пароль. Так повторные прогоны на том же стенде дают одинаковый результат.
    /// </summary>
    public async Task<Guid> EnsureUserAsync(string name, string password, object[] roles, bool temporary = false)
    {
        var found = await Admin.GetFromJsonAsync<JsonElement>($"/api/admin/users?search={name}");
        Guid id;
        if (found.GetProperty("total").GetInt32() == 0)
        {
            var created = await (await Admin.PostAsJsonAsync("/api/admin/users", new
            {
                userName = name, email = $"{name}@tsl.local", password, mustChangePassword = temporary, roles
            })).Content.ReadFromJsonAsync<JsonElement>();
            id = created.GetProperty("user").GetProperty("id").GetGuid();
        }
        else
        {
            id = found.GetProperty("items")[0].GetProperty("id").GetGuid();
            await Admin.PutAsJsonAsync($"/api/admin/users/{id}", new { userName = name, email = $"{name}@tsl.local", isActive = true, roles });
            (await Admin.PostAsJsonAsync($"/api/admin/users/{id}/password", new { password, mustChangePassword = temporary })).EnsureSuccessStatusCode();
        }
        // Снимаем возможную блокировку после неудачных входов в прошлых прогонах (тест с неверным паролем).
        await Admin.PostAsync($"/api/admin/users/{id}/unlock", null);
        return id;
    }

    /// <summary>Новая страница в отдельном контексте браузера: свои cookie, поэтому тесты не делят сессии.</summary>
    public async Task<IPage> NewPageAsync(string? locale = "ru-RU")
    {
        var context = await Browser.NewContextAsync(new() { Locale = locale, ViewportSize = new() { Width = 1280, Height = 900 } });
        var page = await context.NewPageAsync();
        page.SetDefaultTimeout(TimeoutMs);
        return page;
    }

    public static Task ShotAsync(IPage page, string name) =>
        page.ScreenshotAsync(new() { Path = Path.Combine(Artifacts, $"{name}.png"), FullPage = true });

    /// <summary>Вход на странице TSL Auth (в т.ч. при редиректе из приложения).</summary>
    public static async Task LoginAsync(IPage page, string user, string password)
    {
        await page.FillAsync("#Login", user);
        await page.FillAsync("#Password", password);
        await page.ClickAsync("button[type=submit].primary");
    }

    public async Task DisposeAsync()
    {
        await Browser.DisposeAsync();
        Playwright.Dispose();
        Admin.Dispose();
    }
}

/// <summary>Коллекция xUnit: все UI-тесты делят один браузер и один UiFixture.</summary>
[CollectionDefinition("ui")]
public sealed class UiCollection : ICollectionFixture<UiFixture>;
