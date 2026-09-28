using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Playwright;
using static Microsoft.Playwright.Assertions;

namespace TslAuth.UiTests;

/// <summary>
/// UI-сценарии (Playwright): страница входа, админка, демо-приложения, регистрация, персональные токены.
/// Работают против поднятого стенда через <see cref="UiFixture"/>; запуск: <c>dotnet test tests/TslAuth.UiTests</c>.
/// Ожидания Expect(...) сами повторяют проверку до таймаута Playwright, поэтому явных задержек в тестах нет.
/// </summary>
[Collection("ui")]
public sealed class UiScenarios(UiFixture fx)
{
    // Уникальный суффикс: сущности от прошлых прогонов остаются на стенде и не должны конфликтовать.
    private static string Unique(string p) => $"{p}-{Guid.NewGuid().ToString("N")[..6]}";

    // ---------- Страница входа ----------

    /// <summary>«Глазок» переключает видимость пароля; неверный пароль даёт локализованное сообщение об ошибке.</summary>
    [Fact]
    public async Task Login_WrongPassword_ShowsError_PasswordEyeToggles()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync($"{UiFixture.Auth}/Account/Login");
        await page.FillAsync("#Password", "secret-value");
        Assert.Equal("password", await page.GetAttributeAsync("#Password", "type"));
        await page.ClickAsync(".password-toggle");
        Assert.Equal("text", await page.GetAttributeAsync("#Password", "type")); // «глазок» показывает пароль
        await UiFixture.ShotAsync(page, "01-login-eye");

        await UiFixture.LoginAsync(page, UiFixture.UiAdmin, "wrong-password");
        await Expect(page.Locator(".alert.error")).ToContainTextAsync(UiFixture.Ru("login.error.invalid"));
        await UiFixture.ShotAsync(page, "02-login-error");
    }

    [Fact]
    public async Task Login_LanguageSwitch_ToEnglish()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync($"{UiFixture.Auth}/Account/Login");
        await page.ClickAsync(".lang-switch a[lang=en]");
        await Expect(page.Locator("h2")).ToHaveTextAsync("Sign in");
        await Expect(page.Locator("label[for=Login]")).ToHaveTextAsync("Username or email");
        await UiFixture.ShotAsync(page, "03-login-english");
    }

    // ---------- Админка ----------

    /// <summary>Администратор открывает каждый раздел админки и документацию; у каждой страницы ожидаемый заголовок.</summary>
    [Fact]
    public async Task Admin_NavigatesAllSections()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync($"{UiFixture.Auth}/Admin");
        await UiFixture.LoginAsync(page, UiFixture.UiAdmin, UiFixture.UiAdminPassword);
        await Expect(page.Locator("h1")).ToHaveTextAsync("Обзор");
        await UiFixture.ShotAsync(page, "10-admin-dashboard");

        foreach (var (path, title, shot) in new[]
                 {
                     ("/Admin/Apps", "Приложения", "11-admin-apps"),
                     ("/Admin/Apps/Matrix?clientId=demo-node-api", "Матрица доступа", "12-admin-matrix"),
                     ("/Admin/Users", "Пользователи", "13-admin-users"),
                     ("/Admin/Requests", "Заявки на доступ", "14-admin-requests"),
                     ("/Admin/Sessions", "Активные сессии", "15-admin-sessions"),
                     ("/Admin/Webhooks", "События и уведомления", "16-admin-events"),
                     ("/Admin/Audit", "Журнал безопасности", "17-admin-audit"),
                     ("/Admin/Languages", "Языковые пакеты", "18-admin-languages"),
                     ("/Admin/Settings", "Настройки", "19-admin-settings")
                 })
        {
            await page.GotoAsync(UiFixture.Auth + path);
            await Expect(page.Locator("h1")).ToContainTextAsync(title);
            await UiFixture.ShotAsync(page, shot);
        }

        await page.GotoAsync($"{UiFixture.Auth}/docs");
        await Expect(page.Locator("h1")).ToHaveTextAsync("Интеграция с TSL Auth");
        await UiFixture.ShotAsync(page, "20-docs");
    }

    /// <summary>
    /// Регистрация приложения через UI показывает секрет один раз; затем в матрице создаются разрешение и роль,
    /// связь сохраняется, и результат подтверждается через Admin API.
    /// </summary>
    [Fact]
    public async Task Admin_RegistersApp_AndEditsMatrix()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync($"{UiFixture.Auth}/Admin/Apps/Edit");
        await UiFixture.LoginAsync(page, UiFixture.UiAdmin, UiFixture.UiAdminPassword);

        var clientId = Unique("ui-app");
        await page.FillAsync("#NewClientId", clientId);
        await page.FillAsync("#DisplayName", "UI-тест приложение");
        await page.FillAsync("#RedirectUris", "https://ui.local/callback");
        await page.ClickAsync("form button.primary");
        await Expect(page.Locator(".alert.secret")).ToContainTextAsync("Секрет клиента");
        await UiFixture.ShotAsync(page, "21-app-created");

        await page.ClickAsync("text=Матрица доступа →");
        await page.FillAsync("form[action*=AddPermission] input[name=Name]", "docs.read");
        await page.ClickAsync("form[action*=AddPermission] button");
        // Роль: техническое имя (в токенах) + название для пользователей.
        await page.FillAsync("form[action*=AddRole] input[name=Name]", "reader");
        await page.FillAsync("form[action*=AddRole] input[name=DisplayName]", "Читатель документов");
        await page.ClickAsync("form[action*=AddRole] button");
        await Expect(page.Locator("table.matrix")).ToContainTextAsync("Читатель документов");
        await page.CheckAsync("input[value='reader|docs.read']");
        await page.ClickAsync("button[form=matrix]");
        await Expect(page.Locator(".alert.ok")).ToContainTextAsync("Матрица сохранена");
        await UiFixture.ShotAsync(page, "22-matrix-saved");

        // Проверка по API: сообщение в UI не гарантирует, что матрица действительно записана.
        var matrix = await fx.Admin.GetFromJsonAsync<JsonElement>($"/api/admin/applications/{clientId}/matrix");
        Assert.Equal("docs.read", matrix.GetProperty("roles")[0].GetProperty("permissions")[0].GetString());
        Assert.Equal("Читатель документов", matrix.GetProperty("roles")[0].GetProperty("displayName").GetString());
    }

    /// <summary>Пользователь с временным паролем при первом входе обязан сменить его и после смены попадает в личный кабинет.</summary>
    [Fact]
    public async Task TemporaryPassword_ForcesChangeOnFirstLogin()
    {
        var name = Unique("temp");
        await fx.EnsureUserAsync(name, "Temp-Passw0rd-1", [], temporary: true);

        var page = await fx.NewPageAsync();
        await page.GotoAsync($"{UiFixture.Auth}/Account/Login");
        await UiFixture.LoginAsync(page, name, "Temp-Passw0rd-1");
        await Expect(page.Locator(".alert.secret")).ToContainTextAsync(UiFixture.Ru("change.forced"));
        await UiFixture.ShotAsync(page, "30-forced-change");

        await page.FillAsync("#Current", "Temp-Passw0rd-1");
        await page.FillAsync("#Password", "New-Passw0rd-22");
        await page.FillAsync("#Confirm", "New-Passw0rd-22");
        await page.ClickAsync("button.primary");
        await Expect(page).Not.ToHaveURLAsync(new System.Text.RegularExpressions.Regex("ChangePassword"));
        // Без returnUrl и без прав администрирования — личный кабинет, а не «Доступ запрещён» в /Admin.
        await Expect(page).ToHaveURLAsync(new System.Text.RegularExpressions.Regex("/Account$"));
        await Expect(page.Locator(".alert.ok")).ToContainTextAsync(UiFixture.Ru("change.done"));
    }

    // ---------- Демо-приложения на разных стеках ----------

    /// <summary>
    /// SPA входит по Authorization Code + PKCE через брендированную страницу, вызывает API на Node и Go,
    /// проверяет цепочку Go → Node через token exchange и обновление токена.
    /// </summary>
    [Fact]
    public async Task NodeSpa_BrandedLogin_Pkce_ApisAndTokenExchange()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync(UiFixture.Spa);
        await page.ClickAsync("#login");

        // Страница входа в стиле приложения (оформление из админки).
        await Expect(page.Locator(".login-brand h1")).ToHaveTextAsync("Портал заказов");
        await UiFixture.ShotAsync(page, "40-spa-branded-login");
        await UiFixture.LoginAsync(page, "alice", UiFixture.DemoPassword);

        await Expect(page.Locator("#who")).ToContainTextAsync("alice");
        await UiFixture.ShotAsync(page, "41-spa-logged-in");

        await page.ClickAsync("#node");
        await Expect(page.Locator("#out")).ToContainTextAsync("\"status\": 200");
        await page.ClickAsync("#go");
        await Expect(page.Locator("#out")).ToContainTextAsync("Выручка");
        await page.ClickAsync("#chain");
        await Expect(page.Locator("#out")).ToContainTextAsync("\"calledVia\": \"demo-go-api\""); // Node видит, что вызов пришёл через Go
        await UiFixture.ShotAsync(page, "42-spa-token-exchange");

        await page.ClickAsync("#refresh");
        await Expect(page.Locator("#out")).ToContainTextAsync("токен обновлён");
    }

    /// <summary>Пользователь без роли в demo-go-api получает 403 от Go API, хотя Node API ему доступен.</summary>
    [Fact]
    public async Task NodeSpa_UserWithoutRole_GetsForbidden()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync(UiFixture.Spa);
        await page.ClickAsync("#login");
        await UiFixture.LoginAsync(page, "bob", UiFixture.DemoPassword);
        await Expect(page.Locator("#who")).ToContainTextAsync("bob");

        await page.ClickAsync("#node");
        await Expect(page.Locator("#out")).ToContainTextAsync("\"status\": 200");  // viewer в demo-node-api
        await page.ClickAsync("#go");
        await Expect(page.Locator("#out")).ToContainTextAsync("\"status\": 403"); // нет роли в demo-go-api
        await UiFixture.ShotAsync(page, "43-spa-bob-forbidden");
    }

    /// <summary>ASP.NET MVC-пример: вход по OIDC, разрешения из токена в политиках авторизации, вызов Go API и обновление токена.</summary>
    [Fact]
    public async Task DotnetMvc_Oidc_Login_Authorization_Refresh()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync($"{UiFixture.Dotnet}/login");
        await UiFixture.LoginAsync(page, "alice", UiFixture.DemoPassword);
        await Expect(page.Locator("main")).ToContainTextAsync("demo-dotnet:dashboard.view");
        await UiFixture.ShotAsync(page, "50-dotnet-logged-in");

        await page.GotoAsync($"{UiFixture.Dotnet}/dashboard");
        await Expect(page.Locator("main")).ToContainTextAsync("Доступ к панели разрешён");
        await page.GotoAsync($"{UiFixture.Dotnet}/go-reports");
        await Expect(page.Locator("main")).ToContainTextAsync("200");
        // Обновление токена — POST-форма с antiforgery на главной примера (GET /refresh больше не поддерживается).
        await page.GotoAsync($"{UiFixture.Dotnet}/");
        await page.ClickAsync("form[action='/refresh'] button");
        await Expect(page.Locator("main")).ToContainTextAsync("Токен обновлён");
        await UiFixture.ShotAsync(page, "51-dotnet-refresh");
    }

    /// <summary>
    /// Python-пример: вход по password grant с проверкой подписи JWT, создание пользователя через API приложения
    /// (выдаётся временный пароль) и интроспекция токена.
    /// </summary>
    [Fact]
    public async Task Python_PasswordGrant_And_AppApiUserManagement()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync(UiFixture.Python);
        await page.FillAsync("input[name=username]", "alice");
        await page.FillAsync("input[name=password]", UiFixture.DemoPassword);
        await page.ClickAsync("form[action='/login'] button");
        await Expect(page.Locator("main")).ToContainTextAsync("подпись JWT проверена");
        await Expect(page.Locator("main")).ToContainTextAsync("demo-python:tickets.read");

        var newUser = Unique("py");
        await page.FillAsync("form[action='/users/create'] input[name=userName]", newUser);
        await page.SelectOptionAsync("form[action='/users/create'] select[name=role]", "support");
        await page.ClickAsync("form[action='/users/create'] button");
        await Expect(page.Locator(".msg").First).ToContainTextAsync("временный пароль");
        await Expect(page.Locator("table")).ToContainTextAsync(newUser);
        await UiFixture.ShotAsync(page, "60-python-app-api");

        await page.ClickAsync("form[action='/introspect'] button");
        await Expect(page.Locator(".msg").First).ToContainTextAsync("active=True");
    }

    // ---------- Самостоятельная регистрация + одобрение ----------

    /// <summary>
    /// Пользователь регистрируется со страницы входа приложения и запрашивает роль; администратор одобряет заявку,
    /// после чего роль появляется у пользователя (проверяется через Admin API).
    /// </summary>
    [Fact]
    public async Task SelfRegistration_RequestIsApprovedByAdmin()
    {
        var name = Unique("reg");
        var page = await fx.NewPageAsync();
        await page.GotoAsync(UiFixture.Spa);
        await page.ClickAsync("#login");
        await page.ClickAsync("a[href*='/Account/Register']");
        await page.FillAsync("#UserName", name);
        await page.FillAsync("#Password", "Reg-Passw0rd-1");
        await page.FillAsync("#Confirm", "Reg-Passw0rd-1");
        await page.CheckAsync("input[name=Roles][value='demo-node-api|viewer']");
        await page.FillAsync("#Comment", "UI-тест: нужен просмотр заказов");
        await UiFixture.ShotAsync(page, "70-register-form");
        await page.ClickAsync("button.primary");
        await Expect(page.Locator(".alert.ok")).ToContainTextAsync(UiFixture.Ru("register.doneWithRequest"));

        // Администратор работает в отдельном контексте браузера, чтобы не смешивать сессии.
        var admin = await fx.NewPageAsync();
        await admin.GotoAsync($"{UiFixture.Auth}/Admin/Requests");
        await UiFixture.LoginAsync(admin, UiFixture.UiAdmin, UiFixture.UiAdminPassword);
        var row = admin.Locator("tr", new() { HasText = name });
        await UiFixture.ShotAsync(admin, "71-admin-requests");
        await row.Locator("button", new() { HasText = "Одобрить" }).ClickAsync();
        await Expect(admin.Locator(".alert.ok")).ToContainTextAsync("одобрена");

        var user = await fx.Admin.GetFromJsonAsync<JsonElement>($"/api/admin/users?search={name}");
        Assert.Contains(user.GetProperty("items")[0].GetProperty("roles").EnumerateArray(), r => r.GetProperty("role").GetString() == "viewer");
    }

    // ---------- Персональный токен ----------

    /// <summary>
    /// Персональный токен, выпущенный в личном кабинете, обменивается на JWT через /connect/token
    /// и принимается Node API; в конце токен отзывается.
    /// </summary>
    [Fact]
    public async Task PersonalAccessToken_CreatedInUi_WorksForAutomation()
    {
        var page = await fx.NewPageAsync();
        await page.GotoAsync($"{UiFixture.Auth}/Account/Tokens");
        await UiFixture.LoginAsync(page, "alice", UiFixture.DemoPassword);
        var name = Unique("ui-pat");
        await page.FillAsync("#Name", name);
        await page.CheckAsync("input[name=Audiences][value=demo-node-api]");
        await page.ClickAsync("form[action*=Create] button");
        var secret = (await page.Locator("#pat-secret").TextContentAsync())!.Trim();
        Assert.StartsWith("tslpat_", secret);
        await UiFixture.ShotAsync(page, "80-pat-created");

        using var http = new HttpClient();
        var token = await (await http.PostAsync($"{UiFixture.Auth}/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:tsl:grant-type:pat", ["client_id"] = "tsl-pat", ["token"] = secret
        }))).Content.ReadFromJsonAsync<JsonElement>();
        http.DefaultRequestHeaders.Authorization = new("Bearer", token.GetProperty("access_token").GetString());
        var orders = await http.GetAsync($"{UiFixture.Spa}/api/orders");
        Assert.Equal(200, (int)orders.StatusCode); // JWT по PAT принимается Node API

        // Уборка: токен отзывается, иначе повторные прогоны упрутся в лимит активных PAT на пользователя.
        // Кнопка отзыва спрашивает подтверждение через confirm() — принимаем диалог автоматически.
        page.Dialog += (_, dialog) => dialog.AcceptAsync();
        await page.Locator("tr", new() { HasText = name }).Locator("form[action*=Revoke] button").ClickAsync();
        await Expect(page.Locator(".alert.ok")).ToContainTextAsync(UiFixture.Ru("tokens.revoked"));
    }
}
