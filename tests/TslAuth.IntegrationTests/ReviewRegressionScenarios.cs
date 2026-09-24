using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using TslAuth.Data;
using TslAuth.IntegrationTests.Infrastructure;
using TslAuth.Services;

namespace TslAuth.IntegrationTests;

/// <summary>
/// Регрессионные тесты по отчёту ревизии кода (docs/code-review-2026-09-24.md): каждый тест воспроизводит
/// найденный дефект и проверяет исправление. Выполняются на SQLite и PostgreSQL — часть дефектов
/// (время без зоны, длины столбцов, регистр ключей) проявлялась только на PostgreSQL.
/// </summary>
public abstract class ReviewRegressionScenarios<TFixture>(TFixture fx) where TFixture : AuthFixture
{
    private static readonly string Password = TestApi.NewPassword();

    // ---------- H1: ссылки в письмах не зависят от заголовка Host ----------

    [Fact]
    public async Task H1_InviteLink_UsesIssuer_NotHostHeader()
    {
        var admin = await fx.Factory.AdminAsync();
        var name = TestApi.Unique("h1");
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/admin/users?invite=true")
        {
            Content = JsonContent.Create(new { userName = name, email = $"{name}@it.local" })
        };
        request.Headers.Host = "evil.example"; // Host-header poisoning
        var created = await (await admin.SendAsync(request)).JsonAsync();
        var link = created.GetProperty("invite").GetProperty("link").GetString()!;
        Assert.StartsWith("http://localhost/Account/", link);
        Assert.DoesNotContain("evil.example", link);
    }

    // ---------- H2: уникальный email, логин не занимает чужой адрес, дубликаты из старых БД не роняют вход ----------

    [Fact]
    public async Task H2_Email_IsUnique_AndLoginCannotSquatForeignEmail()
    {
        var admin = await fx.Factory.AdminAsync();
        var victim = TestApi.Unique("victim");
        var victimEmail = $"{victim}@it.local";
        await admin.PostJsonAsync("/api/admin/users", new { userName = victim, email = victimEmail, password = Password });

        // Тот же email у другой учётной записи — отказ.
        var sameEmail = await admin.PostAsJsonAsync("/api/admin/users",
            new { userName = TestApi.Unique("attacker"), email = victimEmail, password = Password });
        Assert.Equal(HttpStatusCode.BadRequest, sameEmail.StatusCode);

        // Логин, равный чужому email, — отказ; логин, равный собственному email, — можно.
        var squat = await admin.PostAsJsonAsync("/api/admin/users",
            new { userName = victimEmail, email = $"{TestApi.Unique("other")}@it.local", password = Password });
        Assert.Equal(HttpStatusCode.BadRequest, squat.StatusCode);
        var own = $"{TestApi.Unique("own")}@it.local";
        await admin.PostJsonAsync("/api/admin/users", new { userName = own, email = own, password = Password });

        // Ошибка несёт ключ локализации для пользовательских страниц.
        using var scope = fx.Factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        var ex = await Assert.ThrowsAsync<AdminException>(() =>
            users.CreateAsync(new UserInput(TestApi.Unique("dup"), victimEmail, null, true, Password)));
        Assert.Equal("error.emailTaken", ex.Key);
    }

    [Fact]
    public async Task H2_LegacyDuplicateEmails_DoNotBreakLogin()
    {
        var admin = await fx.Factory.AdminAsync();
        var client = TestApi.Unique("h2web");
        await admin.PostJsonAsync("/api/admin/applications",
            new { clientId = client, clientType = "public", grantTypes = new[] { "password" }, scopes = new[] { "profile" } });
        var email = $"{TestApi.Unique("legacy")}@it.local";
        var first = TestApi.Unique("first");
        var second = TestApi.Unique("second");
        await admin.PostJsonAsync("/api/admin/users", new { userName = first, email, password = Password });
        var created = await admin.PostJsonAsync("/api/admin/users",
            new { userName = second, email = $"{second}@it.local", password = Password });

        // Дубликат, как в БД старой версии (без проверки уникальности), — напрямую, мимо валидатора.
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var user = await db.Users.FirstAsync(u => u.Id == created.GetProperty("user").GetProperty("id").GetGuid());
            user.Email = email;
            user.NormalizedEmail = email.ToUpperInvariant();
            await db.SaveChangesAsync();
        }

        // Поиск по email неоднозначен → «не найден» (400 invalid_grant), а не 500; вход по логину работает.
        var http = fx.Factory.CreateClient();
        var byEmail = await http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = email, ["password"] = Password
        }));
        Assert.True(byEmail.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden, $"{(int)byEmail.StatusCode}");
        var byLogin = await http.TokenAsync(new()
        {
            ["grant_type"] = "password", ["client_id"] = client, ["username"] = first, ["password"] = Password
        });
        Assert.True(byLogin.TryGetProperty("access_token", out _));
        var forgot = await http.GetAsync("/Account/ForgotPassword");
        Assert.Equal(HttpStatusCode.OK, forgot.StatusCode);
        using (var scope = fx.Factory.Services.CreateScope())
            Assert.NotNull(await scope.ServiceProvider.GetRequiredService<UserService>().FindByLoginAsync(first));
    }

    // ---------- H3: SSE-поток не обрывается на пульсе ----------

    [Fact]
    public async Task H3_EventStream_SurvivesHeartbeat()
    {
        var admin = await fx.Factory.AdminAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/events/stream");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        using var response = await admin.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
        response.EnsureSuccessStatusCode();
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(cts.Token));

        // Пульс приходит примерно раз в 15 с; до исправления сериализация пульса обрывала поток.
        string? pingData = null;
        while (pingData is null && await reader.ReadLineAsync(cts.Token) is { } line)
            if (line == "event: ping") pingData = await reader.ReadLineAsync(cts.Token);
        Assert.NotNull(pingData);
        Assert.StartsWith("data: ", pingData);
        using var ping = JsonDocument.Parse(pingData!["data: ".Length..]);
        Assert.Equal(JsonValueKind.Object, ping.RootElement.GetProperty("data").ValueKind);
    }

    // ---------- H4: ошибки валидации API не пишутся в журнал как сбой ----------

    [Fact]
    public async Task H4_ValidationError_IsAuditedWithItsStatus_NotAsFailure()
    {
        var admin = await fx.Factory.AdminAsync();
        var app = TestApi.Unique("h4");
        await admin.PostJsonAsync("/api/admin/applications", new { clientId = app, clientType = "public", grantTypes = Array.Empty<string>() });
        var bad = await admin.PostAsJsonAsync($"/api/admin/applications/{app}/roles", new { name = "Bad Name" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);

        var audit = await admin.GetJsonAsync($"/api/admin/audit?type={AuditTypes.AdminChange}&clientId={app}");
        var entry = audit.EnumerateArray().First(e => e.GetProperty("details").GetProperty("path").GetString()!.EndsWith("/roles"));
        Assert.Equal(400, entry.GetProperty("details").GetProperty("status").GetInt32());
        Assert.False(entry.GetProperty("success").GetBoolean());
        Assert.Equal("info", entry.GetProperty("severity").GetString());
    }

    // ---------- H5: фильтр журнала по датам (время без зоны) ----------

    [Fact]
    public async Task H5_AuditDateFilter_WorksWithoutTimeZone()
    {
        var admin = await fx.Factory.AdminAsync();
        var from = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss");
        var to = DateTime.UtcNow.AddDays(1).ToString("yyyy-MM-ddTHH:mm:ss");
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync($"/api/admin/audit?from={from}&to={to}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync($"/api/admin/audit.csv?from={from}&to={to}")).StatusCode);
        var entries = await admin.GetJsonAsync($"/api/admin/audit?from={from}&to={to}&take=5");
        Assert.True(entries.GetArrayLength() > 0);
    }

    // ---------- H6: коды языков, различающиеся регистром, не роняют сервис ----------

    [Fact]
    public async Task H6_LanguageCodes_AreCanonical_AndCaseDuplicatesDoNotBreakPages()
    {
        var admin = await fx.Factory.AdminAsync();
        var strings = new Dictionary<string, string> { ["_name"] = "Kazakh" };
        await admin.PutJsonAsync("/api/admin/languages/KK", new { name = "Қазақша", strings });
        await admin.PutJsonAsync("/api/admin/languages/kk", new { name = "Қазақша", strings });

        var languages = await admin.GetJsonAsync("/api/admin/languages");
        Assert.Single(languages.EnumerateArray(), l => string.Equals(l.GetProperty("culture").GetString(), "kk", StringComparison.OrdinalIgnoreCase));

        // Дубликат по регистру, как в БД старой версии, — напрямую; затем сброс кэша сохранением другого пакета.
        using (var scope = fx.Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.LanguagePacks.Add(new LanguagePack { Culture = "KK", Name = "legacy", Json = "{\"_name\":\"legacy\"}", IsEnabled = true });
            await db.SaveChangesAsync();
        }
        await admin.PutJsonAsync("/api/admin/languages/uz-latn", new { name = "Oʻzbekcha", strings });

        Assert.Equal(HttpStatusCode.OK, (await fx.Factory.CreateClient().GetAsync("/Account/Login")).StatusCode);
        Assert.Contains((await admin.GetJsonAsync("/api/admin/languages")).EnumerateArray(),
            l => l.GetProperty("culture").GetString() == "uz-Latn");
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync("/api/admin/languages/kk")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await fx.Factory.CreateClient().GetAsync("/Account/Login")).StatusCode);
    }
}

/// <summary>Регрессионные тесты ревизии на SQLite.</summary>
[Collection("sqlite-review")]
public sealed class SqliteReviewRegression(SqliteFixture fx) : ReviewRegressionScenarios<SqliteFixture>(fx), IClassFixture<SqliteFixture>;

/// <summary>Регрессионные тесты ревизии на PostgreSQL.</summary>
[Collection("postgres-review")]
public sealed class PostgresReviewRegression(PostgresFixture fx) : ReviewRegressionScenarios<PostgresFixture>(fx), IClassFixture<PostgresFixture>;

/// <summary>H1: без Issuer сервис вне Development не стартует (проверка конфигурации при запуске).</summary>
[Collection("sqlite-review")]
public sealed class IssuerStartupCheck
{
    [Fact]
    public void H1_ServiceRefusesToStart_WithoutIssuer_OutsideDevelopment()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Production");
            b.UseSetting("Auth:Issuer", "");
            b.UseSetting("Encryption:MasterKey", AuthFixture.MasterKey);
        });
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("Auth:Issuer", (ex.InnerException ?? ex).Message + ex.Message);
    }
}
