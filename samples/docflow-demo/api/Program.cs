// Демо «Документооборот» поверх TSL Auth.
//   • Вход — в PWA (authorization code + PKCE, public-клиент docflow-web); сюда приходит access-токен с aud=docflow-api.
//   • Права — только из матрицы docflow-api в TSL Auth: claim permissions = "docflow-api:<разрешение>".
//   • Пользователи и назначение ролей — страница «Пользователи» в PWA → этот API → App API TSL Auth.
//   • Чат с ботом безопасности — /api/chat проксируется в сервис Docflow.Bot (он держит client_credentials бота).
// Этот же процесс раздаёт собранную PWA (wwwroot) и config.js с адресом TSL Auth.
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Docflow.Api;
using Docflow.Shared;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;

// Проверка здоровья для Docker HEALTHCHECK: в distroless-образе нет curl, поэтому проверяет сам процесс.
if (args is ["healthcheck", ..])
{
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
    try { return (await http.GetAsync("http://127.0.0.1:8080/health")).IsSuccessStatusCode ? 0 : 1; }
    catch { return 1; }
}

var builder = WebApplication.CreateBuilder(args);
// Секреты (секрет клиента TSL Auth) — из OpenBao, если задан OpenBao__Address.
Docflow.Shared.OpenBaoConfiguration.Attach(builder.Configuration);
var auth = builder.Configuration.GetSection("Auth").Get<AuthOptions>() ?? new AuthOptions();
var botUrl = builder.Configuration["BotUrl"] ?? "http://localhost:5201/";

builder.Services.AddSingleton(auth);
builder.Services.AddHttpClient();
builder.Services.AddSingleton<TslAuthClient>();
builder.Services.AddHostedService<DemoDataSeeder>();
builder.Services.AddDbContext<DocflowDb>(o => o.UseSqlite(builder.Configuration.GetConnectionString("Docflow") ?? "Data Source=docflow.db"));
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddScoped(sp => CurrentUser.From(sp.GetRequiredService<IHttpContextAccessor>().HttpContext!.User, auth.ClientId));
builder.Services.AddHttpContextAccessor();
// Справочник API: /docs (Scalar) и /openapi/v1.json — какие методы есть, какие разрешения нужны, как вызывать.
builder.Services.AddDemoApiDocs("Docflow API", """
    REST API демо «Документооборот» поверх TSL Auth. Им пользуется PWA; его же можно вызывать из своих сервисов.

    * Токен — access-токен TSL Auth с `aud = docflow-api` (вход в PWA: authorization code + PKCE, клиент `docflow-web`).
    * Права — разрешения матрицы приложения `docflow-api` (claim `permissions`); у каждого метода указано нужное.
    * Ошибки — JSON `{ status, detail }`.
    """, auth.ClientId, new Dictionary<string, string>
{
    ["GET /health"] = "Проверка работоспособности",
    ["GET /config.js"] = "Конфигурация PWA: адрес TSL Auth и client_id",
    ["GET /api/me"] = "Текущий пользователь, его роли и разрешения",
    ["GET /api/me/requests"] = "Мои заявки на роли (саморегистрация)",
    ["GET /api/documents/types"] = "Типы документов",
    ["GET /api/documents"] = "Список документов (фильтры status, search, scope)",
    ["GET /api/documents/{id}"] = "Документ с маршрутом, комментариями и вложениями",
    ["POST /api/documents"] = "Создать черновик",
    ["PUT /api/documents/{id}"] = "Изменить черновик",
    ["DELETE /api/documents/{id}"] = "Удалить черновик",
    ["POST /api/documents/{id}/submit"] = "Отправить на согласование",
    ["POST /api/documents/{id}/decide"] = "Решение по этапу маршрута (согласовать, утвердить, вернуть)",
    ["POST /api/documents/{id}/archive"] = "Отправить в архив",
    ["POST /api/documents/{id}/comments"] = "Добавить комментарий",
    ["POST /api/documents/{id}/attachments"] = "Загрузить вложение (multipart/form-data)",
    ["GET /api/documents/{id}/attachments/{fileId}"] = "Скачать вложение",
    ["DELETE /api/documents/{id}/attachments/{fileId}"] = "Удалить вложение",
    ["GET /api/dashboard"] = "Сводка для панели руководителя",
    ["GET /api/notifications"] = "Мои уведомления",
    ["POST /api/notifications/read"] = "Отметить уведомления прочитанными",
    ["GET /api/directory"] = "Справочник сотрудников (для выбора согласующих)",
    ["GET /api/roles"] = "Роли приложения из матрицы TSL Auth",
    ["GET /api/users"] = "Пользователи приложения (App API TSL Auth)",
    ["GET /api/users/matrix"] = "Матрица доступа приложения",
    ["POST /api/users"] = "Создать пользователя в TSL Auth",
    ["POST /api/users/link"] = "Подключить существующего пользователя TSL Auth",
    ["PUT /api/users/{id}"] = "Изменить профиль пользователя",
    ["PUT /api/users/{id}/roles"] = "Назначить роли пользователю",
    ["DELETE /api/users/{id}"] = "Отключить пользователя от приложения",
    ["POST /api/users/{id}/temporary-password"] = "Выдать временный пароль",
    ["POST /api/users/{id}/invite"] = "Отправить приглашение",
    ["GET /api/users/requests"] = "Заявки на роли (фильтр status)",
    ["POST /api/users/requests/{id}/approve"] = "Одобрить заявку",
    ["POST /api/users/requests/{id}/reject"] = "Отклонить заявку",
    ["GET /api/users/audit"] = "Журнал действий по приложению",
    ["GET /api/chat/{path}"] = "Чат с ботом безопасности (прокси в Docflow.Bot, см. его /docs/api)",
    ["POST /api/chat/{path}"] = "Чат с ботом безопасности: отправить сообщение (прокси в Docflow.Bot)",
    ["DELETE /api/chat/{path}"] = "Чат с ботом безопасности: очистить историю (прокси в Docflow.Bot)",
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    // Ключи — из JWKS TSL Auth (по внутреннему адресу в Docker), issuer — публичный, как в токене.
    o.Authority = auth.Internal;
    o.MetadataAddress = new Uri(new Uri(auth.Internal), ".well-known/openid-configuration").ToString();
    o.RequireHttpsMetadata = auth.Internal.StartsWith("https");
    o.MapInboundClaims = false;
    o.BackchannelHttpHandler = new IssuerRewriteHandler(auth.Issuer, auth.Internal);
    o.TokenValidationParameters.ValidIssuer = auth.Issuer;
    o.TokenValidationParameters.ValidAudience = auth.ClientId;
    o.TokenValidationParameters.ValidAlgorithms = ["RS256"];
    o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
    o.TokenValidationParameters.NameClaimType = "preferred_username";
});
builder.Services.AddAuthorization(o =>
{
    // Каждое разрешение матрицы — политика с тем же именем.
    foreach (var p in new[] { "documents.view", "documents.create", "documents.review", "documents.approve", "documents.archive", "dashboard.view", "users.manage" })
        o.AddPolicy(p, policy => policy.RequireClaim("permissions", $"{auth.ClientId}:{p}"));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<DocflowDb>().Database.EnsureCreated();

// Ошибки бизнес-логики и App API → ProblemDetails с понятным текстом для PWA.
app.UseExceptionHandler(e => e.Run(async ctx =>
{
    var ex = ctx.Features.Get<IExceptionHandlerFeature>()?.Error;
    var (status, detail) = ex switch
    {
        ApiException a => (a.Status, a.Message),
        TslAuthException t => (t.Status == 401 ? 502 : t.Status, t.Message),
        HttpRequestException => (502, "TSL Auth недоступен"),
        _ => (500, "Внутренняя ошибка")
    };
    if (status >= 500) ctx.RequestServices.GetRequiredService<ILogger<Program>>().LogError(ex, "Ошибка {Path}", ctx.Request.Path);
    ctx.Response.StatusCode = status;
    await ctx.Response.WriteAsJsonAsync(new { status, detail });
}));

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => "ok");
app.MapDemoApiDocs("Docflow API");

// Конфигурация PWA: адрес TSL Auth и client_id задаются в окружении контейнера, а не при сборке фронта.
app.MapGet("/config.js", () => Results.Text(
    $"window.DOCFLOW_CONFIG = {JsonSerializer.Serialize(new { issuer = auth.Issuer, clientId = auth.WebClientId, apiClientId = auth.ClientId })};",
    "application/javascript"));

app.MapGet("/api/me", (CurrentUser me) => me).RequireAuthorization();

// Мои заявки на роли (саморегистрация): пользователь без ролей видит, что заявка на рассмотрении.
// Доступно без разрешений матрицы — только вошедшему пользователю и только про него самого.
app.MapGet("/api/me/requests", async (CurrentUser me, TslAuthClient auth, CancellationToken ct) =>
{
    var all = await auth.CallAsync(HttpMethod.Get, "/access-requests", ct: ct);
    return all.EnumerateArray()
        .Where(r => r.GetProperty("userId").GetGuid() == me.Id)
        .Select(r => new
        {
            role = r.GetProperty("role").GetString(),
            roleTitle = r.TryGetProperty("roleTitle", out var t) ? t.GetString() : r.GetProperty("role").GetString(),
            status = r.GetProperty("status").GetString()?.ToLowerInvariant(),
            createdAt = r.GetProperty("createdAt").GetDateTime(),
            decisionComment = r.TryGetProperty("decisionComment", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null
        })
        .OrderByDescending(r => r.createdAt)
        .ToList();
}).RequireAuthorization();
app.MapDocuments();
app.MapUsers();

// Чат с ботом: пересылаем запрос с тем же access-токеном пользователя — бот сам проверяет подпись
// и берёт из токена sub (это externalId отправителя в «мессенджере» docflow-chat).
app.MapMethods("/api/chat/{**path}", ["GET", "POST", "DELETE"], async (HttpContext ctx, string? path, IHttpClientFactory http) =>
{
    var client = http.CreateClient();
    using var request = new HttpRequestMessage(new HttpMethod(ctx.Request.Method), new Uri(new Uri(botUrl), $"chat/{path}{ctx.Request.QueryString}"));
    if (ctx.Request.Headers.Authorization.Count > 0)
        request.Headers.Authorization = AuthenticationHeaderValue.Parse(ctx.Request.Headers.Authorization!);
    if (ctx.Request.ContentLength > 0 || ctx.Request.Headers.TransferEncoding.Count > 0)
    {
        request.Content = new StreamContent(ctx.Request.Body);
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(ctx.Request.ContentType ?? "application/json");
    }
    try
    {
        using var response = await client.SendAsync(request, ctx.RequestAborted);
        ctx.Response.StatusCode = (int)response.StatusCode;
        ctx.Response.ContentType = response.Content.Headers.ContentType?.ToString() ?? "application/json";
        await response.Content.CopyToAsync(ctx.Response.Body, ctx.RequestAborted);
    }
    catch (HttpRequestException)
    {
        ctx.Response.StatusCode = 502;
        await ctx.Response.WriteAsJsonAsync(new { status = 502, detail = "Бот недоступен" });
    }
}).RequireAuthorization();

// SPA-маршруты (/documents/…, /users) отдаём index.html; /api/* сюда не попадает.
app.MapFallbackToFile("index.html");

app.Run();
return 0;
