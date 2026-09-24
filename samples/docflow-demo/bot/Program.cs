// Демо-бот безопасности для TSL Auth: «мессенджер» — встроенный чат PWA документооборота.
//
// Как это устроено:
//   • Бот — confidential-клиент docflow-security-bot с ролью security-bot в tsl-auth-admin
//     (разрешения password_reset, user_lock, password_force). Токен: client_credentials, scope tsl-auth-admin.
//   • Отправитель сообщения определяется по access-токену пользователя PWA (подпись проверяется по JWKS):
//     provider = "docflow-chat", externalId = sub. Так же бот Mattermost использовал бы user_id отправителя.
//   • Сначала пользователь привязывает чат к учётной записи: код из личного кабинета TSL Auth → /link КОД.
//   • Над собой команды доступны всем; над другими — только пользователям с ролью security-officer
//     (это решает TSL Auth по своей матрице, бот права не проверяет и не хранит).
using System.Collections.Concurrent;
using Docflow.Bot;
using Microsoft.AspNetCore.Authentication.JwtBearer;

// Проверка здоровья для Docker HEALTHCHECK: в distroless-образе нет curl, поэтому проверяет сам процесс.
if (args is ["healthcheck", ..])
{
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
    try { return (await http.GetAsync("http://127.0.0.1:8080/health")).IsSuccessStatusCode ? 0 : 1; }
    catch { return 1; }
}

var builder = WebApplication.CreateBuilder(args);
var options = builder.Configuration.GetSection("Auth").Get<BotOptions>() ?? new BotOptions();
builder.Services.AddSingleton(options);
builder.Services.AddHttpClient();
builder.Services.AddSingleton<AuthBotClient>();
builder.Services.AddSingleton<ChatStore>();
builder.Services.AddSingleton<CommandHandler>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.Authority = options.Internal;
    o.MetadataAddress = new Uri(new Uri(options.Internal), ".well-known/openid-configuration").ToString();
    o.RequireHttpsMetadata = options.Internal.StartsWith("https");
    o.MapInboundClaims = false;
    o.BackchannelHttpHandler = new IssuerRewriteHandler(options.Issuer, options.Internal);
    o.TokenValidationParameters.ValidIssuer = options.Issuer;
    o.TokenValidationParameters.ValidAudience = options.Audience;
    o.TokenValidationParameters.ValidAlgorithms = ["RS256"];
});
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => "ok");

var chat = app.MapGroup("/chat").RequireAuthorization();

// История чата текущего пользователя; при первом открытии бот здоровается.
chat.MapGet("/history", async (HttpContext ctx, ChatStore store, CommandHandler bot) =>
{
    var sender = Sender.From(ctx.User);
    var history = store.Get(sender.Sub);
    if (history.Count == 0) store.Add(sender.Sub, await bot.WelcomeAsync(sender, ctx.RequestAborted));
    return store.Get(sender.Sub);
});

chat.MapPost("/messages", async (HttpContext ctx, IncomingMessage input, ChatStore store, CommandHandler bot) =>
{
    var sender = Sender.From(ctx.User);
    var text = (input.Text ?? "").Trim();
    if (text.Length == 0 || text.Length > 500) return Results.BadRequest(new { detail = "Пустое или слишком длинное сообщение" });
    var mine = ChatMessage.FromUser(text);
    store.Add(sender.Sub, mine);
    var replies = await bot.HandleAsync(sender, text, ctx.RequestAborted);
    foreach (var r in replies) store.Add(sender.Sub, r);
    return Results.Ok(new[] { mine }.Concat(replies));
});

chat.MapDelete("/history", (HttpContext ctx, ChatStore store) =>
{
    store.Clear(Sender.From(ctx.User).Sub);
    return Results.NoContent();
});

app.Run();
return 0;

namespace Docflow.Bot
{
    public sealed record IncomingMessage(string? Text);

    /// <summary>Кнопка быстрого ответа: <c>Send</c> — текст, который PWA отправит боту; <c>Url</c> — ссылка.</summary>
    public sealed record ChatButton(string Label, string? Send = null, string? Url = null, string Style = "default");

    public sealed record ChatMessage(Guid Id, string From, string Text, DateTime At, string Kind, IReadOnlyList<ChatButton> Buttons, string? Secret = null)
    {
        public static ChatMessage FromUser(string text) => new(Guid.NewGuid(), "user", text, DateTime.UtcNow, "text", []);
        public static ChatMessage Bot(string text, string kind = "text", IReadOnlyList<ChatButton>? buttons = null, string? secret = null) =>
            new(Guid.NewGuid(), "bot", text, DateTime.UtcNow, kind, buttons ?? [], secret);
    }

    /// <summary>Отправитель: sub и имя из проверенного access-токена PWA.</summary>
    public sealed record Sender(string Sub, string Name)
    {
        public static Sender From(System.Security.Claims.ClaimsPrincipal p) =>
            new(p.FindFirst("sub")!.Value, p.FindFirst("name")?.Value ?? p.FindFirst("preferred_username")?.Value ?? "?");
    }

    /// <summary>История чатов в памяти процесса (демо; последние 100 сообщений на пользователя).</summary>
    public sealed class ChatStore
    {
        private readonly ConcurrentDictionary<string, List<ChatMessage>> _chats = new();

        public List<ChatMessage> Get(string sub)
        {
            var list = _chats.GetOrAdd(sub, _ => []);
            lock (list) return [.. list];
        }

        public void Add(string sub, ChatMessage message)
        {
            var list = _chats.GetOrAdd(sub, _ => []);
            lock (list)
            {
                list.Add(message);
                if (list.Count > 100) list.RemoveRange(0, list.Count - 100);
            }
        }

        public void Clear(string sub) => _chats.TryRemove(sub, out _);
    }
}
