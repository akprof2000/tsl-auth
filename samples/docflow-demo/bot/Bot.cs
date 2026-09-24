using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Docflow.Bot;

public sealed class BotOptions
{
    public string Issuer { get; set; } = "http://localhost:8080/";
    public string? InternalUrl { get; set; }
    /// <summary>Аудитория токенов PWA, которыми пользователь представляется боту.</summary>
    public string Audience { get; set; } = "docflow-api";
    public string BotClientId { get; set; } = "docflow-security-bot";
    public string BotClientSecret { get; set; } = "";
    /// <summary>Имя «мессенджера» в привязках TSL Auth.</summary>
    public string Provider { get; set; } = "docflow-chat";
    public string Internal => string.IsNullOrEmpty(InternalUrl) ? Issuer : InternalUrl;
}

/// <summary>Ответ Bot API: успех с JSON или ошибка с текстом из ProblemDetails.</summary>
public sealed record BotApiResult(bool Ok, int Status, JsonElement Body, string? Error);

/// <summary>Клиент Bot API TSL Auth: токен бота (client_credentials) кэшируется до истечения.</summary>
public sealed class AuthBotClient(IHttpClientFactory http, BotOptions options, ILogger<AuthBotClient> log)
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _token;
    private DateTime _expires;

    private async Task<string> TokenAsync(CancellationToken ct)
    {
        if (_token is not null && DateTime.UtcNow < _expires) return _token;
        await _lock.WaitAsync(ct);
        try
        {
            if (_token is not null && DateTime.UtcNow < _expires) return _token;
            var response = await http.CreateClient().PostAsync(new Uri(new Uri(options.Internal), "connect/token"),
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials", ["client_id"] = options.BotClientId,
                    ["client_secret"] = options.BotClientSecret, ["scope"] = "tsl-auth-admin"
                }), ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Токен бота не выдан: {body}");
            var json = JsonDocument.Parse(body).RootElement;
            _token = json.GetProperty("access_token").GetString();
            _expires = DateTime.UtcNow.AddSeconds(json.GetProperty("expires_in").GetInt32() - 60);
            return _token!;
        }
        finally { _lock.Release(); }
    }

    /// <summary>POST /api/bot/{action}: отправитель всегда передаётся как provider + externalId.</summary>
    public async Task<BotApiResult> CallAsync(string action, string externalId, object? extra = null, CancellationToken ct = default)
    {
        var payload = new Dictionary<string, object?> { ["provider"] = options.Provider, ["externalId"] = externalId };
        if (extra is not null)
            foreach (var p in extra.GetType().GetProperties()) payload[p.Name] = p.GetValue(extra);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(options.Internal), $"api/bot/{action}"))
            {
                Content = JsonContent.Create(payload)
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await TokenAsync(ct));
            using var response = await http.CreateClient().SendAsync(request, ct);
            var text = await response.Content.ReadAsStringAsync(ct);
            var body = text.Length > 0 ? JsonDocument.Parse(text).RootElement.Clone() : default;
            if (response.IsSuccessStatusCode) return new(true, (int)response.StatusCode, body, null);
            var error = body.ValueKind == JsonValueKind.Object && body.TryGetProperty("detail", out var d) ? d.GetString() : null;
            if ((int)response.StatusCode == 403 && error is null)
                error = "У бота нет разрешения на это действие в TSL Auth (нужна роль security-bot).";
            if ((int)response.StatusCode is 404 or 405 && error is null)
                error = "Эта версия TSL Auth не поддерживает команду: обновите образ до версии с расширенным Bot API.";
            return new(false, (int)response.StatusCode, body, error ?? $"Ошибка TSL Auth ({(int)response.StatusCode})");
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException)
        {
            log.LogWarning(ex, "Bot API {Action} недоступен", action);
            return new(false, 503, default, "TSL Auth сейчас недоступен, попробуйте позже.");
        }
    }
}

/// <summary>
/// Разбор команд чата. Понимает слэш-команды и простые фразы по-русски («заблокируй ivan», «сменить пароль»).
/// Разрушительные действия (блокировка, смена пароля) требуют подтверждения кнопкой в течение 2 минут.
/// </summary>
public sealed partial class CommandHandler(AuthBotClient api, BotOptions options)
{
    private sealed record Pending(string Action, string? Target, DateTime Expires);
    private readonly ConcurrentDictionary<string, Pending> _pending = new();

    private string Cabinet => new Uri(new Uri(options.Issuer), "Account/Messenger").ToString();

    public async Task<ChatMessage> WelcomeAsync(Sender sender, CancellationToken ct)
    {
        var who = await api.CallAsync("whois", sender.Sub, ct: ct);
        if (who.Ok && who.Body.GetProperty("linked").GetBoolean())
            return ChatMessage.Bot($"Здравствуйте! Чат привязан к учётной записи **{who.Body.GetProperty("userName").GetString()}**. " +
                                   "Я помогу со сбросом пароля и блокировкой учётных записей.", buttons: MainButtons());
        return ChatMessage.Bot("Здравствуйте! Я бот безопасности TSL Auth. Чтобы я мог действовать от вашего имени, привяжите чат: " +
                               "получите код в личном кабинете и отправьте мне `/link КОД`.", "info",
            [new("Получить код привязки", Url: Cabinet, Style: "primary"), new("Что ты умеешь?", "/help")]);
    }

    public async Task<IReadOnlyList<ChatMessage>> HandleAsync(Sender sender, string text, CancellationToken ct)
    {
        var (command, arg) = Parse(text);
        return command switch
        {
            "help" => [Help()],
            "whoami" => [await WhoAmIAsync(sender, ct)],
            "link" => [await LinkAsync(sender, arg, ct)],
            "unlink" => [await SimpleAsync(sender, "unlink", ct)],
            "reset" => [await ResetAsync(sender, ct)],
            "lock" or "unlock" or "forcepwd" => [Ask(sender, command, arg)],
            "confirm" => [await ConfirmAsync(sender, ct)],
            "cancel" => [Cancel(sender)],
            _ => [ChatMessage.Bot("Не понял команду. Вот что я умею:", buttons: MainButtons()), Help()]
        };
    }

    // ---------- Команды ----------

    private ChatMessage Help() => ChatMessage.Bot(
        """
        **Команды**
        `/link КОД` — привязать чат к учётной записи (код — в личном кабинете TSL Auth)
        `/whoami` — к какой учётной записи привязан чат
        `/reset` — сбросить свой пароль (одноразовая ссылка)
        `/forcepwd` — потребовать смену своего пароля и завершить все сеансы
        `/lock` — срочно заблокировать свою учётную запись (например, украли телефон)
        `/unlink` — отвязать чат

        **Для офицера безопасности** (роль security-officer в TSL Auth)
        `/lock логин` — заблокировать учётную запись сотрудника
        `/unlock логин` — разблокировать
        `/forcepwd логин` — принудительно сменить пароль
        """, "help", MainButtons());

    private static List<ChatButton> MainButtons() =>
    [
        new("Кто я?", "/whoami"), new("Сбросить пароль", "/reset"),
        new("Сменить пароль принудительно", "/forcepwd"), new("Заблокировать себя", "/lock", Style: "danger")
    ];

    private async Task<ChatMessage> WhoAmIAsync(Sender sender, CancellationToken ct)
    {
        var r = await api.CallAsync("whois", sender.Sub, ct: ct);
        if (!r.Ok) return Error(r);
        return r.Body.GetProperty("linked").GetBoolean()
            ? ChatMessage.Bot($"Чат привязан к учётной записи **{r.Body.GetProperty("userName").GetString()}**.", "success")
            : ChatMessage.Bot("Чат ещё не привязан. Получите код в личном кабинете и отправьте `/link КОД`.", "info",
                [new("Получить код привязки", Url: Cabinet, Style: "primary")]);
    }

    private async Task<ChatMessage> LinkAsync(Sender sender, string? code, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(code))
            return ChatMessage.Bot("Отправьте код вместе с командой: `/link K7Q2M9XA`.", "info", [new("Получить код привязки", Url: Cabinet, Style: "primary")]);
        var r = await api.CallAsync("link", sender.Sub, new { code }, ct);
        if (!r.Ok) return Error(r);
        var who = await api.CallAsync("whois", sender.Sub, ct: ct);
        var name = who.Ok && who.Body.GetProperty("linked").GetBoolean() ? who.Body.GetProperty("userName").GetString() : "учётной записи";
        return ChatMessage.Bot($"Готово! Чат привязан к **{name}**.", "success", MainButtons());
    }

    private async Task<ChatMessage> SimpleAsync(Sender sender, string action, CancellationToken ct)
    {
        var r = await api.CallAsync(action, sender.Sub, ct: ct);
        if (!r.Ok) return Error(r);
        return r.Body.GetProperty("unlinked").GetBoolean()
            ? ChatMessage.Bot("Чат отвязан. Команды от вашего имени больше не выполняются.", "success")
            : ChatMessage.Bot("Чат и так не был привязан.", "info");
    }

    private async Task<ChatMessage> ResetAsync(Sender sender, CancellationToken ct)
    {
        var r = await api.CallAsync("password-reset", sender.Sub, ct: ct);
        if (!r.Ok) return Error(r);
        var expires = r.Body.GetProperty("expiresAt").GetDateTime().ToLocalTime().ToString("HH:mm dd.MM");
        if (r.Body.GetProperty("mode").GetString() == "temporary")
            return ChatMessage.Bot($"Временный пароль для **{r.Body.GetProperty("userName").GetString()}** (действует до {expires}, при входе попросят сменить):",
                "secret", secret: r.Body.GetProperty("temporaryPassword").GetString());
        return ChatMessage.Bot($"Одноразовая ссылка для сброса пароля (действует до {expires}). Никому её не пересылайте.", "success",
            [new("Задать новый пароль", Url: r.Body.GetProperty("resetLink").GetString(), Style: "primary")]);
    }

    /// <summary>Разрушительная команда: сначала спрашиваем подтверждение.</summary>
    private ChatMessage Ask(Sender sender, string action, string? target)
    {
        if (action == "unlock" && string.IsNullOrWhiteSpace(target))
            return ChatMessage.Bot("Укажите, кого разблокировать: `/unlock логин`. Свою учётную запись разблокирует администратор.", "info");
        _pending[sender.Sub] = new Pending(action, string.IsNullOrWhiteSpace(target) ? null : target.Trim(), DateTime.UtcNow.AddMinutes(2));
        var whom = target is null ? "**вашу** учётную запись" : $"учётную запись **{target}**";
        var text = action switch
        {
            "lock" => target is null
                ? "Заблокировать вашу учётную запись? Все сеансы завершатся, войти снова можно будет только после разблокировки администратором."
                : $"Заблокировать {whom}? Все её сеансы будут завершены.",
            "unlock" => $"Разблокировать {whom}?",
            _ => $"Потребовать смену пароля {(target is null ? "для вашей учётной записи" : $"у **{target}**")}? Все сеансы завершатся, при следующем входе нужно будет задать новый пароль."
        };
        return ChatMessage.Bot(text, "confirm",
            [new("Подтвердить", "/confirm", Style: action == "unlock" ? "primary" : "danger"), new("Отмена", "/cancel")]);
    }

    private async Task<ChatMessage> ConfirmAsync(Sender sender, CancellationToken ct)
    {
        if (!_pending.TryRemove(sender.Sub, out var p) || p.Expires < DateTime.UtcNow)
            return ChatMessage.Bot("Нет действия, ожидающего подтверждения (или прошло больше 2 минут).", "info");
        var r = await api.CallAsync(p.Action == "forcepwd" ? "force-password-change" : p.Action, sender.Sub, new { target = p.Target }, ct);
        if (!r.Ok) return Error(r);
        var user = r.Body.GetProperty("userName").GetString();
        var self = r.Body.GetProperty("self").GetBoolean();
        var changed = r.Body.GetProperty("changed").GetBoolean();
        return p.Action switch
        {
            "lock" when !changed => ChatMessage.Bot($"Учётная запись **{user}** уже заблокирована.", "info"),
            "lock" => ChatMessage.Bot(self
                ? "Ваша учётная запись заблокирована, все сеансы завершены. Для разблокировки обратитесь к администратору."
                : $"🔒 Учётная запись **{user}** заблокирована, сеансы завершены.", "success"),
            "unlock" when !changed => ChatMessage.Bot($"Учётная запись **{user}** и так активна.", "info"),
            "unlock" => ChatMessage.Bot($"🔓 Учётная запись **{user}** разблокирована.", "success"),
            _ => ChatMessage.Bot(self
                ? "Готово: все сеансы завершены, при следующем входе нужно будет задать новый пароль."
                : $"🔑 Для **{user}** потребована смена пароля, сеансы завершены.", "success")
        };
    }

    private ChatMessage Cancel(Sender sender) =>
        _pending.TryRemove(sender.Sub, out _) ? ChatMessage.Bot("Отменено.", "info") : ChatMessage.Bot("Отменять нечего.", "info");

    private static ChatMessage Error(BotApiResult r) =>
        ChatMessage.Bot(r.Status == 404 && r.Error?.Contains("Привязка") == true
            ? "Сначала привяжите чат к учётной записи: `/link КОД` (код — в личном кабинете TSL Auth)."
            : r.Error ?? "Ошибка", "error");

    // ---------- Разбор текста ----------

    private static (string Command, string? Arg) Parse(string text)
    {
        var t = text.Trim();
        if (t.StartsWith('/'))
        {
            var parts = t[1..].Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var cmd = parts.Length > 0 ? parts[0].ToLowerInvariant() : "";
            return (cmd switch { "start" => "help", "force" or "forcepassword" or "force-password" => "forcepwd", _ => cmd }, parts.ElementAtOrDefault(1));
        }
        var lower = t.ToLowerInvariant();
        if (lower is "да" or "подтверждаю" or "ок") return ("confirm", null);
        if (lower is "нет" or "отмена") return ("cancel", null);
        if (Code().Match(t) is { Success: true } code) return ("link", code.Value);
        Match m;
        if ((m = Unlock().Match(lower)).Success) return ("unlock", m.Groups[1].Value.NullIfEmpty());
        if ((m = Lock().Match(lower)).Success) return ("lock", m.Groups[1].Value.NullIfEmpty());
        if ((m = Force().Match(lower)).Success) return ("forcepwd", m.Groups[1].Value.NullIfEmpty());
        if (lower.Contains("сброс") || lower.Contains("забыл")) return ("reset", null);
        if (lower.Contains("кто я")) return ("whoami", null);
        if (lower.Contains("помощ") || lower.Contains("умеешь") || lower.Contains("привет")) return ("help", null);
        return ("", null);
    }

    [GeneratedRegex(@"^[A-HJ-NP-Z2-9]{8}$")] private static partial Regex Code();
    [GeneratedRegex(@"разблок\w*\s*(?:учётк\w*|учетк\w*|пользовател\w*)?\s*([\w.@-]*)")] private static partial Regex Unlock();
    [GeneratedRegex(@"заблок\w*\s*(?:учётк\w*|учетк\w*|пользовател\w*|меня|себя)?\s*([\w.@-]*)")] private static partial Regex Lock();
    [GeneratedRegex(@"(?:смен\w*|поменя\w*)\s+парол\w*\s*(?:для|у)?\s*([\w.@-]*)")] private static partial Regex Force();
}

internal static class StringExtensions
{
    public static string? NullIfEmpty(this string s) => s.Length == 0 ? null : s;
}
