using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using TslAuth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TslAuth.Services;

/// <summary>
/// Коды типов событий аудита. Префикс (auth., token., password. …) используется для фильтрации
/// в журнале и для правил срока хранения в настройках.
/// </summary>
public static class AuditTypes
{
    public const string LoginSucceeded = "auth.login.succeeded";
    public const string LoginFailed = "auth.login.failed";
    public const string LockedOut = "auth.locked_out";
    public const string Logout = "auth.logout";
    public const string TokenIssued = "token.issued";
    public const string TokenRejected = "token.rejected";
    public const string TokenExchanged = "token.exchanged";
    public const string PasswordChanged = "password.changed";
    public const string PasswordReset = "password.reset";
    public const string PasswordResetRequested = "password.reset_requested";
    public const string InviteAccepted = "user.invite_accepted";
    public const string Registered = "user.registered";
    public const string AdminChange = "admin.change";
    public const string AppApiChange = "app_api.change";
    public const string AccessDenied = "access.denied";
}

/// <summary>Запись журнала для API/UI; Details — исходный JSON с подробностями события.</summary>
public sealed record AuditDto(
    long Id, DateTime OccurredAt, string Type, string Severity, bool Success, string? Actor, string? ActorName,
    Guid? SubjectUserId, string? ClientId, string? Ip, string? UserAgent, string? Instance, JsonElement? Details);

/// <summary>Фильтр журнала; <c>BeforeId</c> — keyset-пагинация «следующая страница старее этого Id».</summary>
public sealed record AuditQuery(
    DateTime? From = null, DateTime? To = null, string? Type = null, AuditSeverity? MinSeverity = null,
    string? ClientId = null, Guid? UserId = null, bool? Success = null, long? BeforeId = null, int Take = 100);

/// <summary>
/// Журнал безопасности. Контекст (кто, IP, User-Agent, экземпляр) берётся из текущего HTTP-запроса.
/// Запись идёт в отдельном scope БД: ошибка основной операции не мешает аудиту и наоборот.
/// События уровня Warning+ дублируются в ленту событий (security.alert) для ботов.
/// Регистрируется и как singleton-сервис, и как hosted service (фоновая запись пачек).
/// Пишут в журнал AuthorizationController, страницы Account/*, Admin/App API (через AuditHooks);
/// читают — страница Admin/Audit и Admin API; чистит по срокам хранения TokenPruningService.
/// </summary>
public sealed class AuditService(IServiceScopeFactory scopes, IHttpContextAccessor http, ILogger<AuditService> logger)
    : BackgroundService
{
    private static readonly string Instance = Environment.MachineName;

    // Информационные события (выдача токенов, успешные входы — самые частые) пишутся пачками:
    // под нагрузкой это одна транзакция на сотни событий вместо сотен транзакций.
    // Очередь ограничена: при переполнении писатели ждут (backpressure), а не теряют события и не раздувают память.
    private readonly System.Threading.Channels.Channel<AuditEntry> _queue =
        System.Threading.Channels.Channel.CreateBounded<AuditEntry>(new System.Threading.Channels.BoundedChannelOptions(50_000)
        {
            FullMode = System.Threading.Channels.BoundedChannelFullMode.Wait, SingleReader = true
        });
    // FlushAsync вызывается и фоновым циклом, и перед чтением/очисткой журнала — не даём им пересекаться.
    private readonly SemaphoreSlim _flushLock = new(1, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (await _queue.Reader.WaitToReadAsync(stoppingToken))
            {
                await Task.Delay(200, stoppingToken); // копим пачку
                await FlushAsync();
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            await FlushAsync(); // при остановке сервиса дописываем очередь
        }
    }

    /// <summary>Записывает накопленные события. Вызывается фоново и перед чтением журнала (консистентность чтения).</summary>
    public async Task FlushAsync()
    {
        await _flushLock.WaitAsync();
        try
        {
            var batch = new List<AuditEntry>();
            while (batch.Count < 1000 && _queue.Reader.TryRead(out var e)) batch.Add(e);
            if (batch.Count == 0) return;
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.AuditEntries.AddRange(batch);
            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            // Пачка теряется, но фоновый цикл продолжает работу — сбой БД не должен останавливать аудит навсегда.
            logger.LogError(ex, "Не удалось записать пачку событий аудита.");
        }
        finally
        {
            _flushLock.Release();
        }
    }

    /// <summary>
    /// Регистрирует событие. Info — в очередь (пишется пачкой в течение ~200 мс), Warning/Critical — сразу в БД и в ленту событий.
    /// Актор, IP и User-Agent по умолчанию берутся из текущего HTTP-запроса.
    /// </summary>
    public async Task WriteAsync(string type, bool success = true, AuditSeverity severity = AuditSeverity.Info,
        string? clientId = null, Guid? subjectUserId = null, object? details = null, string? actor = null, string? actorName = null)
    {
        // Контекст запроса снимаем здесь, синхронно: к моменту фоновой записи HttpContext уже недоступен.
        var ctx = http.HttpContext;
        var (defaultActor, defaultName) = ResolveActor(ctx?.User);
        var entry = new AuditEntry
        {
            Type = type,
            Success = success,
            Severity = severity,
            Actor = actor ?? defaultActor,
            ActorName = actorName ?? defaultName,
            SubjectUserId = subjectUserId,
            ClientId = clientId,
            Ip = ctx?.Connection.RemoteIpAddress?.ToString(),
            UserAgent = ctx?.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua[..Math.Min(ua.Length, 512)] : null,
            Instance = Instance,
            Details = details is null ? null : JsonSerializer.Serialize(details)
        };

        if (severity == AuditSeverity.Info)
        {
            await _queue.Writer.WriteAsync(entry);
            return;
        }

        // Warning/Critical — сразу и с алертом: важны для реакции и для лимитов (например, сбросов через бота).
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.AuditEntries.Add(entry);
            await db.SaveChangesAsync();

            if (severity >= AuditSeverity.Warning)
            {
                var text = $"⚠️ [{severity}] {type}: {entry.ActorName ?? entry.Actor}" +
                           (clientId is null ? "" : $", приложение {clientId}") + (entry.Ip is null ? "" : $", IP {entry.Ip}");
                await scope.ServiceProvider.GetRequiredService<WebhookService>().PublishAsync("security.alert", text,
                    new { auditId = entry.Id, type, severity = severity.ToString(), entry.Actor, clientId, subjectUserId, entry.Ip });
            }
        }
        catch (Exception ex)
        {
            // Аудит не должен ронять основную операцию, но пропуск записи — повод для алерта в логах.
            logger.LogError(ex, "Не удалось записать событие аудита {Type} ({Actor}).", type, entry.Actor);
        }
    }

    /// <summary>Выборка журнала по фильтру, новые записи первыми (не более 1000 за раз).</summary>
    public async Task<List<AuditDto>> QueryAsync(AuditQuery q, CancellationToken ct = default)
    {
        // Сбрасываем очередь, чтобы только что произошедшие события были видны в выборке.
        await FlushAsync();
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var query = db.AuditEntries.AsNoTracking().AsQueryable();
        // Время из query-строки API приходит без зоны (Kind=Unspecified): PostgreSQL (timestamptz) такое отвергает,
        // SQLite молча сравнивает строки. Нормализуем в UTC здесь, в одной точке для Admin API, App API и страниц.
        if (q.From is { } from) { var f = AsUtc(from); query = query.Where(e => e.OccurredAt >= f); }
        if (q.To is { } to) { var t = AsUtc(to); query = query.Where(e => e.OccurredAt <= t); }
        if (!string.IsNullOrWhiteSpace(q.Type)) query = query.Where(e => e.Type.StartsWith(q.Type));
        if (q.MinSeverity is { } sev) query = query.Where(e => e.Severity >= sev);
        if (!string.IsNullOrWhiteSpace(q.ClientId)) query = query.Where(e => e.ClientId == q.ClientId);
        if (q.UserId is { } uid) query = query.Where(e => e.SubjectUserId == uid);
        if (q.Success is { } ok) query = query.Where(e => e.Success == ok);
        if (q.BeforeId is { } before) query = query.Where(e => e.Id < before);

        var rows = await query.OrderByDescending(e => e.Id).Take(Math.Clamp(q.Take, 1, 1000)).ToListAsync(ct);
        return rows.Select(e => new AuditDto(e.Id, e.OccurredAt, e.Type, e.Severity.ToString().ToLowerInvariant(), e.Success,
            e.Actor, e.ActorName, e.SubjectUserId, e.ClientId, e.Ip, e.UserAgent, e.Instance,
            e.Details is null ? null : JsonSerializer.Deserialize<JsonElement>(e.Details))).ToList();
    }

    /// <summary>Экспорт в CSV (разделитель «;», как ожидает Excel в русской локали).</summary>
    public static string ToCsv(IEnumerable<AuditDto> rows)
    {
        static string Esc(object? v)
        {
            var s = v?.ToString() ?? "";
            // Защита от CSV-инъекций в Excel: значения, начинающиеся с = + - @, экранируются апострофом.
            if (s.Length > 0 && "=+-@".Contains(s[0])) s = "'" + s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }

        var sb = new StringBuilder("id;occurred_at_utc;type;severity;success;actor;actor_name;subject_user_id;client_id;ip;instance;details\n");
        foreach (var r in rows)
            sb.AppendJoin(';', Esc(r.Id), Esc(r.OccurredAt.ToString("O")), Esc(r.Type), Esc(r.Severity), Esc(r.Success), Esc(r.Actor),
                Esc(r.ActorName), Esc(r.SubjectUserId), Esc(r.ClientId), Esc(r.Ip), Esc(r.Instance), Esc(r.Details?.GetRawText())).Append('\n');
        return sb.ToString();
    }

    /// <summary>Удаляет записи старше срока хранения их типа (правила — в настройках в БД).</summary>
    public async Task<int> PruneAsync(RuntimeSettings settings, CancellationToken ct)
    {
        await FlushAsync();
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var types = await db.AuditEntries.Select(e => e.Type).Distinct().ToListAsync(ct);

        // По одному DELETE на тип: у каждого типа свой срок хранения, а ExecuteDelete не грузит записи в память.
        var deleted = 0;
        foreach (var type in types)
        {
            var threshold = DateTime.UtcNow.AddDays(-settings.RetentionFor(type));
            deleted += await db.AuditEntries.Where(e => e.Type == type && e.OccurredAt < threshold).ExecuteDeleteAsync(ct);
        }
        return deleted;
    }

    /// <summary>Типы событий, реально встречающиеся в журнале (для настройки сроков хранения).</summary>
    public async Task<List<string>> ListTypesAsync(CancellationToken ct = default)
    {
        using var scope = scopes.CreateScope();
        var known = typeof(AuditTypes).GetFields().Select(f => (string)f.GetValue(null)!);
        var used = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().AuditEntries
            .Select(e => e.Type).Distinct().ToListAsync(ct);
        return known.Union(used).Order().ToList();
    }

    // Актор в виде "user:{id}" / "client:{client_id}" / "anonymous": клиенты приходят с bearer-токеном App/Admin API,
    // пользователи — с cookie (NameIdentifier) или токеном (sub).
    private static (string Actor, string? Name) ResolveActor(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true) return ("anonymous", null);
        if (user.GetClaim(CustomClaims.SubjectType) == "client")
            return ($"client:{user.GetClaim(Claims.Subject)}", user.GetClaim(Claims.Subject));
        var id = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.GetClaim(Claims.Subject);
        var name = user.Identity?.Name ?? user.GetClaim(Claims.PreferredUsername);
        return ($"user:{id}", name);
    }

    /// <summary>Время без зоны считается UTC (так документирован API), локальное переводится в UTC.</summary>
    internal static DateTime AsUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
    };
}
