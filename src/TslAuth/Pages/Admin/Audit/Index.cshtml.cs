using Microsoft.AspNetCore.Mvc;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Pages.Admin.Audit;

/// <summary>
/// Журнал аудита с фильтрами (тип, важность, приложение, пользователь, успех, период) и выгрузкой в CSV.
/// Постраничность — keyset по BeforeId (id последней записи предыдущей страницы). Доступ — политика UiView.
/// Использует AuditService.
/// </summary>
public sealed class IndexModel(AuditService audit) : AdminPageModel
{
    [BindProperty(SupportsGet = true)] public string? Type { get; set; }
    [BindProperty(SupportsGet = true)] public AuditSeverity? MinSeverity { get; set; }
    [BindProperty(SupportsGet = true)] public string? ClientId { get; set; }
    [BindProperty(SupportsGet = true)] public Guid? UserId { get; set; }
    [BindProperty(SupportsGet = true)] public bool? Success { get; set; }
    [BindProperty(SupportsGet = true)] public DateTime? From { get; set; }
    [BindProperty(SupportsGet = true)] public DateTime? To { get; set; }
    [BindProperty(SupportsGet = true)] public long? BeforeId { get; set; }

    public List<AuditDto> Items { get; private set; } = [];
    public List<string> Types { get; private set; } = [];
    public const int PageSize = 100;

    /// <summary>Значения полей периода (datetime-local) — в UTC, как и фильтр.</summary>
    public string? FromValue => Utc(From)?.ToString("yyyy-MM-ddTHH:mm");
    public string? ToValue => Utc(To)?.ToString("yyyy-MM-ddTHH:mm");

    private AuditQuery Query(int take) => new(Utc(From), Utc(To), Type, MinSeverity, ClientId, UserId, Success, BeforeId, take);

    /// <summary>
    /// Даты фильтра — в UTC (так подписаны поля, и так же выводится время в таблице и в CSV). Раньше значение
    /// datetime-local считалось временем сервера, которое не совпадает ни с браузером администратора, ни с UTC в БД.
    /// Значение с явной зоной (…Z, +03:00) переводится в UTC, без зоны — считается UTC.
    /// </summary>
    private static DateTime? Utc(DateTime? value) => value is not { } v ? null
        : v.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(v, DateTimeKind.Utc) : v.ToUniversalTime();

    public async Task OnGetAsync(CancellationToken ct)
    {
        Items = await audit.QueryAsync(Query(PageSize), ct);
        Types = await audit.ListTypesAsync(ct);
    }

    /// <summary>
    /// Выгрузка в CSV с текущими фильтрами: до 1000 последних записей (без учёта страницы).
    /// UTF-8 BOM в начале нужен, чтобы Excel правильно распознал кириллицу.
    /// </summary>
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        var csv = AuditService.ToCsv(await audit.QueryAsync(Query(1000) with { BeforeId = null }, ct));
        return File(System.Text.Encoding.UTF8.GetPreamble().Concat(System.Text.Encoding.UTF8.GetBytes(csv)).ToArray(),
            "text/csv", $"audit-{DateTime.UtcNow:yyyyMMdd-HHmm}.csv");
    }
}
