namespace TslAuth.Pages;

/// <summary>
/// Общие мелочи разметки, которые раньше повторялись по страницам: форматы дат и цвет бейджа статуса.
/// Доступны во всех представлениях (пространство имён подключено в _ViewImports).
/// </summary>
public static class Ui
{
    // В БД время хранится в UTC; на страницах (кроме журнала безопасности) показывается время сервера —
    // как и раньше, только формат теперь в одном месте.

    /// <summary>Дата и время по часам сервера: «24.09.2026 14:05»; null — <paramref name="empty"/>.</summary>
    public static string Time(DateTime? value, string empty = "") => value?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? empty;

    /// <summary>Только дата по часам сервера: «24.09.2026».</summary>
    public static string Date(DateTime? value) => value?.ToLocalTime().ToString("dd.MM.yyyy") ?? "";

    /// <summary>Дата и время в UTC с секундами (журнал безопасности: сверка с логами других систем).</summary>
    public static string UtcTime(DateTime value) =>
        (value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : value).ToString("dd.MM.yyyy HH:mm:ss");

    /// <summary>
    /// CSS-класс бейджа по статусу заявки или доставки: успех — ok, отказ/ошибка — danger, остальное (ожидание) — warn.
    /// </summary>
    public static string StatusClass(string? status) => status switch
    {
        "approved" or "succeeded" => "ok",
        "rejected" or "failed" => "danger",
        _ => "warn"
    };
}
