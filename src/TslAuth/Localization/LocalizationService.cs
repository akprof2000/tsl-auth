using System.Reflection;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using TslAuth.Data;
using TslAuth.Services;

namespace TslAuth.Localization;

/// <summary>Язык для списков выбора и админки: встроенный ли, есть ли переопределения в БД, включён ли.</summary>
public sealed record LanguageInfo(string Culture, string Name, bool BuiltIn, bool HasOverrides, bool IsEnabled);

/// <summary>
/// Языковые пакеты: встроенные (ru, en — ресурсы сборки) + пакеты из БД (новые языки или переопределения строк).
/// Поиск строки: пакет БД → встроенный пакет → родительская культура (uz-Latn → uz) → язык по умолчанию → ключ.
/// Кэш 30 секунд — изменения, сделанные на одном экземпляре, подхватываются всеми.
/// Singleton; строки для текущего запроса отдаёт <see cref="Texts"/>, управление пакетами — админка и Admin API.
/// </summary>
public sealed class LocalizationService(IServiceScopeFactory scopes, ILogger<LocalizationService> logger)
{
    public const string DefaultCulture = "ru";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(30);

    private static readonly Dictionary<string, Dictionary<string, string>> BuiltIn = LoadBuiltIn();
    private Dictionary<string, (LanguagePack Pack, Dictionary<string, string> Strings)> _db = [];
    private DateTime _loadedAt = DateTime.MinValue;
    private readonly SemaphoreSlim _lock = new(1, 1);

    // Встроенные пакеты — embedded-ресурсы Localization/Packs/*.json; культура берётся из имени файла.
    private static Dictionary<string, Dictionary<string, string>> LoadBuiltIn()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in assembly.GetManifestResourceNames().Where(n => n.Contains(".Localization.Packs.") && n.EndsWith(".json")))
        {
            using var stream = assembly.GetManifestResourceStream(name)!;
            var culture = name.Split('.')[^2];
            result[culture] = JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
        }
        return result;
    }

    /// <summary>Строка встроенного пакета (с фолбэком на язык по умолчанию) — запасной вариант для сломанного перевода.</summary>
    public static string? GetBuiltIn(string culture, string key)
    {
        foreach (var c in Chain(culture))
            if (BuiltIn.TryGetValue(c, out var pack) && pack.TryGetValue(key, out var value)) return value;
        return null;
    }

    /// <summary>Шаблон пакета (все ключи со значениями из встроенного языка) — для перевода на новый язык.</summary>
    public static Dictionary<string, string> Template(string culture = DefaultCulture) =>
        new(BuiltIn.TryGetValue(culture, out var pack) ? pack : BuiltIn[DefaultCulture]);

    /// <summary>Поиск строки с предварительной загрузкой/обновлением кэша (для кода вне HTTP-запроса).</summary>
    public async Task<string?> GetAsync(string culture, string key)
    {
        await EnsureLoadedAsync();
        return Get(culture, key);
    }

    /// <summary>Синхронный поиск по уже загруженному кэшу (кэш прогревает LanguageMiddleware на каждом запросе).</summary>
    public string? Get(string culture, string key)
    {
        // Локальная копия ссылки: кэш заменяется целиком, чтение без блокировки видит согласованный снимок.
        var dbPacks = _db;
        foreach (var c in Chain(culture))
        {
            if (dbPacks.TryGetValue(c, out var db) && db.Pack.IsEnabled && db.Strings.TryGetValue(key, out var v1)) return v1;
            if (BuiltIn.TryGetValue(c, out var builtIn) && builtIn.TryGetValue(key, out var v2)) return v2;
        }
        return null;
    }

    /// <summary>Встроенные языки и языки из БД; встроенные доступны всегда, пакеты БД — только включённые.</summary>
    public async Task<IReadOnlyList<LanguageInfo>> ListAsync(bool includeDisabled = false)
    {
        await EnsureLoadedAsync();
        var cultures = BuiltIn.Keys.Union(_db.Keys, StringComparer.OrdinalIgnoreCase).Order();
        return cultures.Select(c =>
            {
                var hasDb = _db.TryGetValue(c, out var db);
                var builtIn = BuiltIn.TryGetValue(c, out var pack);
                var name = hasDb ? db.Pack.Name : pack!.GetValueOrDefault("_name", c);
                return new LanguageInfo(c, name, builtIn, hasDb, builtIn || (hasDb && db.Pack.IsEnabled));
            })
            .Where(l => includeDisabled || l.IsEnabled).ToList();
    }

    public async Task<bool> IsAvailableAsync(string culture) =>
        (await ListAsync()).Any(l => l.Culture.Equals(culture, StringComparison.OrdinalIgnoreCase));

    public async Task<LanguagePack?> GetPackAsync(string culture)
    {
        await EnsureLoadedAsync();
        return _db.TryGetValue(culture, out var db) ? db.Pack : null;
    }

    /// <summary>
    /// Создаёт или заменяет пакет в БД. Ключи проверяются по встроенному пакету по умолчанию —
    /// опечатка в ключе иначе молча не дала бы эффекта.
    /// </summary>
    public async Task SavePackAsync(string culture, string name, string json, bool enabled, string updatedBy, CancellationToken ct = default)
    {
        culture = Canonical(culture);
        // 20 символов — длина первичного ключа в БД (на PostgreSQL длиннее просто не сохранится).
        if (culture.Length > 20 || !System.Text.RegularExpressions.Regex.IsMatch(culture, "^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})*$"))
            throw new AdminException("Код языка: например ru, en, kk, uz-Latn (до 20 символов).");
        Dictionary<string, string> strings;
        try
        {
            strings = JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                      ?? throw new AdminException("Пакет пуст.");
        }
        catch (JsonException ex)
        {
            throw new AdminException($"Некорректный JSON пакета: {ex.Message}");
        }
        var unknown = strings.Keys.Where(k => k != "_name" && !BuiltIn[DefaultCulture].ContainsKey(k)).Take(5).ToList();
        if (unknown.Count > 0) throw new AdminException($"Неизвестные ключи: {string.Join(", ", unknown)}.");
        // Плейсхолдеры {0}, {1}… должны разбираться string.Format: иначе строка ломала бы страницу при показе.
        var broken = strings.Where(kv => kv.Key != "_name" && !FormatIsValid(kv.Value)).Select(kv => kv.Key).Take(5).ToList();
        if (broken.Count > 0)
            throw new AdminException($"Некорректные плейсхолдеры ({{0}}, {{1}}…; фигурную скобку в тексте удваивайте: {{{{ }}}}): {string.Join(", ", broken)}.");

        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        // Сравнение без учёта регистра в памяти (пакетов единицы): в БД старых версий могли остаться «RU» и «ru» —
        // оставляем одну запись с каноническим кодом, остальные удаляем.
        var existing = (await db.LanguagePacks.ToListAsync(ct))
            .Where(p => string.Equals(p.Culture, culture, StringComparison.OrdinalIgnoreCase)).ToList();
        var pack = existing.FirstOrDefault(p => p.Culture == culture);
        db.LanguagePacks.RemoveRange(existing.Where(p => p != pack));
        if (pack is null) db.LanguagePacks.Add(pack = new LanguagePack { Culture = culture, Name = "", Json = "" });
        pack.Name = string.IsNullOrWhiteSpace(name) ? strings.GetValueOrDefault("_name", culture) : name.Trim();
        pack.Json = JsonSerializer.Serialize(strings, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        pack.IsEnabled = enabled;
        pack.UpdatedAt = DateTime.UtcNow;
        pack.UpdatedBy = updatedBy;
        await db.SaveChangesAsync(ct);
        // Сброс кэша: на этом экземпляре изменения видны сразу, на остальных — через CacheTtl.
        _loadedAt = DateTime.MinValue;
    }

    /// <summary>Удаляет пакет из БД (встроенный язык при этом возвращается к исходным строкам).</summary>
    public async Task DeletePackAsync(string culture, CancellationToken ct = default)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        // Без учёта регистра: удаляются и варианты «RU»/«ru», оставшиеся от старых версий.
        var matches = (await db.LanguagePacks.ToListAsync(ct))
            .Where(p => string.Equals(p.Culture, culture.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0) throw AdminException.NotFound("Языковой пакет");
        db.LanguagePacks.RemoveRange(matches);
        await db.SaveChangesAsync(ct);
        _loadedAt = DateTime.MinValue;
    }

    /// <summary>
    /// Канонический вид кода языка (BCP 47): язык — строчными, регион — прописными, письменность — с заглавной
    /// (ru, en-US, uz-Latn). Без CultureInfo: образ работает в invariant-режиме глобализации.
    /// </summary>
    public static string Canonical(string culture)
    {
        var parts = culture.Trim().Split('-');
        for (var i = 0; i < parts.Length; i++)
            parts[i] = i == 0 ? parts[i].ToLowerInvariant()
                : parts[i].Length == 2 ? parts[i].ToUpperInvariant()
                : parts[i].Length == 4 ? char.ToUpperInvariant(parts[i][0]) + parts[i][1..].ToLowerInvariant()
                : parts[i].ToLowerInvariant();
        return string.Join('-', parts);
    }

    // Проверка формата строки: подстановка десяти пустых аргументов не должна бросать FormatException.
    private static bool FormatIsValid(string value)
    {
        try { _ = string.Format(value, new object?[10]); return true; }
        catch (FormatException) { return false; }
    }

    // Цепочка фолбэка культур: точная → родительская → язык по умолчанию.
    private static IEnumerable<string> Chain(string culture)
    {
        yield return culture;
        var dash = culture.IndexOf('-');
        if (dash > 0) yield return culture[..dash];
        if (!culture.StartsWith(DefaultCulture, StringComparison.OrdinalIgnoreCase)) yield return DefaultCulture;
    }

    /// <summary>Перезагружает пакеты из БД, если кэш устарел.</summary>
    public async Task EnsureLoadedAsync()
    {
        if (DateTime.UtcNow - _loadedAt < CacheTtl) return;
        // Double-checked: при истечении кэша в БД идёт один запрос, остальные параллельные запросы ждут его.
        await _lock.WaitAsync();
        try
        {
            if (DateTime.UtcNow - _loadedAt < CacheTtl) return;
            try
            {
                using var scope = scopes.CreateScope();
                var packs = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().LanguagePacks.AsNoTracking().ToListAsync();
                // Дубликаты кода, различающиеся регистром (данные старых версий), не должны ронять загрузку:
                // берём последний изменённый пакет. Пакет с битым JSON пропускается, остальные работают.
                var loaded = new Dictionary<string, (LanguagePack, Dictionary<string, string>)>(StringComparer.OrdinalIgnoreCase);
                foreach (var pack in packs.OrderBy(p => p.UpdatedAt))
                {
                    try
                    {
                        loaded[pack.Culture] = (pack, JsonSerializer.Deserialize<Dictionary<string, string>>(pack.Json) ?? []);
                    }
                    catch (JsonException ex)
                    {
                        logger.LogWarning(ex, "Языковой пакет {Culture} в БД повреждён и пропущен.", pack.Culture);
                    }
                }
                _db = loaded;
            }
            catch (Exception ex)
            {
                // Кэш загружается на каждом запросе (LanguageMiddleware): сбой БД или данных не должен превращать
                // в 500 все страницы — работаем на прежнем кэше и встроенных пакетах, повтор через CacheTtl.
                logger.LogError(ex, "Не удалось загрузить языковые пакеты из БД — используется прежний кэш.");
            }
            _loadedAt = DateTime.UtcNow;
        }
        finally
        {
            _lock.Release();
        }
    }
}
