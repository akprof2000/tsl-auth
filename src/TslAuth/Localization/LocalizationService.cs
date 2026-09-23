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
public sealed class LocalizationService(IServiceScopeFactory scopes)
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
        culture = culture.Trim();
        if (!System.Text.RegularExpressions.Regex.IsMatch(culture, "^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})*$"))
            throw new AdminException("Код языка: например ru, en, kk, uz-Latn.");
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

        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var pack = await db.LanguagePacks.FirstOrDefaultAsync(p => p.Culture == culture, ct);
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
        if (await db.LanguagePacks.Where(p => p.Culture == culture).ExecuteDeleteAsync(ct) == 0)
            throw AdminException.NotFound("Языковой пакет");
        _loadedAt = DateTime.MinValue;
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
            using var scope = scopes.CreateScope();
            var packs = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().LanguagePacks.AsNoTracking().ToListAsync();
            _db = packs.ToDictionary(p => p.Culture,
                p => (p, JsonSerializer.Deserialize<Dictionary<string, string>>(p.Json) ?? []), StringComparer.OrdinalIgnoreCase);
            _loadedAt = DateTime.UtcNow;
        }
        finally
        {
            _lock.Release();
        }
    }
}
