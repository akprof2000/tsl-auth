namespace TslAuth.Infrastructure;

/// <summary>
/// Чтение секрета из файла (docker secrets, Kubernetes secrets): <c>*File</c>-варианты настроек.
/// Пустой путь — настройка не задана; указанный, но отсутствующий файл — ошибка старта (а не молчаливый пустой секрет).
/// </summary>
public static class SecretFile
{
    /// <summary>Читает секрет из файла; <paramref name="setting"/> — имя настройки для текста ошибки.</summary>
    public static string? Read(string? path, string setting)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        if (!File.Exists(path))
            throw new InvalidOperationException($"{setting}: файл '{path}' не найден.");
        // Файлы секретов обычно заканчиваются переводом строки — он не часть значения.
        return File.ReadAllText(path).Trim();
    }
}
