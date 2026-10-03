using System.Text.Json;
using TslAuth.Client;

namespace TslAuth.Client.Tests;

/// <summary>Часы для тестов: фиксированный момент, который можно сдвигать.</summary>
public sealed class FakeTimeProvider : TimeProvider
{
    private DateTimeOffset _now;
    public FakeTimeProvider(DateTimeOffset now) => _now = now;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Set(DateTimeOffset now) => _now = now;
    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Один случай из vectors.json.</summary>
public sealed record VectorCase(string Name, string Token, string Expect, long? Now, bool SkipIfNoNbf, string? Issuer)
{
    public override string ToString() => Name;
}

/// <summary>Чтение tests/sdk-contract/vectors.json (путь — SDK_CONTRACT_VECTORS или поиск вверх по каталогам).</summary>
public sealed class Vectors
{
    private static readonly Lazy<Vectors> Instance = new(Load);
    public static Vectors Current => Instance.Value;

    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public required string JwksUri { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    /// <summary>Владелец подчинённых клиентов (id, секрет, префикс client_id, роль) для сценария private_key_jwt.</summary>
    public required (string Id, string Secret, string Prefix, string Role) ManagedOwner { get; init; }
    /// <summary>Сервис-робот и токен подключения, который ему выписал sdk-operator (пусто — стенд без робота).</summary>
    public required (string Id, string Secret, string ConnectionToken) Robot { get; init; }
    public required IReadOnlyDictionary<string, (string Username, string Password)> Users { get; init; }
    public required JsonElement Expected { get; init; }
    public required IReadOnlyList<VectorCase> Cases { get; init; }

    public VectorCase Case(string name) => Cases.First(c => c.Name == name);

    public TslAuthOptions Options(TimeProvider? clock = null, string? issuer = null) => new()
    {
        Issuer = issuer ?? Issuer,
        Audience = Audience,
        JwksUri = JwksUri,
        ClientId = ClientId,
        ClientSecret = ClientSecret,
        TimeProvider = clock ?? TimeProvider.System,
    };

    private static Vectors Load()
    {
        var path = Environment.GetEnvironmentVariable("SDK_CONTRACT_VECTORS");
        if (string.IsNullOrWhiteSpace(path))
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            {
                var candidate = Path.Combine(dir.FullName, "tests", "sdk-contract", "vectors.json");
                if (File.Exists(candidate)) { path = candidate; break; }
            }
        }
        if (path is null || !File.Exists(path))
            throw new FileNotFoundException("vectors.json не найден: задайте SDK_CONTRACT_VECTORS или сгенерируйте tests/sdk-contract/make-vectors.py");

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        var users = new Dictionary<string, (string, string)>();
        foreach (var u in root.GetProperty("users").EnumerateObject())
            users[u.Name] = (u.Value.GetProperty("username").GetString()!, u.Value.GetProperty("password").GetString()!);
        var cases = new List<VectorCase>();
        foreach (var c in root.GetProperty("cases").EnumerateArray())
            cases.Add(new VectorCase(
                c.GetProperty("name").GetString()!,
                c.GetProperty("token").GetString()!,
                c.GetProperty("expect").GetString()!,
                c.TryGetProperty("now", out var now) ? now.GetInt64() : null,
                c.TryGetProperty("skipIfNoNbf", out var skip) && skip.ValueKind == JsonValueKind.True,
                c.TryGetProperty("issuer", out var iss) ? iss.GetString() : null));
        return new Vectors
        {
            Issuer = root.GetProperty("issuer").GetString()!,
            Audience = root.GetProperty("audience").GetString()!,
            JwksUri = root.GetProperty("jwksUri").GetString()!,
            ClientId = root.GetProperty("client").GetProperty("id").GetString()!,
            ClientSecret = root.GetProperty("client").GetProperty("secret").GetString()!,
            ManagedOwner = root.TryGetProperty("managedOwner", out var owner)
                ? (owner.GetProperty("id").GetString()!, owner.GetProperty("secret").GetString()!, owner.GetProperty("prefix").GetString()!, owner.GetProperty("role").GetString()!)
                : ("", "", "", ""),
            Robot = root.TryGetProperty("robot", out var robot)
                ? (robot.GetProperty("id").GetString()!, robot.GetProperty("secret").GetString()!, robot.GetProperty("connectionToken").GetString()!)
                : ("", "", ""),
            Users = users,
            Expected = root.GetProperty("expected").Clone(),
            Cases = cases,
        };
    }
}
