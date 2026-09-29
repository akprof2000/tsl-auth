using System.Security.Claims;
using System.Text.Json;

namespace TslAuth.Client;

/// <summary>Цепочка token exchange из claim <c>act</c>: кто действует от имени субъекта.</summary>
public sealed record TslActor(string Subject, TslActor? Actor);

/// <summary>Результат успешной проверки токена (docs/client-contract.md §4).</summary>
public sealed class TslPrincipal
{
    private readonly HashSet<string> _permissions;
    private readonly HashSet<string> _roles;

    internal TslPrincipal(JsonElement payload, string? audience)
    {
        Claims = payload.Clone();
        Subject = Str(payload, "sub") ?? "";
        SubjectType = Str(payload, "subject_type") ?? "";
        Username = Str(payload, "preferred_username");
        Name = Str(payload, "name");
        Email = Str(payload, "email");
        AllRoles = List(payload, "role");
        AllPermissions = List(payload, "permissions");
        Amr = List(payload, "amr");
        Audiences = List(payload, "aud");
        Scopes = (Str(payload, "scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        ExpiresAt = payload.TryGetProperty("exp", out var exp) && exp.TryGetInt64(out var e)
            ? DateTimeOffset.FromUnixTimeSeconds(e)
            : DateTimeOffset.MaxValue;
        Actor = payload.TryGetProperty("act", out var act) ? ParseActor(act) : null;

        // Роли и разрешения этого API: значения "<audience>:<x>" с обрезанным префиксом.
        var prefix = string.IsNullOrEmpty(audience) ? null : audience + ":";
        Roles = Strip(AllRoles, prefix);
        Permissions = Strip(AllPermissions, prefix);
        _roles = new HashSet<string>(Roles, StringComparer.Ordinal);
        _permissions = new HashSet<string>(Permissions, StringComparer.Ordinal);
    }

    /// <summary><c>sub</c>: id пользователя или <c>client_id</c> сервиса.</summary>
    public string Subject { get; }
    /// <summary><c>subject_type</c>: <c>user</c> или <c>client</c>.</summary>
    public string SubjectType { get; }
    /// <summary><c>preferred_username</c>; у сервисных токенов отсутствует.</summary>
    public string? Username { get; }
    /// <summary><c>name</c>.</summary>
    public string? Name { get; }
    /// <summary><c>email</c>.</summary>
    public string? Email { get; }
    /// <summary>Роли этого API без префикса <c>&lt;audience&gt;:</c>.</summary>
    public IReadOnlyList<string> Roles { get; }
    /// <summary>Разрешения этого API без префикса <c>&lt;audience&gt;:</c>.</summary>
    public IReadOnlyList<string> Permissions { get; }
    /// <summary>Все роли из токена, с префиксами (для API-шлюзов).</summary>
    public IReadOnlyList<string> AllRoles { get; }
    /// <summary>Все разрешения из токена, с префиксами.</summary>
    public IReadOnlyList<string> AllPermissions { get; }
    /// <summary><c>scope</c> списком.</summary>
    public IReadOnlyList<string> Scopes { get; }
    /// <summary><c>amr</c> — способы аутентификации.</summary>
    public IReadOnlyList<string> Amr { get; }
    /// <summary><c>aud</c> списком.</summary>
    public IReadOnlyList<string> Audiences { get; }
    /// <summary>Цепочка token exchange (<c>act</c>) или <c>null</c>.</summary>
    public TslActor? Actor { get; }
    /// <summary>Момент истечения (<c>exp</c>).</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>Сырые claims токена.</summary>
    public JsonElement Claims { get; }
    /// <summary>Вход с двухфакторной аутентификацией: <c>amr</c> содержит <c>mfa</c>.</summary>
    public bool IsMfa => Amr.Contains("mfa");

    /// <summary>Есть ли разрешение этого API (короткая форма, без префикса audience).</summary>
    public bool HasPermission(string permission) => _permissions.Contains(permission);

    /// <summary>Есть ли роль этого API (короткая форма, без префикса audience).</summary>
    public bool HasRole(string role) => _roles.Contains(role);

    /// <summary>
    /// <see cref="ClaimsPrincipal"/> для <c>HttpContext.User</c>: claims как в токене (<c>role</c>, <c>permissions</c>
    /// с префиксами), имя — <c>preferred_username</c>, тип роли — <c>role</c>.
    /// </summary>
    public ClaimsPrincipal ToClaimsPrincipal(string authenticationType = "TslAuth")
    {
        var identity = new ClaimsIdentity(authenticationType, "preferred_username", "role");
        foreach (var p in Claims.EnumerateObject())
        {
            if (p.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in p.Value.EnumerateArray())
                    identity.AddClaim(ToClaim(p.Name, item));
            }
            else
            {
                identity.AddClaim(ToClaim(p.Name, p.Value));
            }
        }
        return new ClaimsPrincipal(identity);
    }

    private static Claim ToClaim(string type, JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => new Claim(type, value.GetString() ?? ""),
        JsonValueKind.Number => new Claim(type, value.GetRawText(), ClaimValueTypes.Integer64),
        JsonValueKind.True or JsonValueKind.False => new Claim(type, value.GetRawText(), ClaimValueTypes.Boolean),
        JsonValueKind.Null => new Claim(type, ""),
        _ => new Claim(type, value.GetRawText(), "JSON"),
    };

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Claim-список: строка (одно значение) или массив → список; отсутствует → пустой.</summary>
    internal static IReadOnlyList<string> List(JsonElement e, string name)
    {
        if (!e.TryGetProperty(name, out var v)) return Array.Empty<string>();
        if (v.ValueKind == JsonValueKind.String) return new[] { v.GetString()! };
        if (v.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
        var list = new List<string>();
        foreach (var item in v.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String) list.Add(item.GetString()!);
        return list;
    }

    private static IReadOnlyList<string> Strip(IReadOnlyList<string> values, string? prefix)
    {
        if (prefix is null) return Array.Empty<string>();
        var list = new List<string>();
        foreach (var v in values)
            if (v.StartsWith(prefix, StringComparison.Ordinal)) list.Add(v.Substring(prefix.Length));
        return list;
    }

    private static TslActor? ParseActor(JsonElement act)
    {
        if (act.ValueKind != JsonValueKind.Object) return null;
        var sub = Str(act, "sub");
        if (sub is null) return null;
        return new TslActor(sub, act.TryGetProperty("act", out var inner) ? ParseActor(inner) : null);
    }
}
