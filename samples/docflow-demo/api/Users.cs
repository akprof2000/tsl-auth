// Управление пользователями приложения — внутри демо, но через App API TSL Auth.
// Роли и матрица «роль × разрешение» настраиваются ТОЛЬКО в TSL Auth (админка или seed-скрипт);
// здесь роли лишь читаются и назначаются пользователям. Нужно разрешение users.manage.
using System.Text.Json;

namespace Docflow.Api;

public sealed record CreateUserInput(string UserName, string? Email, string? DisplayName, List<string> Roles, bool Invite);
public sealed record LinkUserInput(string Login, List<string> Roles);
public sealed record UpdateUserInput(string UserName, string? Email, string? DisplayName);
public sealed record RequestDecisionInput(string? Comment);

public static class Users
{
    public static void MapUsers(this IEndpointRouteBuilder app)
    {
        // Справочник для выбора исполнителей маршрута — доступен всем, кто работает с документами.
        app.MapGet("/api/directory", async (TslAuthClient auth, CancellationToken ct) =>
            (await auth.UsersAsync(ct: ct)).Where(u => !u.KnownInactive).Select(u => new { u.Id, u.UserName, name = u.Display, u.Roles }))
            .RequireAuthorization("documents.view");

        // Роли приложения с названиями для людей (из матрицы TSL Auth, только чтение).
        app.MapGet("/api/roles", async (TslAuthClient auth, CancellationToken ct) => Roles(await auth.CallAsync(HttpMethod.Get, "/matrix", ct: ct)))
            .RequireAuthorization("documents.view");

        var users = app.MapGroup("/api/users").RequireAuthorization("users.manage");

        users.MapGet("/", async (TslAuthClient auth, CancellationToken ct) => await auth.UsersAsync(force: true, ct));

        users.MapGet("/matrix", async (TslAuthClient auth, CancellationToken ct) => await auth.CallAsync(HttpMethod.Get, "/matrix", ct: ct));

        users.MapPost("/", async (CreateUserInput input, TslAuthClient auth, CancellationToken ct) =>
        {
            var result = await auth.CallAsync(HttpMethod.Post, "/users", new
            {
                userName = input.UserName.Trim(), email = Empty(input.Email), displayName = Empty(input.DisplayName),
                roles = input.Roles, invite = input.Invite
            }, ct);
            auth.InvalidateUsers();
            return result;
        });

        users.MapPost("/link", async (LinkUserInput input, TslAuthClient auth, CancellationToken ct) =>
        {
            var result = await auth.CallAsync(HttpMethod.Post, "/users/link", new { login = input.Login.Trim(), roles = input.Roles }, ct);
            auth.InvalidateUsers();
            return result;
        });

        users.MapPut("/{id:guid}", async (Guid id, UpdateUserInput input, TslAuthClient auth, CancellationToken ct) =>
        {
            var result = await auth.CallAsync(HttpMethod.Put, $"/users/{id}", new
            {
                userName = input.UserName.Trim(), email = Empty(input.Email), displayName = Empty(input.DisplayName)
            }, ct);
            auth.InvalidateUsers();
            return result;
        });

        users.MapPut("/{id:guid}/roles", async (Guid id, List<string> roles, TslAuthClient auth, CancellationToken ct) =>
        {
            var result = await auth.CallAsync(HttpMethod.Put, $"/users/{id}/roles", roles, ct);
            auth.InvalidateUsers();
            return result;
        });

        users.MapDelete("/{id:guid}", async (Guid id, TslAuthClient auth, CancellationToken ct) =>
        {
            var result = await auth.CallAsync(HttpMethod.Delete, $"/users/{id}", ct: ct);
            auth.InvalidateUsers();
            return result;
        });

        users.MapPost("/{id:guid}/temporary-password", async (Guid id, TslAuthClient auth, CancellationToken ct) =>
            await auth.CallAsync(HttpMethod.Post, $"/users/{id}/temporary-password", ct: ct));

        users.MapPost("/{id:guid}/invite", async (Guid id, TslAuthClient auth, CancellationToken ct) =>
            await auth.CallAsync(HttpMethod.Post, $"/users/{id}/invite?sendEmail=false", ct: ct));

        // Заявки на роли приложения (самостоятельная регистрация на странице входа TSL Auth).
        users.MapGet("/requests", async (string? status, TslAuthClient auth, CancellationToken ct) =>
            await auth.CallAsync(HttpMethod.Get, $"/access-requests?status={Uri.EscapeDataString(status ?? "Pending")}", ct: ct));
        users.MapPost("/requests/{id:guid}/approve", async (Guid id, RequestDecisionInput? input, TslAuthClient auth, CancellationToken ct) =>
        {
            var result = await auth.CallAsync(HttpMethod.Post, $"/access-requests/{id}/approve", new { comment = input?.Comment }, ct);
            auth.InvalidateUsers();
            return result;
        });
        users.MapPost("/requests/{id:guid}/reject", async (Guid id, RequestDecisionInput? input, TslAuthClient auth, CancellationToken ct) =>
            await auth.CallAsync(HttpMethod.Post, $"/access-requests/{id}/reject", new { comment = input?.Comment }, ct));

        users.MapGet("/audit", async (TslAuthClient auth, CancellationToken ct) =>
            await auth.CallAsync(HttpMethod.Get, "/audit", ct: ct));
    }

    private static IEnumerable<object> Roles(JsonElement matrix) =>
        matrix.GetProperty("roles").EnumerateArray().Select(r => new
        {
            name = r.GetProperty("name").GetString(),
            title = r.TryGetProperty("displayName", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : r.GetProperty("name").GetString(),
            description = r.TryGetProperty("description", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() : null,
            permissions = r.GetProperty("permissions").EnumerateArray().Select(p => p.GetString()).ToList()
        });

    private static string? Empty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
