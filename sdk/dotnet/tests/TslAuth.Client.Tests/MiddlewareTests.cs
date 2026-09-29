using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TslAuth.Client;
using TslAuth.Client.AspNetCore;

namespace TslAuth.Client.Tests;

/// <summary>§8 п. 3 middleware: реальный Kestrel на свободном порту, ответы 401/403 по §5.</summary>
public class MiddlewareTests : IAsyncLifetime
{
    private WebApplication? _app;
    private HttpClient _http = null!;
    private static Vectors V => Vectors.Current;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddTslAuth(o =>
        {
            o.Issuer = V.Issuer;
            o.Audience = V.Audience;
            o.JwksUri = V.JwksUri;
        });
        _app = builder.Build();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.MapGet("/me", (HttpContext ctx) => Results.Json(new { username = ctx.GetTslPrincipal()!.Username })).RequireTslAuth();
        _app.MapGet("/orders", () => Results.Json(new { orders = Array.Empty<string>() })).RequireTslPermission("orders.read");
        _app.MapGet("/orders/write", () => Results.Json(new { ok = true })).RequireTslPermission("orders.write");
        _app.MapGet("/admin", () => Results.Ok()).RequireTslRole("admin");
        _app.MapGet("/mfa", () => Results.Ok()).RequireTslMfa();
        _app.MapGet("/clients-only", () => Results.Ok()).RequireTslSubjectType("client");
        await _app.StartAsync();
        var address = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        _http = new HttpClient { BaseAddress = new Uri(address) };
    }

    public async Task DisposeAsync()
    {
        _http.Dispose();
        if (_app is not null) await _app.DisposeAsync();
    }

    private async Task<(HttpStatusCode Status, string? WwwAuth, JsonElement? Body)> Get(string path, string? token)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var res = await _http.SendAsync(req);
        var text = await res.Content.ReadAsStringAsync();
        var www = res.Headers.WwwAuthenticate.ToString();
        JsonElement? body = string.IsNullOrEmpty(text) ? null : JsonDocument.Parse(text).RootElement.Clone();
        if (res.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            Assert.StartsWith("application/json", res.Content.Headers.ContentType?.ToString());
        return (res.StatusCode, string.IsNullOrEmpty(www) ? null : www, body);
    }

    [Fact]
    public async Task No_token_401_missing()
    {
        var (status, www, body) = await Get("/me", null);
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("Bearer realm=\"tsl-auth\", error=\"invalid_token\", error_description=\"missing\"", www);
        Assert.Equal("invalid_token", body!.Value.GetProperty("error").GetString());
        Assert.Equal("missing", body.Value.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task Broken_token_401_with_code()
    {
        var (status, www, body) = await Get("/me", V.Case("tampered_payload").Token);
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("Bearer realm=\"tsl-auth\", error=\"invalid_token\", error_description=\"bad_signature\"", www);
        Assert.Equal("bad_signature", body!.Value.GetProperty("error_description").GetString());

        (status, www, _) = await Get("/orders", "not.a.jwt");
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Contains("error_description=\"malformed\"", www);
    }

    [Fact]
    public async Task Viewer_403_insufficient_permissions()
    {
        var (status, www, body) = await Get("/orders/write", V.Case("ok_viewer").Token);
        Assert.Equal(HttpStatusCode.Forbidden, status);
        Assert.Equal($"Bearer realm=\"tsl-auth\", error=\"insufficient_permissions\", error_description=\"{V.Audience}:orders.write\"", www);
        Assert.Equal("insufficient_permissions", body!.Value.GetProperty("error").GetString());
        Assert.Equal($"{V.Audience}:orders.write", body.Value.GetProperty("error_description").GetString());

        // Роль, MFA, тип субъекта — свои коды.
        (_, www, body) = await Get("/admin", V.Case("ok_viewer").Token);
        Assert.Contains("error=\"insufficient_role\"", www);
        Assert.Equal($"{V.Audience}:admin", body!.Value.GetProperty("error_description").GetString());
        (_, www, _) = await Get("/mfa", V.Case("ok_viewer").Token);
        Assert.Contains("error=\"mfa_required\"", www);
        (status, www, _) = await Get("/clients-only", V.Case("ok_viewer").Token);
        Assert.Equal(HttpStatusCode.Forbidden, status);
        Assert.Contains("error=\"subject_type_not_allowed\"", www);
        (status, _, _) = await Get("/clients-only", V.Case("ok_client").Token);
        Assert.Equal(HttpStatusCode.OK, status);
    }

    [Fact]
    public async Task User_200()
    {
        var (status, www, body) = await Get("/me", V.Case("ok_user").Token);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Null(www);
        Assert.Equal("sdk-operator", body!.Value.GetProperty("username").GetString());

        (status, _, _) = await Get("/orders", V.Case("ok_user").Token);
        Assert.Equal(HttpStatusCode.OK, status);
        (status, _, _) = await Get("/orders/write", V.Case("ok_user").Token);
        Assert.Equal(HttpStatusCode.OK, status);
        (status, _, _) = await Get("/orders", V.Case("ok_viewer").Token);
        Assert.Equal(HttpStatusCode.OK, status);
    }
}
