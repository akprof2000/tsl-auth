using System.Net;
using System.Text;
using TslAuth.Client;

namespace TslAuth.Client.Tests;

/// <summary>§8 п. 3: живые сценарии против стенда (кроме middleware — см. MiddlewareTests).</summary>
public class LiveScenarioTests
{
    private static Vectors V => Vectors.Current;

    [Fact]
    public async Task Refresh_rotation()
    {
        var client = new TokenClient(V.Options());
        var (user, pwd) = V.Users["operator"];
        var first = await client.PasswordAsync(user, pwd, new[] { "openid", "offline_access", V.Audience });
        Assert.NotNull(first.RefreshToken);
        Assert.True(first.ExpiresAt > DateTimeOffset.UtcNow);

        var second = await client.RefreshAsync(first.RefreshToken!);
        Assert.NotNull(second.RefreshToken);
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);

        // Новый refresh работает повторно.
        var third = await client.RefreshAsync(second.RefreshToken!);
        Assert.NotNull(third.RefreshToken);

        // После отзыва refresh новый refresh — invalid_grant.
        await client.RevokeAsync(third.RefreshToken!);
        var err = await Assert.ThrowsAsync<TokenError>(() => client.RefreshAsync(third.RefreshToken!));
        Assert.Equal("invalid_grant", err.Error);
        Assert.Equal(400, err.Status);
    }

    [Fact]
    public async Task Introspection_revoked()
    {
        var client = new TokenClient(V.Options());
        var (user, pwd) = V.Users["viewer"];
        var set = await client.PasswordAsync(user, pwd, new[] { "openid", V.Audience });

        var options = V.Options();
        options.Introspect = true;
        var verifier = new TslAuthVerifier(options);
        var p = await verifier.VerifyAsync(set.AccessToken);
        Assert.Equal(user, p.Username);

        var intro = await client.IntrospectAsync(set.AccessToken);
        Assert.True(intro.Active);

        await client.RevokeAsync(set.AccessToken);
        var ex = await Assert.ThrowsAsync<TslAuthException>(() => verifier.VerifyAsync(set.AccessToken));
        Assert.Equal(TslAuthErrorCodes.Revoked, ex.Code);
        Assert.False((await client.IntrospectAsync(set.AccessToken)).Active);
    }

    [Fact]
    public async Task Client_credentials_cache()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var client = new TokenClient(V.Options(clock));
        var scopes = new[] { V.Audience };

        var a = await client.ClientCredentialsAsync(scopes);
        var b = await client.ClientCredentialsAsync(scopes);
        Assert.Equal(a.AccessToken, b.AccessToken);

        // Параллельные вызовы при пустом кэше (другой scope) — один токен на всех.
        var other = new TokenClient(V.Options(clock));
        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => other.ClientCredentialsAsync(scopes)));
        Assert.Single(results.Select(r => r.AccessToken).Distinct());

        // Часы на exp — кэш протух, новый токен.
        clock.Set(a.ExpiresAt);
        var c = await client.ClientCredentialsAsync(scopes);
        Assert.NotEqual(a.AccessToken, c.AccessToken);
    }

    [Fact]
    public async Task Jwks_rotation()
    {
        // Заглушка JWKS: сначала пустой набор, потом настоящий; считает обращения.
        using var http = new HttpClient();
        var realJwks = await http.GetStringAsync(V.JwksUri);
        var hits = 0;
        var serveReal = false;
        using var listener = new HttpListener();
        var port = FreePort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        var serving = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); } catch { return; }
                Interlocked.Increment(ref hits);
                var body = Encoding.UTF8.GetBytes(serveReal ? realJwks : "{\"keys\":[]}");
                ctx.Response.ContentType = "application/json";
                await ctx.Response.OutputStream.WriteAsync(body);
                ctx.Response.Close();
            }
        });

        try
        {
            var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
            var options = V.Options(clock);
            options.JwksUri = $"http://127.0.0.1:{port}/jwks";
            options.JwksMinRefresh = TimeSpan.FromSeconds(1);
            var verifier = new TslAuthVerifier(options);
            var token = V.Case("ok_user").Token;

            var ex = await Assert.ThrowsAsync<TslAuthException>(() => verifier.VerifyAsync(token));
            Assert.Equal(TslAuthErrorCodes.UnknownKey, ex.Code);
            Assert.Equal(1, hits);

            // Тот же неизвестный kid сразу же — лимит частоты, заглушка не трогается.
            serveReal = true;
            ex = await Assert.ThrowsAsync<TslAuthException>(() => verifier.VerifyAsync(token));
            Assert.Equal(TslAuthErrorCodes.UnknownKey, ex.Code);
            Assert.Equal(1, hits);

            // Прошёл JWKS_MIN_REFRESH — перечитываем, ключ найден.
            clock.Advance(TimeSpan.FromSeconds(2));
            var p = await verifier.VerifyAsync(token);
            Assert.Equal("sdk-operator", p.Username);
            Assert.Equal(2, hits);

            // Ключ в кэше — новых обращений нет.
            await verifier.VerifyAsync(token);
            Assert.Equal(2, hits);
        }
        finally
        {
            listener.Stop();
            await serving;
        }
    }

    internal static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
