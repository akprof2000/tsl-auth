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

    /// <summary>
    /// §6 токен подключения: робот своим секретом обменивает токен, который ему выписал пользователь, на JWT с правами
    /// пользователя и claim act = робот; JWT кэшируется; клиент без потока connection_token — unauthorized_client.
    /// </summary>
    [Fact]
    public async Task Connection_token_robot()
    {
        Assert.False(string.IsNullOrEmpty(V.Robot.Id), "в vectors.json нет robot — обновите make-vectors.py");
        var expected = V.Expected.GetProperty("robot");
        var options = V.Options();
        options.ClientId = V.Robot.Id;
        options.ClientSecret = V.Robot.Secret;
        using var robot = new TokenClient(options);

        var set = await robot.ConnectionTokenAsync(V.Robot.ConnectionToken);
        Assert.Null(set.RefreshToken);
        Assert.Same(set, await robot.ConnectionTokenAsync(V.Robot.ConnectionToken)); // кэш до expiresAt − 30 с

        var p = await new TslAuthVerifier(V.Options()).VerifyAsync(set.AccessToken);
        Assert.Equal(expected.GetProperty("subjectType").GetString(), p.SubjectType);
        Assert.Equal(expected.GetProperty("username").GetString(), p.Username);
        Assert.Equal(expected.GetProperty("actorSub").GetString(), p.Actor?.Subject);
        foreach (var perm in expected.GetProperty("permissions").EnumerateArray())
            Assert.True(p.HasPermission(perm.GetString()!), perm.GetString());

        // Обычному клиенту (без разрешения администратора на токены подключения) обмен недоступен.
        using var stranger = new TokenClient(V.Options());
        var err = await Assert.ThrowsAsync<TokenError>(() => stranger.ConnectionTokenAsync(V.Robot.ConnectionToken));
        Assert.Equal("unauthorized_client", err.Error);
    }

    /// <summary>
    /// §6 private_key_jwt: владелец регистрирует подчинённого с открытым ключом SDK, подчинённый получает токен
    /// без секрета (ES256-assertion), в токене роль владельца; тот же клиент с секретом «wrong» — invalid_client.
    /// </summary>
    [Fact]
    public async Task Private_key_jwt_managed_client()
    {
        var (ownerId, ownerSecret, prefix, role) = V.ManagedOwner;
        Assert.False(string.IsNullOrEmpty(ownerId), "в vectors.json нет managedOwner — обновите make-vectors.py");
        var owner = new TokenClient(new TslAuthOptions { Issuer = V.Issuer, ClientId = ownerId, ClientSecret = ownerSecret });
        var ownerToken = await owner.ClientCredentialsAsync(new[] { "tsl-auth-app" });

        var pem = ClientKeys.GeneratePrivateKeyPem();
        using var http = new HttpClient { BaseAddress = new Uri(V.Issuer) };
        http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", ownerToken.AccessToken);
        using var jwks = System.Text.Json.JsonDocument.Parse(ClientKeys.PublicJwks(pem));
        var body = new { clientIdSuffix = "dotnet-" + Guid.NewGuid().ToString("N")[..8], displayName = "SDK .NET", roles = new[] { role }, jwks = jwks.RootElement };
        var response = await http.PostAsync("/api/app/clients", new StringContent(System.Text.Json.JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"));
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        using var created = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var clientId = created.RootElement.GetProperty("client").GetProperty("clientId").GetString()!;
        Assert.StartsWith(prefix, clientId);
        Assert.Equal(ClientKeys.KeyId(pem), created.RootElement.GetProperty("client").GetProperty("keys")[0].GetProperty("kid").GetString());

        try
        {
            var agent = new TokenClient(new TslAuthOptions { Issuer = V.Issuer, ClientId = clientId, ClientPrivateKeyPem = pem });
            Assert.True(agent.UsesPrivateKeyJwt);
            var set = await agent.ClientCredentialsAsync(new[] { ownerId });
            var claims = System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(Pad(set.AccessToken.Split('.')[1]))).RootElement;
            Assert.Equal(clientId, claims.GetProperty("sub").GetString());
            // Claim с одним значением сериализуется строкой, с несколькими — массивом.
            var roles = claims.GetProperty("role");
            Assert.Contains($"{ownerId}:{role}", roles.ValueKind == System.Text.Json.JsonValueKind.Array
                ? roles.EnumerateArray().Select(r => r.GetString()) : new[] { roles.GetString() });
            Assert.True((await agent.IntrospectAsync(set.AccessToken)).Active);

            // Другой ключ с тем же client_id — отказ.
            var impostor = new TokenClient(new TslAuthOptions { Issuer = V.Issuer, ClientId = clientId, ClientPrivateKeyPem = ClientKeys.GeneratePrivateKeyPem() });
            var err = await Assert.ThrowsAsync<TokenError>(() => impostor.ClientCredentialsAsync(new[] { ownerId }));
            Assert.Equal("invalid_client", err.Error);
        }
        finally
        {
            await http.DeleteAsync($"/api/app/clients/{clientId}");
        }
    }

    private static string Pad(string b64) => b64.Replace('-', '+').Replace('_', '/') + new string('=', (4 - b64.Length % 4) % 4);

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
