using System.Text.Json;
using Microsoft.Extensions.Configuration;
using TslAuth.Client;

namespace TslAuth.Client.Tests;

/// <summary>§8 п. 2: каждый случай vectors.json даёт ровно ожидаемый код; для ok_* — поля principal.</summary>
public class ContractVectorTests
{
    public static IEnumerable<object[]> Cases() => Vectors.Current.Cases.Select(c => new object[] { c });

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Vector(VectorCase c)
    {
        var v = Vectors.Current;
        if (c.Name == "not_yet_valid" && c.SkipIfNoNbf) return; // в токене нет nbf — случай пропускается по контракту

        var clock = c.Now is { } now ? new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(now)) : null;
        var verifier = new TslAuthVerifier(v.Options(clock, c.Issuer));

        if (c.Expect == "ok")
        {
            var p = await verifier.VerifyAsync(c.Token);
            CheckExpected(v, c.Name, p);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<TslAuthException>(() => verifier.VerifyAsync(c.Token));
            Assert.Equal(c.Expect, ex.Code);
        }
    }

    private static void CheckExpected(Vectors v, string name, TslPrincipal p)
    {
        Assert.True(v.Expected.TryGetProperty(name, out var e), $"нет expected для {name}");
        if (e.TryGetProperty("subjectType", out var st)) Assert.Equal(st.GetString(), p.SubjectType);
        if (e.TryGetProperty("subject", out var s)) Assert.Equal(s.GetString(), p.Subject);
        if (e.TryGetProperty("username", out var u)) Assert.Equal(u.GetString(), p.Username);
        if (e.TryGetProperty("permissions", out var perms))
            Assert.Equal(perms.EnumerateArray().Select(x => x.GetString()!).OrderBy(x => x), p.Permissions.OrderBy(x => x));
        if (e.TryGetProperty("roles", out var roles))
            Assert.Equal(roles.EnumerateArray().Select(x => x.GetString()!).OrderBy(x => x), p.Roles.OrderBy(x => x));
        if (e.TryGetProperty("actorSub", out var act))
        {
            Assert.NotNull(p.Actor);
            Assert.Equal(act.GetString(), p.Actor!.Subject);
        }

        switch (name)
        {
            case "ok_user":
                Assert.True(p.HasPermission("orders.read"));
                Assert.True(p.HasPermission("orders.write"));
                Assert.True(p.HasRole("operator"));
                Assert.False(p.HasPermission(v.Audience + ":orders.read")); // полная форма не принимается
                Assert.Contains(v.Audience + ":orders.read", p.AllPermissions);
                Assert.Null(p.Actor);
                break;
            case "ok_viewer":
                Assert.False(p.HasPermission("orders.write"));
                break;
            case "ok_client":
                Assert.Null(p.Username);
                break;
        }
        Assert.Equal(JsonValueKind.Object, p.Claims.ValueKind);
        Assert.True(p.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(-1));
    }

    [Fact]
    public async Task ClaimsPrincipal_keeps_token_claims()
    {
        var v = Vectors.Current;
        var p = await new TslAuthVerifier(v.Options()).VerifyAsync(v.Case("ok_user").Token);
        var cp = p.ToClaimsPrincipal();
        Assert.Equal("sdk-operator", cp.Identity!.Name);
        Assert.Contains(cp.FindAll("permissions"), c => c.Value == v.Audience + ":orders.read");
        Assert.Contains(cp.FindAll("role"), c => c.Value == v.Audience + ":operator");
        Assert.True(cp.Identity.IsAuthenticated);
    }

    [Fact]
    public void Options_from_environment_and_configuration()
    {
        var cfg = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TslAuth:Issuer"] = "https://cfg.example/",
                ["TslAuth:Audience"] = "api",
                ["TslAuth:ClockSkewSeconds"] = "5",
                ["TslAuth:Introspect"] = "true",
            }).Build();
        var o = TslAuthOptions.FromConfiguration(cfg.GetSection("TslAuth"), environmentOverrides: false);
        Assert.Equal("https://cfg.example/", o.Issuer);
        Assert.Equal("api", o.Audience);
        Assert.Equal(TimeSpan.FromSeconds(5), o.ClockSkew);
        Assert.True(o.Introspect);
        Assert.Equal(TimeSpan.FromSeconds(600), o.JwksTtl);
        Assert.Equal(TimeSpan.FromSeconds(10), o.JwksMinRefresh);
        Assert.Equal(TimeSpan.FromSeconds(10), o.HttpTimeout);
    }
}
