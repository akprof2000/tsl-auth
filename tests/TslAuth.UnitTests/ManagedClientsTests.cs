// Unit-тесты подчинённых клиентов и входа по ключу: политика (префикс, роли, потоки, пределы), разбор JWKS
// (только EC P-256, отпечаток RFC 7638, без закрытой части, не больше двух ключей), правила assertion
// (alg, срок, jti) и блокировка client_id после серии отказов. Запуск: dotnet test tests/TslAuth.UnitTests.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using TslAuth.Infrastructure;
using TslAuth.Services;

namespace TslAuth.UnitTests;

public sealed class ManagedClientsPolicyTests
{
    /// <summary>Нормализация подставляет умолчания: client_credentials, private_key_jwt.</summary>
    [Fact]
    public void Normalize_Defaults()
    {
        var p = new ManagedClientsPolicy("import-agent-", ["uploader"]).Normalize();
        Assert.Equal(["client_credentials"], p.GrantTypes);
        Assert.Equal(["private_key_jwt"], p.AuthMethods);
        Assert.True(p.AllowsKeys);
        Assert.False(p.AllowsSecret);
        Assert.Equal(200, p.MaxClients);
        Assert.Equal(5, p.AccessTokenLifetime);
        Assert.True(p.RequireDelegation);
    }

    [Theory]
    [InlineData("Import-")]
    [InlineData("")]
    [InlineData("a b")]
    [InlineData("very-long-prefix-that-exceeds-the-allowed-length-for-client-ids-1")]
    public void Normalize_BadPrefix_Throws(string prefix) =>
        Assert.Throws<AdminException>(() => new ManagedClientsPolicy(prefix).Normalize());

    [Fact]
    public void Normalize_OtherGrantOrMethod_Throws()
    {
        Assert.Throws<AdminException>(() => new ManagedClientsPolicy("a-", GrantTypes: ["password"]).Normalize());
        Assert.Throws<AdminException>(() => new ManagedClientsPolicy("a-", AuthMethods: ["none"]).Normalize());
        Assert.Throws<AdminException>(() => new ManagedClientsPolicy("a-", MaxClients: 0).Normalize());
        Assert.Throws<AdminException>(() => new ManagedClientsPolicy("a-", AccessTokenLifetime: 0).Normalize());
        Assert.Throws<AdminException>(() => new ManagedClientsPolicy("a-", ManagePermission: "bad permission").Normalize());
        Assert.Throws<AdminException>(() => new ManagedClientsPolicy("a-", Roles: ["Bad Role"]).Normalize());
    }

    /// <summary>client_id: префикс обязателен, символы [a-z0-9-], длина ≤ 64.</summary>
    [Fact]
    public void ValidateClientId_PrefixCharsLength()
    {
        var p = new ManagedClientsPolicy("agent-", ["uploader"]).Normalize();
        Assert.Equal("agent-01", p.ValidateClientId(" agent-01 "));
        Assert.Throws<AdminException>(() => p.ValidateClientId("other-01"));
        Assert.Throws<AdminException>(() => p.ValidateClientId("agent-A1"));
        Assert.Throws<AdminException>(() => p.ValidateClientId("agent-" + new string('a', 60)));
        Assert.Equal(["uploader"], p.ValidateRoles(["uploader", "uploader"]));
        Assert.Throws<AdminException>(() => p.ValidateRoles(["admin"]));
    }
}

public sealed class ManagedClientKeysTests
{
    private static (JsonElement Jwk, string X, string Y) NewJwk(ECCurve? curve = null, bool withPrivate = false)
    {
        using var ecdsa = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(withPrivate);
        var x = Base64UrlEncoder.Encode(p.Q.X!);
        var y = Base64UrlEncoder.Encode(p.Q.Y!);
        var crv = curve is null ? "P-256" : "P-384";
        var d = withPrivate ? $",\"d\":\"{Base64UrlEncoder.Encode(p.D!)}\"" : "";
        return (JsonSerializer.Deserialize<JsonElement>($"{{\"kty\":\"EC\",\"crv\":\"{crv}\",\"x\":\"{x}\",\"y\":\"{y}\",\"kid\":\"client-chosen\"{d}}}"), x, y);
    }

    private static JsonElement Set(params JsonElement[] keys) =>
        JsonSerializer.SerializeToElement(new { keys });

    /// <summary>kid — отпечаток RFC 7638 (SHA-256 канонического JSON), а не значение из запроса.</summary>
    [Fact]
    public void Parse_ComputesRfc7638Thumbprint()
    {
        var (jwk, x, y) = NewJwk();
        var set = ManagedClientKeys.Parse(Set(jwk));
        var expected = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));
        Assert.Equal(expected, set.Keys.Single().KeyId);
        Assert.Equal("ES256", set.Keys.Single().Alg);
        // Один JWK без обёртки keys тоже принимается.
        Assert.Equal(expected, ManagedClientKeys.Parse(jwk).Keys.Single().KeyId);
    }

    [Fact]
    public void Parse_RejectsPrivateOtherCurveAndTooMany()
    {
        Assert.Throws<AdminException>(() => ManagedClientKeys.Parse(Set(NewJwk(withPrivate: true).Jwk)));
        Assert.Throws<AdminException>(() => ManagedClientKeys.Parse(Set(NewJwk(ECCurve.NamedCurves.nistP384).Jwk)));
        Assert.Throws<AdminException>(() => ManagedClientKeys.Parse(Set(NewJwk().Jwk, NewJwk().Jwk, NewJwk().Jwk)));
        Assert.Throws<AdminException>(() => ManagedClientKeys.Parse(JsonSerializer.SerializeToElement(new { keys = Array.Empty<object>() })));
        Assert.Throws<AdminException>(() => ManagedClientKeys.Parse(JsonSerializer.Deserialize<JsonElement>("""{"kty":"RSA","n":"AQAB","e":"AQAB"}""")));
        Assert.Throws<AdminException>(() => ManagedClientKeys.Parse(JsonSerializer.Deserialize<JsonElement>("""{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}""")));
        var same = NewJwk().Jwk;
        Assert.Throws<AdminException>(() => ManagedClientKeys.Parse(Set(same, same)));
    }
}

public sealed class ClientAssertionRulesTests
{
    private static string Token(string alg, int lifetimeSeconds = 60, bool jti = true, bool iat = true, SecurityKey? key = null)
    {
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object> { ["sub"] = "agent-1" };
        if (jti) claims["jti"] = Guid.NewGuid().ToString("N");
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "agent-1", Audience = "http://localhost/", Claims = claims, Expires = now.AddSeconds(lifetimeSeconds), NotBefore = now,
            IssuedAt = iat ? now : null,
            SigningCredentials = alg == "none" ? null : new SigningCredentials(key ?? new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)), alg)
        };
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    [Fact]
    public void Valid_Es256_Passes()
    {
        Assert.Null(ClientAssertionRules.Check(Token("ES256"), out var token));
        Assert.Equal("agent-1", token!.Subject);
    }

    [Fact]
    public void Rejects_None_Hs256_Rs256()
    {
        Assert.Equal("alg", ClientAssertionRules.Check(Token("none"), out _));
        Assert.Equal("alg", ClientAssertionRules.Check(Token("HS256", key: new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32))), out _));
        Assert.Equal("alg", ClientAssertionRules.Check(Token("RS256", key: new RsaSecurityKey(RSA.Create(2048))), out _));
    }

    [Fact]
    public void Rejects_LongLifetime_MissingJti_MissingIat_Garbage()
    {
        Assert.Equal("lifetime", ClientAssertionRules.Check(Token("ES256", lifetimeSeconds: 301), out _));
        Assert.Null(ClientAssertionRules.Check(Token("ES256", lifetimeSeconds: 300), out _));
        Assert.Equal("jti_missing", ClientAssertionRules.Check(Token("ES256", jti: false), out _));
        Assert.Equal("iat_missing", ClientAssertionRules.Check(Token("ES256", iat: false), out _));
        Assert.Equal("malformed", ClientAssertionRules.Check("not.a.jwt", out _));
    }
}

public sealed class ClientFailureLimiterTests
{
    /// <summary>Управляемые часы: тест сдвигает время вместо ожидания минуты.</summary>
    private sealed class TestClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>После N отказов клиент блокируется на минуту; окно отказов и блокировка истекают по часам.</summary>
    [Fact]
    public void Blocks_AfterThreshold_ForOneMinute()
    {
        var clock = new TestClock(DateTimeOffset.Parse("2026-09-30T10:00:00Z"));
        var limiter = new ClientFailureLimiter(3, clock);
        Assert.False(limiter.RecordFailure("a"));
        Assert.False(limiter.RecordFailure("a"));
        Assert.False(limiter.IsBlocked("a"));
        Assert.True(limiter.RecordFailure("a"));
        Assert.True(limiter.IsBlocked("a"));
        Assert.False(limiter.IsBlocked("b"));
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.False(limiter.IsBlocked("a"));
        // Окно сброшено: снова нужны три отказа.
        Assert.False(limiter.RecordFailure("a"));
        Assert.False(limiter.IsBlocked("a"));
    }

    [Fact]
    public void Disabled_WhenZero()
    {
        var limiter = new ClientFailureLimiter(0);
        for (var i = 0; i < 50; i++) Assert.False(limiter.RecordFailure("a"));
        Assert.False(limiter.IsBlocked("a"));
    }
}
