using System.Text.Json;

namespace TslAuth.Client.Internal;

/// <summary>Общий HttpClient и discovery с кэшем на срок JwksTtl (§1). Один экземпляр на TslAuthOptions.</summary>
internal sealed class TslHttp
{
    private readonly TslAuthOptions _options;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private Discovery? _discovery;
    private DateTimeOffset _discoveryLoadedAt;

    public TslHttp(TslAuthOptions options)
    {
        _options = options;
        Client = options.HttpMessageHandler is null ? new HttpClient() : new HttpClient(options.HttpMessageHandler, disposeHandler: false);
        Client.Timeout = options.HttpTimeout;
    }

    public HttpClient Client { get; }

    public DateTimeOffset Now => _options.TimeProvider.GetUtcNow();

    /// <summary>Документ discovery; загружается лениво и кэшируется на JwksTtl (single-flight).</summary>
    public async Task<Discovery> GetDiscoveryAsync(CancellationToken ct)
    {
        var d = _discovery;
        if (d is not null && Now - _discoveryLoadedAt < _options.JwksTtl) return d;

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            d = _discovery;
            if (d is not null && Now - _discoveryLoadedAt < _options.JwksTtl) return d;
            var url = _options.RequireIssuer() + "/.well-known/openid-configuration";
            try
            {
                using var doc = await GetJsonAsync(url, ct).ConfigureAwait(false);
                var root = doc.RootElement;
                d = new Discovery(
                    Get(root, "jwks_uri"), Get(root, "token_endpoint"), Get(root, "introspection_endpoint"),
                    Get(root, "revocation_endpoint"), Get(root, "authorization_endpoint"), Get(root, "end_session_endpoint"));
                _discovery = d;
                _discoveryLoadedAt = Now;
                return d;
            }
            catch (Exception) when (_discovery is not null)
            {
                return _discovery; // старый документ лучше, чем отказ
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<JsonDocument> GetJsonAsync(string url, CancellationToken ct)
    {
        using var response = await Client.GetAsync(url, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        return await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
    }

    private static string? Get(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

internal sealed record Discovery(
    string? JwksUri, string? TokenEndpoint, string? IntrospectionEndpoint,
    string? RevocationEndpoint, string? AuthorizationEndpoint, string? EndSessionEndpoint);
