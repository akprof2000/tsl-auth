namespace Docflow.Api;

/// <summary>
/// В Docker браузер ходит в TSL Auth по публичному адресу (issuer, например http://localhost:8080/), а контейнеры —
/// по внутреннему (http://tsl-auth:8080/). Discovery-документ содержит публичные адреса (jwks_uri и т. п.),
/// поэтому для запросов сервер→сервер подменяем схему/хост/порт публичного адреса на внутренний.
/// </summary>
public sealed class IssuerRewriteHandler(string publicUrl, string internalUrl) : DelegatingHandler(new HttpClientHandler())
{
    private readonly Uri _public = new(publicUrl);
    private readonly Uri _internal = new(internalUrl);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.RequestUri is { } uri && _public != _internal &&
            Uri.Compare(uri, _public, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0)
        {
            request.RequestUri = new UriBuilder(uri) { Scheme = _internal.Scheme, Host = _internal.Host, Port = _internal.Port }.Uri;
        }
        return base.SendAsync(request, ct);
    }
}
