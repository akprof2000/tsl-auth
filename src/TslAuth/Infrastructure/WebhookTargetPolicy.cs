using System.Net;
using System.Net.Sockets;

namespace TslAuth.Infrastructure;

/// <summary>
/// Куда можно доставлять вебхуки (защита от SSRF: подписку может создать бот с ролью notifier).
/// Всегда запрещены loopback, link-local (в т.ч. 169.254.169.254 — метаданные облака), multicast, broadcast
/// и неопределённый адрес: там живут сервисы самого узла и инфраструктуры, а не получатели уведомлений.
/// Частные сети по умолчанию разрешены — в закрытом контуре бот/мессенджер обычно во внутренней сети;
/// ограничить доставку конкретными сетями можно настройкой Webhooks:AllowedNetworks (CIDR через запятую).
/// Проверяется адрес, к которому реально идёт соединение (после DNS), — подмена DNS (rebinding) не обходит проверку.
/// </summary>
public sealed class WebhookTargetPolicy(IReadOnlyList<IPNetwork> allowed)
{
    public static WebhookTargetPolicy FromConfig(IConfiguration config)
    {
        var value = config["Webhooks:AllowedNetworks"];
        var networks = string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(n => IPNetwork.TryParse(n, out var net) ? net
                    : throw new InvalidOperationException($"Webhooks:AllowedNetworks: '{n}' — не CIDR.")).ToList();
        return new WebhookTargetPolicy(networks);
    }

    public bool IsAllowed(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.Broadcast) || address.IsIPv6LinkLocal || address.IsIPv6Multicast)
            return false;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            if (b[0] == 169 && b[1] == 254) return false; // link-local, метаданные облака
            if (b[0] >= 224) return false;                 // multicast и зарезервированные
            if (b[0] == 0) return false;
        }
        return allowed.Count == 0 || allowed.Any(n => n.Contains(address));
    }

    /// <summary>Проверка при сохранении подписки: явно запрещённые адреса и «localhost» отклоняются сразу.</summary>
    public string? Reject(Uri uri)
    {
        if (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return "Адрес вебхука не может указывать на сам сервер (localhost).";
        if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && !IsAllowed(ip))
            return "Адрес вебхука запрещён политикой (loopback, link-local, multicast или вне Webhooks:AllowedNetworks).";
        return null;
    }

    /// <summary>
    /// Соединение для HttpClient вебхуков: разрешает имя, проверяет все адреса и подключается к разрешённому.
    /// Если хотя бы один адрес имени запрещён — отказ целиком (имя, указывающее на внутренний сервис, подозрительно).
    /// </summary>
    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
        if (addresses.Length == 0 || addresses.Any(a => !IsAllowed(a)))
            throw new HttpRequestException($"Адрес '{context.DnsEndPoint.Host}' запрещён политикой доставки вебхуков.");
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
