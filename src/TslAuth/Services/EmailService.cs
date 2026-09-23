using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace TslAuth.Services;

/// <summary>Настройки SMTP из секции конфигурации "Smtp". Без Host отправка почты отключена.</summary>
public sealed class SmtpOptions
{
    public const string Section = "Smtp";

    public string? Host { get; set; }
    public int Port { get; set; } = 587;

    /// <summary>None | Auto | SslOnConnect | StartTls | StartTlsWhenAvailable</summary>
    public SecureSocketOptions Security { get; set; } = SecureSocketOptions.StartTlsWhenAvailable;

    public string? UserName { get; set; }
    public string? Password { get; set; }
    public string From { get; set; } = "TSL Auth <no-reply@localhost>";

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Host);
}

/// <summary>
/// Отправка писем (приглашения, сброс пароля, уведомления о заявках). Реализация — <see cref="SmtpEmailSender"/>;
/// используется AccountLinks, AccessRequestService и страницами Account/ForgotPassword, Admin/Index.
/// </summary>
public interface IEmailSender
{
    /// <summary>Настроена ли почта; если нет — UI показывает ссылки администратору вместо отправки.</summary>
    bool IsConfigured { get; }

    /// <summary>Отправляет HTML-письмо; бросает <see cref="AdminException"/>, если почта не настроена.</summary>
    Task SendAsync(string to, string subject, string html, CancellationToken ct = default);
}

/// <summary>Реализация через MailKit (singleton): новое SMTP-соединение на каждое письмо — писем мало, пул не нужен.</summary>
public sealed class SmtpEmailSender(IOptions<SmtpOptions> options, ILogger<SmtpEmailSender> logger) : IEmailSender
{
    public bool IsConfigured => options.Value.IsConfigured;

    public async Task SendAsync(string to, string subject, string html, CancellationToken ct = default)
    {
        var o = options.Value;
        if (!o.IsConfigured)
        {
            // Без SMTP письмо не отправляется; ссылки приглашений доступны администратору в интерфейсе.
            logger.LogWarning("SMTP не настроен, письмо '{Subject}' не отправлено.", subject);
            throw new AdminException("Отправка почты не настроена (секция Smtp).");
        }

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(o.From));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = new BodyBuilder { HtmlBody = html }.ToMessageBody();

        using var client = new SmtpClient();
        await client.ConnectAsync(o.Host!, o.Port, o.Security, ct);
        if (!string.IsNullOrEmpty(o.UserName))
            await client.AuthenticateAsync(o.UserName, o.Password ?? "", ct);
        await client.SendAsync(message, ct);
        await client.DisconnectAsync(true, ct);
    }
}
