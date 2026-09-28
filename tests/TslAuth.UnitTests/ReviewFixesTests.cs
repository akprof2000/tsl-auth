// Unit-тесты исправлений по ревизии: политика адресов вебхуков, доверенные сети, язык, аудит, профиль.
// Запуск: dotnet test tests/TslAuth.UnitTests. Внешние зависимости не нужны: проверяются
// отдельные классы сервиса без поднятия HTTP-хоста и БД.

using System.Net;
using TslAuth.Infrastructure;
using TslAuth.Localization;
using TslAuth.Services;

namespace TslAuth.UnitTests;

/// <summary>Регрессионные unit-тесты исправлений по отчёту ревизии (docs/code-review-2026-09-24.md).</summary>
public sealed class WebhookTargetPolicyTests
{
    private static readonly WebhookTargetPolicy Default = new([]);

    // M6: адреса самого узла и инфраструктуры — всегда запрещены.
    /// <summary>Эти адреса запрещены для вебхуков при любых настройках.</summary>
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("169.254.169.254")] // метаданные облака
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("fe80::1")]
    [InlineData("::ffff:127.0.0.1")] // IPv4-mapped loopback
    public void Forbidden_Always(string address) => Assert.False(Default.IsAllowed(IPAddress.Parse(address)));

    // Закрытый контур: частные сети по умолчанию разрешены (бот/мессенджер во внутренней сети).
    /// <summary>Эти адреса разрешены политикой по умолчанию.</summary>
    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("192.168.1.10")]
    [InlineData("172.20.0.5")]
    [InlineData("93.184.216.34")]
    public void Allowed_ByDefault(string address) => Assert.True(Default.IsAllowed(IPAddress.Parse(address)));

    /// <summary>Список разрешённых сетей сужает допустимые адреса.</summary>
    [Fact]
    public void AllowedNetworks_RestrictTargets()
    {
        var policy = new WebhookTargetPolicy([IPNetwork.Parse("10.20.0.0/16")]);
        Assert.True(policy.IsAllowed(IPAddress.Parse("10.20.5.5")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("10.21.0.1")));
        Assert.False(policy.IsAllowed(IPAddress.Parse("127.0.0.1")));
    }

    /// <summary>Недопустимый URL вебхука отклоняется при сохранении.</summary>
    [Theory]
    [InlineData("http://localhost:8080/hook")]
    [InlineData("http://127.0.0.1/hook")]
    [InlineData("http://[::1]/hook")]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    public void Reject_OnSave(string url) => Assert.NotNull(Default.Reject(new Uri(url)));

    [Fact]
    public void Accept_InternalHostName() => Assert.Null(Default.Reject(new Uri("https://mattermost.corp/hooks/abc")));
}

public sealed class KnownNetworksTests
{
    // H7: по умолчанию — loopback и частные сети; прочие адреса не могут подменять X-Forwarded-*.
    /// <summary>Доверенные сети по умолчанию — только loopback и частные диапазоны.</summary>
    [Fact]
    public void Default_IsLoopbackAndPrivateOnly()
    {
        var networks = ServiceSetup.ParseKnownNetworks(null);
        Assert.Contains(networks, n => n.Contains(IPAddress.Parse("172.18.0.3")));
        Assert.Contains(networks, n => n.Contains(IPAddress.Parse("127.0.0.1")));
        Assert.DoesNotContain(networks, n => n.Contains(IPAddress.Parse("93.184.216.34")));
    }

    /// <summary>Явный список доверенных сетей заменяет список по умолчанию.</summary>
    [Fact]
    public void Explicit_ReplacesDefault()
    {
        var networks = ServiceSetup.ParseKnownNetworks("10.0.5.0/24; 192.168.7.0/24");
        Assert.Equal(2, networks.Count);
        Assert.DoesNotContain(networks, n => n.Contains(IPAddress.Parse("172.18.0.3")));
    }

    [Fact]
    public void Invalid_FailsStartup() => Assert.Throws<InvalidOperationException>(() => ServiceSetup.ParseKnownNetworks("10.0.0.0/33"));
}

public sealed class SmallFixesTests
{
    // H6: код языка канонизируется — «RU» и «ru» не становятся разными пакетами.
    /// <summary>Код языка приводится к каноническому виду.</summary>
    [Theory]
    [InlineData("RU", "ru")]
    [InlineData("en-us", "en-US")]
    [InlineData("UZ-latn", "uz-Latn")]
    [InlineData(" kk ", "kk")]
    public void CultureIsCanonical(string input, string expected) => Assert.Equal(expected, LocalizationService.Canonical(input));

    // H5: время без зоны из API считается UTC (PostgreSQL не принимает Kind=Unspecified).
    /// <summary>Даты фильтра аудита приводятся к UTC.</summary>
    [Fact]
    public void AuditDates_AreUtc()
    {
        var unspecified = new DateTime(2026, 9, 24, 10, 0, 0, DateTimeKind.Unspecified);
        var utc = AuditService.AsUtc(unspecified);
        Assert.Equal(DateTimeKind.Utc, utc.Kind);
        Assert.Equal(unspecified.Ticks, utc.Ticks);
    }

    // L5: в журнал — не сырой ввод логина (туда вводят пароли), а маска.
    /// <summary>Логин в аудите частично маскируется.</summary>
    [Fact]
    public void Login_IsMaskedInAudit()
    {
        Assert.Equal("P@… (12)", UserService.MaskLogin("P@ssw0rd-123"));
        Assert.Equal("", UserService.MaskLogin(null));
    }

    // L17: длины полей профиля проверяются до записи в БД.
    /// <summary>Длины полей профиля проверяются.</summary>
    [Fact]
    public void ProfileLengths_AreChecked()
    {
        var ex = Assert.Throws<AdminException>(() => UserService.CheckLengths(new UserInput(new string('a', 257), null, null, true)));
        Assert.Equal("error.userNameInvalid", ex.Key);
        UserService.CheckLengths(new UserInput(new string('я', 256), "a@b.c", new string('я', 200), true));
    }

    // L28: «не найдено» локализуется на пользовательских страницах.
    [Fact]
    public void NotFound_HasLocalizationKey() => Assert.Equal("error.notFound", AdminException.NotFound("Токен").Key);
}
