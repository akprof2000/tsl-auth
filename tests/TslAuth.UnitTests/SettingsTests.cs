using System.Text.Json;
using TslAuth.Localization;
using TslAuth.Services;

namespace TslAuth.UnitTests;

/// <summary>Настройки времени выполнения: сроки хранения журнала (по префиксу типа), валидация, сериализация.</summary>
public sealed class RuntimeSettingsTests
{
    [Fact]
    public void Defaults_AreValid() => new RuntimeSettings().Validate();

    [Fact]
    public void RetentionFor_UsesLongestPrefix_ThenDefault()
    {
        var s = new RuntimeSettings(AuditRetentionDays: 100, AuditRetentionByType: new()
        {
            ["auth."] = 30,
            ["auth.login.failed"] = 400
        });
        Assert.Equal(400, s.RetentionFor("auth.login.failed"));
        Assert.Equal(30, s.RetentionFor("auth.logout"));
        Assert.Equal(100, s.RetentionFor("admin.change"));
    }

    [Fact]
    public void DefaultRules_KeepAdminChangesLongerThanTokens()
    {
        var s = new RuntimeSettings();
        Assert.True(s.RetentionFor(AuditTypes.AdminChange) > s.RetentionFor(AuditTypes.TokenIssued));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4000)]
    public void Validate_RejectsBadRetention(int days) =>
        Assert.Throws<AdminException>(() => new RuntimeSettings(AuditRetentionDays: days).Validate());

    [Fact]
    public void Validate_RejectsBadPerTypeRetention() =>
        Assert.Throws<AdminException>(() => new RuntimeSettings(AuditRetentionByType: new() { ["x"] = 0 }).Validate());

    [Fact]
    public void SerializationRoundtrip_KeepsNestedPolicies()
    {
        var s = new RuntimeSettings(PasswordPolicy: new PasswordPolicy(MinLength: 12, HistoryCount: 5),
            TokenPolicy: new TokenPolicy(AccessTokenMinutes: 5), BotResetPolicy: new BotResetPolicy(Mode: "temporary"));
        var back = JsonSerializer.Deserialize<RuntimeSettings>(JsonSerializer.Serialize(s))!;
        Assert.Equal(12, back.Passwords.MinLength);
        Assert.Equal(5, back.Passwords.HistoryCount);
        Assert.Equal(5, back.Tokens.AccessTokenMinutes);
        Assert.Equal("temporary", back.BotReset.Mode);
    }
}

/// <summary>Границы допустимых значений политик паролей, токенов, бота и сроков жизни приложения.</summary>
public sealed class PolicyValidationTests
{
    [Theory]
    [InlineData(5)]
    [InlineData(129)]
    public void PasswordPolicy_MinLengthBounds(int length) =>
        Assert.Throws<AdminException>(() => new PasswordPolicy(MinLength: length).Validate());

    [Fact]
    public void PasswordPolicy_UniqueCharsCannotExceedLength() =>
        Assert.Throws<AdminException>(() => new PasswordPolicy(MinLength: 8, MinUniqueChars: 9).Validate());

    [Fact]
    public void TokenPolicy_CodeLifetimeMax30() =>
        Assert.Throws<AdminException>(() => new TokenPolicy(AuthorizationCodeMinutes: 31).Validate());

    [Fact]
    public void BotPolicy_UnknownMode() =>
        Assert.Throws<AdminException>(() => new BotResetPolicy(Mode: "sms").Validate());

    [Fact]
    public void AppLifetimes_Bounds() =>
        Assert.Throws<AdminException>(() => new AppTokenLifetimes(AccessTokenMinutes: 0).Validate());
}

/// <summary>Встроенные языковые пакеты ru/en: одинаковый набор ключей и совпадающие плейсхолдеры {N}.</summary>
public sealed class LanguagePackTests
{
    [Fact]
    public void BuiltInPacks_HaveSameKeys()
    {
        var ru = LocalizationService.Template("ru").Keys.ToHashSet();
        var en = LocalizationService.Template("en").Keys.ToHashSet();
        Assert.Empty(ru.Except(en));
        Assert.Empty(en.Except(ru));
    }

    [Fact]
    public void BuiltInPacks_FormatPlaceholdersMatch()
    {
        var ru = LocalizationService.Template("ru");
        var en = LocalizationService.Template("en");
        foreach (var (key, value) in ru)
        {
            var placeholders = System.Text.RegularExpressions.Regex.Matches(value, @"\{\d\}").Select(m => m.Value).Order();
            var enPlaceholders = System.Text.RegularExpressions.Regex.Matches(en[key], @"\{\d\}").Select(m => m.Value).Order();
            Assert.True(placeholders.SequenceEqual(enPlaceholders), $"Плейсхолдеры отличаются в ключе {key}");
        }
    }
}
