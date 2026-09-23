using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using TslAuth.Security;

namespace TslAuth.Data;

/// <summary>
/// Единый EF Core контекст сервиса: таблицы ASP.NET Core Identity (пользователи с ключом Guid),
/// сущности OpenIddict (приложения, авторизации, токены, scope), ключи Data Protection
/// (общие для всех экземпляров кластера) и собственные таблицы — матрица доступа, аудит, события/вебхуки,
/// PAT, настройки и т. д. Абстрактный: у каждой СУБД свой наследник со своим набором миграций.
/// Шифрование персональных данных прозрачно для остального кода — делается value converter'ами ниже.
/// </summary>
public abstract class AuthDbContext(DbContextOptions options)
    : IdentityDbContext<AppUser, IdentityRole<Guid>, Guid>(options), IDataProtectionKeyContext
{
    // Персональные данные хранятся зашифрованными (AES-256-GCM),
    // нормализованные логин/email — в виде HMAC-индекса для поиска на равенство.
    // Шифротекст недетерминирован (случайный nonce), поэтому по нему нельзя ни искать, ни строить
    // уникальный индекс; для этого служит blind index — детерминированный HMAC с отдельным ключом.
    // Identity ищет пользователей по NormalizedUserName/NormalizedEmail: EF применяет тот же конвертер
    // к параметру запроса, так что сравнение HMAC = HMAC работает без изменений в коде Identity.
    // Обратного преобразования у индекса нет (v => v): исходное значение восстанавливается только из
    // зашифрованных UserName/Email.
    private static readonly ValueConverter<string?, string?> Encrypted =
        new(v => FieldCrypto.Encrypt(v), v => FieldCrypto.Decrypt(v));

    private static readonly ValueConverter<string, string> EncryptedRequired =
        new(v => FieldCrypto.Encrypt(v)!, v => FieldCrypto.Decrypt(v)!);

    private static readonly ValueConverter<string?, string?> BlindIndexed =
        new(v => FieldCrypto.BlindIndex(v), v => v);

    private static readonly ValueConverter<string, string> BlindIndexedRequired =
        new(v => FieldCrypto.BlindIndex(v)!, v => v);

    // Шифротекст (префикс + base64 от nonce + данные + тег) заметно длиннее исходной строки.
    private const int EncryptedMaxLength = 1024;

    public DbSet<AccessPermission> AccessPermissions { get; set; } = null!;
    public DbSet<AccessRole> AccessRoles { get; set; } = null!;
    public DbSet<AccessRolePermission> AccessRolePermissions { get; set; } = null!;
    public DbSet<AccessRoleAssignment> AccessRoleAssignments { get; set; } = null!;
    public DbSet<KeyMaterial> KeyMaterials { get; set; } = null!;
    public DbSet<AccessRequest> AccessRequests { get; set; } = null!;
    public DbSet<WebhookEvent> WebhookEvents { get; set; } = null!;
    public DbSet<AuditEntry> AuditEntries { get; set; } = null!;
    public DbSet<SystemSetting> SystemSettings { get; set; } = null!;
    public DbSet<PasswordHistoryEntry> PasswordHistory { get; set; } = null!;
    public DbSet<PersonalAccessToken> PersonalAccessTokens { get; set; } = null!;
    public DbSet<LanguagePack> LanguagePacks { get; set; } = null!;
    public DbSet<ExternalIdentity> ExternalIdentities { get; set; } = null!;
    public DbSet<BotLinkCode> BotLinkCodes { get; set; } = null!;
    public DbSet<WebhookSubscription> WebhookSubscriptions { get; set; } = null!;
    public DbSet<WebhookDelivery> WebhookDeliveries { get; set; } = null!;
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        // Регистрирует сущности OpenIddict с ключами Guid (как у Identity).
        builder.UseOpenIddict<Guid>();

        builder.Entity<AppUser>(e =>
        {
            e.Property(u => u.UserName).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength);
            e.Property(u => u.Email).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength);
            e.Property(u => u.PhoneNumber).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength);
            e.Property(u => u.DisplayName).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength);
            e.Property(u => u.NormalizedUserName).HasConversion(BlindIndexed);
            e.Property(u => u.NormalizedEmail).HasConversion(BlindIndexed);
            e.HasIndex(u => u.CreatedAt);
            e.Property(u => u.CreatedByClientId).HasMaxLength(100);
            e.HasIndex(u => u.CreatedByClientId);
        });

        builder.Entity<AccessPermission>(e =>
        {
            e.ToTable("AccessPermissions");
            e.Property(p => p.ClientId).HasMaxLength(100);
            e.Property(p => p.Name).HasMaxLength(100);
            e.Property(p => p.Description).HasMaxLength(500);
            e.HasIndex(p => new { p.ClientId, p.Name }).IsUnique();
        });

        builder.Entity<AccessRole>(e =>
        {
            e.ToTable("AccessRoles");
            e.Property(r => r.ClientId).HasMaxLength(100);
            e.Property(r => r.Name).HasMaxLength(100);
            e.Property(r => r.Description).HasMaxLength(500);
            e.HasIndex(r => new { r.ClientId, r.Name }).IsUnique();
        });

        builder.Entity<AccessRolePermission>(e =>
        {
            e.ToTable("AccessRolePermissions");
            e.HasKey(x => new { x.RoleId, x.PermissionId });
            e.HasOne(x => x.Role).WithMany(r => r.Permissions).HasForeignKey(x => x.RoleId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Permission).WithMany(p => p.Roles).HasForeignKey(x => x.PermissionId).OnDelete(DeleteBehavior.Cascade);
        });

        // Назначение полиморфно (пользователь или сервисный клиент), поэтому SubjectId — строка без внешнего ключа.
        builder.Entity<AccessRoleAssignment>(e =>
        {
            e.ToTable("AccessRoleAssignments");
            e.HasKey(x => new { x.RoleId, x.SubjectType, x.SubjectId });
            e.Property(x => x.SubjectId).HasMaxLength(100);
            e.HasIndex(x => new { x.SubjectType, x.SubjectId });
            e.HasOne(x => x.Role).WithMany(r => r.Assignments).HasForeignKey(x => x.RoleId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<AccessRequest>(e =>
        {
            e.ToTable("AccessRequests");
            e.Property(r => r.Comment).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength * 2);
            e.Property(r => r.DecisionComment).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength * 2);
            e.Property(r => r.DecidedBy).HasMaxLength(150);
            e.HasIndex(r => new { r.Status, r.CreatedAt });
            e.HasIndex(r => r.UserId);
            e.HasOne(r => r.Role).WithMany().HasForeignKey(r => r.RoleId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<AppUser>().WithMany().HasForeignKey(r => r.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        // Автоинкрементный Id — курсор ленты событий (/api/admin/events, SSE).
        builder.Entity<WebhookEvent>(e =>
        {
            e.ToTable("WebhookEvents");
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.Type).HasMaxLength(100);
            e.Property(x => x.Text).HasConversion(EncryptedRequired);
            e.Property(x => x.Data).HasConversion(EncryptedRequired);
            e.HasIndex(x => x.OccurredAt);
        });

        // Составные индексы (фильтр, OccurredAt) под типовые выборки журнала: по клиенту, пользователю, типу.
        builder.Entity<AuditEntry>(e =>
        {
            e.ToTable("AuditLog");
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.Property(x => x.Type).HasMaxLength(100);
            e.Property(x => x.Actor).HasMaxLength(150);
            e.Property(x => x.ActorName).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength);
            e.Property(x => x.ClientId).HasMaxLength(100);
            e.Property(x => x.Ip).HasMaxLength(64);
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.Property(x => x.Instance).HasMaxLength(100);
            e.Property(x => x.Details).HasConversion(Encrypted);
            e.HasIndex(x => x.OccurredAt);
            e.HasIndex(x => new { x.ClientId, x.OccurredAt });
            e.HasIndex(x => new { x.SubjectUserId, x.OccurredAt });
            e.HasIndex(x => new { x.Type, x.OccurredAt });
        });

        builder.Entity<PasswordHistoryEntry>(e =>
        {
            e.ToTable("PasswordHistory");
            e.Property(x => x.Id).ValueGeneratedOnAdd();
            e.HasIndex(x => new { x.UserId, x.CreatedAt });
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<PersonalAccessToken>(e =>
        {
            e.ToTable("PersonalAccessTokens");
            e.Property(x => x.Name).HasMaxLength(100);
            e.Property(x => x.TokenHash).HasMaxLength(100);
            e.Property(x => x.Prefix).HasMaxLength(20);
            e.Property(x => x.Audiences).HasMaxLength(2000);
            e.Property(x => x.LastUsedIp).HasMaxLength(64);
            // Поиск PAT при предъявлении — по SHA-256 хешу; сам токен нигде не хранится.
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => x.UserId);
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ExternalIdentity>(e =>
        {
            e.ToTable("ExternalIdentities");
            e.Property(x => x.Provider).HasMaxLength(50);
            // Внешний ID нужен только для поиска «кто прислал сообщение боту», поэтому хранится лишь blind index.
            e.Property(x => x.ExternalId).HasConversion(BlindIndexedRequired).HasMaxLength(100);
            e.Property(x => x.LinkedByClientId).HasMaxLength(100);
            e.HasIndex(x => new { x.Provider, x.ExternalId }).IsUnique();
            e.HasIndex(x => x.UserId);
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<BotLinkCode>(e =>
        {
            e.ToTable("BotLinkCodes");
            e.HasKey(x => x.CodeHash);
            e.Property(x => x.CodeHash).HasMaxLength(100);
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<LanguagePack>(e =>
        {
            e.ToTable("LanguagePacks");
            e.HasKey(x => x.Culture);
            e.Property(x => x.Culture).HasMaxLength(20);
            e.Property(x => x.Name).HasMaxLength(100);
            e.Property(x => x.UpdatedBy).HasMaxLength(150);
        });

        builder.Entity<SystemSetting>(e =>
        {
            e.ToTable("SystemSettings");
            e.HasKey(x => x.Key);
            e.Property(x => x.Key).HasMaxLength(100);
            e.Property(x => x.UpdatedBy).HasMaxLength(150);
        });

        builder.Entity<WebhookSubscription>(e =>
        {
            e.ToTable("WebhookSubscriptions");
            e.Property(x => x.Name).HasMaxLength(100);
            e.Property(x => x.Url).HasMaxLength(2000);
            e.Property(x => x.Secret).HasConversion(Encrypted).HasMaxLength(EncryptedMaxLength);
            e.Property(x => x.Events).HasMaxLength(2000);
            e.Property(x => x.CreatedBy).HasMaxLength(150);
        });

        // Индекс (Status, NextAttemptAt) — выборка очереди доставки фоновым отправителем.
        builder.Entity<WebhookDelivery>(e =>
        {
            e.ToTable("WebhookDeliveries");
            e.Property(x => x.LockedBy).HasMaxLength(100);
            e.Property(x => x.LastError).HasMaxLength(1000);
            e.HasIndex(x => new { x.Status, x.NextAttemptAt });
            e.HasOne(x => x.Subscription).WithMany().HasForeignKey(x => x.SubscriptionId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Event).WithMany().HasForeignKey(x => x.EventId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<KeyMaterial>(e =>
        {
            e.ToTable("KeyMaterials");
            e.Property(k => k.Id).HasMaxLength(100);
            e.Property(k => k.Value).HasConversion(EncryptedRequired);
        });
    }
}

/// <summary>Контекст для SQLite (одиночная установка/разработка); миграции — Data/Migrations/Sqlite.</summary>
public sealed class SqliteAuthDbContext(DbContextOptions<SqliteAuthDbContext> options) : AuthDbContext(options);

/// <summary>Контекст для PostgreSQL (продакшен и кластер из нескольких экземпляров).</summary>
public sealed class PostgresAuthDbContext(DbContextOptions<PostgresAuthDbContext> options) : AuthDbContext(options);

// Фабрики для `dotnet ef migrations` — строки подключения здесь не используются для реальной работы.
public sealed class SqliteDesignTimeFactory : IDesignTimeDbContextFactory<SqliteAuthDbContext>
{
    public SqliteAuthDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<SqliteAuthDbContext>().UseSqlite("Data Source=design.db").Options);
}

public sealed class PostgresDesignTimeFactory : IDesignTimeDbContextFactory<PostgresAuthDbContext>
{
    public PostgresAuthDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<PostgresAuthDbContext>().UseNpgsql("Host=localhost;Database=design").Options);
}
