// Модель данных демо-документооборота. Всё, что связано с учётными записями и ролями, здесь НЕ хранится:
// пользователи живут в TSL Auth, права приходят в JWT, назначения ролей делаются через App API.
// В базе — только документы и то, что к ним относится (версии, маршрут, комментарии, вложения, история).
using Microsoft.EntityFrameworkCore;

namespace Docflow.Api;

public enum DocStatus { Draft, InReview, Approved, Rejected, Archived }
public enum StepKind { Review, Approve }
public enum StepStatus { Pending, Active, Done, Rejected }

public sealed class Document
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Number { get; set; } = "";
    public string Title { get; set; } = "";
    public string Type { get; set; } = "Служебная записка";
    public string Content { get; set; } = "";
    public DocStatus Status { get; set; } = DocStatus.Draft;
    public Guid AuthorId { get; set; }
    public string AuthorName { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public int Version { get; set; } = 1;
    public List<DocumentVersion> Versions { get; set; } = [];
    public List<RouteStep> Steps { get; set; } = [];
    public List<Comment> Comments { get; set; } = [];
    public List<Attachment> Attachments { get; set; } = [];
    public List<HistoryEntry> History { get; set; } = [];
}

/// <summary>Снимок документа на момент отправки на согласование (версии нумеруются с 1).</summary>
public sealed class DocumentVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DocumentId { get; set; }
    public int Number { get; set; }
    public string Title { get; set; } = "";
    public string Content { get; set; } = "";
    public string CreatedByName { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? Note { get; set; }
}

/// <summary>Шаг маршрута: исполнитель — конкретный пользователь или любой с ролью (например reviewer).</summary>
public sealed class RouteStep
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DocumentId { get; set; }
    public int Order { get; set; }
    public StepKind Kind { get; set; }
    public string? AssigneeRole { get; set; }
    public Guid? AssigneeUserId { get; set; }
    public string? AssigneeName { get; set; }
    public StepStatus Status { get; set; } = StepStatus.Pending;
    public Guid? DecidedById { get; set; }
    public string? DecidedByName { get; set; }
    public DateTime? DecidedAt { get; set; }
    public string? Comment { get; set; }
}

public sealed class Comment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DocumentId { get; set; }
    public Guid AuthorId { get; set; }
    public string AuthorName { get; set; } = "";
    public string Text { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>Вложение хранится прямо в SQLite (демо; лимит 5 МБ на файл).</summary>
public sealed class Attachment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DocumentId { get; set; }
    public string FileName { get; set; } = "";
    public string ContentType { get; set; } = "application/octet-stream";
    public long Size { get; set; }
    public byte[] Data { get; set; } = [];
    public string UploadedByName { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public sealed class HistoryEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DocumentId { get; set; }
    public DateTime At { get; set; } = DateTime.UtcNow;
    public string ActorName { get; set; } = "";
    public string Action { get; set; } = "";
    public string? Details { get; set; }
}

/// <summary>Уведомление пользователю в приложении (задача по маршруту, решение по документу, комментарий).</summary>
public sealed class Notification
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string Text { get; set; } = "";
    public string? Link { get; set; }
    public string Kind { get; set; } = "info";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ReadAt { get; set; }
}

public sealed class DocflowDb(DbContextOptions<DocflowDb> options) : DbContext(options)
{
    public DbSet<Document> Documents => Set<Document>();
    public DbSet<DocumentVersion> Versions => Set<DocumentVersion>();
    public DbSet<RouteStep> Steps => Set<RouteStep>();
    public DbSet<Comment> Comments => Set<Comment>();
    public DbSet<Attachment> Attachments => Set<Attachment>();
    public DbSet<HistoryEntry> History => Set<HistoryEntry>();
    public DbSet<Notification> Notifications => Set<Notification>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Document>().HasIndex(d => d.Number).IsUnique();
        b.Entity<Document>().HasMany(d => d.Versions).WithOne().HasForeignKey(v => v.DocumentId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<Document>().HasMany(d => d.Steps).WithOne().HasForeignKey(s => s.DocumentId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<Document>().HasMany(d => d.Comments).WithOne().HasForeignKey(c => c.DocumentId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<Document>().HasMany(d => d.Attachments).WithOne().HasForeignKey(a => a.DocumentId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<Document>().HasMany(d => d.History).WithOne().HasForeignKey(h => h.DocumentId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<Notification>().HasIndex(n => new { n.UserId, n.ReadAt });

        // SQLite не хранит DateTimeKind: всё пишется в UTC и читается как UTC, чтобы в JSON уходило "…Z".
        var utc = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTime, DateTime>(
            v => v.ToUniversalTime(), v => DateTime.SpecifyKind(v, DateTimeKind.Utc));
        var utcNullable = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTime?, DateTime?>(
            v => v.HasValue ? v.Value.ToUniversalTime() : v, v => v.HasValue ? DateTime.SpecifyKind(v.Value, DateTimeKind.Utc) : v);
        foreach (var property in b.Model.GetEntityTypes().SelectMany(t => t.GetProperties()))
        {
            // Id задаются в коде (Guid.NewGuid()): без этого EF посчитает новую дочернюю запись
            // (шаг, версию, комментарий) существующей и сделает UPDATE вместо INSERT.
            if (property.IsPrimaryKey()) property.ValueGenerated = Microsoft.EntityFrameworkCore.Metadata.ValueGenerated.Never;
            if (property.ClrType == typeof(DateTime)) property.SetValueConverter(utc);
            else if (property.ClrType == typeof(DateTime?)) property.SetValueConverter(utcNullable);
        }
    }
}
