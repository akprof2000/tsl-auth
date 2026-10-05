// Документооборот: документы, маршрут согласования (несколько шагов), версии, комментарии, вложения,
// история, задачи «мне на согласование», дашборд. Права — из разрешений матрицы docflow-api в JWT:
//   documents.view / create / review / approve / archive, dashboard.view.
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Docflow.Api;

public sealed record StepInput(StepKind Kind, string? AssigneeRole, Guid? AssigneeUserId);
public sealed record DocumentInput(string Title, string Type, string Content, List<StepInput>? Steps);
public sealed record DecisionInput(bool Approve, string? Comment);
public sealed record CommentInput(string Text);

public static class Documents
{
    public static readonly string[] Types = ["Приказ", "Договор", "Служебная записка", "Регламент", "Заявка"];

    public static void MapDocuments(this IEndpointRouteBuilder app)
    {
        var docs = app.MapGroup("/api/documents").RequireAuthorization("documents.view");

        docs.MapGet("/types", () => Types);

        // Список с фильтрами: статус, поиск по номеру/названию, «мои» (я автор) и «задачи» (жду моего решения).
        docs.MapGet("/", async (DocflowDb db, CurrentUser me, string? status, string? search, string? scope, TslAuthClient auth, CancellationToken ct) =>
        {
            var q = db.Documents.AsNoTracking().Include(d => d.Steps).AsQueryable();
            if (Enum.TryParse<DocStatus>(status, true, out var st)) q = q.Where(d => d.Status == st);
            if (scope == "mine") q = q.Where(d => d.AuthorId == me.Id);
            var list = await q.OrderByDescending(d => d.UpdatedAt).Take(500).ToListAsync(ct);
            // Поиск — в памяти: lower() в SQLite не понимает кириллицу.
            if (!string.IsNullOrWhiteSpace(search))
            {
                var s = search.Trim();
                list = list.Where(d => new[] { d.Title, d.Number, d.AuthorName }.Any(x => x.Contains(s, StringComparison.OrdinalIgnoreCase))).ToList();
            }
            if (scope == "tasks") list = list.Where(d => ActiveStep(d) is { } step && IsAssignee(step, me)).ToList();
            return list.Select(d => Summary(d, me));
        });

        docs.MapGet("/{id:guid}", async (Guid id, DocflowDb db, CurrentUser me, CancellationToken ct) =>
            await LoadAsync(db, id, ct) is { } d ? Results.Ok(Full(d, me)) : Results.NotFound());

        docs.MapPost("/", async (DocumentInput input, DocflowDb db, CurrentUser me, TslAuthClient auth, CancellationToken ct) =>
        {
            Validate(input);
            var year = DateTime.UtcNow.Year;
            // Следующий номер за год: максимум + 1 (удалённые черновики не приводят к повтору номера).
            var numbers = await db.Documents.Where(d => d.Number.StartsWith($"DOC-{year}-")).Select(d => d.Number).ToListAsync(ct);
            var next = numbers.Select(n => int.TryParse(n[(n.LastIndexOf('-') + 1)..], out var x) ? x : 0).DefaultIfEmpty(0).Max() + 1;
            var doc = new Document
            {
                Number = $"DOC-{year}-{next:0000}", Title = input.Title.Trim(), Type = input.Type, Content = input.Content,
                AuthorId = me.Id, AuthorName = me.DisplayName
            };
            doc.Steps = await BuildStepsAsync(input.Steps, auth, ct);
            doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = "Создан", Details = doc.Type });
            db.Documents.Add(doc);
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/documents/{doc.Id}", Full(doc, me));
        }).RequireAuthorization("documents.create");

        // Черновик редактирует автор (или администратор). Маршрут можно менять, пока документ не отправлен.
        docs.MapPut("/{id:guid}", async (Guid id, DocumentInput input, DocflowDb db, CurrentUser me, TslAuthClient auth, CancellationToken ct) =>
        {
            Validate(input);
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            RequireAuthor(doc, me);
            if (doc.Status is not (DocStatus.Draft or DocStatus.Rejected)) throw new ApiException("Редактировать можно только черновик или отклонённый документ", 409);
            doc.Title = input.Title.Trim(); doc.Type = input.Type; doc.Content = input.Content; doc.UpdatedAt = DateTime.UtcNow;
            if (input.Steps is not null)
            {
                db.Steps.RemoveRange(doc.Steps);
                doc.Steps = await BuildStepsAsync(input.Steps, auth, ct);
            }
            if (doc.Status == DocStatus.Rejected)
            {
                doc.Status = DocStatus.Draft;
                doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = "Возвращён в черновики", Details = "после отклонения" });
            }
            doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = "Изменён" });
            await db.SaveChangesAsync(ct);
            return Full(doc, me);
        }).RequireAuthorization("documents.create");

        docs.MapDelete("/{id:guid}", async (Guid id, DocflowDb db, CurrentUser me, CancellationToken ct) =>
        {
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            RequireAuthor(doc, me);
            if (doc.Status != DocStatus.Draft) throw new ApiException("Удалить можно только черновик", 409);
            db.Documents.Remove(doc);
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization("documents.create");

        // Отправка на согласование: снимок версии, первый шаг становится активным, исполнителям — уведомление.
        docs.MapPost("/{id:guid}/submit", async (Guid id, DocflowDb db, CurrentUser me, TslAuthClient auth, CancellationToken ct) =>
        {
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            RequireAuthor(doc, me);
            if (doc.Status is not (DocStatus.Draft or DocStatus.Rejected)) throw new ApiException("Документ уже на согласовании или завершён", 409);
            if (doc.Steps.Count == 0) throw new ApiException("Добавьте хотя бы один шаг маршрута", 400);
            if (doc.Versions.Count > 0) doc.Version++;
            doc.Versions.Add(new DocumentVersion { Number = doc.Version, Title = doc.Title, Content = doc.Content, CreatedByName = me.DisplayName,
                Note = doc.Version == 1 ? "Первая отправка" : "Повторная отправка после доработки" });
            foreach (var s in doc.Steps) { s.Status = StepStatus.Pending; s.DecidedAt = null; s.DecidedById = null; s.DecidedByName = null; s.Comment = null; }
            var first = doc.Steps.OrderBy(s => s.Order).First();
            first.Status = StepStatus.Active;
            doc.Status = DocStatus.InReview; doc.UpdatedAt = DateTime.UtcNow;
            doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = "Отправлен на согласование", Details = $"версия {doc.Version}" });
            await NotifyStepAsync(db, doc, first, auth, ct);
            await db.SaveChangesAsync(ct);
            return Full(doc, me);
        }).RequireAuthorization("documents.create");

        // Решение по активному шагу. Нужны разрешение по виду шага и назначение на исполнителя.
        docs.MapPost("/{id:guid}/decide", async (Guid id, DecisionInput input, DocflowDb db, CurrentUser me, TslAuthClient auth, CancellationToken ct) =>
        {
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            var step = ActiveStep(doc) ?? throw new ApiException("Документ не на согласовании", 409);
            if (!IsAssignee(step, me)) throw new ApiException("Этот шаг назначен не вам", 403);
            if (!me.Has(step.Kind == StepKind.Approve ? "documents.approve" : "documents.review"))
                throw new ApiException(step.Kind == StepKind.Approve ? "Нужно разрешение documents.approve" : "Нужно разрешение documents.review", 403);
            if (!input.Approve && string.IsNullOrWhiteSpace(input.Comment)) throw new ApiException("Укажите причину отклонения", 400);

            step.DecidedAt = DateTime.UtcNow; step.DecidedById = me.Id; step.DecidedByName = me.DisplayName; step.Comment = input.Comment?.Trim();
            doc.UpdatedAt = DateTime.UtcNow;
            if (input.Approve)
            {
                step.Status = StepStatus.Done;
                doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = step.Kind == StepKind.Approve ? "Утвердил" : "Согласовал", Details = step.Comment });
                var next = doc.Steps.Where(s => s.Order > step.Order).OrderBy(s => s.Order).FirstOrDefault();
                if (next is null)
                {
                    doc.Status = DocStatus.Approved;
                    doc.History.Add(new HistoryEntry { ActorName = "Система", Action = "Согласование завершено" });
                    db.Notifications.Add(new Notification { UserId = doc.AuthorId, Kind = "success", Text = $"Документ {doc.Number} «{doc.Title}» утверждён", Link = $"/documents/{doc.Id}" });
                }
                else
                {
                    next.Status = StepStatus.Active;
                    await NotifyStepAsync(db, doc, next, auth, ct);
                }
            }
            else
            {
                step.Status = StepStatus.Rejected;
                doc.Status = DocStatus.Rejected;
                doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = "Отклонил", Details = step.Comment });
                db.Notifications.Add(new Notification { UserId = doc.AuthorId, Kind = "danger", Text = $"Документ {doc.Number} отклонён: {step.Comment}", Link = $"/documents/{doc.Id}" });
            }
            await db.SaveChangesAsync(ct);
            return Full(doc, me);
        });

        docs.MapPost("/{id:guid}/archive", async (Guid id, DocflowDb db, CurrentUser me, CancellationToken ct) =>
        {
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            if (doc.Status is not (DocStatus.Approved or DocStatus.Rejected)) throw new ApiException("В архив — только завершённые документы", 409);
            doc.Status = DocStatus.Archived; doc.UpdatedAt = DateTime.UtcNow;
            doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = "Перемещён в архив" });
            await db.SaveChangesAsync(ct);
            return Full(doc, me);
        }).RequireAuthorization("documents.archive");

        docs.MapPost("/{id:guid}/comments", async (Guid id, CommentInput input, DocflowDb db, CurrentUser me, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(input.Text)) throw new ApiException("Пустой комментарий", 400);
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            doc.Comments.Add(new Comment { AuthorId = me.Id, AuthorName = me.DisplayName, Text = input.Text.Trim() });
            if (doc.AuthorId != me.Id)
                db.Notifications.Add(new Notification { UserId = doc.AuthorId, Text = $"{me.DisplayName} прокомментировал {doc.Number}", Link = $"/documents/{doc.Id}" });
            await db.SaveChangesAsync(ct);
            return Full(doc, me);
        });

        docs.MapPost("/{id:guid}/attachments", async (Guid id, HttpRequest request, DocflowDb db, CurrentUser me, CancellationToken ct) =>
        {
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            var form = await request.ReadFormAsync(ct);
            var file = form.Files.FirstOrDefault() ?? throw new ApiException("Файл не передан", 400);
            if (file.Length > 5 * 1024 * 1024) throw new ApiException("Файл больше 5 МБ", 413);
            using var ms = new MemoryStream();
            await file.CopyToAsync(ms, ct);
            doc.Attachments.Add(new Attachment { FileName = Path.GetFileName(file.FileName), ContentType = file.ContentType, Size = file.Length, Data = ms.ToArray(), UploadedByName = me.DisplayName });
            doc.History.Add(new HistoryEntry { ActorName = me.DisplayName, Action = "Добавил вложение", Details = file.FileName });
            await db.SaveChangesAsync(ct);
            return Full(doc, me);
        }).DisableAntiforgery();

        docs.MapGet("/{id:guid}/attachments/{fileId:guid}", async (Guid id, Guid fileId, DocflowDb db, CancellationToken ct) =>
            await db.Attachments.FirstOrDefaultAsync(a => a.Id == fileId && a.DocumentId == id, ct) is { } a
                ? Results.File(a.Data, a.ContentType, a.FileName) : Results.NotFound());

        docs.MapDelete("/{id:guid}/attachments/{fileId:guid}", async (Guid id, Guid fileId, DocflowDb db, CurrentUser me, CancellationToken ct) =>
        {
            var doc = await LoadAsync(db, id, ct) ?? throw new ApiException("Документ не найден", 404);
            RequireAuthor(doc, me);
            var a = doc.Attachments.FirstOrDefault(x => x.Id == fileId) ?? throw new ApiException("Вложение не найдено", 404);
            doc.Attachments.Remove(a);
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        // ---------- Дашборд и уведомления ----------
        app.MapGet("/api/dashboard", async (DocflowDb db, CurrentUser me, CancellationToken ct) =>
        {
            var all = await db.Documents.AsNoTracking().Include(d => d.Steps).ToListAsync(ct);
            var since = DateTime.UtcNow.Date.AddDays(-7 * 7);
            var weekStart = since.AddDays(-(int)since.DayOfWeek + 1);
            var weeks = Enumerable.Range(0, 8).Select(i => weekStart.AddDays(7 * i)).Select(w => new
            {
                week = w.ToString("dd.MM"),
                created = all.Count(d => d.CreatedAt >= w && d.CreatedAt < w.AddDays(7)),
                approved = all.Count(d => d.Status == DocStatus.Approved && d.UpdatedAt >= w && d.UpdatedAt < w.AddDays(7))
            });
            var history = await db.History.AsNoTracking().OrderByDescending(h => h.At).Take(12)
                .Join(db.Documents, h => h.DocumentId, d => d.Id, (h, d) => new { h.At, h.ActorName, h.Action, h.Details, docId = d.Id, d.Number, d.Title })
                .ToListAsync(ct);
            return new
            {
                byStatus = Enum.GetValues<DocStatus>().ToDictionary(s => s.ToString(), s => all.Count(d => d.Status == s)),
                total = all.Count,
                mine = all.Count(d => d.AuthorId == me.Id),
                tasks = all.Count(d => ActiveStep(d) is { } s && IsAssignee(s, me)),
                inReview = all.Count(d => d.Status == DocStatus.InReview),
                byType = Types.Select(t => new { type = t, count = all.Count(d => d.Type == t) }),
                weeks,
                recent = history,
                avgApprovalHours = all.Where(d => d.Status == DocStatus.Approved).Select(d => (d.UpdatedAt - d.CreatedAt).TotalHours).DefaultIfEmpty(0).Average()
            };
        }).RequireAuthorization("dashboard.view");

        var notes = app.MapGroup("/api/notifications").RequireAuthorization();
        notes.MapGet("/", async (DocflowDb db, CurrentUser me, CancellationToken ct) =>
            await db.Notifications.AsNoTracking().Where(n => n.UserId == me.Id).OrderByDescending(n => n.CreatedAt).Take(50).ToListAsync(ct));
        notes.MapPost("/read", async (DocflowDb db, CurrentUser me, CancellationToken ct) =>
        {
            await db.Notifications.Where(n => n.UserId == me.Id && n.ReadAt == null).ExecuteUpdateAsync(s => s.SetProperty(n => n.ReadAt, DateTime.UtcNow), ct);
            return Results.NoContent();
        });
    }

    private static void Validate(DocumentInput input)
    {
        if (string.IsNullOrWhiteSpace(input.Title) || input.Title.Length > 200) throw new ApiException("Укажите название (до 200 символов)", 400);
        if (!Types.Contains(input.Type)) throw new ApiException("Неизвестный тип документа", 400);
        if (input.Steps is { Count: > 10 }) throw new ApiException("Не более 10 шагов маршрута", 400);
    }

    private static void RequireAuthor(Document doc, CurrentUser me)
    {
        if (doc.AuthorId != me.Id && !me.Has("documents.archive")) throw new ApiException("Только автор документа или администратор", 403);
    }

    private static async Task<List<RouteStep>> BuildStepsAsync(List<StepInput>? steps, TslAuthClient auth, CancellationToken ct)
    {
        var result = new List<RouteStep>();
        if (steps is null) return result;
        var users = await auth.UsersAsync(ct: ct);
        var order = 0;
        foreach (var s in steps)
        {
            var step = new RouteStep { Order = ++order, Kind = s.Kind };
            if (s.AssigneeUserId is { } uid)
            {
                var u = users.FirstOrDefault(x => x.Id == uid) ?? throw new ApiException("Исполнитель не найден среди пользователей приложения", 400);
                step.AssigneeUserId = u.Id; step.AssigneeName = u.Display;
            }
            else if (!string.IsNullOrWhiteSpace(s.AssigneeRole)) step.AssigneeRole = s.AssigneeRole.Trim();
            else throw new ApiException("У шага должен быть исполнитель: пользователь или роль", 400);
            result.Add(step);
        }
        return result;
    }

    private static async Task NotifyStepAsync(DocflowDb db, Document doc, RouteStep step, TslAuthClient auth, CancellationToken ct)
    {
        var text = $"{(step.Kind == StepKind.Approve ? "На утверждение" : "На согласование")}: {doc.Number} «{doc.Title}»";
        IEnumerable<Guid> targets = step.AssigneeUserId is { } uid
            ? [uid]
            : (await auth.UsersAsync(ct: ct)).Where(u => u.Roles.Contains(step.AssigneeRole!)).Select(u => u.Id);
        foreach (var id in targets.Distinct())
            db.Notifications.Add(new Notification { UserId = id, Kind = "task", Text = text, Link = $"/documents/{doc.Id}" });
    }

    private static Task<Document?> LoadAsync(DocflowDb db, Guid id, CancellationToken ct) => db.Documents
        .Include(d => d.Steps).Include(d => d.Versions).Include(d => d.Comments).Include(d => d.History)
        .Include(d => d.Attachments).FirstOrDefaultAsync(d => d.Id == id, ct);

    private static RouteStep? ActiveStep(Document d) => d.Steps.FirstOrDefault(s => s.Status == StepStatus.Active);

    private static bool IsAssignee(RouteStep step, CurrentUser me) =>
        step.AssigneeUserId is { } uid ? uid == me.Id : step.AssigneeRole is { } role && me.InRole(role);

    private static object Summary(Document d, CurrentUser me)
    {
        var active = ActiveStep(d);
        return new
        {
            d.Id, d.Number, d.Title, d.Type, status = d.Status.ToString(), d.AuthorName, d.AuthorId, d.CreatedAt, d.UpdatedAt, d.Version,
            stepsTotal = d.Steps.Count, stepsDone = d.Steps.Count(s => s.Status == StepStatus.Done),
            currentStep = active is null ? null : new { active.Kind, assignee = active.AssigneeName ?? active.AssigneeRole },
            isMine = d.AuthorId == me.Id, myTask = active is not null && IsAssignee(active, me)
        };
    }

    private static object Full(Document d, CurrentUser me)
    {
        var active = ActiveStep(d);
        var canDecide = active is not null && IsAssignee(active, me) && me.Has(active.Kind == StepKind.Approve ? "documents.approve" : "documents.review");
        var isAuthor = d.AuthorId == me.Id || me.Has("documents.archive");
        return new
        {
            d.Id, d.Number, d.Title, d.Type, d.Content, status = d.Status.ToString(), d.AuthorName, d.AuthorId, d.CreatedAt, d.UpdatedAt, d.Version,
            steps = d.Steps.OrderBy(s => s.Order).Select(s => new
            {
                s.Id, s.Order, kind = s.Kind.ToString(), status = s.Status.ToString(), s.AssigneeRole, s.AssigneeUserId, s.AssigneeName,
                s.DecidedByName, s.DecidedAt, s.Comment
            }),
            versions = d.Versions.OrderByDescending(v => v.Number).Select(v => new { v.Id, v.Number, v.Title, v.Content, v.CreatedByName, v.CreatedAt, v.Note }),
            comments = d.Comments.OrderBy(c => c.CreatedAt).Select(c => new { c.Id, c.AuthorName, c.AuthorId, c.Text, c.CreatedAt }),
            attachments = d.Attachments.OrderBy(a => a.CreatedAt).Select(a => new { a.Id, a.FileName, a.ContentType, a.Size, a.UploadedByName, a.CreatedAt }),
            history = d.History.OrderByDescending(h => h.At).Select(h => new { h.At, h.ActorName, h.Action, h.Details }),
            can = new
            {
                edit = isAuthor && d.Status is DocStatus.Draft or DocStatus.Rejected && me.Has("documents.create"),
                submit = isAuthor && d.Status is DocStatus.Draft or DocStatus.Rejected && me.Has("documents.create"),
                delete = d.AuthorId == me.Id && d.Status == DocStatus.Draft,
                decide = canDecide,
                archive = me.Has("documents.archive") && d.Status is DocStatus.Approved or DocStatus.Rejected,
                attach = isAuthor && d.Status != DocStatus.Archived
            }
        };
    }
}

public sealed class ApiException(string message, int status) : Exception(message)
{
    public int Status { get; } = status;
}
