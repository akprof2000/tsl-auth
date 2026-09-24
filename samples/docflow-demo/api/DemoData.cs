// Демо-наполнение: при пустой базе (и Demo:SeedDocuments=true) создаёт документы за последние 8 недель
// в разных статусах, чтобы дашборд, списки и маршруты выглядели «живыми». Исполнители и авторы берутся
// из справочника пользователей приложения в TSL Auth, поэтому сид ждёт, пока TSL Auth станет доступен.
using Microsoft.EntityFrameworkCore;

namespace Docflow.Api;

public sealed class DemoDataSeeder(IServiceScopeFactory scopes, TslAuthClient auth, IConfiguration config, ILogger<DemoDataSeeder> log) : BackgroundService
{
    private static readonly (string Type, string Title, string Text)[] Samples =
    [
        ("Приказ", "О проведении инвентаризации", "В целях обеспечения достоверности учёта провести инвентаризацию основных средств до конца квартала."),
        ("Договор", "Договор поставки канцелярских товаров", "Поставщик обязуется передать товар в количестве и ассортименте согласно спецификации."),
        ("Служебная записка", "О переносе сроков проекта «Портал»", "Прошу согласовать перенос этапа тестирования на две недели в связи с изменением требований."),
        ("Регламент", "Регламент обработки обращений", "Документ устанавливает порядок регистрации, распределения и контроля исполнения обращений."),
        ("Заявка", "Заявка на закупку ноутбуков", "Прошу закупить 5 ноутбуков для новых сотрудников отдела разработки."),
        ("Приказ", "О назначении ответственных за охрану труда", "Назначить ответственными за охрану труда руководителей структурных подразделений."),
        ("Договор", "Договор аренды офиса", "Арендодатель предоставляет помещение площадью 240 м² на срок 11 месяцев."),
        ("Служебная записка", "О премировании сотрудников", "Прошу премировать сотрудников отдела продаж по итогам квартала."),
        ("Заявка", "Заявка на обучение", "Прошу направить двух сотрудников на курсы повышения квалификации."),
        ("Регламент", "Регламент резервного копирования", "Резервные копии создаются ежедневно и хранятся не менее 30 дней."),
        ("Приказ", "Об утверждении графика отпусков", "Утвердить график отпусков на следующий год согласно приложению."),
        ("Служебная записка", "О замене серверного оборудования", "Прошу согласовать замену двух серверов, выработавших ресурс.")
    ];

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (!config.GetValue("Demo:SeedDocuments", true)) return;
        for (var attempt = 0; attempt < 60 && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                await SeedAsync(ct);
                return;
            }
            catch (Exception ex) when (ex is TslAuthException or HttpRequestException)
            {
                log.LogInformation("Демо-данные: жду TSL Auth ({Message})", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(10), ct);
            }
        }
    }

    private async Task SeedAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<DocflowDb>();
        if (await db.Documents.AnyAsync(ct)) return;
        var users = (await auth.UsersAsync(force: true, ct)).Where(u => u.IsActive).ToList();
        var authors = users.Where(u => u.Roles.Any(r => r is "employee" or "reviewer" or "approver")).ToList();
        var reviewer = users.FirstOrDefault(u => u.Roles.Contains("reviewer"));
        var approver = users.FirstOrDefault(u => u.Roles.Contains("approver"));
        if (authors.Count == 0 || reviewer is null || approver is null)
        {
            log.LogInformation("Демо-данные: нет пользователей с ролями employee/reviewer/approver — пропускаю");
            return;
        }

        var rnd = new Random(42);
        var now = DateTime.UtcNow;
        var number = 0;
        for (var i = 0; i < 26; i++)
        {
            var s = Samples[i % Samples.Length];
            var author = authors[rnd.Next(authors.Count)];
            var created = now.AddDays(-rnd.Next(1, 55)).AddHours(-rnd.Next(0, 9));
            var doc = new Document
            {
                Number = $"DOC-{created.Year}-{++number:0000}", Title = i < Samples.Length ? s.Title : $"{s.Title} ({i / Samples.Length + 1})",
                Type = s.Type, Content = s.Text, AuthorId = author.Id, AuthorName = author.Display, CreatedAt = created, UpdatedAt = created
            };
            doc.History.Add(new HistoryEntry { At = created, ActorName = author.Display, Action = "Создан", Details = doc.Type });
            var review = new RouteStep { Order = 1, Kind = StepKind.Review, AssigneeRole = "reviewer" };
            var approve = new RouteStep { Order = 2, Kind = StepKind.Approve, AssigneeUserId = approver.Id, AssigneeName = approver.Display };
            doc.Steps = [review, approve];

            // Распределение статусов: больше завершённых в прошлом, свежие — на согласовании и в черновиках.
            var age = (now - created).TotalDays;
            var outcome = age < 4 ? rnd.Next(3) switch { 0 => "draft", 1 => "review", _ => "approve" }
                : rnd.Next(10) switch { < 6 => "approved", 6 => "rejected", 7 => "archived", 8 => "approve", _ => "review" };
            if (outcome == "draft") { db.Documents.Add(doc); continue; }

            var t = created.AddHours(rnd.Next(1, 20));
            if (t > now) t = now.AddMinutes(-rnd.Next(5, 90));
            doc.Status = DocStatus.InReview;
            doc.Versions.Add(new DocumentVersion { Number = 1, Title = doc.Title, Content = doc.Content, CreatedByName = author.Display, CreatedAt = t, Note = "Первая отправка" });
            doc.History.Add(new HistoryEntry { At = t, ActorName = author.Display, Action = "Отправлен на согласование", Details = "версия 1" });
            review.Status = StepStatus.Active;
            if (outcome != "review")
            {
                t = t.AddHours(rnd.Next(2, 40));
                if (t > now) t = now.AddMinutes(-rnd.Next(5, 90));
                review.Status = StepStatus.Done; review.DecidedAt = t; review.DecidedById = reviewer.Id; review.DecidedByName = reviewer.Display;
                review.Comment = rnd.Next(3) == 0 ? "Замечаний нет" : null;
                doc.History.Add(new HistoryEntry { At = t, ActorName = reviewer.Display, Action = "Согласовал", Details = review.Comment });
                approve.Status = StepStatus.Active;
                if (rnd.Next(3) == 0)
                    doc.Comments.Add(new Comment { AuthorId = reviewer.Id, AuthorName = reviewer.Display, Text = "Проверил сроки и суммы, всё сходится.", CreatedAt = t });
            }
            if (outcome is "approved" or "archived" or "rejected")
            {
                t = t.AddHours(rnd.Next(2, 48));
                if (t > now) t = now.AddMinutes(-rnd.Next(5, 90));
                approve.DecidedAt = t; approve.DecidedById = approver.Id; approve.DecidedByName = approver.Display;
                if (outcome == "rejected")
                {
                    approve.Status = StepStatus.Rejected; approve.Comment = "Нужно обоснование бюджета";
                    doc.Status = DocStatus.Rejected;
                    doc.History.Add(new HistoryEntry { At = t, ActorName = approver.Display, Action = "Отклонил", Details = approve.Comment });
                }
                else
                {
                    approve.Status = StepStatus.Done;
                    doc.Status = outcome == "archived" ? DocStatus.Archived : DocStatus.Approved;
                    doc.History.Add(new HistoryEntry { At = t, ActorName = approver.Display, Action = "Утвердил" });
                    doc.History.Add(new HistoryEntry { At = t, ActorName = "Система", Action = "Согласование завершено" });
                    if (outcome == "archived") doc.History.Add(new HistoryEntry { At = t.AddHours(3), ActorName = "Делопроизводитель", Action = "Перемещён в архив" });
                }
            }
            doc.UpdatedAt = t > now ? now : t;
            db.Documents.Add(doc);
        }
        await db.SaveChangesAsync(ct);
        // Номера по порядку создания, как если бы документы регистрировались один за другим.
        var ordered = await db.Documents.OrderBy(d => d.CreatedAt).ToListAsync(ct);
        for (var i = 0; i < ordered.Count; i++) ordered[i].Number = $"TMP-{i}";
        await db.SaveChangesAsync(ct);
        for (var i = 0; i < ordered.Count; i++) ordered[i].Number = $"DOC-{ordered[i].CreatedAt.Year}-{i + 1:0000}";
        await db.SaveChangesAsync(ct);
        log.LogInformation("Демо-данные: создано {Count} документов", ordered.Count);
    }
}
