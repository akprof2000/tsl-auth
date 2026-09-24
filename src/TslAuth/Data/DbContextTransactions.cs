using Microsoft.EntityFrameworkCore;

namespace TslAuth.Data;

/// <summary>Атомарность составных операций без вложенных транзакций.</summary>
public static class DbContextTransactions
{
    /// <summary>
    /// Выполняет действие в транзакции. Если вызывающий код уже открыл транзакцию на этом контексте, действие
    /// становится её частью (вложенный BeginTransaction на том же соединении невозможен); иначе — своя транзакция.
    /// </summary>
    public static async Task<T> InTransactionAsync<T>(this DbContext db, Func<Task<T>> action, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is not null) return await action();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var result = await action();
        await tx.CommitAsync(ct);
        return result;
    }

    public static Task InTransactionAsync(this DbContext db, Func<Task> action, CancellationToken ct = default) =>
        db.InTransactionAsync(async () => { await action(); return true; }, ct);
}
