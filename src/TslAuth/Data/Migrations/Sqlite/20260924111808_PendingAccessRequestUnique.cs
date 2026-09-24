using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TslAuth.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class PendingAccessRequestUnique : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Дубли ожидающих заявок из прежних версий (параллельная отправка формы) мешают уникальному индексу:
            // самая ранняя заявка на пару «пользователь × роль» остаётся, остальные закрываются как отклонённые
            // (DecidedBy = system:dedupe). SQL одинаков для SQLite и PostgreSQL.
            migrationBuilder.Sql("""
                UPDATE "AccessRequests" SET "Status" = 2, "DecidedBy" = 'system:dedupe', "DecidedAt" = "CreatedAt"
                WHERE "Status" = 0 AND EXISTS (
                    SELECT 1 FROM "AccessRequests" AS b
                    WHERE b."Status" = 0 AND b."UserId" = "AccessRequests"."UserId" AND b."RoleId" = "AccessRequests"."RoleId"
                      AND (b."CreatedAt" < "AccessRequests"."CreatedAt"
                           OR (b."CreatedAt" = "AccessRequests"."CreatedAt" AND b."Id" < "AccessRequests"."Id")));
                """);

            migrationBuilder.CreateIndex(
                name: "IX_AccessRequests_Pending",
                table: "AccessRequests",
                columns: new[] { "UserId", "RoleId" },
                unique: true,
                filter: "\"Status\" = 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AccessRequests_Pending",
                table: "AccessRequests");
        }
    }
}
