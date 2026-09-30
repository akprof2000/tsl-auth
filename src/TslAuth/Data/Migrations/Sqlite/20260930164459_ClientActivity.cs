using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TslAuth.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class ClientActivity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ClientActivities",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    LastTokenIssuedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientActivities", x => x.ClientId);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ClientActivities");
        }
    }
}
