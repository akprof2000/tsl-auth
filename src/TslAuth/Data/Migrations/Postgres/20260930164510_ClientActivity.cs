using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TslAuth.Data.Migrations.Postgres
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
                    ClientId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    LastTokenIssuedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
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
