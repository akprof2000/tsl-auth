using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TslAuth.Data.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class ManagedClients : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ClientAssertionJtis",
                columns: table => new
                {
                    Jti = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientAssertionJtis", x => x.Jti);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ClientAssertionJtis_ExpiresAt",
                table: "ClientAssertionJtis",
                column: "ExpiresAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ClientAssertionJtis");
        }
    }
}
