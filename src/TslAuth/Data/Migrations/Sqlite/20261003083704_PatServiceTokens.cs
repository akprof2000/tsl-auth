using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TslAuth.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class PatServiceTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AllApplications",
                table: "PersonalAccessTokens",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "ClientId",
                table: "PersonalAccessTokens",
                type: "TEXT",
                maxLength: 100,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_PersonalAccessTokens_ClientId",
                table: "PersonalAccessTokens",
                column: "ClientId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PersonalAccessTokens_ClientId",
                table: "PersonalAccessTokens");

            migrationBuilder.DropColumn(
                name: "AllApplications",
                table: "PersonalAccessTokens");

            migrationBuilder.DropColumn(
                name: "ClientId",
                table: "PersonalAccessTokens");
        }
    }
}
