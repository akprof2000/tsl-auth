using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TslAuth.Data.Migrations.Sqlite
{
    /// <inheritdoc />
    public partial class RoleDisplayName : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DisplayName",
                table: "AccessRoles",
                type: "TEXT",
                maxLength: 200,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DisplayName",
                table: "AccessRoles");
        }
    }
}
