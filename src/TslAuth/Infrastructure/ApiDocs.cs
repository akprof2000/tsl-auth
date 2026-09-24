using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using Scalar.AspNetCore;

namespace TslAuth.Infrastructure;

/// <summary>
/// Документация API: OpenAPI (/openapi/v1.json) + интерактивный справочник Scalar (/docs/api)
/// со встроенными ресурсами (без CDN — работает в закрытом контуре) и руководство /docs.
/// </summary>
public static class ApiDocs
{
    public const string ReferencePath = "/docs/api";

    /// <summary>Регистрирует генерацию OpenAPI-документа с описанием и схемами безопасности.</summary>
    public static void AddTslApiDocs(this IServiceCollection services) =>
        services.AddOpenApi(o => o.AddDocumentTransformer((document, context, _) =>
        {
            // Документ строится на запрос — TokenUrl берём от текущего хоста, чтобы «Try it» работал за прокси/на любом адресе.
            var request = context.ApplicationServices.GetRequiredService<IHttpContextAccessor>().HttpContext?.Request;
            var baseUrl = request is null ? "" : $"{request.Scheme}://{request.Host}{request.PathBase}";

            document.Info = new OpenApiInfo
            {
                Title = "TSL Auth API",
                Version = "v1",
                Description = """
                    API сервиса аутентификации и авторизации TSL Auth.

                    * **Admin** — администрирование (роль `administrator`/`auditor` в приложении `tsl-auth-admin`, scope `tsl-auth-admin`).
                    * **App (self-management)** — приложение управляет своими пользователями и ролями (scope `tsl-auth-app`, флаг «Самоуправление»).
                    * **Events** — лента событий для ботов: long-polling, SSE, вебхуки (роль `notifier`).
                    * **Bot** — привязка мессенджера и сброс пароля через бота (роль `reset-bot`).

                    Токен: `POST /connect/token` с `grant_type=client_credentials`. Руководство по интеграции — [/docs](/docs).
                    """
            };

            var schemes = document.Components ??= new OpenApiComponents();
            schemes.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
            schemes.SecuritySchemes["oauth2"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Description = "OAuth 2.0 client credentials (клиент с нужной ролью в матрице tsl-auth-admin).",
                Flows = new OpenApiOAuthFlows
                {
                    ClientCredentials = new OpenApiOAuthFlow
                    {
                        TokenUrl = new Uri($"{baseUrl}/connect/token", UriKind.RelativeOrAbsolute),
                        Scopes = new Dictionary<string, string>
                        {
                            ["tsl-auth-admin"] = "Admin API, Events API, Bot API",
                            ["tsl-auth-app"] = "App API (самоуправление приложения)"
                        }
                    }
                }
            };
            schemes.SecuritySchemes["bearer"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT",
                Description = "Готовый access-токен (JWT)."
            };
            document.Security ??= [];
            document.Security.Add(new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("oauth2", document)] = ["tsl-auth-admin"] });
            document.Security.Add(new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("bearer", document)] = [] });
            return Task.CompletedTask;
        }));

    /// <summary>Публикует /openapi/v1.json и справочник Scalar по <see cref="ReferencePath"/>.</summary>
    public static void MapTslApiDocs(this WebApplication app)
    {
        // Docs:Public=false (внешний контур) — описание API видят только вошедшие пользователи с правом просмотра админки.
        var isPublic = app.Configuration.GetValue("Docs:Public", true);
        var openApi = app.MapOpenApi();
        if (!isPublic) openApi.RequireAuthorization(AdminPolicies.UiView);
        var reference = app.MapScalarApiReference(ReferencePath, o =>
        {
            // Примеры кода — для языков, которые используются у нас: shell (curl), Python, Java, C# (.NET), Node.js, Go.
            o.EnabledTargets = [ScalarTarget.Shell, ScalarTarget.Python, ScalarTarget.Java, ScalarTarget.CSharp, ScalarTarget.Node, ScalarTarget.Go];
            o.WithDefaultHttpClient(ScalarTarget.Shell, ScalarClient.Curl)
            .WithTitle("TSL Auth API")
            .WithOpenApiRoutePattern("/openapi/{documentName}.json")
            // Закрытый контур: никаких внешних ресурсов и облачных функций Scalar (AI-агент, MCP, телеметрия, deploy).
            .DisableDefaultFonts()
            .DisableAgent()
            .DisableMcp()
            .DisableTelemetry()
            .HideDeveloperTools()

            .WithTheme(ScalarTheme.Default)
            .AddPreferredSecuritySchemes(["oauth2"])
            .AddClientCredentialsFlow("oauth2", flow => flow.SelectedScopes = ["tsl-auth-admin"]);
        });
        if (!isPublic) reference.RequireAuthorization(AdminPolicies.UiView);
    }
}
