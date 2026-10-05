// Общая для API и бота документация REST API — как в TSL Auth: /docs — руководство, /docs/api — интерактивный справочник
// Scalar по OpenAPI (/openapi/v1.json); ресурсы встроенные — без CDN, работает в закрытом контуре.
// Подписи методов задаются словарём «МЕТОД путь → описание» (код эндпоинтов не меняется), нужное разрешение матрицы
// берётся из политики авторизации эндпоинта и дописывается в описание.
using Microsoft.AspNetCore.Authorization;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi;
using Scalar.AspNetCore;

namespace Docflow.Shared;

public static class ApiDocs
{
    public const string GuidePath = "/docs";
    public const string ReferencePath = "/docs/api";
    private static string _guide = "";

    /// <summary>
    /// Регистрирует OpenAPI-документ: заголовок, описание, схема «Bearer JWT», подписи методов из
    /// <paramref name="summaries"/> (ключ — «GET /api/me») и требуемые разрешения матрицы <paramref name="audience"/>.
    /// </summary>
    public static void AddSampleApiDocs(this IServiceCollection services, string title, string description, string audience,
        IReadOnlyDictionary<string, string> summaries) =>
        services.AddOpenApi(o =>
        {
            _guide = Guide(title, description);
            o.AddDocumentTransformer((document, _, _) =>
            {
                document.Info = new OpenApiInfo { Title = title, Version = "v1", Description = description };
                var components = document.Components ??= new OpenApiComponents();
                components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
                components.SecuritySchemes["bearer"] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT",
                    Description = $"Access-токен TSL Auth с aud = {audience} (вход пользователя через PWA или client_credentials)."
                };
                document.Security ??= [];
                document.Security.Add(new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("bearer", document)] = [] });
                return Task.CompletedTask;
            });
            o.AddOperationTransformer((operation, context, _) =>
            {
                var d = context.Description;
                // Ключ без ограничений маршрута: api/documents/{id:guid} → /api/documents/{id}, {**path} → {path}.
                var path = System.Text.RegularExpressions.Regex.Replace(d.RelativePath ?? "", @"\{\**(\w+)[^}]*\}", "{$1}");
                var key = $"{d.HttpMethod} /{path.TrimEnd('/')}";
                if (summaries.TryGetValue(key, out var summary)) operation.Summary = summary;
                // Требования к доступу — из политик эндпоинта: имя политики = разрешение матрицы.
                var meta = d.ActionDescriptor.EndpointMetadata;
                if (meta.OfType<IAllowAnonymous>().Any() || !meta.OfType<IAuthorizeData>().Any())
                    operation.Description = "Без токена.";
                else
                {
                    var policies = meta.OfType<IAuthorizeData>().Select(a => a.Policy).Where(p => p is not null).Distinct().ToList();
                    operation.Description = policies.Count == 0
                        ? "Нужен access-токен (любой вошедший пользователь)."
                        : "Нужен access-токен с разрешением " + string.Join(" и ", policies.Select(p => $"`{audience}:{p}`")) + " (матрица TSL Auth).";
                }
                return Task.CompletedTask;
            });
        });

    /// <summary>Публикует руководство <see cref="GuidePath"/>, /openapi/v1.json и справочник <see cref="ReferencePath"/>.</summary>
    public static void MapSampleApiDocs(this WebApplication app, string title)
    {
        app.MapGet(GuidePath, () => Results.Content(_guide, "text/html; charset=utf-8")).AllowAnonymous().ExcludeFromDescription();
        app.MapOpenApi().AllowAnonymous();
        app.MapScalarApiReference(ReferencePath, o =>
        {
            o.EnabledTargets = [ScalarTarget.Shell, ScalarTarget.Python, ScalarTarget.Java, ScalarTarget.CSharp, ScalarTarget.Node, ScalarTarget.Go];
            o.WithDefaultHttpClient(ScalarTarget.Shell, ScalarClient.Curl)
                .WithTitle(title)
                .WithOpenApiRoutePattern("/openapi/{documentName}.json")
                // Закрытый контур: никаких внешних шрифтов и облачных функций Scalar.
                .DisableDefaultFonts()
                .DisableAgent()
                .DisableMcp()
                .DisableTelemetry()
                .HideDeveloperTools()
                .AddPreferredSecuritySchemes(["bearer"]);
        }).AllowAnonymous();
    }

    /// <summary>Руководство: назначение модуля, как получить токен и вызвать API, ссылки на справочник и OpenAPI.</summary>
    private static string Guide(string title, string description)
    {
        var body = string.Join("\n", description.Trim().Replace("\r", "").Split("\n\n").Select(block =>
        {
            var lines = block.Split('\n').Select(l => l.Trim()).ToArray();
            string Html(string s) => System.Text.RegularExpressions.Regex.Replace(WebUtility.HtmlEncode(s), "`([^`]+)`", "<code>$1</code>");
            return lines.All(l => l.StartsWith("* "))
                ? "<ul>" + string.Concat(lines.Select(l => $"<li>{Html(l[2..])}</li>")) + "</ul>"
                : $"<p>{Html(string.Join(' ', lines))}</p>";
        }));
        return $$"""
            <!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{{WebUtility.HtmlEncode(title)}} · Документация</title>
            <style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:32px auto;padding:0 16px;color:#1f2328}
            code,pre{background:#f3f4f6;border-radius:4px;padding:1px 4px}pre{padding:12px;overflow:auto}a{color:#0969da}</style></head>
            <body><h1>{{WebUtility.HtmlEncode(title)}}</h1>{{body}}
            <h2>Как вызвать</h2>
            <pre>curl -H "Authorization: Bearer $TOKEN" http://&lt;адрес&gt;/api/me</pre>
            <p>Все методы, параметры, нужные разрешения и примеры на curl, Python, Java, C#, Node.js и Go — в
            <a href="{{ReferencePath}}">интерактивном справочнике</a> (OpenAPI: <a href="/openapi/v1.json">/openapi/v1.json</a>).
            Там же можно вызвать метод, вставив access-токен.</p></body></html>
            """;
    }
}
