# syntax=docker/dockerfile:1
# Демо-бот безопасности (чат PWA ↔ Bot API TSL Auth). Контекст сборки — samples/docflow-demo.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY bot/Docflow.Bot.csproj bot/
RUN dotnet restore bot/Docflow.Bot.csproj
COPY bot/ bot/
RUN dotnet publish bot/Docflow.Bot.csproj -c Release --no-restore -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0-distroless AS runtime
LABEL org.opencontainers.image.title="TSL Auth demo: security bot" \
      org.opencontainers.image.source="https://github.com/akprof2000/tsl-auth"
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 Urls=http://+:8080 DOTNET_EnableDiagnostics=0
COPY --from=build --chown=0:0 --chmod=0755 /out /app
USER 1654:1654
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 CMD ["dotnet", "/app/Docflow.Bot.dll", "healthcheck"]
ENTRYPOINT ["dotnet", "/app/Docflow.Bot.dll"]
