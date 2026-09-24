# syntax=docker/dockerfile:1
# API документооборота + собранная PWA в одном образе. Контекст сборки — samples/docflow-demo.
# Сборке нужен доступ к npm и NuGet; готовый образ работает без интернета (шрифты и библиотеки — внутри).

# ---------- PWA (React + Vite) ----------
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npx tsc -b && npx vite build --outDir /webout --emptyOutDir

# ---------- API ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY api/Docflow.Api.csproj api/
RUN dotnet restore api/Docflow.Api.csproj
COPY api/ api/
RUN dotnet publish api/Docflow.Api.csproj -c Release --no-restore -o /out && rm -rf /out/wwwroot && mkdir -p /data
COPY --from=web /webout /out/wwwroot

# ---------- Выполнение (distroless, без shell) ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0-distroless AS runtime
LABEL org.opencontainers.image.title="TSL Auth demo: Docflow API + PWA" \
      org.opencontainers.image.source="https://github.com/akprof2000/tsl-auth"
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 Urls=http://+:8080 ConnectionStrings__Docflow="Data Source=/app/data/docflow.db" \
    DOTNET_EnableDiagnostics=0
COPY --from=build --chown=0:0 --chmod=0755 /out /app
COPY --from=build --chown=1654:1654 --chmod=0700 /data /app/data
USER 1654:1654
VOLUME /app/data
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 CMD ["dotnet", "/app/Docflow.Api.dll", "healthcheck"]
ENTRYPOINT ["dotnet", "/app/Docflow.Api.dll"]
