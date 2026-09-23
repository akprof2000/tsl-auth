# syntax=docker/dockerfile:1
# Сборка требует доступа к NuGet; готовый образ работает полностью автономно
# (перенос в закрытый контур — scripts/export-images.*).

FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY src/TslAuth/TslAuth.csproj src/TslAuth/
RUN dotnet restore src/TslAuth/TslAuth.csproj -r linux-musl-x64
COPY src/TslAuth/ src/TslAuth/
RUN dotnet publish src/TslAuth/TslAuth.csproj -c Release -r linux-musl-x64 --self-contained false --no-restore -o /out \
    && rm -f /out/appsettings.Development.json

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime
# Обновления безопасности пакетов базового образа на момент сборки.
RUN apk upgrade --no-cache
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true \
    DOTNET_EnableDiagnostics=0 \
    DOTNET_gcServer=0
COPY --from=build /out .
# `tslauth admin reset-password <логин>` — восстановление доступа администратора.
RUN printf '#!/bin/sh\nexec dotnet /app/TslAuth.dll "$@"\n' > /usr/local/bin/tslauth \
    && chmod +x /usr/local/bin/tslauth \
    && mkdir -p /app/data && chown -R app:app /app/data
USER app
VOLUME /app/data
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health/ready > /dev/null || exit 1
ENTRYPOINT ["dotnet", "/app/TslAuth.dll"]
