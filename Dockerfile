# syntax=docker/dockerfile:1
#
# Образ TSL Auth, собранный по требованиям CIS Docker Benchmark / NIST SP 800-190:
#   • финальный образ — Microsoft distroless на Azure Linux 3.0: нет shell, пакетного менеджера, wget/curl;
#     выбран по результатам Trivy: 0 уязвимостей любого уровня (Ubuntu chiseled — 7 MEDIUM в glibc, Alpine — есть shell/apk);
#   • базовые образы закреплены по digest (защита цепочки поставки), обновляет Dependabot;
#   • процесс — непривилегированный пользователь с числовым UID 1654; файлы приложения принадлежат root
#     и недоступны процессу на запись; запись возможна только в том /app/data;
#   • HEALTHCHECK без внешних утилит (встроенная команда сервиса);
#   • в CI образ сканируется Trivy/Dockle, подписывается cosign, к нему прикладываются SBOM и provenance.
#
# Сборка требует доступа к NuGet; готовый образ работает полностью автономно
# (перенос в закрытый контур — scripts/export-images.*).

# ---------- Сборка ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:35d40304542c8689331f8cab17c65926cdf48fe711e289321d71924b230a7d29 AS build
WORKDIR /src
COPY src/TslAuth/TslAuth.csproj src/TslAuth/
RUN dotnet restore src/TslAuth/TslAuth.csproj -r linux-x64
COPY src/TslAuth/ src/TslAuth/
RUN dotnet publish src/TslAuth/TslAuth.csproj -c Release -r linux-x64 --self-contained false --no-restore -o /out \
    && rm -f /out/appsettings.Development.json \
    && mkdir -p /data

# ---------- Выполнение (distroless) ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0-distroless@sha256:42e74b1e732f4b17c6a292c189f2110d3501b6caa96bb59edda698eb059ecc9b AS runtime

LABEL org.opencontainers.image.title="TSL Auth" \
      org.opencontainers.image.description="Сервис аутентификации и авторизации: OAuth 2.0 / OIDC, JWT, RBAC" \
      org.opencontainers.image.source="https://github.com/akprof2000/tsl-auth"

WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true \
    DOTNET_EnableDiagnostics=0 \
    DOTNET_gcServer=0

# Код приложения — владелец root (процесс не может изменить свои файлы); данные — владелец UID 1654.
COPY --from=build --chown=0:0 --chmod=0755 /out /app
COPY --from=build --chown=1654:1654 --chmod=0700 /data /app/data

USER 1654:1654
VOLUME /app/data
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD ["dotnet", "/app/TslAuth.dll", "healthcheck"]

# Восстановление доступа администратора (shell в образе нет):
#   docker exec -it tsl-auth dotnet /app/TslAuth.dll admin reset-password admin
ENTRYPOINT ["dotnet", "/app/TslAuth.dll"]
