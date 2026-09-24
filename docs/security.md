# Безопасность

## Модель угроз и меры

| Угроза | Мера |
|---|---|
| Утечка дампа БД | ПДн (логин, email, телефон, имя, комментарии, детали аудита) — AES-256-GCM; пароли — PBKDF2-SHA512 (100k итераций); секреты клиентов, PAT, коды привязки — хеши; ключи подписи и Data Protection — зашифрованы мастер-ключом, который в БД не хранится |
| Подбор пароля | блокировка после N неудачных попыток (настраивается), rate limiting на вход и на `/connect/token`, `/connect/introspect`, `/connect/revoke` (перебор секрета клиента), аудит + `security.alert` при блокировке |
| Слабые / повторяющиеся пароли | политика в БД: длина, классы символов, уникальные символы, запрет логина в пароле, история N паролей, срок действия |
| Перехват кода авторизации | PKCE (S256) обязателен для всех клиентов |
| Кража refresh-токена | ротация при каждом использовании, ссылочные токены (отзываемые), отзыв при смене пароля/отключении пользователя, абсолютный срок сессии (`tokenPolicy.maxSessionDays`, по умолчанию 90 дней от входа) |
| Подмена `Host` (ссылка сброса пароля на чужой домен, чужой `iss`) | `Auth__Issuer` обязателен вне Development: `iss`, discovery и ссылки в письмах строятся только из него, не из заголовка `Host`; `AllowedHosts` отсекает запросы с чужим `Host` |
| Подделка IP клиента через `X-Forwarded-For` (обход лимитов, ложный IP в журнале) | заголовки принимаются только при `Auth__TrustForwardedHeaders` и только от сетей `Auth__KnownNetworks`; `X-Forwarded-Host` не принимается; узлы кластера наружу не публикуются, точка входа — балансировщик |
| Захват учётной записи через email | email уникален; логин с `@` допускается, только если совпадает с email этой же учётной записи (нельзя занять чужой email как логин) |
| Временный пароль в чужих руках | до смены временного пароля недоступны админка и личный кабинет (`/Account`, токены, мессенджер, запрос доступа) — нельзя, например, привязать свой мессенджер как канал сброса |
| Использование чужого токена в другом API | обязательная проверка `aud`; token exchange только для токенов, адресованных обменивающему сервису |
| Эскалация прав приложением | App API изолирован срезом приложения; PAT не превышает текущих прав владельца; права админки проверяются по БД на каждый запрос |
| XSS / clickjacking | строгий CSP (`script-src 'self'`, без inline; на `/connect` — только хеш скрипта form_post), `frame-ancestors 'none'`, `X-Frame-Options: DENY`, кодирование вывода Razor |
| CSRF | antiforgery во всех формах, `state` в OAuth, SameSite cookie. Выход — POST с antiforgery; `GET /connect/logout` без `id_token_hint` не выходит сразу, а показывает страницу подтверждения (`/Account/EndSession`), с валидным `id_token_hint` — выход без подтверждения (RP-initiated logout) |
| Перечисление пользователей | одинаковые ответы на «забыли пароль», одинаковые ошибки входа; App API отвечает 404 на чужих пользователей |
| CSV-инъекции | экранирование значений, начинающихся с `= + - @`, в выгрузке журнала |
| Подмена вебхука | HMAC-SHA256 подпись тела секретом подписки |
| SSRF через вебхуки | доставка никогда не идёт на loopback, link-local (в т.ч. `169.254.169.254`), multicast и `0.0.0.0`; редиректы не выполняются, системный прокси не используется; `Webhooks__AllowedNetworks` ограничивает получателей заданными сетями |
| Утечки через внешние сервисы | нет внешних вызовов: интерфейс и справочник API без CDN, облачные функции Scalar отключены |
| Компрометация контейнера | non-root, read-only корневая ФС, `cap_drop: ALL`, `no-new-privileges`, лимиты pids/памяти/CPU, `noexec` tmpfs, отключён диагностический IPC .NET, distroless-образ без shell и пакетного менеджера |
| Откат версии с порчей данных | старт на БД новее образа запрещён |
| Подмена образа в реестре / цепочке поставки | подпись cosign (keyless, Sigstore) того же digest, что прошёл Trivy и Dockle; SBOM и provenance SLSA в реестре; базовые образы сервиса и инструменты CI (Dockle, mermaid-cli, k6) закреплены по digest, GitHub Actions — по SHA коммита; Dependabot |

## Криптография

| Назначение | Алгоритм |
|---|---|
| Подпись JWT | RSA-2048, RS256 (ключ общий для кластера, хранится зашифрованным в БД) |
| Шифрование refresh-токенов и кодов | A256KW + A256CBC-HS512 (OpenIddict) |
| Поля БД | AES-256-GCM, случайный nonce; ключи выводятся из мастер-ключа через HKDF-SHA256 |
| Поиск по зашифрованным полям | HMAC-SHA256 «слепой индекс» (детерминированный, необратимый) |
| Пароли | ASP.NET Core Identity v3: PBKDF2-HMAC-SHA512, 100 000 итераций, соль 128 бит |
| TLS | 1.2 / 1.3 (Kestrel или nginx) |

## Образ контейнера

| Требование | Реализация |
|---|---|
| Минимальная поверхность атаки | `mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0-distroless`: только рантайм .NET и glibc — нет shell, пакетного менеджера, curl/wget |
| Воспроизводимость | базовые образы сборки и выполнения закреплены по `sha256`-digest; Dependabot предлагает обновления, каждое проходит CI. `postgres` и `nginx` в compose — по тегу (для переноса в закрытый контур), их digest фиксирует `scripts/export-images.ps1` |
| Непривилегированный запуск | `USER 1654:1654` в образе и `user: "1654:1654"` в compose; файлы приложения принадлежат root и доступны только на чтение (`0755`), каталог данных — только владельцу (`0700`) |
| Неизменяемая ФС | `read_only: true`, запись только в том `/app/data` и tmpfs `/tmp` (`noexec,nosuid,nodev`, 64 МБ) |
| Минимум прав ядра | `cap_drop: [ALL]`, `security_opt: no-new-privileges:true` |
| Ограничение ресурсов | `pids_limit`, `mem_limit`, `cpus`; ротация логов json-file (5 × 20 МБ) |
| Проверка состояния без shell | `HEALTHCHECK` вызывает сам сервис: `dotnet /app/TslAuth.dll healthcheck` |
| Отключённая диагностика | `DOTNET_EnableDiagnostics=0` — нет IPC-канала отладчика/профилировщика |
| Балансировщик (кластер) | nginx `read_only`, tmpfs для кэша и pid, `cap_drop: ALL` + только `CHOWN`, `SETGID`, `SETUID`, `no-new-privileges` |

Почему distroless Azure Linux: при выборе базового образа Trivy показал

| Базовый образ | Уязвимостей ОС (все уровни) |
|---|---|
| `aspnet:10.0-noble-chiseled` (Ubuntu) | 7 (MEDIUM, без исправлений) |
| `aspnet:10.0-alpine` | 0, но есть shell и `apk` |
| **`aspnet:10.0-azurelinux3.0-distroless`** | **0**, нет shell и пакетного менеджера |

## Результаты сканирования

Проверки выполняются в CI при каждой сборке ([ci.yml](../.github/workflows/ci.yml)). Образ собирается один раз и загружается
в реестр по digest без тегов; Trivy и Dockle проверяют именно этот digest, и только после этого на него ставятся теги
и cosign-подпись. Публикация блокируется при находках CRITICAL/HIGH в Trivy и предупреждениях Dockle, а для ветки `main`
и релизных тегов — ещё и при падении полного стенда E2E. Полный отчёт Trivy (SARIF) загружается во вкладку
**Security → Code scanning** репозитория.

| Проверка | Инструмент | Результат |
|---|---|---|
| Уязвимости ОС образа (Azure Linux 3.0 distroless) | Trivy | **0** |
| Уязвимости .NET-зависимостей и рантайма | Trivy, `dotnet list package --vulnerable` | **0** |
| Секреты в образе и репозитории | Trivy secret | **0** |
| Ошибки конфигурации Dockerfile / compose | Trivy misconfig | **0** |
| Лучшие практики образа (CIS Docker Benchmark) | Dockle | **0** предупреждений |

Запуск локально:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image tsl-auth:latest
docker run --rm -v "$PWD:/src:ro" aquasec/trivy fs --scanners secret,misconfig /src
docker save tsl-auth:latest -o tsl-auth.tar && docker run --rm -v "$PWD/tsl-auth.tar:/image.tar:ro" goodwithtech/dockle --input /image.tar
dotnet list TslAuth.sln package --vulnerable --include-transitive
```

## Проверка подлинности образа

Образы в GHCR и Docker Hub подписываются в CI через cosign без ключей (OIDC-идентичность GitHub Actions, журнал прозрачности Rekor).
Перед развёртыванием (и перед переносом в закрытый контур) проверьте подпись:

```bash
cosign verify ghcr.io/akprof2000/tsl-auth:latest \
  --certificate-identity-regexp 'https://github.com/akprof2000/tsl-auth/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Вместе с образом публикуются SBOM (SPDX) и provenance (SLSA, `mode=max`):

```bash
docker buildx imagetools inspect ghcr.io/akprof2000/tsl-auth:latest --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/akprof2000/tsl-auth:latest --format '{{ json .Provenance }}'
```

## Рекомендации по эксплуатации

* Всегда используйте HTTPS (`AUTH_REQUIRE_HTTPS=true`), задавайте `AUTH_ISSUER` (обязателен) и `AUTH_ALLOWED_HOSTS`
  (`AllowedHosts`, например `auth.corp`).
* За прокси включайте `Auth__TrustForwardedHeaders` только вместе с закрытым прямым доступом к узлам; подсеть внешнего
  прокси задайте в `Auth__KnownNetworks`.
* Храните мастер-ключ в секрет-хранилище и отдельно от бэкапов БД; секреты передавайте файлами
  (`docker-compose.secrets.yml`, `docker-compose.ha-secrets.yml` — [docker secrets](deployment.md#секреты-файлами-docker-secrets)),
  а не переменными окружения.
* Ограничьте получателей вебхуков (`Webhooks__AllowedNetworks`) сетями, где действительно работают боты.
* Держите access-токены короткими (5–15 мин); для чувствительных API используйте introspection.
* Выдавайте администраторам минимальные роли (`auditor` для просмотра), ботам — только `notifier` / `reset-bot`.
* Настройте вебхук или бота на `security.alert` — блокировки, сбросы через бота, отказы в доступе.
* Регулярно обновляйте образ: Dependabot еженедельно предлагает новые digest базовых образов и пакеты NuGet.
* Проверяйте подпись cosign и используйте теги версий или digest, а не `latest`.
