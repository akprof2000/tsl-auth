# Сборка на GitFlic

Репозиторий зеркалируется с GitHub на [GitFlic](https://gitflic.ru/project/akprof2000/tsl-auth) (workflow `mirror-gitflic.yml`).
Каждая площадка собирает сама и публикует у себя:

| Площадка | Конвейер | Куда публикуется образ |
|---|---|---|
| GitHub | `.github/workflows/*.yml` | Docker Hub `akprof2000/tsl-auth`, GHCR `ghcr.io/akprof2000/tsl-auth` |
| GitFlic | [`gitflic-ci.yaml`](../gitflic-ci.yaml) | Реестр GitFlic проекта (`$CI_REGISTRY_IMAGE`) |

## Конвейер GitFlic

Запускается на push в `main` и на тег `v*` — они приходят на GitFlic зеркалом с GitHub.

| Этап | Задания |
|---|---|
| build | Сборка решения с `-warnaserror`, unit-тесты |
| test | Интеграционные тесты (SQLite, PostgreSQL и OpenBao в Testcontainers через `docker:dind`), проверка документации |
| image | Сборка образа из `Dockerfile` |
| scan | Trivy: уязвимости HIGH/CRITICAL с исправлением прерывают конвейер |
| publish | `main` — теги `latest` и `sha-<коммит>`; тег `vX.Y.Z` — тег `X.Y.Z` в реестре GitFlic |
| release | Релиз GitFlic для тега `vX.Y.Z` |

Результаты тестов (`TestResults/*.trx`) сохраняются артефактами на 14 дней.

## Агент

На gitflic.ru общих агентов нет: конвейер выполняет агент, подключённый к проекту. Нужна машина с Docker,
доступная в интернет (агент сам обращается к GitFlic, входящие подключения не нужны).

1. На GitFlic: проект → «Настройки» → «Агенты CI/CD». Там указаны URL регистрации и регистрационный токен.
   Токен — секрет: не пересылайте его в чаты и не сохраняйте в репозитории.
2. На машине агента создайте `docker-compose.yaml` (значения URL и токена — со страницы из шага 1):

   ```yaml
   services:
     runner:
       container_name: gitflic-runner-tsl-auth
       image: registry.gitflic.ru/company/gitflic/runner:latest
       environment:
         # URL со страницы «Агенты CI/CD», но с явным портом :443: без него агент 5.0.0 сохраняет порт «-1»
         # и падает при запросе конфигурации («Bad authority»).
         REG_URL: "https://coordinator.gitflic.ru:443/-/runner/registration"
         REG_TOKEN: "${GITFLIC_RUNNER_TOKEN}"                                # токен — из переменной окружения
         NAME: "tsl-auth"
         TAGS: "tsl-auth"             # задания конвейера помечены этим тегом
         PRIVILEGED: "true"           # нужно для сервиса docker:dind (сборка образа, Testcontainers)
         LOG_LEVEL: INFO
         # Несколько заданий одновременно (стадии test и image содержат по два): один агент, три потока.
         CONCURRENCY_MODE: CUSTOM
         LIMIT_OF_CONCURRENCY_TO_PROCESS_JOBS: "3"
       volumes:
         - /var/run/docker.sock:/var/run/docker.sock
         - runner-config:/gitflic-runner/config
         - runner-log:/gitflic-runner/log
       network_mode: host
       restart: unless-stopped
   volumes:
     runner-config:
     runner-log:
   ```

3. Запустите агент, передав токен через переменную окружения (в файл он не попадает):

   ```bash
   GITFLIC_RUNNER_TOKEN='<токен со страницы агентов>' docker compose -p gitflic-runner up -d
   ```

4. Агент появится в списке «Агенты CI/CD» проекта. После регистрации нажмите там «Сбросить токен»: старый токен
   больше не нужен, а новый агент получит уже новый. Следующий push в `main` на GitHub запустит конвейер на GitFlic.

Один агент выполняет до трёх заданий параллельно (`LIMIT_OF_CONCURRENCY_TO_PROCESS_JOBS`); каждому заданию
нужны ~2 ГБ памяти под SDK и `docker:dind`. Второй агент на другой машине подключается тем же способом с тем же
тегом `tsl-auth` — GitFlic распределит задания между ними.

Привилегированный режим нужен только агенту этого проекта: задания выполняются в отдельных контейнерах
и используют `docker:dind`, а не Docker хоста. Выделите под агент отдельную машину или виртуальную машину.

## Образ из реестра GitFlic

```bash
docker login registry.gitflic.ru
```

```bash
docker pull registry.gitflic.ru/project/akprof2000/tsl-auth:latest
```

Точный путь образа показан на странице проекта «Реестр контейнеров и пакетов». В закрытый контур образ
переносится через `docker save` / `docker load`, как описано в [развёртывании](deployment.md).
