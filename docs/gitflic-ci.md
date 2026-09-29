# Сборка на GitFlic

Репозиторий зеркалируется с GitHub на [GitFlic](https://gitflic.ru/project/uklad/tsl-auth) (workflow `mirror-gitflic.yml`).
Каждая площадка собирает сама и публикует у себя:

| Площадка | Конвейер | Куда публикуется образ |
|---|---|---|
| GitHub | `.github/workflows/*.yml` | Docker Hub `akprof2000/tsl-auth`, GHCR `ghcr.io/akprof2000/tsl-auth` |
| GitFlic | [`gitflic-ci.yaml`](../gitflic-ci.yaml) | Реестр GitFlic проекта: `registry.gitflic.ru/project/uklad/tsl-auth/tsl-auth` |

## Конвейер GitFlic

Запускается на push в `main` и на тег `v*` — они приходят на GitFlic зеркалом с GitHub.

| Этап | Задания |
|---|---|
| build | Параллельно: сборка решения с `-warnaserror` и unit-тесты; сборка образа из `Dockerfile`; проверка документации |
| test | Параллельно: интеграционные тесты (SQLite, PostgreSQL и OpenBao в Testcontainers через `docker:dind`, без пересборки — бинарники из артефакта build); Trivy — уязвимости HIGH/CRITICAL с исправлением прерывают конвейер |
| publish | `main` — теги `latest` и `sha-<коммит>`; тег `vX.Y.Z` — тег `X.Y.Z` в реестре GitFlic. Загрузка — `crane` (клиент без демона): демон `docker:dind` на агенте не дожидается ответа `registry.gitflic.ru` |
| release | Релиз GitFlic для тега `vX.Y.Z`; задания `publish-sdk-nuget/npm/pypi/maven` публикуют клиентские библиотеки той же версии в реестр пакетов проекта (`…/package/-/<тип>`), если заданы переменные проекта `GITFLIC_PKG_USER` и `GITFLIC_PKG_TOKEN` (логин и транспортный токен GitFlic). Контрактные тесты SDK идут в CI GitHub (`sdk.yml`) |

Пакеты NuGet кэшируются между конвейерами (`cache: nuget`), поэтому `restore` после первого прогона занимает секунды.

После каждого `dotnet test` задание проверяет файл результатов `scripts/ci-check-trx.sh`: тестов выполнено не меньше
ожидаемого и ни один не упал. Без этой проверки `dotnet test --no-build` без собранных бинарников (или без найденных
тестов) завершается с кодом 0 и пустым выводом, и конвейер был бы зелёным при нуле выполненных тестов.
Агент выполняет несколько заданий одновременно, так что стадия занимает столько, сколько самое долгое задание в ней.
Публикация образа объявлена через `needs` зависимой от всех проверок: без этого GitFlic запускал `publish-image`,
как только освобождался агент, ещё до окончания интеграционных тестов.

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

4. Агент появится в списке «Агенты CI/CD» проекта. Токен агенту нужен при каждом старте контейнера (агент 5.0.0
   регистрируется заново), поэтому не сбрасывайте его на странице, пока агент может перезапускаться; после сброса
   перезапустите агент с новым токеном. Следующий push в `main` на GitHub запустит конвейер на GitFlic.

Координатор GitFlic выдаёт агенту по одному заданию примерно раз в минуту, и настройки частоты у агента нет, поэтому
скорость раздачи заданий растёт с числом агентов: два агента получают задания вдвое быстрее. На одной машине
можно поднять несколько агентов (второй — копия compose с другими именами контейнера, томов и `NAME`), общий предел
параллельных заданий (`LIMIT_OF_CONCURRENCY_TO_PROCESS_JOBS` на каждом) подбирают по памяти: заданию с SDK
и `docker:dind` нужно ~2 ГБ. Агенты на других машинах подключаются тем же способом с тем же тегом `tsl-auth`.

Привилегированный режим нужен только агенту этого проекта: задания выполняются в отдельных контейнерах
и используют `docker:dind`, а не Docker хоста. Выделите под агент отдельную машину или виртуальную машину.

## Образ из реестра GitFlic

```bash
docker login registry.gitflic.ru
```

```bash
docker pull registry.gitflic.ru/project/uklad/tsl-auth/tsl-auth:latest
```

Путь образа в реестре GitFlic — `registry.gitflic.ru/project/<владелец>/<проект>/<имя образа>:<тег>`; для входа
с рабочей машины нужен транспортный токен профиля GitFlic (пароль в `docker login`). В закрытый контур образ
переносится через `docker save` / `docker load`, как описано в [развёртывании](deployment.md).
