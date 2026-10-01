# Постоянный API: загрузка и история анализа

Этот срез реализует загрузку UTF-8 конфигурации, сохранение канонического снимка,
policy-анализ, локальные объяснения и получение истории. Web UI пока нет;
проверить сценарий можно через OpenAPI или HTTP-клиент.

## Локальный запуск с SQLite

Из корня проекта после установки `python -m pip install -e ".[dev]"`:

```powershell
New-Item -ItemType Directory -Path artifacts -Force | Out-Null
$env:NETCONFIG_DATABASE_URL = 'sqlite:///artifacts/api.sqlite3'
$env:NETCONFIG_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:NETCONFIG_ENCRYPTION_KEY = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python -m app.db.migrate
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Генерируйте ключ только один раз для новой БД. Сохраните его и токен в защищённом
локальном secret storage или игнорируемом `.env`: значения выше существуют только
в текущем процессе PowerShell. На следующем запуске используйте те же значения,
иначе старые payload не расшифруются. Для запуска из заполненного `.env` доступен
`uvicorn app.main:app --app-dir backend --env-file .env`; миграция читает переменные
процесса, а не `.env`. Не отправляйте секреты в Git или в запросы поддержки.

Поддерживаются файловая `sqlite:///...` и `postgresql+psycopg://...`.
SQLAlchemy использует отдельный [диалект psycopg](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#module-sqlalchemy.dialects.postgresql.psycopg).
Схема создаётся только явной миграцией; startup приложения не меняет БД.
Повторная миграция сохраняет записи. Destructive downgrade не поддерживается.
SQLite покрыта интеграционными тестами. PostgreSQL 17 проверен отдельным
[успешным CI job](https://github.com/itbortnik/netconfig-sentinel/actions/runs/36924852321)
со свежим контейнером: миграции, encrypted history, анализ и перезапуск приложения.
Локально он включается переменной `NETCONFIG_TEST_DATABASE_URL`: только
`postgresql+psycopg` и имя БД с суффиксом `_test`. Тест создаёт отдельную случайную
схему и удаляет только её после проверки; не указывайте рабочую БД.

## HTTP-сценарий

Все `/api/v1/*` требуют `Authorization: Bearer <token>`.
В `/docs` нажмите Authorize и введите токен; схема запроса загрузки описана в OpenAPI.
Создайте стабильный UUID устройства: его следующие снимки должны сохранять
vendor, platform и hostname. Несовпадение возвращает 409, не создавая новую запись.
Для переименования устройства отдельный workflow пока отсутствует.

В другом PowerShell с тем же настроенным токеном:

```powershell
$headers = @{ Authorization = "Bearer $env:NETCONFIG_API_TOKEN" }
$body = @{
    device_id = '00000000-0000-0000-0000-000000000001'
    filename = 'edge.cfg'
    content = "hostname edge`n"
} | ConvertTo-Json
$snapshot = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/v1/configurations' -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
$result = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/configurations/$($snapshot.configuration_id)/analyze" -Headers $headers
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/analyses/$($result.analysis_id)" -Headers $headers
```

| Операция | Путь |
| --- | --- |
| Создать канонический снимок | `POST /api/v1/configurations` |
| История снимков | `GET /api/v1/configurations?device_id=<UUID>&limit=20&offset=0` |
| Получить снимок | `GET /api/v1/configurations/<UUID>` |
| Анализировать сохранённый снимок | `POST /api/v1/configurations/<UUID>/analyze` |
| История анализов | `GET /api/v1/analyses?configuration_id=<UUID>&limit=20&offset=0` |
| Результат с находками, объяснениями и риском | `GET /api/v1/analyses/<UUID>` |
| Только находки | `GET /api/v1/analyses/<UUID>/findings` |

Списки возвращают сводки от новых к старым, `limit` от 1 до 100, `offset` от 0
до 10000. Каждый запуск анализа создаёт отдельную запись; повторные POST не
идемпотентны. Нет endpoints удаления, замены, применения изменений или выхода
на оборудование. Поддерживается только JSON, не multipart/архивы.

Бюджеты: HTTP-body до 3 MiB; текст конфигурации до 2 MiB UTF-8 и 10000 строк;
без управляющих символов кроме CR/LF/TAB. Filename — имя без пути с расширением
`.cfg`, `.conf` или `.txt`, не место назначения на диске. Неизвестные поля,
повторные JSON-ключи, сжатые тела и неподдерживаемый вендор отвергаются.
Некорректный запрос получает общее сообщение без отражения входного текста.

## Интерпретация результата

`analysis-api-0.1.0` содержит фактическую версию policy-каталога, SHA-256 исходного
текста, UUID снимка и устройства. `completed` означает завершённый policy-анализ
полностью разобранного текста в ограниченной поддерживаемой области, а не
полную проверку корректности сети. При warnings/unparsed/confidence < 1 результат
`partial`, а `risk` — null. Доступные находки и ограничения сохраняются.

В risk доступны только политики; peer baseline, ML и формальная проверка не
запускались. Оценки не калиброваны на реальных сетях. Объяснения детерминированные,
повторно сверяют находки, не вызывают LLM и не обосновывают применение патча.

БД хранит каноническую модель, а не полную копию исходного файла. Полностью
поддержанные команды представлены нормализованными значениями и provenance;
неизвестные фрагменты сохраняют raw text. Авторизованный GET может вернуть
конфиденциальные сведения. Payload снимков, анализов и identity устройств
зашифрованы; UUID, hashes, timestamps, связи и action metadata открыты.
Подробнее — [модель угроз](threat-model.md).

`/health` проверяет жизнь процесса. `/ready` проверяет registry парсеров и,
если storage настроено, schema revision и доступность таблиц. Без storage
probes работают, но `persistent_api=false`, `database_schema=null`; бизнес-API
возвращает 503. Readiness не проверяет расшифровку каждого payload: неверный
ключ или повреждение данных выявляются при чтении и дают 503.

## Docker Compose

Создайте локальный `.env` из `.env.example` и заполните `NETCONFIG_API_TOKEN`,
`NETCONFIG_ENCRYPTION_KEY`, `NETCONFIG_POSTGRES_PASSWORD` предложенными командами.
Для пароля используйте hex, поскольку Compose включает его в database URL.
`NETCONFIG_DATABASE_URL` в `.env` для Compose не нужен — внутренний URL задаётся
в service environment. Compose [интерполирует `.env`](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)
и откажется работать с пустыми обязательными секретами.

```powershell
docker compose up --build
```

Используется [официальный образ PostgreSQL 17](https://hub.docker.com/_/postgres)
с постоянным volume. Сначала healthcheck БД, затем одноразовая миграция, затем
API от непривилегированного OS-пользователя. API привязан к loopback хоста;
порт БД не опубликован. Не удаляйте volume и не теряйте ключ шифрования.
Изменение переменной пароля не меняет уже инициализированный пароль БД.

Это dev-конфигурация: DB-role, созданная стандартным entrypoint, обладает
superuser-правами. Для production нужны отдельные роли миграции и приложения,
TLS, менеджер секретов, backup/restore-проверка, RBAC и лимиты запросов.
PostgreSQL smoke-тест выполняется в CI, но полный запуск Compose с backend
container пока не проверен. Локально Docker отсутствует.
