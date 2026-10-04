# Доступ по ролям service-ключей

API разделяет операции между четырьмя фиксированными ролями. Это RBAC для
service credentials, **не** индивидуальные пользователи, SSO, подтверждение
личности инженера или изоляция устройств/организаций. Каждая настроенная роль
может читать всю сохранённую историю и конфиденциальные данные снимков.
Раздавайте reader key только тому, кому разрешено такое чтение.

| Операция | reader | analyst | engineer | admin |
| --- | --- | --- | --- | --- |
| История, снимки, анализы, модели, diff, источники, feedback/draft/review history | да | да | да | да |
| Загрузка снимков и запуск анализа | нет | да | да | да |
| Feedback, создание черновика, локальная проверка | нет | нет | да | да |
| Явный запрос настроенной локальной LLM | нет | нет | да | да |
| Обучение Isolation Forest и добавление модели в registry | нет | нет | нет | да |

Доступ не включает применение, patch approval или formal pass: таких операций
по-прежнему нет. Разрешение роли на LLM **не заменяет** отдельную настройку
оператора и строгий `allow_local_model_context=true` в запросе.

## Настройка без новой миграции

`NETCONFIG_API_TOKEN` сохраняет admin permissions: прежний запуск совместим.
Необязательные `NETCONFIG_READER_TOKEN`, `NETCONFIG_ANALYST_TOKEN`,
`NETCONFIG_ENGINEER_TOKEN` включают соответствующие роли. Пустая переменная
отключает роль. Значения должны быть разными, содержать 32–512 печатных ASCII
символов без пробелов. Совпадающие, короткие, слишком длинные или некорректные
ключи останавливают startup; повышающего права fallback нет.

Генерируйте каждый ключ отдельно, храните в защищённом local secret storage
или игнорируемом `.env`, не в репозитории. Например, до запуска API:

```powershell
$env:NETCONFIG_READER_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Database URL, admin key и Fernet key по-прежнему настраиваются вместе по
[инструкции API](persistent-api.md). Дополнительные роли без основных настроек
не включают API. Optional role variables передаются в Compose без default keys;
синтетические тестовые ключи существуют только в тестах/CI, не в runtime defaults.

Настройки читаются при startup. Для отзыва/ротации замените или очистите ключ и
перезапустите **все** процессы/реплики API; старый bearer после restart получает
401. БД и история от смены role key не меняются; Fernet key не меняйте.
Нет hot-reload revocation, identity provider, token expiry или key-management UI.
Logout очищает только browser session и не отзывает сам service key.

## Серверная граница

Каждый protected endpoint проверяет bearer и право до чтения write body и
доступа к хранилищу. Отсутствующий/неверный key — 401; действующий key без
разрешения — общий 403, без раскрытия существования указанной записи.
Все configured keys сравниваются через constant-time digest comparison;
credentials не пишутся в request state, ответы или собственные логи.
Структурированный LLM selection проверяется после bounded JSON parsing,
но до target lookup/передачи в модель. `role`/`permissions` из request body
не принимаются и не могут повысить права.

Авторизованный `GET /api/v1/session` возвращает только контракт
`service-access-0.1.0`: role, точный список permissions,
`individual_identity_verified=false`, `device_scope=all_saved_devices`.
Ни key, ни список настроенных keys, ни identity оператора не возвращаются.
Схема storage должна быть актуальной, как для других protected reads.

UI получает этот контракт при входе, проверяет фиксированную role/permission
матрицу и отображает роль. Неизвестный/несогласованный ответ или ошибка endpoint
не разрешают вход с правами admin. Недоступные операции скрыты/отключены,
история остаётся читаемой. Permissions хранятся только в памяти и очищаются при
logout/reload; поздний ответ закрытой сессии не восстанавливает права.
UI не является механизмом авторизации: прямой HTTP-запрос тоже проверяет сервер.

## Ограничения и проверки

Reader key даёт доступ ко всем устройствам; device-scoped policy, tenants,
индивидуальная attribution и полноценный access/failed-attempt audit пока не
реализованы. Существующий append-only audit фиксирует успешные creations;
feedback `actor=shared_service_token` не превращается в идентифицированного
инженера из-за имени роли. TLS, OS permissions, backup и protection от кражи
bearer по-прежнему нужны. Это не production security certification.

API tests проверяют матрицу всех write operations, отказы до body/storage,
права на local/model explanations, неотражение keys, restart revocation,
реальные engineer feedback/draft/review writes и чтение reader. CI повторяет
их на отдельных PostgreSQL test schemas. Unit/browser tests проверяют exact
permissions, отсутствие admin fallback, очистку поздней сессии, роли в UI,
неизменность saved analysis, desktop/mobile и отсутствие browser storage.
