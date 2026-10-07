# Зашифрованный журнал операций

Persistent API сохраняет receipt **до** выполнения `/api/v1/*` и completion после
формирования ответа. Фиксируются чтения, отказы, ошибки и запросы объяснений.
Это история ответов сервиса, не доказательство доставки, отката, качества модели,
применения конфигурации, formal pass или личности владельца ключа.

## Схема и содержимое

Сохраните backup БД и прежний Fernet key, затем выполните `python -m app.db.migrate`
в той же настроенной среде: требуется `0005_operation_journal`. Startup не мигрирует
БД. Domain records и атомарные audit events сохраняются; прошедшим операциям receipt
не приписывается. Новый журнал автоматически включён для актуального persistent API.
На старой схеме business dependencies запрещают работу; запросы до upgrade в журнал
не входят. Health/static/OpenAPI и offline CLI не журналируются.

Содержательные metadata в `operation_receipts` и `operation_completions` зашифрованы.
SQL раскрывает UUID и время строки, Fernet — время ciphertext. Envelope связывает
тип и UUID; completion — SHA receipt, время, HTTP status и решения RBAC. При чтении
проверяются ciphertext, строгие контракты, UUID/timestamp binding и права роли.

Сохраняются фиксированное имя операции, allowlisted метод, роль проверенного ключа
или `null`, permissions, status и duration. Неизвестные маршруты — `unmatched_api`,
другие методы — `OTHER`. Не сохраняются ключ/его fingerprint, IP, URL/query/headers.
`authorization=allowed` означает разрешение **роли**, не всех проверок запроса:
отсутствующее разрешение передачи контекста может дать 403 при допустимой роли.

Успешный результат связывает выбранные UUID/hashes, количество и доступные в
контракте версии policy/model/schema/knowledge. Preview ограничен 16 UUID;
`metadata_sha256` покрывает выбранные bindings всей коллекции, **не** полный body.
Проекция `operation-result-projection-0.1.0` определена в `app.audit.results`.
Объяснение связывает hashes всех документов; semantic supplement — index SHA,
публичный query SHA и fingerprint encoder identity с pipeline/runtime/weights revision.
Модельный черновик — context SHA и SHA настроенного alias; alias не удостоверяет
реальные веса instruct-модели. Summary не выдаётся за заново выполненный полный анализ.

Конфигурации, неизвестные команды, имена файлов, адреса, feedback comments, значения
diff, промпты, embeddings и проза объяснений/модели в журнал не сериализуются.
UUID/hashes всё равно конфиденциальны: реальные journal exports не публикуйте.

## Неподтверждённый итог

Если receipt не сохранён, endpoint не выполняется, ответ — общий 503. Если completion
не удалось подтвердить, receipt остаётся `pending`, ответ — 503 с `X-Operation-Id`.
Domain write к этому времени **мог уже commit**. Cancellation/остановка процесса тоже
могут оставить pending. Нет автоматического повторного запуска или выдуманного итога.

`successful_response`, `rejected_response`, `failed_response` описывают формируемый
ответ. Даже 500 не доказывает отсутствие изменения: проверьте предметную историю до
повторного POST. Доставка body/disconnect не подтверждаются. Идентичный completion
можно повторно проверить, отличающийся не перезаписывает старый.
Domain `audit_events` и domain record по-прежнему commit/rollback в одной транзакции;
эта гарантия не распространяется на независимые receipt/completion.

## Admin API/UI

Только admin имеет `read_audit`; остальные роли — 403, неизвестный key — 401. Отказы
фиксируются без чтения предметных записей/body. Session теперь `service-access-0.2.0`;
UI принимает прежний 0.1, но не выдаёт ему новое право.

| Операция | Путь |
| --- | --- |
| Новейшая страница | `GET /api/v1/operation-audit?limit=20` |
| Следующая | `GET /api/v1/operation-audit?limit=20&before=<next_before>` |
| Запись | `GET /api/v1/operation-audit/<operation_id>` |

Limit 1–100; unknown cursor — 400, missing ID — 404, corruption — общий 503.
Keyset timestamp/UUID descending не сдвигается при новых запросах. Чтение само
фиксируется, собственный незавершённый receipt исключён из страницы. Update/delete нет.
UI показывает по 20 записей/детали, проверяет порядок долей миллисекунды,
status/permissions и SHA receipt. Неверная привязка не показывается; logout и late
response не восстанавливают данные. Browser storage не используется.

## Граница гарантии

Это application-level append-only history, не внешний WORM/подписанный log.
DB-admin/обладатель ключа может удалить/переписать строки или откатить всю БД.
Проверка страницы не обнаруживает все удаления/перемещения за её границу. Часы
сервера не являются независимой аттестацией. Нет individual identity, tenants,
автоматической retention/rotation, quotas или rate limiter. Отказы тоже занимают
место: ограничение запросов/диска — обязанность deployment. Запросы, не дошедшие
до приложения, и действия внешней модели не покрыты. Reverse proxy, server access
logs и tracing/APM настраиваются отдельно: они могут записывать секретные данные.

Синтетические тесты с настоящим ciphertext проверяют SQLite/opt-in PostgreSQL,
receipt-before-write, corruption, denials, keyset, restart, pending, cancellation,
atomic domain events и model/document bindings. Browser checks покрывают admin/
denied roles, receipt integrity, paging/storage и desktop/mobile; pending UI
проверяется отдельным явно синтетическим ответом.
