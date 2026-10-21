# Сохранённые черновики и проверка точных исходников

API/UI сохраняют план различий между двумя каноническими снимками и отдельную
историю локального рассмотрения. Это не готовые команды и не исполняемый патч.
При явном согласии во время upload API сохраняет отдельный зашифрованный
[точный исходник](original-source-retention.md). Новый v2 workflow проверяет такую пару
и явно выбранные неизменные соседние устройства через локальный Batfish.
Без сохранённого исходника текст не восстанавливается из IR.
Offline-инструменты для исходных файлов описаны отдельно
в [черновиках по тексту](patch-drafts.md).
Ограниченный [генератор native-кандидатов](vendor-patch-drafts.md) тоже требует
явного raw-source: API не восстанавливает его из IR и не подменяет этим свой diff.

## Сценарий в браузере

1. Выберите ранний снимок кнопкой «Выбрать для diff», откройте следующий снимок
   того же устройства и нажмите «Показать различия объектов».
2. Нажмите «Сохранить черновик объектов». Нужны различающиеся source hashes
   и хотя бы одно изменение в поддерживаемых объектах. Только комментарий или
   неизвестная команда не создают такой черновик.
3. Запустите «Локальная проверка черновика»: сервер сравнит нарушения политик,
   отклонения от раннего снимка и сохранит отчёт. Черновик остаётся `draft`,
   отчёт — `needs_review`, формальная проверка и ML — `not_run`.
4. После повторного входа откройте поздний снимок и «Обновить черновики».
   Выберите сохранённый черновик, затем проверку. История не требует повторного
   вычисления diff в браузере и не исчезает после перезапуска сервера.

История черновиков привязана к позднему снимку, история проверок — к точному
черновику. Списки показывают по 20 записей. Неполный разбор явно выделен:
сравнение новых/исчезнувших нарушений недоступно (`null`, не ложный ноль).
Риск нового снимка по политикам доступен только при его полном разборе.
Исчезновение находки не доказывает исправление или безопасность сети.

## HTTP-контракты

Все операции требуют service bearer-token и [соответствующей роли](service-roles.md).
Ключ не удостоверяет личность инженера. Для существующей БД после backup и сохранения
старого ключа выполните явный upgrade до `0014_deterministic_rechecks`:
`python -m app.db.migrate`. Startup не меняет схему.

| Операция | Путь |
| --- | --- |
| Создать черновик | `POST /api/v1/patches` |
| История позднего снимка | `GET /api/v1/patches?after_configuration_id=<UUID>&limit=20&offset=0` |
| Черновик с полным diff | `GET /api/v1/patches/<UUID>` |
| Записать локальную проверку | `POST /api/v1/patches/<UUID>/verify` |
| История проверок | `GET /api/v1/patches/<UUID>/verifications?limit=20&offset=0` |
| Полный сохранённый отчёт | `GET /api/v1/patches/<UUID>/verifications/<UUID>` |

Тело создания:

```json
{
  "patch_id": "00000000-0000-0000-0000-000000000003",
  "before_configuration_id": "00000000-0000-0000-0000-000000000001",
  "after_configuration_id": "00000000-0000-0000-0000-000000000002",
  "before_source_sha256": "<64 lowercase hex characters from before snapshot>",
  "after_source_sha256": "<64 lowercase hex characters from after snapshot>"
}
```

UUID и placeholders выше иллюстрируют поля, не готовый запрос к рабочей БД.
Сервер проверяет сохранённые hashes, identity, время приёма и бюджеты diff.
Ответ `snapshot-patch-draft-0.1.0` содержит весь нормализованный diff,
`draft_sha256`, `requires_human_review=true`. Fingerprint вычисляется сервером
как SHA-256 canonical JSON `[version, diff]`: sorted keys, UTF-8, compact
separators, без NaN. UUID и время создания черновика не входят в fingerprint.
Он связывает содержимое, но не является подписью автора.

Тело локальной проверки:

```json
{
  "verification_id": "00000000-0000-0000-0000-000000000004",
  "draft_sha256": "<fingerprint from saved draft>",
  "mode": "local_preflight"
}
```

Ответ `snapshot-patch-review-0.1.0` связывает UUID проверки/черновика, fingerprint,
оба снимка и `PreflightReport`. Всегда присутствуют блокеры
`formal_verification_not_run` и `human_review_required`; дополнительно отмечены
неполный разбор, недоступность reference comparison и нарушения политик.
Явный `mode=batfish` возвращает 503 **без fallback и без записи проверки**.
Другой mode, неизвестные поля, команды, `approved`/`applied` не принимаются.

## Повтор после сбоя

Для каждого намерения клиент заранее задаёт UUID. Новая запись возвращает 201;
тот же ID и то же намерение — 200 с исходным временем и содержимым. Другое
намерение под существующим ID — 409. Параллельные повторы не дублируют запись
или audit-event. Повтор проверки возвращает исторический отчёт, а не заново
оценивает его текущим каталогом политик. Новый запуск требует нового UUID.

В UI UUID сохраняется в памяти до подтверждённого ответа и загрузки истории.
Повтор после потери ответа использует тот же ID. После подтверждённого запуска
следующая локальная проверка получает новый ID. После закрытия формы, выбора
другого снимка или reload сначала изучите историю: память намерения утрачена,
отмена ожидания не откатывает транзакцию сервера.

## Хранение и ограничения

`patch_proposals` и `verification_runs` содержат Fernet-payload, связанный с
типом записи и UUID. Metadata/связи/timestamps открыты. Создание черновика и
`patch.draft_created`, создание проверки и `patch.local_review_recorded` атомарны.
Чтение сверяет контракт, metadata, родительские снимки и пересчитанный diff;
проверка сверяется с fingerprint и bindings черновика. Повреждение, неверный
ключ или перенос ciphertext дают общий 503 без содержимого конфигурации.
Исторические policy reports при чтении не переоцениваются новым каталогом.

Write-body ограничен 16 KiB, draft/review — 4 MiB сериализованного JSON;
сохраняются [бюджеты diff](snapshot-diff.md). В списках limit 1–100, offset
0–10000; offset-пагинация может смещаться при новых записях. Общих quotas,
очереди и распределённой блокировки нет.

Нормализованные значения не обезличиваются и могут быть конфиденциальны.
Нет изменения/удаления истории, approval/apply, импорта команд или обращения
к устройствам/внешнему провайдеру. Черновик и его локальная проверка не меняют
сохранённые анализы, feedback, модели или риск. Физическая сеть, происхождение
снимков и production-безопасность этим workflow не удостоверяются.

## Сетевая проверка сохранённых исходников

Этот отдельный путь не требует находки или модельного предложения. Сначала
сохраните оба исходника при upload и создайте обычный object draft. В его панели
откройте «Сетевая проверка сохранённых исходников», выберите при необходимости
по одному снимку соседних устройств, задайте hostname начального узла и точный
IPv4 prefix назначения. Соседи включаются неизменными с обеих сторон. Введите
новое согласие на передачу всех выбранных исходников локальному движку.

Оператор отдельно разрешает worker через `NETCONFIG_PATCH_ALLOW_ENGINE_UPLOAD=1`
и устанавливает extra `verification`. Используется только loopback Batfish;
endpoint, код и model paths нельзя передать в запросе. Разрешение оператора и
согласие запроса не являются health check. SDK/engine могут вернуть unavailable,
error, incomplete или inconclusive; это сохраняется отдельным результатом.

| Операция | Путь |
| --- | --- |
| Настройка, без probing движка | `GET /api/v2/patches/capabilities` |
| Новая сетевая попытка | `POST /api/v2/patches/<patch UUID>/verify` |
| История сетевых попыток | `GET /api/v2/patches/<patch UUID>/verifications?limit=20&offset=0` |
| Полный сетевой отчёт | `GET /api/v2/patches/<patch UUID>/verifications/<verification UUID>` |

Для POST нужна роль engineer/admin, включая повтор существующего ID. Read-роли
могут читать историю. Тело `source-patch-request-0.1.0`:

```json
{
  "verification_id": "00000000-0000-0000-0000-000000000005",
  "draft_sha256": "<fingerprint from saved draft>",
  "companions": [
    {
      "configuration_id": "00000000-0000-0000-0000-000000000006",
      "source_sha256": "<source hash from selected companion>"
    }
  ],
  "scope": {"start_node": "edge", "destination": "198.51.100.1/32"},
  "allow_local_engine_upload": true
}
```

Пара target берётся из сохранённого draft; другой source text или commands
запрос не принимает. Сервер повторно читает и разбирает точные originals,
сверяет source/canonical hashes, identity и полноту parsing. Максимум — 32
устройства и 8 MiB текста сети, с прежними лимитами каждого исходника.
Сетевой adapter сохраняет собственную поддержанную семантику: canonical1.2
не разрешает неизвестные ему route-map команды. Некорректная пара, companions,
partial parse или отсутствующий start node дают409 до SDK; некорректный формат
scope даёт400. Отсутствие согласия403, disabled503,
занятый общий worker429. Это не vendor syntax validation.

До SDK атомарно сохраняются encrypted intent и
`patch.network_verification_requested`; после — outcome и
`patch.network_verification_completed`. Новые таблицы
`patch_network_review_intents`/`patch_network_review_outcomes` связывают payload
с типом и UUID. Parent draft/snapshot hashes проверяются и при чтении. Миграция
0011 не меняет старые строки или v1 contracts. POST body ≤16 KiB; intent/outcome
≤4 MiB каждый. Перед резервированием canonical intent оставляет256 KiB+8192
байта для completion; canonical результат SDK ограничен256 KiB. Недостаточный
бюджет даёт413 до SDK, чрезмерный результат — bounded `worker_failed`.

Ответ `source-patch-verification-0.1.0` разделяет target source hashes,
canonical hashes и fingerprints всей supplied network. `outcome.intent_sha256`
связывает результат с точным intent. `review_json` содержит точные UTF-8 байты
Python compact sorted-key JSON тела без собственных `review_json`/`review_sha256`;
`review_sha256` — их SHA-256. Browser проверяет outer proof, typed equality и
raw nested intent hash, сохраняя Python float representation. Hash binding
подтверждает соответствие записей, не истинность источника или личность инженера.

Один ID резервирует только один вызов SDK, в том числе при двух процессах.
После потери ответа прочитайте тот же ID: GET не запускает worker и не читает
originals заново. Повтор идентичного POST возвращает прежнюю запись даже при
отключённом worker; другое намерение даёт409. Наличие intent без outcome означает
`pending_unknown`, а не доказательство работающего worker; автоматического
повторного запуска или тайного восстановления результата нет.

UI после неопределённого ответа блокирует новый POST и предлагает чтение истории.
При явном отказе сервера и последующем GET404 доступен отдельный сброс с новым ID
и новым согласием. Lost response плюс GET404 не разрешает повтор: исходный запрос
ещё мог дойти до резервации. Reload теряет память запроса; сначала изучите историю.

`no_differences_in_scope` — только scoped network result. `cleanup_complete=null`
остаётся неизвестным, `false` означает неподтверждённое удаление. Итог всегда
`needs_review`, ML `not_run`, approved/applied false. Локальный preflight сохраняется
даже при ошибке SDK; история policies при чтении не пересчитывается. Проверка
синтаксиса на устройстве, management access, rollback, approved baseline и
индивидуальное инженерное решение остаются отдельными незакрытыми gates.

Для тех же exact retained before/after доступна отдельная
[парная ML-диагностика](source-ml-rechecks.md) без finding/analysis/model proposal.
Для явно выбранного before analysis доступен отдельный
[повтор исходной Isolation Forest](source-forest-rechecks.md): обе retained стороны,
тот же numeric artifact, точное совпадение original before tuple и отдельная
immutable история. Этот результат не повышает статусы прежних reviews.
Её UUID, consent, intent/outcome и proof независимы от network0.1; она не меняет
исторический `ml_status=not_run` сетевого отчёта или approval gates.


Отдельный [повтор исходных политик, эталона и peer profile](source-deterministic-rechecks.md)
использует явно выбранный before analysis, его каталог и сохранённый контекст
для обеих retained сторон. Старые preflight/reference, network/ML/Forest reviews
не пересчитываются; общий qualified result и approval автоматически не возникают.
