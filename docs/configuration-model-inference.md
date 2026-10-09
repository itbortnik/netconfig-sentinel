# Конфигурационная модель в сохранённом анализе

Отдельная экспериментальная диагностика вызывает уже зарегистрированные
native/foundation config heads для исходника сохранённого анализа. Это не LLM,
document retrieval, повторный policy-анализ или pre/post проверка патча. Старые
`AnalysisResult`, findings, severity, risk и объяснения не меняются. Некалиброванные
scores не включаются в гибридный риск и не получают threshold/вердикт безопасности.
Результат не подтверждает independent quality, formal pass, approval или применение.

## Выбор оператора и API

Default — disabled. Нужны authenticated persistent API, миграция
`0009_configuration_model_runs`, проверенный [private registry](transformer-model-registry.md)
и independent pin. Native требует training extra; foundation — retrieval extra
и существующий pinned publisher source. HTTP не выбирает пути, код или веса.

```powershell
$env:NETCONFIG_CONFIG_MODEL_REGISTRY = 'C:/private/config-models'
$env:NETCONFIG_CONFIG_MODEL_SHA256 = '<independent-full-lowercase-sha256>'
# Только для foundation; с native не задавайте:
$env:NETCONFIG_CONFIG_MODEL_FOUNDATION_SOURCE = 'C:/private/pinned-encoder'
```

Registry/pin задаются вместе; неполная настройка останавливает startup.
Пути абсолютные, в ответах отсутствуют. Это отдельная настройка, не
`NETCONFIG_PATCH_*`. Никаких downloads/refit/автоматической активации нет.
Default startup и чтение истории не импортируют PyTorch/Transformers.

| Операция | Путь |
| --- | --- |
| Настройка без health check | `GET /api/v1/configuration-model-runs/capabilities` |
| Одна новая попытка | `POST /api/v1/configuration-model-runs` |
| История анализа | `GET /api/v1/configuration-model-runs?analysis_id=<UUID>&limit=20&offset=0` |
| Сохранённая попытка | `GET /api/v1/configuration-model-runs/<inference_id>` |

Capabilities возвращает configured/disabled, pin и `health_checked=false`:
веса этим не проверяются. POST разрешён engineer/admin с `configuration_model`,
чтение — всем ролям. Строгое тело: `inference_id`, `analysis_id`, `source_sha256`,
`model_sha256`, `allow_local_model_context=true`. Boolean не приводится из
числа/строки; default false. [Original retention](original-source-retention.md)
сама по себе не разрешает передачу контекста выбранной локальной модели.

Нужен exact encrypted retained original, соответствующий canonical snapshot;
текст из IR не восстанавливается. Partial parsing/unknown fragments/warnings,
чужой source/model pin или отсутствующий оригинал дают 409 до reservation/inference.
Неверный analysis ID — 404; disabled — 503. Один worker на процесс API, без очереди:
занятый slot даёт 429 до reservation. Это не общий лимит replicas/rate limiter.

UI показывает отдельный блок даже без findings, pin, предупреждения и
неотмеченное согласие. Reader/analyst не получают запуск. Принятый ответ проверяется
по UUID/source/model/analysis bindings. После неясного POST UI удерживает UUID и
предлагает явный GET для сверки; автоматического POST retry нет. Новая попытка —
новый UUID и новое согласие. Logout/reload не сохраняет consent/credentials в
browser storage; до 20 последних серверных записей доступны для просмотра.
Default browser timeout 30 секунд может сработать раньше worker deadline;
это не отмена серверной попытки: сначала проверьте её UUID через GET.

## Inference и неизменяемая история

До reservation проверяются согласие, права, exact analysis/source, полный разбор
и оригинал. Сервер фиксирует SHA всего сохранённого analysis, snapshot binding,
число исходных строк, модель и время. Это fingerprint связи, не attestation truth.
Intent и `configuration_model.requested` commit атомарно. При конкуренции один
UUID резервируется один раз; проигравший читает запись без нового worker.

Отдельный `-I` child получает bounded job через stdin, заново разбирает original
и сверяет snapshot, загружает registry bundle и проверяет independent pin/model
card. Actual `predict_multitask`/`predict_foundation_transfer` использует transient
sanitized text, исходные line coordinates и eval-only CPU runtime. Private key
псевдонимизации новый на попытку и не сохраняется: новая попытка не обещает
идентичные sanitized hashes/scores. История не пересчитывает прошлую санитизацию
и не требует доступности весов или оригинала для повторного inference.

Child environment allowlist не передаёт API/DB/Fernet secrets; HF downloads и
telemetry отключены. Deadline default 60 секунд, job 16 MiB/result 4 MiB;
timeout убивает/reaps child. Это изоляция trusted operator-selected pipeline,
не OS sandbox враждебного модельного кода. Parent сверяет source/model/line count,
classes/enabled heads и numeric contracts до сохранения.

Outcome и `configuration_model.completed` commit атомарно. Failure сохраняется
без rejected scores; ответ 503 предлагает проверить историю. Crash/ошибка storage
может оставить `pending`: это reservation, **не** подтверждение живого процесса.
Идентичный POST возвращает прежний outcome/pending с 200 даже при disabled модели
после restart; другой запрос с тем же UUID — 409. Нет автоматического resume,
повторного inference или перезаписи terminal record.

Intent/outcome зашифрованы с type/UUID binding; SQL раскрывает UUID/время. Card
содержит training/source/tokenizer/encoder hashes, классы, counts и target semantics.
`injected_mutation` не становится confirmed anomaly; foundation pretraining exposure
остаётся unknown. Category/line/anomaly scores раздельны, severity distribution не
равна Finding.severity, attention не causal. Disabled heads — `null`, не invented
zeros. Embedding хранится только как SHA/размерность, не вектор. Raw/sanitized text,
ключ, paths и prompts отсутствуют в outcome/journal. Journal связывает IDs/hashes/
status, не scores. Hashes linkable и конфиденциальны; ACL/backup нужны отдельно.

## Проверки и незакрытые gates

Unit/API tests проверяют tiny actual native inference, pins, private sanitization,
сохранение RNG/threads, disabled heads, source/analysis binding, corruption,
reservation race, terminal audit rollback, timeout/reap/output/environment guards.
Synthetic protocol adapters отделены от actual isolated native workers Cisco/JunOS.
Desktop/mobile fixtures проверяют consent, lost response, binding refusal и
отсутствие повторного POST, не model quality.

На 2026-10-09 [installed-package diagnostic](evaluation/owned-configuration-model-http.json)
выполнил четыре actual CPU worker inference: native 0.2 и foundation, Cisco/JunOS.
Четыре отказа без consent произошли до reservation; восемь replay POST и четыре
restart GET не запускали модель. Все прежние analysis неизменны; temporary БД
удалены, API parent не импортировал Torch/Transformers. HTTP время с загрузкой
worker: native 4.67/6.50 с, foundation 22.86/21.04 с. Это единичные owned recipes
при фоновой регрессии, не квалификация latency. Parent импортирован из wheel,
220 Python files и built assets byte-equal; strict исключение editable checkout
paths внутри child отдельно не подтверждалось и не заявляется.
Default Compose не передаёт эти переменные и не содержит model extras/weights;
проверка этого этапа выполнена на локальной установленной сборке, не на model-enabled
контейнере. Для контейнерного включения нужен отдельно проверенный image/readonly
mount операторского registry/source; автоматический mount private folders не добавлен.

Полная локальная регрессия этой поставки: 1998 passed, 23 skipped, пять warnings
(четыре dependency deprecations и прежний SQLite ResourceWarning); coverage 89.44%
измеряет покрытие кода, не ML quality. Skips относятся к optional SDK/live Batfish
и отдельному PostgreSQL test environment. Ruff и mypy default/win32 прошли;
frontend typecheck/format/build, 394 unit и 126 desktop/mobile browser tests прошли,
отдельные 22 model-candidate browser tests тоже. Они используют synthetic providers,
не новые LLM/formal/real-model quality experiments. PostgreSQL scenario добавлен
в CI; локальный PostgreSQL запуск отсутствовал.

Этот путь закрывает функциональное подключение существующих config models к
saved analysis, не качество. Большой разрешённый корпус, реальные confirmed labels,
independent paired benchmark/calibration, полный multi-class/severity transfer и
production/security gates открыты. У прежних owned checkpoints selection F1/line
recall=0; HTTP/UI не улучшает эти результаты и не разрешает перенос scores в risk.
