# Saved source-bound model patch proposals

Отдельный API связывает сохранённую находку и **точный retained original** с одной
попыткой локальной генерации. Старые `/api/v1/patches` остаются неизменными
normalized-object drafts; эти два представления нельзя подменять друг другом.
Generation маршрут не применяет изменения, не запускает Batfish/ML и не утверждает
проверку vendor syntax, доступности SSH или согласие конкретного инженера.
Последующая [saved candidate verification и решения](saved-model-patch-reviews.md)
имеют отдельные permissions, intent/result records и explicit worker opt-ins.

## Three independent permissions

1. При загрузке нужен `retain_original_source=true`: разрешение на encrypted
   хранение source, не на его передачу модели.
2. Оператор явно настраивает existing literal-loopback LLM adapter и дополнительно
   `NETCONFIG_LLM_ALLOW_PATCH_DRAFT=1`. Default blank/`0` — generation disabled.
   Existing `/findings/{id}/explain` остаётся **null-only**, включая patch opt-in.
3. Запрос инженера/admin содержит strict boolean `allow_local_model_context=true`.
   Обе server permissions `draft` и `model_explanation` проверяются до body.
   Reader/analyst не могут генерировать. Service keys не удостоверяют человека.

Endpoint выбирается только настройкой оператора, не body. Existing loopback
worker не следует redirects, не использует HTTP proxy/DNS, ограничивает bytes и
hard process deadline; default 10 seconds не увеличен. Explanation и patch
разделяют один nonblocking slot на процесс. Это не global GPU scheduler или
изоляция недоверенного локального server.

## Request and immutable history

`POST /api/v1/model-patches` принимает body не более 16 KiB:

```json
{
  "patch_id": "00000000-0000-0000-0000-000000000010",
  "analysis_id": "00000000-0000-0000-0000-000000000020",
  "finding_id": "00000000-0000-0000-0000-000000000030",
  "finding_sha256": "<exact fingerprint selected from the analysis explanation>",
  "source_sha256": "<exact selected configuration source hash>",
  "allow_local_model_context": true
}
```

Optional `baseline_configuration_id` и `baseline_source_sha256` передаются
вместе. Baseline должен иметь retained original, тот же device/parsed identity,
быть отдельным не более новым снимком. Его approval **not proven**; он не становится
организационной политикой. Missing source не восстанавливается из canonical IR.

Finding берётся только из выбранного saved analysis; independent finding/source
pins, device, snapshot и baseline проверяются до provider call. Fresh narrow
patch prompt передаёт только whitelist Telnet/SSH commands, anchors, minimized
facts и sealed project documents, не полный source/hostname/password/filename.
Это всё ещё confidential operational context, не гарантия полной anonymization.
Область остаётся двумя явными management policies Cisco IOS/JunOS; incomplete
parse и unsupported categories отказаны до генерации.

Migration `0007_model_patch_intents` добавляет encrypted `model_patch_intents`
и отдельный `model_patch_outcomes`. Startup не мигрирует БД. Upgrade не меняет
старые normalized drafts/reviews, sources, analyses или policy releases.
Перед миграцией сохраните backup и прежний encryption key.

Intent и `model_patch.requested` commit **до** единственного provider вызова.
Terminal result и `model_patch.completed` commit атомарно отдельно. Уникальный
intent ID предотвращает второй provider call, в том числе между API processes.
Повтор идентичного запроса даёт 200 с прежней записью; другой selection под тем
же ID — 409. Новый ID явно означает новую попытку, не скрытый retry.

Состояния generation history:

| Status | Meaning |
| --- | --- |
| `generating` | Intent сохранён, completion отсутствует; выполнение не подтверждено |
| `draft` | Принят schema-valid ответ с разрешёнными source-bound edits |
| `declined` | Принят ответ с `patch_draft=null`; шаблон не подставлялся |
| `failed` | Provider/answer отказан; raw rejected output не сохранён |

Новая неудачная генерация возвращает 503; состояние читается по выбранному ID.
При потере completion intent остаётся `generating`, без автоматического повторного
вызова/таймера/ложного failed или successful результата. `generation_attempt_limit=1`
означает лимит зарезервированной попытки, **не доказательство одного GPU inference**.

`GET /api/v1/model-patches/{patch_id}` и
`GET /api/v1/model-patches?analysis_id=...&limit=20&offset=0` доступны роли read.
Они возвращают original snapshot binding, selected pins, candidate/context/
proposal/document hashes, configured model-alias hash, timestamps, untrusted
answer и status. Полный original/candidate text, prompt и credentials не выдаются.
Candidate детерминированно восстанавливается только внутренним проверяющим кодом
из exact retained source и принятых edits; это не новая генерация или fallback.
Чтение проверяет encrypted envelopes, parent rows, fresh prompt и accepted edits.
Изменение источников/контрактов, не совпадающее с историческим binding, даёт отказ,
а не новое толкование старого ответа.

Ни один status не означает `validated`, `approved` или `applied`.
Formal/ML verification остаются `not_run`; `requires_human_review=true`,
`approved=false`, `applied=false`, `model_execution_authenticated=false`.
Configured alias/hash не доказывает реальные weights или выполнение inference.
Schema, permitted edits и citations не устанавливают истинность свободного prose.
Отдельные [verification records и решение](saved-model-patch-reviews.md) реализованы
следующим самостоятельным slice; они не переписывают эти generation flags.

Operation journal содержит только explicit metadata projection, не answer,
commands, prompt, raw source или API key. Domain payloads encrypted at rest;
доверенный процесс/host/key holder может читать их plaintext. Нет raw-download,
device connection, execution, автоматического retry или внешней отправки.

## Verification scope

Integration tests используют собственный literal-loopback HTTP server с явно
**синтетическими** ответами: это wire/schema/persistence/security checks, не
оценка LLM. Проверяются both vendors, valid/null/rejected outputs, permissions,
selected identity/baseline, lost completion, atomic audit rollback, encrypted
tamper, restart и concurrent reservations. В PostgreSQL CI каждый case использует
отдельную UUID-named `_test` schema; локальный SQLite прогон не заменяет этот job.

## Actual installed API/model diagnostic

[Numeric report](evaluation/owned-saved-model-patch-http.json) retains **all four**
actual requests through the installed wheel, bounded worker and pinned local
Qwen3-4B-Instruct-2507 on RTX 5080. No-baseline cohort: Cisco and JunOS both returned
valid null patches. Separate explicit-unapproved-baseline cohort: Cisco produced
one permitted SSHv2 candidate; JunOS declined again. The second cohort is a
different supplied input, not a hidden repair/retry or independent quality set.
All four completed responses passed structural/citation validation; **one draft
and three declines** are not a 100% remediation success rate.

Measured generation times are 18.375/5.915 and 18.425/6.405 seconds, respectively.
This diagnostic explicitly selected the existing maximum HTTP deadline of 20s;
the default 10s remains unchanged and is **not qualified** by these measurements.
Twelve installed runtime/migration files were byte-equal to source. Consent denial,
idempotent replay, provider-free restart reads, encrypted domain records and
unchanged saved analyses passed. The owned temporary databases were removed and
diagnostic keys were not persisted; operator services/settings were not activated.
Raw answers remain private, only reviewed numeric bindings are published.
Neither prose semantics nor independent real-data quality, formal/ML verification,
production throughput or human approval was established by this diagnostic.

The workflow adds 40 integration cases and nine operator-setting cases. The final
full local rerun passed **1736 tests with 21 skips** and four dependency warnings
in 169.43 seconds, including the tightened public projection validators.
Ruff and mypy for 197 source files (default and win32) pass. Live PostgreSQL
qualification for this new workflow requires the corresponding new-commit CI job.
