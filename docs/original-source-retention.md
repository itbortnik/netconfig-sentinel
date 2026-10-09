# Explicit encrypted original-text retention

Для source-preserving patch нужен исходный текст: canonical IR не позволяет
восстановить комментарии, неизвестные команды, пробелы и переносы строк.
`POST /api/v1/configurations` принимает optional **strict boolean**
`retain_original_source`; default — `false`. Это согласие на хранение в этой БД,
не разрешение передачи модели/движку или применения команды.

```json
{
  "device_id": "00000000-0000-0000-0000-000000000001",
  "filename": "owned.cfg",
  "content": "hostname owned\n",
  "retain_original_source": true
}
```

Без opt-in original не сохраняется. При `true` после повторного парсинга и
сравнения с создаваемым canonical snapshot сохраняется `StoredOriginalSource`
(`configuration-source-0.1.0`). Inventory role/site class/service profile —
отдельные operator labels, не source commands; они учитываются явно. Проверка
не устанавливает достоверность этих labels.

Источник привязан к configuration/device UUID, source SHA-256, snapshot timestamp,
filename и canonical content hash. Сохраняется точная UTF-8 строка, **полученная
API**, включая CR/LF и unknown constructs; не обещается копия первоначальных
байтов файла до browser UTF-8/BOM decoding или редактирования. Existing limits
2 MiB UTF-8 / 10 000 lines и HTTP body 3 MiB не увеличены.

## Storage and privacy

Migration `0006_configuration_sources` добавляет optional FK-linked
`configuration_sources`. Payload использует existing Fernet key и envelope,
связанный с kind `configuration_source` и UUID снимка. Configuration, source,
`configuration.created` и `configuration.source_retained` commit атомарно.
Сбой аудита не оставляет отдельный исходник или снимок. Readiness требует новую
схему; миграция выполняется только явно, после backup и сохранения прежнего ключа.
Старым записям source не приписывается; idempotent upgrade не меняет историю.
Destructive downgrade отсутствует.

Original может содержать **полные секреты**: он не обезличивается и не становится
безопасным для публикации. Encryption защищает at-rest payload, не процесс,
ключ, память, доверенный код или хост. Key storage, backup/rotation, filesystem
access и объём БД остаются обязанностью оператора. Content/filename исключены из
`repr`, но JSON/model serialization содержит plaintext: не используйте его в
логах или публичных отчётах. Operation journal хранит только прежнюю metadata,
не body/source text.

В React checkbox выключен по умолчанию. Согласие сбрасывается при смене
устройства/файла/имени/текста и после успешной загрузки; не сохраняется в browser
storage. Форма предупреждает о секретах и отсутствии anonymization. Existing
upload permission проверяется до body. Shared service role не удостоверяет
individual engineer identity или tenant isolation.

## Internal handoff, not a raw-download endpoint

```python
original = SourceRecords(store).get(
    selected_configuration_id,
    expected_source_sha256=independently_selected_source_sha256,
    allow_local_read=True,
)
# Confidential: original.content is only for the authorized local workflow.
```

Без exact `True`, при отсутствии source или несовпадении selected hash функция
возвращает постоянный `OriginalSourceUnavailable`. Corrupt/wrong-key/foreign-row/
oversized payload, неверные metadata/content/canonical bindings дают постоянный
`StorageIntegrityError`, без отражения частных значений. Ciphertext budget —
16 MiB, decoded record — 8 MiB, source text имеет прежний меньший budget.
Hashes и envelope не удостоверяют физическое устройство или человека.

Original payload не включён в `ConfigurationSnapshot`/summary/explanation или
HTTP response. Endpoint `/configurations/{id}/source` не создан; existing canonical
unknown-fragment visibility не расширяется. Library opt-in не заменяет service
authorization, его нельзя принимать от LLM/документа. Здесь нет model call,
Batfish upload, patch execution или повышения статуса. [Saved model proposal](saved-model-patches.md)
использует отдельное operator/request разрешение. Полный verification workflow
и engineer decision остаются отдельными работами.

## Owned installed-package check

[Actual installed-wheel report](evaluation/owned-original-source-installed.json)
фиксирует три ASGI uploads в отдельную временную encrypted SQLite: Cisco/JunOS
с explicit retention и один default upload. Оба оригинала прочитаны byte-exact
после создания нового Store с тем же ключом; wrong key отвергнут, default source
отсутствует, raw-download route даёт 404. Проверены ciphertexts и пять atomic
domain audit events, byte identity восьми runtime/migration files. БД удалена,
диагностический ключ не сохранён; это не backup/restore qualification. Model
libraries не импортировались, model/engine calls отсутствуют. Original retention
на PostgreSQL отдельно прошла [real CI](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37948390935)
на commit `82673dc`: все четыре jobs завершились success. Этот SQLite check
сам по себе его не заменяет.

Local full suite: **1687 passed, 21 skipped**, четыре dependency deprecation
warnings; 31 новых retention cases входят в набор. Старый migration fixture
переделан на фактическую `0003_finding_feedback` схему вместо ручного отката
version marker современной БД. 192 source files проходят mypy default/win32;
ruff чистый. Frontend: **276 unit tests**, **104 desktop/mobile browser tests**,
typecheck, formatting и production build проходят. Live engine/PostgreSQL skips
не считаются pass и не доказывают production security или готовность полного MVP.
