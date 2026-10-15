# Saved closed-fact model patches

Этот opt-in slice §§17/23.7 связывает [closed-fact generation](grounded-model-patches.md)
с сохранённой находкой, encrypted history и интерфейсом. Старые free-prose
records не преобразуются в достоверные объяснения. Режим не оценивает независимое
качество модели и не заменяет vendor syntax, сеть, ML или решение инженера.

## Явный выбор режима

Помимо existing literal-loopback endpoint/model и
`NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT=1`, оператор отдельно разрешает
`NETCONFIG_LLM_ALLOW_GROUNDED_PATCH_DRAFT=1`. Blank/`0` — disabled.
Старый `NETCONFIG_LLM_ALLOW_PATCH_DRAFT=1` разрешает только legacy writer;
ни один flag не включает другой. Compose по-прежнему не передаёт настройки LLM.
Оба режима делят existing nonblocking slot и bounded isolated HTTP worker;
default deadline 10 секунд не изменён.

Для нового POST необходимы retained exact original, обе permissions `draft`
и `model_explanation`, а также strict `allow_local_model_context=true`.
Тело запроса — прежний `GenerateModelPatch`, не более 16 KiB. Выбранные finding,
source, optional baseline и sealed knowledge проверяются до provider.
Поддержанный slice прежний: явные Cisco/JunOS Telnet/SSHv1 policy findings при
полном разборе. Неизвестные команды не становятся evidence безопасности.

| Маршрут | Контракт |
| --- | --- |
| `POST /api/v1/model-patches` | Только прежняя free-prose generation |
| `POST /api/v2/model-patches` | Только новый closed-fact prompt/answer |
| `GET /api/v1/model-patches[/{id}]` | Только legacy history; grounded ID даёт 404 |
| `GET /api/v2/model-patches[/{id}]` | Обе известные версии с явным outer discriminator |
| `GET /api/v2/model-patches/capabilities` | `saved-model-patch-capabilities-0.2.0`: legacy capabilities и независимый `grounded_generation` |

List требует `analysis_id`, использует limit/offset и стабильный порядок.
Legacy protocol filter применяется **до** pagination. Unknown/missing versions
отказаны, не интерпретируются через fallback. Capabilities — configured/disabled,
не readiness, фактический inference или качество; GET не загружает веса.

## История и replay

Migration `0010_model_patch_protocols` добавляет protocol column с legacy default
и индекс, не переписывая encrypted payloads, старые JSON или их fingerprints.
Startup не выполняет migration. Перед явным upgrade необходимы backup и прежний
encryption key. Автоматический destructive downgrade не поддержан.

Новые intent/outcome имеют отдельные required versions
`grounded-model-patch-intent-0.1.0` / `grounded-model-patch-outcome-0.1.0`.
Row protocol, pair family, selected source/analysis/finding и completion binding
проверяются совместно. Общий UUID остаётся уникальным между режимами: одинаковый
ID с другой protocol family даёт 409 **до** модели. Не требуется новый UUID при
потере ответа: сначала прочитайте прежнюю попытку.

Intent и domain audit записываются атомарно до единственной разрешённой попытки.
Outcome и completion audit — отдельная атомарная транзакция. Статусы прежние:
`generating`, `draft`, `declined`, `failed`. При потере completion сохраняется
`generating`, без скрытого retry. Invalid answer даёт terminal failed без raw
rejected output. Null модели не заменяется deterministic патчем.

Outer response `grounded-source-bound-patch-proposal-0.1.0` сохраняет:

- `presentation_kind=server_derived` и отдельную общую `projection`;
- `context_sha256` **actual нового prompt**, instruction/schema hashes;
- `edit_context_sha256` прежнего edit-review component, не замену actual prompt;
- typed model choices отдельно от server-rendered answer;
- exact fact ledger/digest, renderer version/policy и projection SHA.

Proposal fingerprint связывает actual новые records, не преобразованную legacy
пару. Общая projection нужна прежним review contracts; она не выдаётся старым
generation GET как будто это legacy history. Чтение/restart строго восстанавливает
точные inputs, ledger, raw typed choices, deterministic presentation и candidate.
Другая schema, policy, source или rehashed подмена дают 503, не новое толкование
истории. Чтение не вызывает provider и работает при выключенной модели.

Operation journal включает только allowlisted IDs/hashes/versions; actual
generation context и edit-review context не смешиваются. Ledger values, model
choices, prose, команды и source не попадают в operation metadata. Domain
payloads encrypted at rest; key-holder не становится подтверждённой identity.

## Интерфейс и дальнейшие проверки

Режим выбирается явно, без default generation. Смена protocol, finding или
baseline требует нового согласия. Mixed history хранит outer version; потерянный
POST восстанавливается GET того же family/UUID, без fallback writer. Сохранённый
`generating` может перейти в terminal только при неизменных input/policy bindings.
Browser дополнительно проверяет fact/projection SHA, не объявляя их подписью.

Новый текст явно помечен **BEFORE / этап генерации, server-derived**, а не raw
model prose или результат AFTER. Approval baseline — not_proven, formal/ML —
not_run, syntax/access/rollback — not_checked в этом supplied сценарии.
Это не утверждение, что оператор никогда не проверял их где-либо ещё.
Legacy prose остаётся недоверенной и не получает новую маркировку достоверности.

Candidate review и decisions используют existing
`/api/v1/model-patches/{id}/verify`, `/verifications` и `/decisions` для обеих
семейств через явный version-aware reader. Exact edit-context, candidate, network,
scope и formal/ML/category/attestation gates не ослаблены. Локальный preflight
нельзя утвердить одним согласием или ролью. Решение append-only; BEFORE projection,
анализ и detector scores не переписываются, `applied=false` остаётся false.

## Границы evidence

Текущая source regression: 3068 passed / 15 explicit live/database skips /
5 warnings, 91% line coverage. Ruff и mypy 239 файлов (default/Linux/win32) прошли.
Собранный пакет: 394 passed / 2 live skips / 6 deselected на каждом Pydantic
2.13.5/2.14.0; 239 runtime files и три bundled assets совпали с исходной сборкой.
306 исторических bindings и прежние 234 installed runtime files сохранены.
Это не миграция рабочей БД. Frontend: 556 unit passed, typecheck/format/build pass,
существующее предупреждение о bundle >500 KiB; 36 synthetic model-profile
browser checks прошли без retries.
Независимое ревью нашло и перепроверило исправление audit metadata preview;
review не заменяет фактический model/engine benchmark.

Integration/browser fixtures используют **синтетический** loopback provider.
Они проверяют contracts, permissions, persistence/restart, отсутствие повторных
вызовов, audit rollback, tamper refusal и UI; не являются actual LLM benchmark.
Два первоначальных общих browser прогона дали 157 passed / 1 failed каждый: первый —
desktop explanation overflow, второй — mobile login `ERR_NO_BUFFER_SPACE`
без HTTP response. Это сохранённые failures, не полностью зелёный local gate.
Прежний overflow не повторился в отдельной диагностике и втором полном прогоне;
причина первого не установлена. Повтор не скрывает исходный результат.

### Actual installed API / model run

[Числовой отчёт](evaluation/owned-grounded-saved-http.json) содержит все четыре
заранее выбранных authored inputs с explicit unapproved baseline. Через installed
API, bounded loopback worker и pinned Qwen3-4B фактически начались четыре backend
generations. Первый Cisco Telnet call превысил explicit 20-second deadline:
generation20.021s, HTTP20.087s, POST503, сохранённый terminal `failed` без raw
rejected answer. Equality успешного POST/GET здесь неприменима, не true.

Остальные три вызова — accepted `declined` с `patch_draft=null`; HTTP8.611/8.982/
8.505s. **Ноль actual candidates**: positive draft/review/decision branch нового
режима проверен synthetic fixtures, не этим run. Ни failure, ни null не заменены
патчами; retry/warm-up отсутствовали, default10s не квалифицирован и не изменён.

Четыре consent denials, replay и повторное чтение с выключенной моделью имели
неизменные durable gateway/provider/backend counters. Новый app instance работал
в прежнем Python process — это не fresh-process restart. Saved analyses неизменны.
Drain завершён, incomplete counts0, forced kill отсутствует. Per-attempt start/
completion сохранены приватно; diagnostic key ephemeral, не backup. Parent137 и
gateway60 runtime imports из installed target, checkout0; три bundled assets
отданы побайтно. Gateway блокировал outgoing socket connections, не OS sandbox.
Модель оператора не активирована; browser использовал только synthetic provider.
Engine/ML, device syntax/access/rollback и individual identity здесь не проверялись.

Прежние [четыре actual library generations](evaluation/owned-grounded-model-patches.json)
дали четыре null. Это отдельный исторический run, не измерение нового API/UI,
не подтверждение positive candidate branch и не независимая оценка качества.
Representative real-confirmed данные, vendor/internal corpus, independent
semantic/citation quality, production identity/device/access/rollback остаются
открытыми; отсутствие разрешённого реального набора подтверждено пользователем.
