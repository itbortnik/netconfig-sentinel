# Saved candidate verification and engineer decisions

Сохранённый source-bound model draft теперь имеет отдельную неизменяемую историю
проверок и решений. Это не выполнение команд на оборудовании. Исходный
`ModelPatchProposal`, analysis, риск детекторов и historical `formal_not_run`
не перезаписываются. Новый отчёт остаётся `needs_review`; решение инженера
записывается отдельно с конкретными proposal/review hashes.

## Explicit selection

`POST /api/v1/model-patches/{patch_id}/verify` требует permission `verify`
(engineer/admin) до чтения body. Body не более 16 KiB; duplicate keys, unknown
fields и нестрогие boolean flags отклоняются.

```json
{
  "verification_id": "00000000-0000-0000-0000-000000000040",
  "proposal_sha256": "<exact saved proposal hash>",
  "mode": "local_preflight",
  "network": [
    {
      "configuration_id": "<saved original configuration UUID>",
      "source_sha256": "<exact source hash selected independently>"
    }
  ],
  "scope": {"start_node": "edge", "destination": "203.0.113.1/32"}
}
```

Сеть выбирается из retained originals; canonical IR не используется для
восстановления source. Не более 32 devices/8 MiB, один снимок на device,
уникальные explicit hostnames и полный локальный разбор. Нужен exact original
исправляемого device; остальные device texts сохраняются неизменными в after.
Все выбранные снимки должны быть созданы не позже generation intent. Нет
автоматического поиска соседей, выбора latest или получения operational state.

Generation intent 0.1.0 не выбирал полную сеть: поэтому
`topology_pinned_at_generation=false`. Ограничение нельзя скрывать за временем
создания снимков. Selection здесь фиксируется именно verification intent.
Впоследствии менять network/scope/model под тем же verification UUID нельзя.

## Local, network and ML checks

Local preflight заново воспроизводит whitelisted model edits, разбирает обе
стороны, повторяет policy engine и сравнивает findings. Это не проверка
синтаксиса реальным устройством. Сохранённый before Isolation Forest, если он
выбран в исходном analysis, повторно оценивает before/after тем же encrypted
numeric artifact без обучения. Inventory labels сохраняются; before scores
должны точно совпасть с исходным analysis. Scores не калибруются и не меняют риск.

Для `mode=batfish` нужны одновременно операторский
`NETCONFIG_PATCH_ALLOW_ENGINE_UPLOAD=1` и request
`allow_local_engine_upload=true`. Используется только existing fixed loopback
engine `127.0.0.1:9996` в той же network namespace. HTTP body не выбирает endpoint,
путь или код. Все шесть исходов адаптера сохраняются: unavailable, error,
incomplete, inconclusive, differences_found, no_differences_in_scope.
Empty scope не является успехом. Scoped data-plane check не проверяет SSH,
полноту operational topology или безопасность изменения.

Для Transformer нужны операторские абсолютный `NETCONFIG_PATCH_MODEL_REGISTRY`
и independent `NETCONFIG_PATCH_MODEL_SHA256`; для foundation — также явный
`NETCONFIG_PATCH_FOUNDATION_SOURCE`. Запрос выбирает тот же
`transformer_sha256` и strict `allow_local_model_context=true`. Произвольные
model paths, checkpoints, Python scripts и foundation downloads через HTTP
не принимаются. Registry rechecks immutable card/bundle and weight identity.

Фактическое CPU inference выполняется отдельным installed `python -I` worker
с offline library flags, минимальным environment без service/encryption keys,
эпhemeral private sanitization key и deadline (default 60 s). Parent проверяет
source/model/local-review bindings и bounded output (4 MiB). При timeout worker
убивается и reap выполняется до возврата. Нет автоматического GPU fallback.
Offline flags — не OS firewall; memory/disk quotas и sandbox для скомпрометированного
локального runtime не заявляются. Temporary output ограничивается при приёме;
до deadline это не hard disk quota.

Selected unavailable ML не подменяется fake scores: local/formal report остаётся,
`ml_execution=unavailable`, список supplied ML reviews может быть пустым. Старая
report schema тогда сообщает `ml_model_not_selected` для отсутствующего supplied
результата; authoritative requested pin и execution outcome находятся в saved
verification. Approval blocker `selected_ml_not_completed` сохраняется.
Completed scores — некалиброванная диагностика, не доказательство качества.
Модель только Telnet не удовлетворяет gate для SSHv1.

## Durable attempt and read API

Migration `0008_model_patch_reviews` добавляет encrypted intent, separate outcome
и decision tables. Startup не применяет миграции. Сделайте backup с прежним
encryption key, затем используйте существующий migration command.

Intent и `model_patch.verification_requested` commit атомарно **до** external
checks. Только winner reservation запускает selected workers. Completion и
`model_patch.verification_completed` commit отдельно и атомарно. Повтор того же
ID/request возвращает 200, новый результат — 201, изменённый intent — 409.
Отсутствующий outcome остаётся `running`; failed остаётся failed. Ни чтение,
ни повтор POST не повторяют Batfish/Transformer/LLM. Новый UUID — новая явная
попытка. Local parser/policy/statistical consistency при чтении проверяются заново.
Model/engine могут быть отключены после запуска: history остаётся читаемой.
Per-process nonblocking slot не является global scheduler или quota.

Все read roles могут читать confidential history:

```text
GET /api/v1/model-patches/{patch_id}/verifications
GET /api/v1/model-patches/{patch_id}/verifications/{verification_id}
GET /api/v1/model-patches/{patch_id}/decisions
GET /api/v1/model-patches/{patch_id}/decisions/{decision_id}
```

Lists используют limit/offset. Full source/candidate не возвращаются. Reports,
scope, hashes, permitted edits, findings и model scores всё ещё confidential.
Operation journal получает только explicit hash/UUID/version projection, не
комментарии, hostname/scope, исходники, prompt или model score arrays.

## Engineer decision

`POST /api/v1/model-patches/{patch_id}/decisions` требует `feedback`
(engineer/admin). `decision_id`, `verification_id`, `proposal_sha256`,
`review_sha256`, `verdict` и непустой `comment` обязательны. Verdict:
`approved`, `rejected`, `needs_more_information`. Только terminal verification
можно связать с решением; running hash не используется. Decision+domain audit
атомарны, одинаковый intent идемпотентен, изменение — 409. Старая роль/дата
сохраняются при replay другим разрешённым service key.

Approval требует всех следующих условий:

- nonempty completed formal scope без различий и подтверждённый cleanup;
- полный parser preflight и отсутствие introduced policy findings;
- фактически completed selected Transformer, поддерживающий selected category;
- exact acknowledgement всех `report.missing_checks`;
- strict `device_syntax_checked`, `management_access_checked`, `rollback_ready=true`.

Последние три поля — утверждения service-role reviewer, не независимые измерения.
Даже approved decision не удостоверяет личность инженера, не доказывает
production quality/operational topology и не применяет patch. Все сохранённые
decision/verification/proposal projections сохраняют `applied=false`.
Rejection/needs-more-information допустимы с отсутствующими проверками; они не
переписывают предыдущие решения. Не считайте latest UUID порядком решения:
используйте saved timestamps и явно выбранный run. Этот workflow доступен в
[отдельной панели находки](model-patch-interface.md); normalized patch viewer
сохраняет прежнюю область и не смешивает эти истории.

## Verification evidence and limits

Local integration tests cover restart, pending/failed replay, four concurrent
application instances, encrypted tamper, transactional audit rollback, both
operator/request consents, all synthetic engine statuses, original actual forest
rerun without fit, and two actual isolated tiny-native CPU before/after runs.
Positive approval-gate test uses a **synthetic engine**, not a measured network
success or human decision. Tiny native fixture scores are not independent metrics.

The [installed package diagnostic](evaluation/owned-installed-saved-patch-review.json)
executed two actual isolated CPU workers using the previously pinned native
0.2.0 and foundation registry entries. The draft input was an unchanged replay
of the earlier accepted owned answer under new UUID/context, **not** a fresh LLM
measurement. Original/candidate SHA stayed exact; both ML results completed,
but both models only cover Telnet, so SSHv1 approval remained blocked. Native
score was 0.3203485310 → 0.3207848966; foundation 0.2516936660 → 0.2527509630.
These are uncalibrated diagnostics, not paired independent-test quality or a
measurement of SSH safety. All 11 installed workflow runtime files matched
source byte-for-byte. Model-disabled POST/GET replay, encrypted history, explicit
engineer rejection, unchanged proposal/analysis and temporary DB/key cleanup
passed. Parent did not import Torch/Transformers; no engine run or new LLM call
was performed, and no operator configuration was activated.

The live CI job separately runs the saved HTTP candidate against the real owned
Linux engine on a two-device authored Cisco network (reachable and empty scope),
using a **synthetic loopback draft provider**, not a fresh LLM measurement.
The [actual saved HTTP live result](evaluation/owned-saved-model-review-live.json)
for revision `da94662debf147587f7977c445c30e3b8da677f5` passed in
[CI job 113906751997](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37956062309/job/113906751997):
2 passed / 79 deselected in 9.55 s. Actual engine 2026.08.27.3685 returned
1 → 1 reachable / zero differences for nonempty scope and 0 → 0 / inconclusive
for empty scope. Cleanup completed in both, saved replay after engine permission
was removed passed, and status was not promoted. Earlier library/transport checks
also passed separately (26 tests / 29.00 s). None of these runs proves SSH access,
device syntax, complete operational topology, independent ML quality or a human's
approval. The synthetic provider is not a new model generation measurement.
