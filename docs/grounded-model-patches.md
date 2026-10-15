# Закрытые факты и модельный source-bound patch

Этот отдельный opt-in library/offline режим продвигает ограничение §17: модель
не может выдавать свободную фактическую прозу с вымышленным approval или verifier
pass. Он не меняет прежние explanation/draft/review HTTP contracts и сохранённую
историю. Свободные legacy answers по-прежнему требуют отдельной проверки содержания.

## Что действительно выбирает модель

`GroundedPatchAnswer` версии `grounded-model-patch-answer-0.1.0` содержит только:

- SHA точного supplied fact ledger;
- уникальные references на закрытые BEFORE observations/unknown/not-run facts;
- закрытые impact/recommendation/missing-check codes и существующие citations;
- настоящие source-line edits модели либо `patch_draft=null`;
- обязательное `requires_human_review=true`.

Свободные summary/explanation/assumptions/hypotheses отсутствуют. Unknown,
duplicate, positive approval/pass/safety/apply codes, лишние поля и duplicate JSON
keys отклоняются. Неисправный ответ не ремонтируется и не вызывает повтор модели.
Отказ сохраняется: сервер не подставляет deterministic remediation вместо null.

`build_grounded_patch_prompt` сначала использует прежний exact-source builder:
только полностью разобранный поддержанный Cisco/JunOS Telnet/explicit SSHv1 slice,
связанные finding/source/baseline и sealed internal project documents. Parser
support не является vendor syntax validation; project documents не являются
vendor manuals или одобренной политикой организации. Прежний edit allowlist и
exact candidate replay повторно проверяются после closed-answer validation.

## Серверная проекция — не raw model prose

Модельные references не изменяют факты и не позволяют скрыть обязательные
ограничения. Версионированный renderer добавляет BEFORE/generation-phase блок:
baseline supplied/not_supplied, approval evidence not_proven, formal/ML not_run,
vendor syntax/access/rollback not_checked. Отсутствие supplied approval evidence
не означает отказ; сведения этого сценария не утверждают, что оператор никогда
не выполнял проверок в другом месте. Local management observations не доказывают
effective defaults или состояние работающего устройства.

AFTER candidate и local parser/policy review доступны отдельно через
`GeneratedGroundedPatch.generated`. BEFORE prose не переносится на результат
проверки AFTER. Даже accepted candidate остаётся `needs_review`; formal status,
severity/confidence/score и human approval не повышаются. Единственный impact code
рендерится как условная гипотеза, а recommendation требует review, не application.

`GeneratedGroundedPatch.model_answer` — typed model output;
`generated.answer` — явно **server-derived presentation**, а не оригинальный ответ
модели и не semantic/citation quality score. Такой закрытый словарь ограничивает
доступные утверждения по конструкции, но не оценивает общую достоверность LLM,
релевантность RAG, semantic support произвольных цитат или качество рекомендации.

## Явный runtime и receipt/replay

`LocalInstructProvider(..., allow_grounded_patch_draft=True)` имеет отдельный exact
boolean opt-in, проверяемый до inventory/weight loading. Значение по умолчанию —
false; прежний `allow_patch_draft=True` не разрешает новый prompt/schema. Новый
flag сам по себе не разрешает старый draft или candidate-review contract. Веса,
greedy framing, consent, budgets и фиксированный allowlist runtime не заменены.

Пример library workflow для собственных разрешённых входов:

```python
prepared = build_grounded_patch_prompt(
    before, finding=finding, source_sha256=source_sha256,
    reference_id=reference_id, baseline=baseline, allow_local_context=True,
)
result = generate_grounded_patch_draft(provider, prepared, allow_local_context=True)
receipt = create_grounded_patch_receipt(
    result, prepared=prepared, identity=provider.identity,
    observation=provider.last_generation, expected_inventory_sha256=inventory_pin,
)
save_grounded_patch_receipt(
    receipt, new_private_path, key=operator_key, prepared=prepared,
    expected_inventory_sha256=inventory_pin,
)
replayed = load_grounded_patch_receipt(
    new_private_path, key=operator_key, prepared=prepared,
    expected_inventory_sha256=inventory_pin,
)
assert replayed == receipt
```

Caller импортирует builder/generator из `app.explanation.grounded_patch`, receipt
функции — из `app.explanation.grounded_receipts`; точные before/baseline/finding/
chunks и private key сохраняет отдельно. Функции standalone, не UI activation.

Receipt `private-model-patch-receipt-0.2.0` / `NCS-MODEL-PATCH-2` отдельно связывает
typed raw-model object (без transport whitespace), fact ledger, **новый** actual
prompt/instructions/schema, renderer version/policy SHA, server projection SHA и
exact candidate/review. Observation прежнего component prompt неприемлема. При
replay ledger строго revalidates до equality/hash comparison: `True == 1` не
разрешает unvalidated `model_copy` обход. Некорректные значения не печатаются через
serializer warnings перед обобщённым отказом.

Старые schema/instructions/receipt0.1 сохранены побайтно. Старый и новый loaders
взаимно отвергают другую magic/version; downgrade, unknown versions и plaintext
fallback отсутствуют. Load не вызывает provider/GPU/network. Fernet, budgets,
exclusive creation, path restrictions и operator key responsibilities те же,
что в [private receipts](model-patch-receipts.md). Key-holder authentication не
удостоверяет model/GPU identity, consent, инженерную identity или истинность;
соответствующие truth/activation/application flags остаются false.

HTTP/UI внедрение этого contract требует отдельной persisted policy/version и
version-aware replay. Текущие saved intents не переинтерпретируются автоматически.
Independent/adversarial model quality, реальная разметка, vendor/internal corpus,
device/access/rollback и полный approved engineer workflow остаются открытыми.

## Фактически выполненная диагностика

[Installed owned report](evaluation/owned-grounded-model-patches.json) сохраняет
все четыре actual Qwen3-4B обращения на прежних authored Cisco/JunOS Telnet/SSHv1
случаях. 4/4 completed и accepted новым schema/source validator; **4/4 null,
0 actual candidates**. Все четыре encrypted receipt/replay round trips прошли
без новых generation calls. Positive candidate branch проверен synthetic unit
cases, не этим inference run. Retry/warm-up/repair/fallback отсутствовали.

Weights/revision/inventory прежние; new training, reserved test, HTTP/UI, engine
или downstream ML не запускались. 234 runtime files побайтно совпали с installed
wheel; OLD232 и306 history hashes сохранены. Legacy prompt/schema/context parity
проверена отдельно;65 actual-run и70 installed-test imports — из target, zero
checkout imports. Исходящие socket connections были блокированы в helper, не
OS sandbox. Ключ ephemeral: immediate replay — не долгосрочный backup.

Installed regression:200 pass на каждом Pydantic2.13.5 и2.14.0. Source full suite:
2991 pass/15 explicit live/database skips/5 warnings,91% line coverage; Ruff и
234-file mypy default/Linux/win32 pass. Независимое read-only ревью выявило и
перепроверило две исправленные integrity/privacy ошибки; его94 focused pass и
adversarial codec checks не являются независимым model benchmark. Старые
unsupported free-prose claims не удалены из истории и не объявлены исправленными.
