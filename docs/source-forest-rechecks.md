# Повтор исходной модели Isolation Forest для ordinary draft

Отдельный workflow пересчитывает точные retained before/after исходники обычного
[object draft](persistent-patches.md) **той же сохранённой Isolation Forest**,
которая участвовала в явно выбранном before analysis. Автоматического выбора
последней модели или анализа нет. Это числовой эксперимент, не доказательство
исправления, качества детектора или безопасности конфигурации.

## Выбор и запуск

Нужны сохранённые originals обеих сторон, полный поддержанный разбор, совпадение
device/vendor/platform и исходная экспериментальная модель с numeric artifact.
Inventory labels сторон должны самостоятельно соответствовать peer group модели;
метки не подменяются значениями training group. Target hostname/device/source
должны быть исключены из обучения; training snapshots не позднее target snapshots,
а запись модели не позднее выбранного before analysis.
Отсутствующая или изменённая модель не заменяется новой и не переобучается.

| Операция | Путь |
| --- | --- |
| Явно выбрать исходный анализ | `GET /api/v2/patches/<patch UUID>/statistical-selection/<analysis UUID>` |
| Новая попытка | `POST /api/v2/patches/<patch UUID>/statistical-rechecks` |
| История | `GET /api/v2/patches/<patch UUID>/statistical-rechecks?limit=20&offset=0` |
| Полная запись | `GET /api/v2/patches/<patch UUID>/statistical-rechecks/<recheck UUID>` |

Selection читает metadata исходного анализа, возвращает его UUID/SHA и полный
ModelSummary с artifact SHA и original before tuple. Selection не подтверждает
наличие originals или числового artifact. Неподходящий анализ даёт409, отсутствующий
draft/analysis404. Read-роли могут выбирать анализ и читать историю.
POST, включая replay, требует engineer/admin (`configuration_model`).

Строгое тело `source-forest-request-0.1.0`:

```json
{
  "recheck_id": "00000000-0000-0000-0000-000000000008",
  "draft_sha256": "<saved draft fingerprint>",
  "before_analysis_id": "00000000-0000-0000-0000-000000000009",
  "before_analysis_sha256": "<explicit selection analysis fingerprint>",
  "model_id": "00000000-0000-0000-0000-000000000010",
  "artifact_sha256": "<original numeric artifact SHA-256>",
  "allow_local_model_context": true
}
```

Согласие default false, отдельно от retention и network upload; строка/число не
превращаются в bool. HTTP не принимает source text, paths, weights или endpoints.
Неверное тело даёт400, отсутствие consent403, stale pins/ineligible source409,
превышение бюджета413. Проверки роли выполняются до чтения тела запроса.
Disabled neural runtime не мешает этому numeric workflow.

Сервер проверяет обе retained sources и заново разбирает originals. Один загруженный
numeric artifact оценивает обе стороны без fit. Повторный before tuple должен
точно совпасть с исходными `score_samples`, `decision_function`, `prediction`.
Обе стороны сохраняют свои числа, общий `decision_offset` и исходный ModelSummary.
Соблюдаются диапазоны score/decision, `decision_function = score_samples - offset`
и знак prediction. Эти числа не являются probability, severity или calibrated risk.

## Сохранение и восстановление

Миграция0013 добавляет `patch_statistical_recheck_intents` и
`patch_statistical_recheck_outcomes`, не изменяя прежние domain rows. Сначала
сохраните backup и прежний encryption key, затем выполните явный schema upgrade
по [инструкции persistent API](persistent-api.md). Startup не мигрирует БД.

Encrypted envelope связан с type/UUID. Intent и `patch.statistical_recheck_requested`,
затем outcome и `patch.statistical_recheck_completed` записываются отдельными
атомарными транзакциями. Только победитель reservation считает числа; один UUID
не создаёт вторую оценку. Operation journal хранит allowlisted IDs/hashes/status,
включая before analysis и review binding, без scores, hostname, дерева или raw source.

Успешный новый POST возвращает201 с `execution_status=completed`; идентичный
replay200 возвращает прежний результат, в том числе после удаления модели.
Иной intent с тем же UUID409. Сбой numeric scoring или несовпадение original tuple
даёт сохранённый `failed`, report=null и общий код
`original_baseline_or_numeric_result_unavailable`. Частичных чисел нет.
Intent без outcome означает `pending_unknown`, не доказательство живого процесса.
Автоматического resume или retry evaluation нет. GET/list/replay проверяют parent
и proof bindings, но не читают originals, не загружают модель и не запускают policies.

Body ограничен16 KiB; обе входные стороны вместе с canonical snapshots ≤32 MiB.
Numeric report ≤1 MiB, compact intent/outcome/proof ≤4 MiB, outer JSON ≤16 MiB.
Перед reservation intent оставляет1 MiB+8192 байта для completion. Ответ
`source-forest-recheck-0.1.0` содержит exact Python compact sorted JSON proof и
SHA-256; browser проверяет typed equality, outer proof и raw nested intent hash,
сохраняя Python float representation. Hash binding не удостоверяет truth или identity.

В панели draft откройте «Открыть пересчёт Forest»: введите UUID анализа before,
загрузите selection, проверьте model/artifact и дайте согласие. Смена draft,
анализа или refresh selection сбрасывает согласие. Read-роли видят историю.
После потери POST доступен same-ID GET, новое намерение заморожено. Явный отказ
вместе с GET404 разрешает отдельный reset/new UUID и новое согласие; lost response
плюс404 не разрешает повтор. Reload теряет browser intent memory: сначала изучите
сохранённую историю. Browser timeout не отменяет попытку сервера.

## Фактическое подтверждение и открытые требования

[Functional HTTP report](evaluation/owned-source-forest-functional.json) содержит
две реальные completed пары Cisco/JunOS на ранее сохранённых authored numeric
моделях. До этого setup отдельно обучил две модели на16 authored configurations;
в зафиксированном повторном HTTP-прогоне fit запрещён и новых обучений0.
Проверены исходный before tuple, GET/list/replay, replay после удаления модели на
диагностической копии и additive upgrade0012→0013 с сохранением прежних строк.
520 зафиксированных historical files остались неизменными. Browser tests отдельно
обучают маленькие authored модели через настоящий API; controlled failure покрывает
протокол сбоя. Эти конфигурации не являются независимым реальным корпусом.

Результат всегда `needs_review`, formal `not_run`, quality_proven/calibrated/
risk_fused/approved/applied false. Падение anomaly score не даёт remediation pass.
Повтор всех исходных policy/reference/peer/ML detectors, их общее объединение,
change-specific ML qualification, representative real data, independent quality,
vendor syntax, management access и individual engineer gates остаются открытыми.
Запись не изменяет draft, прежние network/ML reviews, risk или decisions.
Network0.1 по-прежнему хранит собственный ML `not_run`. Отдельная
[нейросетевая парная диагностика](source-ml-rechecks.md) сохраняет свой контракт.
