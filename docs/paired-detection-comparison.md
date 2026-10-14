# Парное сравнение детекторов

`ml.evaluation.comparison_cli` сравнивает **только бинарную anomaly detection**
на одной полной таблице reviewed truth. Он не загружает модели, не требует
PyTorch, не отправляет конфигурации наружу и не меняет risk, registry или patch
status. Это отдельный offline-инструмент, а не признание готовности моделей.

## Контракт

`ComparisonInput` содержит одну таблицу `ComparisonTruth` и 2–8 `DetectorRun`.
Нужен ровно один baseline; имена и model hashes должны различаться. Каждый
детектор обязан предоставить все те же case IDs и source hashes: неполный
результат не превращается в удобное пересечение выборок. Manifest, purpose,
target semantics и latency scope общие; threshold, tokenizer, calibration,
score kind и exposure фиксируются отдельно для каждой модели.

Truth включает opaque source/family/device/site/network keys, origin, vendor,
role, source-review и annotation hashes. Хеши не удостоверяют разрешение,
правильность labels или реальность сетей. Входной JSON и exposure являются
конфиденциальными; публиковать customer artifacts автоматически нельзя.
Отчёт содержит агрегаты и bindings, но не case IDs или entity keys.

Recorded train/selection/calibration exposures каждой модели взаимно
изолируются по всем пяти identity dimensions. `independent_test` запрещает
пересечение truth с любым из них; `validation_diagnostic` допускает selection,
но не train. `common_unseen_sites` исключает объединение площадок exposure
**всех** моделей, поэтому denominators сравнения одинаковы. Это проверка
предоставленных метаданных, не аудит неизвестного внешнего pretraining corpus.

Limits: 20 000 truth rows, 8 models, 100 000 predictions суммарно, 64 роли и
64 MiB JSON. Повторные cases/source hashes, duplicate JSON keys, unknown fields,
linked paths, nonfinite scores и bypassed invalid model copies отклоняются.
Выход — новый `.json` в существующей папке; старый файл не перезаписывается.

```powershell
python -m ml.evaluation.comparison_cli --input artifacts/shared-predictions.json --output artifacts/paired-report.json
```

Synthetic, laboratory и real-confirmed cohorts не объединяются. Отсутствующие
cohorts/vendors остаются `missing`/`null`. По каждой модели и срезу записаны
отдельные роли; ключ `<unrecorded>` обозначает отсутствие role и не совпадает
с допустимым role label `unrecorded`. Metrics включают
TP/FP/FN/TN, P/R/F1, AP, trapezoidal PR-AUC, configuration FP / unique device
и измеренные latency counts/mean/median/p95/max. Формулы и строгий порог
`score > threshold` описаны в [общем evaluator](offline-evaluation.md).
Ranking scores не получают probability calibration metrics. Undefined
denominators и отсутствующие измерения не заменяются нулём или perfect score.

Candidate deltas — candidate minus baseline на этом же срезе. Latency delta
есть только при одинаковых множествах measured cases: две средние по разным
примерам не являются парным результатом. FP/device считает configuration
alerts, не deduplicated incidents. Нет автоматического winner, confidence
intervals, проверки статистической значимости или quality acceptance. Категории,
localization и unknown heads baseline не выдумываются: для них нужны настоящие
соответствующие predictions и отдельный evaluation protocol.

## Фактический owned-fixture прогон

`ml.evaluation.comparison_smoke` загружает явно указанные доверенные native и
external config-head checkpoints с независимыми полными pins; для внешнего
checkpoint отдельно требуется pinned publisher source. Произвольные конфигурации
он не принимает: использует только authored `pretraining_fixtures()` и ту же
Telnet supervision, что обученные heads. Reserved test не открывается.

```powershell
python -m ml.evaluation.comparison_smoke --native-model artifacts/native-model --native-sha256 <full-pin> --foundation-model artifacts/external-heads --foundation-sha256 <full-pin> --foundation-source artifacts/pinned-publisher-source --output artifacts/owned-paired-run
```

Два настоящих Isolation Forest обучаются на original train parents, по одному
на vendor: 8 примеров, 200 estimators, seed 42, contamination 0.1. Группировка
явно лабораторная: authored role `edge-router`, site class `owned-comparison`,
service profile `authored-static-bgp`; это не обнаруженный real inventory.
Эти labels не добавляются в numerical structured features. Forest сохраняется
в bounded numeric JSON, без pickle. Его fixed ranking transform
`0.5 - decision_function / 2` с cutoff 0.5 проверяется против настоящего
`predict == -1`; это не вероятность. Если mapping расходится, прогон отклоняется.
Model binding включает оба леса, manifest и scope training parents.

Native/external validation adapters заново проверяют manifest, annotation и
train/selection fingerprints. Полная truth table обоих outputs должна совпасть.
12 validation views относятся к четырём устройствам двух hypothetical сетей,
не к 12 независимым сетям: 4 injected positives, 8 unmodified/format views.
Немутированный parent не является подтверждённо здоровой конфигурацией.

Фактический [отчёт от 2026-10-07](evaluation/paired-owned-validation.json):

| Модель | F1 @ fixed threshold | Average precision | Trapezoidal PR-AUC |
| --- | ---: | ---: | ---: |
| Isolation Forest | 0 | 0.333333 | 0.666667 |
| Native encoder | 0 | 0.517857 | 0.413095 |
| External frozen encoder | 0 | 0.833333 | 0.791667 |

Все три пропустили четыре positives и не дали false positives. Нулевой FP
при нулевом recall не является хорошим детектором. AP и trapezoidal PR-AUC
не взаимозаменяемы; постоянные/tied scores леса особенно ограничивают смысл
PR-AUC. Разница ranking metrics на этих selection views не доказывает
superiority или пригодность в эксплуатации.

Bindings моделей: native
`289a330ab0de705396df807af86dfdf6ab9c2d14c900b14f900e9097371474b4`, external
`b0122b7099915b52f46ce4b395f09b2c19389f81c601be4d6ba442d03caf1b76`.
Фиксированный общий truth hash:
`b3ed6d232924e6b93abc4ab58c988de359be344e5f4a0875058e8350afa051d8`.
Input hash включает measured timings и при повторном запуске может меняться.

Measured intervals включают parsing и scoring, но исключают первоначальную
загрузку checkpoints, fitting и artifact I/O. External adapter также проверяет
source/weight integrity; это не isolated neural forward latency или HTTP
end-to-end throughput. Hardware, CPU thread policy и порядок запусков отличаются;
числа в JSON — диагностика конкретного запуска, не ресурсный benchmark.
Common unseen-site slice отсутствует, поскольку neural heads выбирались по
этой validation. Real/laboratory/independent quality, calibration fit, внешняя
pretraining isolation и significance не подтверждены. Следующий meaningful
benchmark требует разрешённых representative данных и независимых labels.

## Fixture-backed native 0.3 и тот же контрольный лес

Для `multitask-training-0.3.0` тот же smoke имеет отдельный явный маршрут:

```powershell
python -m ml.evaluation.comparison_smoke --native-model artifacts/fixture-heads --native-sha256 <full-pin> --fixture-admission private/retained-admission.json --output artifacts/new-owned-fixture-comparison
```

`--fixture-admission` использует [bounded private retained-input format](transformer-model-registry.md)
и общий source/annotation/exposure validator, а не ослабленный альтернативный
evaluator. В отличие от общего registry input этот smoke по-прежнему принимает
только точный authored Telnet downstream сценарий: `authored_transfer_splits()`
и соответствующие reviewed examples. Он не превращается в importer произвольных
customer configurations. Отсутствующий/изменённый corpus, source permission,
manifest, annotation или independent model pin приводит к отказу до output.

В этом режиме сравниваются **два** детектора. Старый external checkpoint связан
с другим downstream manifest и сюда не переносится. Любой `--foundation-*`
параметр вместе с fixture admission отвергается; прежний трёхмодельный маршрут
по-прежнему требует все три external параметра. Native fixture route не импортирует
Transformers/safetensors и не требует retrieval extra; реальная загрузка native
weights требует training runtime. Downloads, native retraining, threshold fitting,
model activation и risk updates не выполняются.

Оба леса обучаются прежним алгоритмом только на 16 original train parents
(по восемь на vendor), не на 48 supervised views, selection или reserved test.
Контрольные seed 42/200 trees/contamination 0.1 и strict cutoff 0.5 не менялись.
Native adapter повторно проверяет 415 доступных upstream members против 64
downstream contents, включая test text **только** для overlap gate. Это 26560
проверок доступных текстов, не доказанная физическая/временная изоляция.
Source fixture identifiers не подставляются в downstream device/site/network
identity. Полный recorded Stage A binding отдельно сохраняется в приватном
`fixture-source.json`; `input.json` и `forest.json` также остаются приватными.
Публичный `report.json` — только численные агрегаты и hashes, не входные тексты.

Фактический [отчёт от 2026-10-11](evaluation/paired-owned-fixture-validation.json)
сохраняет все 12 selection views четырёх owned devices: четыре injected positives
и восемь reference/format cases. Это прежние данные, не новая независимая выборка.

| Модель | F1 @ 0.5 | Average precision | Trapezoidal PR-AUC |
| --- | ---: | ---: | ---: |
| Isolation Forest | 0 | 0.333333 | 0.666667 |
| Fixture-backed native encoder | 0 | 0.816667 | 0.795833 |

Обе модели пропустили четыре positives; false positives — 0. В Cisco-срезе
четыре отрицательных примера и ни одного positive: recall/F1/AP/PR-AUC `null`,
не нулевые ошибки или успешная Cisco anomaly qualification. JunOS-срез имеет
восемь views, включая все четыре positives. Real/laboratory cohorts и common
unseen-site slice отсутствуют. Raw probability ECE/Brier — статистика selection,
не результат calibration fit; forest ranking не получает probability metrics.

Этот functional comparison не меняет прежние measured transfer predictions,
line/category metrics или исторический [отчёт 2026-10-07](evaluation/paired-owned-validation.json).
Разница AP/PR-AUC не доказывает превосходство, статистическую значимость или
приемлемую детекцию. Measured parsing+inference intervals исключают loading,
fitting и I/O; разные модели и thread policies не образуют hardware/HTTP benchmark.
Representative real-confirmed labels, independent test, calibration и полный
MVP quality gate остаются открытыми.
Проверки installed parity и границы измерения записаны отдельно в
[aggregate evidence](evaluation/owned-source-fixture-comparison.json).

## Explicit bilateral fixture comparison

The owned fixture route accepts the explicit `--owned-scenario
bilateral-telnet-0.1.0` used by the [transfer demonstration](pretraining-transfer.md#explicit-bilateral-telnet-scenario):

```powershell
python -m ml.evaluation.comparison_smoke --native-model artifacts/new-bilateral-transfer/model --native-sha256 <full-pin> --fixture-admission private/bilateral-admission.json --owned-scenario bilateral-telnet-0.1.0 --output artifacts/new-bilateral-comparison
```

The default legacy route is unchanged. Selected scenario, complete private
admission and actual model bindings must agree; swapping old/new splits,
annotations or models refuses before output. Bilateral cannot be combined with
the historical external encoder route. Both fixture routes remain native-only
and do not import Transformers/safetensors.

[Measured new-scenario evidence](evaluation/owned-bilateral-fixture-transfer.json)
retains all sixteen selection views of four authored devices. Both vendors have
four positives and four negatives. The two forests are fitted only on sixteen
original train parents (eight per vendor), whereas the supervised model fits
64 derived train views. Seed 42, 200 trees, contamination 0.1, the fixed ranking
mapping and strict 0.5 cutoff remain unchanged. Both detectors receive exactly
the same complete truth table, not a successful intersection or convenient
vendor subset.

| Detector | F1 @ 0.5 | AP | True positives / positives | False positives |
| --- | ---: | ---: | ---: | ---: |
| Isolation Forest | 0 | 0.5 | 0 / 8 | 0 |
| Fixture-backed native encoder | 0.857143 | 1 | 6 / 8 | 0 |

Native vendor F1 is 1 for Cisco and 0.666667 for JunOS; each has only two devices
and eight dependent views. These are selection diagnostics, not demonstrated
cross-vendor generalization, statistical superiority or acceptable deployment
quality. Line localization still misses all eight positive lines. Real-confirmed,
laboratory and common unseen-site comparison cohorts are absent. Timing excludes
loading, fitting and I/O and is not an HTTP/hardware benchmark. The legacy
twelve-case report is preserved; because its parents/truth differ, its metrics
are not a paired baseline for this new scenario.

## Explicit train-balanced fixture format 0.4

The same owned route also accepts `multitask-training-0.4.0` with complete
`--fixture-admission` and the exact selected authored scenario. Commands and
fixed forest defaults are unchanged. Admission reconstructs eligible encoded
TRAIN targets and the fitted negative/positive coefficient before forest fitting
or output allocation; a self-consistent forged ratio is not sufficient.
Each detector still receives the entire same anomaly truth table at strict 0.5.

Only this new format adds private `fixture-training.json`, containing the exact
verified native report, localization objective and task weight. Historical
0.3 output layouts and reports are not rewritten. This is still anomaly-only
comparison, not a baseline with invented localization/category heads. Weighted
line scores are cost-sensitive and uncalibrated; they are not calibrated
posterior probabilities. No native training, threshold/calibration fitting,
downloads, activation or risk updates follow from comparison.

Every successful invocation actually fits two control forests on the same
sixteen original TRAIN parents, one per vendor. Repeated fits or selection views
are not new data. Binding/admission reconstruction, checkpoint loading, fitting
and artifact I/O are outside the recorded parsing+inference intervals. Neither
latency nor a comparison against forest establishes hardware/HTTP performance,
independent quality or superiority over another native checkpoint.

[Installed diagnostic from 2026-10-14](evaluation/paired-owned-balanced-validation.json)
uses the existing seed17 balanced `w3=1` pin
`42cb90bdb8247eddc061993699287eb95645bb6051c50b4cfa532c108f90f206`,
not a newly fitted or selected native model. All sixteen reused selection views
are retained: eight positives/eight negatives, four authored devices, eight views
per vendor. At fixed 0.5 the native model finds two of eight positives (F1 0.4)
and forest finds none (F1 0); both have zero false positives. Native AP is
0.970486 and trapezoidal PR-AUC 0.968502, not proof of adequate detection.
Cisco recall is 0.5 and JunOS recall is 0; two devices per vendor do not qualify
cross-vendor generalization. Raw selection ECE/Brier are not a calibration fit.
Real-confirmed, laboratory and common unseen-site cohorts remain missing.

[Aggregate bindings](evaluation/owned-balanced-comparison.json) record three
installed invocations, six actual control fits and zero native fits. Separate
old/new0.3 runs preserve the legacy twelve-case predictions, forests, source
binding and layout; the new0.4 predictions equal their retained training-run
diagnostic. The full objective remains in private `fixture-training.json`.
OLD232/NEW232 runtime, 306 historical hashes and 87 package versions are bound;
each child imports 100 app/ml modules from its selected installed target and
no checkout or external neural runtime. This compatibility check is not a
paired0.3-vs0.4 quality improvement. No old report, model, threshold or history
is recomputed in place. Broader representative labels and independent partitions
are still required; these same toy examples cannot close those gates.
