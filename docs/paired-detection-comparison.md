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
