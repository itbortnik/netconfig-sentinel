# Приватный реестр конфигурационных моделей

`ml.registry` хранит immutable экспериментальные native и external config-head
checkpoints для явного offline-выбора. Это отдельный filesystem registry, не
расширение [HTTP-реестра Isolation Forest](model-registry.md), не модельный
сервер и не deployment approval. Никакая запись не активируется автоматически.

## Запись и проверка

Root создаётся новым в существующей приватной папке. В нём находятся
`registry.json` и директории с именем полного model SHA-256. Каждая запись
содержит `entry.json` и фиксированный `bundle`. Native bundle сохраняет
encoder/tokenizer/report/tensor checkpoint и heads; external bundle — только
heads/report, без копирования внешних publisher weights. Их доверенный source
root оператор задаёт отдельно при каждом выборе внешней модели.

При регистрации обязательный independent pin сравнивается с действительной
моделью; bundle сериализуется, заново загружается и проверяется до завершения
записи. `.incomplete` снимается только после успешной повторной проверки.
Существующий root или model entry не перезаписывается. Ошибка может оставить
недописанную запись для ручного разбора; она не считается пригодной для выбора
и не удаляется автоматически. Не помещайте посторонние файлы в root.

Model card содержит model/report/encoder/tokenizer hashes, training format,
доступный original source manifest, train/selection fingerprints, категории,
enabled heads и actual parameter/example counts. Legacy native 0.1 не имеет
objective manifest: поле остаётся `null`. Native 0.2 сохраняет original objective
manifest. Для внешнего encoder pretraining exposure остаётся `unknown`.
Card не содержит путь publisher source, raw configuration или grouping IDs.
Hashes/fingerprints всё равно linkable: это приватные metadata, не анонимизация.

Для fixture-backed native `multitask-training-0.3.0` используется отдельная
`config-model-card-0.2.0`, а не изменение исторической карточки 0.1. Она сохраняет
точный Stage A source/report/corpus binding и полный recorded exposure audit.
`physical_pretraining_isolation_proven=false`: отсутствие наблюдаемых пересечений
не устанавливает identity сетей, chronology или независимое качество. Внешние
publisher weights здесь не используются; `not_applicable` не означает, что
fixture pretraining изолирован от реальных целевых сетей.

Перед записью этой модели обязательны retained complete fixture manifest/imports,
original downstream splits и все fitted train/selection examples с annotations.
`FixtureAdmissionContext` повторяет **тот же** source/annotation/exposure валидатор,
что metric adapter: permissions, current corpus/Stage A targets, все upstream members
против всех доступных downstream split/derivative contents, exact train/selection
fingerprints. Reserved test text служит только проверке пересечений. Без контекста,
при изменении labels/inputs/exposure или pin запись отказывается до создания entry.
Это проверка связи входов, не подтверждение истинности labels или approval человека.

После успешной регистрации `check`/inference проверяет сохранённые bundle/card/pin;
retained admission JSON повторно не передаётся в API и не требуется для чтения
истории. Он нужен для новой регистрации/повторной оценки, не хранится в самой записи.
Последующая независимая review permissions/physical metadata этим не заменяется.

`list` проверяет metadata checksum и ограниченный файловый layout, не веса:
`binding_rechecked=false`. `check`/`load_registered_model` повторно загружает
выбранный bundle, сравнивает independent pin и заново выводит полный model card.
Подменённые counts/classes/format/hashes отклоняются даже после пересчёта
checksum. Checksum не подпись издателя, а путь с именем SHA не источник доверия:
pin должен прийти из отдельно проверенного операторами источника.

Model status всегда `experimental`; `calibrated`, `production_quality_proven`
и `activated` всегда false. Enabled heads отражают записанные loss weights,
а не придуманные аннотации. Реестр не подставляет severity labels, calibration
artifact или quality metrics.

## Explicit train-balanced format 0.4

Native `multitask-training-0.4.0` uses a new discriminated
`config-model-card-0.3.0`, not a widened or rewritten historical card.
It retains the same fixture source/exposure binding plus the exact
`localization_objective`: closed policy, TRAIN fingerprint, positive/negative/
eligible encoded line counts and fitted negative/positive ratio. The separate
`localization_task_weight` records the existing task coefficient `w3`.
`line_score_semantics=cost_sensitive_uncalibrated` makes the cost-sensitive
line scores explicit; they are not calibrated posterior probabilities.

Admission requires the same complete retained corpus/splits/annotations as 0.3.
`validate_multitask_inputs` also reconstructs eligible encoded TRAIN targets
under the recorded cumulative feature/window budgets and checks the fitted
coefficient. Selection/test prevalence cannot supply it. Missing or altered
inputs, even a self-consistent forged count/ratio with a new model pin, refuse
before entry allocation. Selected loads recompute the card from the bundle;
rehashing modified card metadata cannot substitute its objective or task weight.

The CLI/input layout and independent pin/explicit operator choice stay the same.
No registration fits new weights, thresholds or calibration, and no entry is
automatically activated. Metadata-only readers and API parents use lightweight
localization contracts without importing Torch. Historical 0.1/0.2/0.3 reports
and card 0.1/0.2 remain separate and readable. The shared prediction path now
supports explicit saved-analysis and change diagnostics for registered 0.4.
The separately gated [owned comparison CLI](paired-detection-comparison.md)
also accepts retained 0.4 inputs; it still cannot accept arbitrary downstream
sources or imply independent model quality.

## Команды

Нужна установка проекта и training extra для native выбранных моделей;
external path дополнительно использует фиксированный retrieval runtime. `init`
и metadata-only `list` не импортируют PyTorch/Transformers.
Native fixture admission не требует external retrieval extra: фактический
`init`/`register` проверен в отдельном процессе с запрещёнными импортами
Transformers и safetensors. Это не отказ от PyTorch для загрузки native weights.

```powershell
python -m ml.registry.cli init --root artifacts/private-config-models
python -m ml.registry.cli register --root artifacts/private-config-models --model artifacts/native-model --model-sha256 <independent-full-pin>
python -m ml.registry.cli register --root artifacts/private-config-models --model artifacts/fixture-heads --model-sha256 <independent-full-pin> --fixture-admission private/retained-admission.json
python -m ml.registry.cli register --root artifacts/private-config-models --model artifacts/external-heads --model-sha256 <independent-full-pin> --model-kind foundation --foundation-source artifacts/pinned-publisher-source
python -m ml.registry.cli list --root artifacts/private-config-models
python -m ml.registry.cli check --root artifacts/private-config-models --model-sha256 <independent-full-pin>
python -m ml.registry.cli check --root artifacts/private-config-models --model-sha256 <independent-full-pin> --foundation-source artifacts/pinned-publisher-source
```

`--fixture-admission` — bounded private JSON `fixture-registry-input-0.1.0`:
`manifest` (`DatasetFixtureManifest`), complete `records`
(`ImportedDatasetFixtureRecord[]`), `splits` (`DatasetSplitResult`) и `examples`
с `record`, `parent_sha256`, `annotation` (`SupervisedAnnotation`). До 2048 imported
records, 2–512 examples и 64 MiB; unknown/duplicate keys и linked paths отвергаются.
Данные собираются из уже разрешённых, сохранённых объектов, не из неподтверждённого
customer upload. Это общий input format, не рецепт только для демонстрационных
конфигураций. Для legacy/foundation модели такой контекст явно отказывается,
а не молча игнорируется. JSON содержит приватный sanitized text и labels:
не публикуйте его, не помещайте внутрь registry root и защищайте отдельно.

Путь модели и pin нельзя брать из недоверенного upload. Registry не скачивает
веса, не обучает модель и не передаёт конфигурации в сеть. CLI runtime ошибки
дают общий отказ без private paths, model contents или traceback.
Веса/checkpoint metadata находятся в приватных локальных файлах, не в зашифрованной
API БД. Защиту ACL/диска, backup и доступ к этим файлам обеспечивает оператор;
не публикуйте их автоматически. Одновременные writers, crash/fsync durability,
OS hostile-directory races, retention и remote promotion не квалифицированы:
используйте одного writer и отдельно проверенный private root.

Budgets: 256 entries, 64 KiB metadata per file и фиксированный неглубокий layout.
Directory traversal names, symlink/junction и absolute ancestors относительного
пути отвергаются. Duplicate JSON keys, unknown fields, malformed/oversized metadata,
unexpected directories/files и incomplete entries отклоняются. Loader сохраняет
существующие tensor/numeric bundle limits; это не process deadline или sandbox
для произвольного стороннего executable model code.

## Явная диагностика патча с зарегистрированной моделью

В [private pre/post CLI](ml-change-review.md) `--registry` — альтернатива
`--model`; independent `--model-sha256` остаётся обязательным. Key передаётся
только через `NETCONFIG_ML_PSEUDONYMIZATION_KEY`. External выбор требует
`--model-kind foundation` и explicit publisher source. Нельзя выбрать bundle
и registry одновременно или использовать внешний source с native моделью.

```powershell
python -m ml.inference.change_cli review --before artifacts/before.cfg --after artifacts/candidate.cfg --patch-review artifacts/local-review.json --registry artifacts/private-config-models --model-sha256 <independent-full-pin> --output artifacts/ml-review.json
python -m ml.inference.change_cli check --before artifacts/before.cfg --after artifacts/candidate.cfg --registry artifacts/private-config-models --model-sha256 <independent-full-pin> --artifact artifacts/ml-review.json
```

Результат имеет прежний source-bound формат: выбор registry не меняет локальную
policy/reference оценку, risk, patch status, formal status или исходные файлы.
Секреты обезличиваются transient в памяти до encoder inference. Partial parse
не получает invented scores. Device connections/apply/commit не добавлено.

## Фактические проверки и открытые gates

На 2026-10-14 [installed 0.4 diagnostic](evaluation/owned-balanced-registry.json)
зарегистрировал существующий seed17 checkpoint
`42cb90bdb8247eddc061993699287eb95645bb6051c50b4cfa532c108f90f206`
через direct enrollment API с complete retained inputs, не CLI register или
новое обучение. TRAIN ratio 560/32=17.5 и task weight 1 остались прежними.
Два actual saved-HTTP CPU workers и четыре actual CLI review/check processes
завершились на own Cisco/JunOS texts. API/CLI parents не импортировали optional
runtime; consent/reader/wrong pins отказаны, replay/restart при disabled модели
не повторили inference, analyses/исторические файлы не изменились, temporary
DB/key удалены. OLD231/NEW232 runtime bindings и 266 historical hashes сохранены.
Native 0.1/0.2/0.3 reports/predictions и foundation **card** совпали с historical
installed runtime; новый foundation inference не заявляется. Старые ошибки
диагностики сохранены; только третий frozen run завершён полностью.
Scores по-прежнему некалиброваны: Cisco CLI anomaly score вырос, JunOS снизился;
это не ремонт качества или доказательство безопасности. SSH class остаётся
неподдержанным выбранной Telnet-only моделью.

На 2026-10-07 реально зарегистрированы и повторно загружены owned native 0.2
checkpoint `289a330ab0de705396df807af86dfdf6ab9c2d14c900b14f900e9097371474b4`
и external config-head checkpoint
`b0122b7099915b52f46ce4b395f09b2c19389f81c601be4d6ba442d03caf1b76` с настоящим
pinned publisher encoder. По двум owned Cisco/JunOS native recipes оба прошли
изолированные CLI review/check — восемь actual review процессов. Duplicate
регистрация отказала; metadata listing не загрузил optional model runtime.
Static tests отдельно используют маленькие authored/искусственные tensor fixtures
для legacy 0.1, source binding, повреждений, incomplete и strict privacy contracts.

На 2026-10-11 [fixture-backed diagnostic](evaluation/owned-source-fixture-registry.json)
регистрирует существующий checkpoint
`5016b5621442b84f9c44e8642bee84740ca41be5704fd327d4346a1434ff1297` после
повторной проверки complete retained inputs и 26560 сравнений. Нет нового fit,
calibration cohort или данных. Без admission input запись отказана до allocation;
duplicate enrollment отказан; loaded card/pin совпадает с действительной моделью.
Final installed run выполняет два actual CPU saved-HTTP worker и четыре private
CLI review/check для owned Cisco/JunOS. Исторические модели/данные/predictions
неизменны между двумя isolated package children; все parent app/ml imports — из
выбранных package targets. Эти повторные проверки не увеличивают размер корпуса
или число независимых сетей. Отдельный metadata-only test блокирует imports
PyTorch/Transformers и успешно читает новую карточку.

Это evidence сохранения/выбора/перепроверки конкретных checkpoints, не качества
детекции или приемлемой operational latency. Counts 48 train/12 selection views
относятся к прежним synthetic supervision; real/test/calibration cohort не появился.
[Парное сравнение](paired-detection-comparison.md) по-прежнему имеет F1=0 на этих
selection examples. [Saved-analysis HTTP/UI inference](configuration-model-inference.md)
теперь подключает эти модели отдельной opt-in диагностикой; representative model
evaluation, qualified operational latency и production deployment/security gates
остаются открыты.
