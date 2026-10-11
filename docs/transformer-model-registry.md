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
