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

```powershell
python -m ml.registry.cli init --root artifacts/private-config-models
python -m ml.registry.cli register --root artifacts/private-config-models --model artifacts/native-model --model-sha256 <independent-full-pin>
python -m ml.registry.cli register --root artifacts/private-config-models --model artifacts/external-heads --model-sha256 <independent-full-pin> --model-kind foundation --foundation-source artifacts/pinned-publisher-source
python -m ml.registry.cli list --root artifacts/private-config-models
python -m ml.registry.cli check --root artifacts/private-config-models --model-sha256 <independent-full-pin>
python -m ml.registry.cli check --root artifacts/private-config-models --model-sha256 <independent-full-pin> --foundation-source artifacts/pinned-publisher-source
```

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

Это evidence сохранения/выбора/перепроверки конкретных checkpoints, не качества
детекции или приемлемой operational latency. Counts 48 train/12 selection views
относятся к прежним synthetic supervision; real/test/calibration cohort не появился.
[Парное сравнение](paired-detection-comparison.md) по-прежнему имеет F1=0 на этих
selection examples. Qualified HTTP inference, representative model evaluation и
production deployment/security gates остаются открыты.
