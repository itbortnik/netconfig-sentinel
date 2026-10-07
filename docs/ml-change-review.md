# ML-перепроверка private-пары до/после

`ml.inference.change_cli` связывает существующий offline `PatchReview` с
повторным **фактическим** CPU-inference явно выбранной native multitask-модели
или отдельного [external frozen config checkpoint](foundation-config-transfer.md).
Это отдельный диагностический отчёт: локальные политики/reference/risk не
переписываются, formal остаётся `not_run`, статус — `needs_review`, применения нет.
Он не активирует Transformer в HTTP/UI и не объявляет пригодность лабораторной
модели для реальной детекции.

Вместо прямого `--model` можно явно выбрать private
[`--registry`](transformer-model-registry.md) с тем же обязательным independent
pin. Формат результата и все no-promotion gates остаются прежними; совместный
выбор bundle и registry отвергается.

## Последовательность и границы

1. Выберите точный original snapshot и candidate. Для поддержанных двух
   management-операций можно использовать [vendor drafts](vendor-patch-drafts.md);
   для других изменений оператор явно готовит пару по [offline workflow](patch-drafts.md).
2. Генератор/оператор сохраняет `PatchReview`; vendor draft экспортирует его как
   `local-review.json`. При запуске ML review весь local report пересчитывается,
   включая source hashes, current parser/policy/reference и ограничения.
3. Выберите доверенный checkpoint и **независимо сохранённый** `multitask_identity`
   (native) или `foundation_transfer_identity` (external). Это hash report и heads,
   связанный через report с exact encoder
   и tokenizer; не SHA одного файла, не подпись издателя и не quality verdict.
4. До inference обе стороны обезличиваются в памяти одним private key и scope
   выбранного device UUID. Замены сохраняют количество строк; scores относятся
   к каждой своей стороне, а не к парным строкам diff.
5. Полный поддержанный локальный разбор позволяет фактически повторить inference
   фиксированных anomaly/category/localization/severity/embedding heads.
   Неполный разбор даёт `unavailable/incomplete_parsing` **без scores** обеих сторон.
   Выключенные при обучении головы остаются `null`, не приобретают оценки.
6. Отчёт сохраняется только в новый private JSON; `check` повторяет исходные
   проверки и inference и сравнивает весь результат, не только checksum.
7. [Batfish workflow](batfish-verification.md#привязка-к-существующему-черновику)
   остаётся отдельным явным шагом с выбранными network snapshots/scope и согласием
   на локальную загрузку. ML report не придумывает отсутствующий verifier result.
8. Проверка доступа/rollback/платформенного синтаксиса и решение инженера остаются
   незакрытыми. Даже более низкий score и исчезновение policy finding не разрешают
   применение и не доказывают исправление или сохранение достижимости.

Без `--model` local recheck сохраняется с `not_selected`; опции модели отдельно
без пути/pin отклоняются. Ошибка выбранной модели не заменяется policy-only pass.
Ни inference, ни `check` не обучают/refit модель, не используют labels candidate,
не калибруют её и не меняют сохранённый анализ API.

## Запуск

Для выбранной модели установите training extra (`python -m pip install -e
".[training]"`); для external-пути нужен `.[retrieval]` и уже выбранные pinned
publisher weights, не auto-download. До запуска настройте private 32-byte hex key в переменной
`NETCONFIG_ML_PSEUDONYMIZATION_KEY` через свой secret-management процесс.
Ключ не передавайте аргументом команды, не печатайте и не сохраняйте в Git.
Стабильная перепроверка требует прежнего key; смена key требует нового отчёта.

```powershell
python -m ml.inference.change_cli review --before private-before.cfg --after private-draft-v1/candidate.cfg --patch-review private-draft-v1/local-review.json --model trusted-native-model --model-sha256 <independently-retained-multitask-identity> --output private-ml-review-v1.json
python -m ml.inference.change_cli check --before private-before.cfg --after private-draft-v1/candidate.cfg --artifact private-ml-review-v1.json --model trusted-native-model --model-sha256 <independently-retained-multitask-identity>
```

Работают native training форматы `0.1.0` (MLM-backed) и `0.2.0`
([joint objective source](pretraining-transfer.md)). CLI проверяет фиксированный
двухуровневый inventory и не обходит произвольное дерево папок. Существующие
loaders используют bounded JSON heads, проверяемые manifests и CPU
`torch.load(..., weights_only=True)` для tensor checkpoint; это не приём
произвольных недоверенных модельных файлов. Доверенный checkpoint и key выбирает
оператор. Наличие hashes не удостоверяет происхождение, лицензию, labels или
качество модели; не подменяет проверку безопасной поставки.

Native — default `--model-kind native`. Для external checkpoint явно добавьте
`--model-kind foundation --foundation-source <verified-publisher-directory>` к
**обеим** командам; `--model` тогда указывает на сохранённую пару `heads.json` /
`heads.sha256`, а pin — на полный `foundation_transfer_identity`. Тип модели
не угадывается по содержимому и не меняется при ошибке. Foundation options без
модели, отсутствующий source или external source для native selection дают отказ.
Полный pin проверяется до выделения external модели. Повторно проверяются точные
publisher/runtime/tokenizer/frozen tensor bindings; report содержит
`training_format=foundation-config-transfer-0.1.0`. Native shape/старые numeric
артефакты не меняются; unselected и native пути не импортируют Transformers.
External pretraining exposure остаётся **unknown**, не isolated/proven quality.
Никаких HTTP activation, повторного обучения или калибровки этот выбор не добавляет.

Код 0 означает успешную запись/точную перепроверку, **не formal pass**.
Код 2 — обобщённый отказ без private paths/config/key/exception text.
Stdout содержит только идентификаторы и статусы, без scores или команд.
Исходники, модель и старые результаты не перезаписываются; родители output
должны существовать. Симлинки/junctions и такие родители отклоняются, но это
не OS sandbox и не защита от привилегированной подмены между проверками.

## Что хранится и что означает результат

Private envelope содержит exact local review и numeric supplement:

- raw/sanitized SHA каждой стороны и отдельный line count;
- model/tokenizer/training-report hashes, training format и runtime Torch version;
- uncalibrated scores доступных heads, source-aligned line scores и block attention;
- SHA/dimensions embedding вместо его полного вектора, replacement counters;
- неизменяемые false-flags для risk fusion, production quality, применения и
  independent evaluation.

Raw/sanitized config, pseudonymization key и transient synthetic record-envelope
не сохраняются. Transient record лишь совместим с existing encoder input: его
техническая дата/идентификаторы не означают сбор данных, split membership,
разрешение на обучение, независимую сеть или происхождение корпуса.
Local review может содержать чувствительные сетевые значения; numeric outputs и
hashes также не считаются публичными или анонимными. Файл не шифруется этим
offline-модулем: используйте закрытый каталог ОС, вне Git/внешних сервисов.
Роли и operation journal API не удостоверяют отдельный offline процесс.

Checksum проверяет целостность, не подлинность или semantic truth; пересчитанная
checksum изменённых scores может пройти загрузку, но свежий `check` выявит
расхождение. Смена model/runtime/input/parser/catalog/key требует нового отчёта.
Повреждённый частичный output не объявляется успешным и не исправляется автоматически.

Этот путь проверен на owned fixtures и фактических native/external weights:
четыре native-рецепта, отдельные review/check processes, сохранённый exact local
review и обе текущие системы строк, включая JunOS удаление строки Telnet.
External модель не получает специальной безопасности от размера энкодера. Малые модели
обучались на синтетических мутациях, не подтверждённых реальных аномалиях.
Uncalibrated score — не измеренная вероятность безопасного изменения; сравнение
до/после — не metric improvement, не независимый benchmark и не baseline superiority.
Живые формальные/платформенные проверки и реальное качество по-прежнему отсутствуют.
