# Явная offline instruct-модель

`ml.instruct` добавляет отдельный opt-in runtime для
[Qwen3-4B-Instruct-2507](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507),
revision `cdbee75f17c01a7cc42f958dc650907174af0554`. Publisher декларирует
Apache-2.0; проверены LICENSE и фиксированный inventory. Это не подтверждение
происхождения всех данных обучения, privacy или качества рекомендаций.
`external_training_exposure=unknown` сохраняется в identity.

## Приём checkpoint и ресурсы

Допускаются ровно 12 файлов из `ml/instruct/source.py`, всего 8,060,915,998 bytes:
три safetensors shards, их index, config/generation config, tokenizer/vocab/merges,
README и LICENSE. `.gitattributes`, cache directories, scripts, pickle/bin,
посторонние или неполные файлы не принимаются. Каждый файл проверяется потоковым
SHA-256; размеры и hashes закреплены в коде. Ссылки/junctions на файле, root или
его абсолютных предках запрещены. Проверка не защищает от гонок с оператором,
имеющим доступ на запись: checkpoint должен быть в доверенном read-only каталоге.

Независимый inventory pin:

```text
4060051515ca2008ca1d43b8179d2ac3332407626cbb19fa6d439d8dbe8e5d26
```

Это checksum канонического inventory, не publisher signature. Загрузка весов —
отдельное явное действие оператора с fixed revision; runtime ничего не скачивает.
Не передавайте конфигурации/контексты model hub. Полученные файлы нужно разместить
в отдельном каталоге без cache/служебных файлов, сверить pins и ограничить запись.
Не включайте веса и любые частные контексты в публичный репозиторий.

Extra `.[instruct]` использует уже выбранные версии Torch 2.14.0,
Transformers 5.19.0, tokenizers 0.23.2 и safetensors 0.8.0. Его отдельное имя
обозначает generative runtime, а не embedding/retrieval model. Для GPU нужен
соответствующий официальный CUDA build Torch; CPU-only установка отклоняется.
На проверяемой машине используется отдельный venv с `torch==2.14.0+cu130` из
[официального индекса PyTorch](https://download.pytorch.org/whl/cu130).
Рабочая CPU-среда Config Transformer/document encoder не изменяется.

Перед allocation проверяются CUDA/bfloat16 и минимум 10 GiB свободной GPU memory.
Используется нативный `Qwen3ForCausalLM`, `local_files_only`, safetensors-only,
native SDPA, bfloat16, frozen eval. Auto/custom model code, tools, quantization,
LoRA и publisher Jinja chat template не выполняются. Tensor loading layout и
finite values проверяются; identity включает фактическое число параметров,
versions, device name и source pin. Нет fallback на другой checkpoint/CPU/API.

## Контекст и генерация

`LocalInstructProvider` требует `allow_local_context is True` и независимый pin.
Он не запускает сервер и не включает настройки API/окружения. Caller по-прежнему
отвечает за право передачи минимизированного контекста; псевдонимизация не
доказывает анонимность. HTTP transport сохраняет свои operator/per-request gates.

Только фиксированные system/user/assistant roles, действующие instructions и
answer schema. Source role markers кодируются обычным текстом; другие reserved
controls отклоняются. Пределы: prompt 64 KiB и 4096 tokens; default 1024 new tokens,
максимум 2048; deadline до 20 секунд. Нет silent truncation, sampling, hidden retry,
JSON repair, удаления Markdown wrappers или подмены ответа заготовкой.
EOS обязан завершить assistant body; tools/thought/control tokens, незавершённый,
пустой или oversized output отклоняется.

Step deadline проверяется между decode steps и после GPU synchronization; это
**не hard cancellation GPU kernel**. Caller с таким требованием обязан владеть
изолированным процессом и kill/reap при deadline. Один вызов на экземпляр runtime;
это не cross-process quota. Measurement привязан к context SHA, не переносится
с предыдущего запроса. Deadline и incomplete/control отказ сохраняют только
численные token/time observations с `completed=false`, не rejected text.
JSON schema/citations затем проверяет существующий
`generate_draft`: schema-valid не означает истинный или безопасный текст.

## Собственная диагностическая выборка

```powershell
python -m ml.instruct.smoke --source <trusted-model-root> `
  --expected-source-sha256 4060051515ca2008ca1d43b8179d2ac3332407626cbb19fa6d439d8dbe8e5d26 `
  --allow-owned-context --output <new-private-report.json>
```

Диагностика сама создаёт четыре owned configurations: Telnet/SSHv1 для Cisco/JunOS,
запускает настоящие policy detectors и explanation binding, sealed documents и
редакцию контекста. Raw configs, inventory names и detector risk в prompt не
добавляются. Каждый полученный ответ проверяется без исправления; rejected cases
остаются rejected с `answer=null`, не теряются из знаменателя. Report содержит
model/source/context bindings, фактические token/time observations и только
принятые непроверенные drafts. Новый output создаётся exclusively; старые файлы
не перезаписываются. Unit mock answers — только validator tests, не inference evidence.

Полный checkpoint фактически загружен и проверен, число параметров —
4,022,468,096. Выполнены 16 генераций: исходная и установленная сборки с прежней
инструкцией, затем обе сборки с краткой source-grounded инструкцией. Новый prompt
просит ответ до 220 слов, не добавлять неизвестные standards/versions/commands и
не угадывать исходные имена pseudonyms; это instruction, не semantic verifier.
Model weights, context bindings, schema и четыре cases остались одинаковыми.

[Численный отчёт](evaluation/owned-instruct.json) сохраняет все четыре запуска,
включая неудачные. Прежняя инструкция: 2/4 и 1/4 schema-valid drafts; неполные/
долгие ответы отвергнуты, один completed output не прошёл answer validation.
Новая инструкция: 4/4 в source и 4/4 в установленном wheel. Это **prompt
development на тех же четырёх owned cases**, не независимый test set и не оценка
реальной сети. Нельзя выбирать только успешный запуск или считать 4/4 модельной
точностью. Raw drafts и source/context/entity fingerprints остаются приватными;
в публичном report — identity, instruction/schema hashes, counts, tokens и times.

Новый prompt: 1228–1280 input tokens, 223–255 output tokens. В исходном запуске
первый ответ занял 18.844 секунды, остальные 5.960–6.995; в установленном —
18.762 и 6.156–6.761. Измеряется generation до synchronized CPU transfer,
не загрузка/проверка 8 GB, API round trip или production throughput.
CPU threads=1; GPU/runtime profile указан в report. Первый вызов не укладывается
в default 10-second HTTP deadline: менять default, скрыто warm-up/retry или
объявлять online model service qualified на этом основании нельзя.

Даже принятые drafts всё ещё содержат неподтверждённые утверждения: угадывание
значения `field_0001`, «SSH version 2 or higher», generic noncompliance с
непредоставленными standards, отсутствие доказанного безопасного management
access/rollback. Это реальные наблюдённые ограничения, не hypothetical disclaimer.
Schema/citation membership не проверяет поддержку каждого утверждения источником.
Ни один из этих drafts не принимается как проверенная эксплуатационная рекомендация.

## Фактический owned HTTP round trip

[Отдельный численный отчёт](evaluation/owned-instruct-http.json) фиксирует четыре
ответа настоящего checkpoint через установленный wheel и временный loopback
gateway. Gateway разрешал только четыре точных authored contexts; модель не могла
создавать исходящие соединения. Два независимых owned SQLite stores сохраняли
историю каждого вендора отдельно, без ослабления проверки идентичности устройства.

Каждый сценарий прошёл upload → настоящий policy analysis → отказ 403 без
per-request consent → schema-valid model answer 200 → повторное чтение исходного
analysis. Все четыре сохранённых analysis остались неизменны. Gateway получил
ровно четыре запроса: отказы по consent происходили до обращения к модели.
Использован существующий изолированный HTTP worker и authenticated API.

Deadline 20 секунд задан явно только для этой диагностики; default 10 секунд и
настройки оператора не изменены. Gateway завершён после проверки, сервис не
установлен и не активирован автоматически. Этот результат не проверяет restart,
deployment, нагрузку, semantic truth, patch lifecycle или безопасный access/rollback.

## Оставшийся полный LLM workflow

Этот runtime не завершает полный LLM workflow: действующая HTTP schema требует
`patch_draft=null`. Отдельный [offline source-bound model patch](model-patch-drafts.md)
имеет самостоятельный opt-in и ограниченный management context; это не activation
patch API. Полный vendor-specific workflow с safe diff/baseline/
реальным verifier context, engineer approval и связанный patch API round trip
требуют отдельного этапа. Проверка простого explanation HTTP пути выше не заменяет
их. Не закрыты independent/adversarial/semantic/citation quality,
vendor/internal corpus, реальные конфигурации, нагрузка, production deployment и
access/rollback. Model prose не меняет risk/history/formal status и не применяется.
