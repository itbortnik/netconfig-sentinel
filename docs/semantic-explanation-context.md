# Opt-in семантический контекст объяснения

API/UI могут явно дополнить обязательные источники находки локальным векторным
поиском. По умолчанию `retrieval=explicit_reference`; прежний ответ 0.1.0 не
содержит нового metadata field, сохраняет `patch_draft=null` и не запускает
document model. Поля, оценки и содержимое сохранённого объяснения не меняются.
Новой миграции, feedback, согласования или применения патча нет.

## Настройка оператора

Сначала явно установите optional extra `.[retrieval]`, получите pinned document
weights и постройте оба sealed indexes, как описано в
[офлайн поиске](document-vector-retrieval.md). Затем задайте все четыре переменные:

```text
NETCONFIG_DOCUMENT_MODEL_ROOT=<absolute trusted model directory>
NETCONFIG_DOCUMENT_INDEX_ROOT=<absolute trusted directory containing both release directories>
NETCONFIG_DOCUMENT_INDEX_SHA256_0_1=<legacy index SHA-256 from the verified report>
NETCONFIG_DOCUMENT_INDEX_SHA256_0_2=<current index SHA-256 from the verified report>
```

Paths не выбираются HTTP-пользователем. Полная настройка требует authenticated
persistent API; частичная или неверная настройка останавливает старт. Проверка
наличия weights/index и их фактического runtime binding выполняется при запросе,
не загружает модель в API процесс. Отсутствующие optional dependencies или файлы
дают 503 при semantic request. Основной API остаётся без optional model imports.
Базовый Docker image не устанавливает retrieval extra и не содержит weights:
его opt-in развёртывание требует отдельной подготовки зависимостей и readonly
model/index mounts оператором. Оно здесь не выдаётся за проверенный deployment.

Для расширенных comparison findings 0.2 отдельно постройте knowledge 0.3 index
и задайте `NETCONFIG_DOCUMENT_INDEX_SHA256_0_3`. Первые четыре параметра остаются
обязательными; дополнительный pin необязателен для старых releases. Если pin 0.3
не задан, semantic request новой находки даёт 503 до чтения индекса/запуска worker.
Явные references доступны без encoder. Старые pins не используются для 0.3.

```powershell
.venv\Scripts\python.exe -m ml.retrieval.smoke --model-root artifacts/minilm-public --output-root artifacts/expanded-document-search --knowledge-version project-knowledge-0.3.0
```

Каталог output должен быть новым. При общей index root можно явно повторить
`--knowledge-version` для всех трёх releases. Без этого параметра CLI сохраняет
прежний двухрелизный диагностический сценарий. Полученный hash переносится в
настройку оператором; команда не активирует runtime и не меняет environment.

Index SHA pins должны находиться вне изменяемых manifests. Артефакты разных
NumPy/PyTorch/Transformers/tokenizers/safetensors versions не смешиваются:
identity включает runtime versions. После смены runtime пересоберите оба indexes,
проверьте queries и обновите pins явно. Нельзя просто изменить записанную identity
или recompute manifest и считать прежние vectors заново проверенными.

`GET /api/v1/explanation-capabilities` возвращает version 0.2.0,
`semantic_retrieval=disabled|configured` и `retrieval_health_checked=false`.
Configured означает наличие настройки, не здоровья модели или acceptance quality.
UI принимает legacy capabilities 0.1.0 как отсутствие semantic capability.

## Явный запрос

```http
POST /api/v1/findings/{finding_id}/explain
Authorization: Bearer <service-token>
Content-Type: application/json

{"analysis_id":"<uuid>","finding_sha256":"<sha256>","provider":"local","retrieval":"semantic_supplement"}
```

После авторизации и проверки exact saved analysis/finding/source binding сервер
выбирает sealed knowledge release по записанной версии детектора. Сначала
извлекаются все обязательные `explicit_reference` sections. Query берётся только
из публичного title/remediation соответствующего policy catalog; для reference,
peer и forest используются фиксированные публичные descriptions limitations.
Observed/expected values, evidence, source text, filename, customer inventory,
IDs анализа/устройства и source hashes не отправляются document encoder.
Ни query, ни output не сохраняются в анализе. Reader имеет право на этот read-only
контекст, но это не даёт ему право на instruct-language model request.

Отдельный local worker получает только trusted paths/pin, knowledge version и
public query. Он повторно проверяет каталог/index/model, выполняет настоящий
CPU inference, затем завершается. `-I` исключает CWD/PYTHONPATH; worker восстанавливает
только собственный application package root. Child environment содержит только
необходимые системные path/temp/locale variables, без service/encryption/model keys
и proxy/HF settings. Код/weights должны быть доверенными: процесс не является
OS sandbox или firewall для привилегированного изменения приложения.

В одном API process работает не более одного retrieval worker, без очереди в
runtime: конкурентный запрос даёт 429. Default hard inference deadline — 20 s;
программная настройка допускает 1–60 s. Просроченный child убивается, pipes
закрываются после bounded cleanup. stdout ограничен 64 KiB, schema и все source,
query, encoder и внешние index bindings перепроверяются parent процессом.
Missing/mismatched artifacts, повреждённый output или deadline — 503, без тихой
подмены `semantic_supplement` на explicit-only. Пользователь может отдельно
выбрать explicit mode. Общий rate limiting и production sandbox не заявляются.

## Ответ и граница LLM

`finding-context-0.2.0` сохраняет исходное `explanation` и содержит не более
четырёх документов: обязательные references сначала, затем уникальные semantic
supplements из того же release. Низкий similarity не удаляет обязательный источник.
`semantic_retrieval` фиксирует index SHA, encoder identity, `query_source`, public
query SHA, required citations и citation/content hashes + cosine выбранных extras.
Cosine — ранжирование контекста, не confidence детектора или correctness evidence.
Если extras не поместились/совпали с mandatory, metadata может содержать пустой
список supplements; mandatory всё равно остаются.

UI не включит режим автоматически, отмечает mandatory/supplementary sections,
показывает similarity отдельно от detector confidence и очищает выбор при смене
находки/выходе. Contracts связывают version/method/metadata, все citations и content
hashes; browser дополнительно проверяет хеш фактически показанного текста.
Ранжирование и структура не доказывают истинность текста; Markdown/HTML остаются
обычным текстом и не выполняются.

`provider=llm` может использовать эти же документы только с прежним explicit
local-model permission и соответствующей service role. Ответ тогда имеет
`model-explanation-0.2.0`; модель может цитировать только переданные sections.
Сохраняются redaction, hard loopback deadline, JSON validator, human-review
requirement и запрет изменения scores/verification/patch state. Document MiniLM
не заменяет instruct-LLM. Реальные instruct weights и качество прозы не проверены.

## Доказательства и ограничения

[Фактический workflow diagnostic](evaluation/semantic-workflow.json) подтверждает
настоящий isolated document inference для обоих releases, termination по 1 s
deadline, authenticated API с неизменным анализом и цепочку реального retrieval
в **синтетический** loopback instruct server. Последняя проверяет transport и
citations, не language-model quality. Веса document encoder реальные; инструкции
и конфигурация для smoke — авторские, без customer configurations.

Изолированный запрос с новым импортом/загрузкой weights занял около 8 s в этом
прогоне; 19–21 ms офлайн query latency не является API latency. Нет persistent
GPU worker, нагрузочного SLA, независимых query labels, разрешённых vendor manuals
или production-quality RAG evaluation. Шесть authored retrieval queries и UI
software fixtures не закрывают эти требования.
