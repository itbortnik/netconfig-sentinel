# Локальные источники и граница языковой модели

Для сохранённой находки доступен защищённый read-only запрос:

```http
POST /api/v1/findings/{finding_id}/explain
Authorization: Bearer <service-token>
Content-Type: application/json

{"analysis_id":"<uuid>","finding_sha256":"<sha256>","provider":"local"}
```

Ответ `finding-context-0.1.0` содержит неизменное локальное объяснение из выбранного
анализа, IDs/hash находки и снимка, выбранные разделы документов, ссылки
`document_id#section`, hashes исходных документов и текста разделов, версию/hash
каталога, метод `explicit_reference`, `provider=deterministic_local` и
`llm_status=unavailable`. Риск, severity, confidence, история и feedback не меняются.
Повтор не создаёт анализ или запись аудита. Новой миграции нет.

Запрос требует ID анализа даже при повторяющемся finding ID. Несовпадение hash —
409, отсутствующая пара — 404, неверный JSON — 400, лимит 16 KiB — 413,
неподдерживаемый content type — 415. Авторизация выполняется до чтения тела;
ответы — no-store. Ошибки не отражают закрытые значения или пути.

## Какие источники доступны

Каждый каталог `project-knowledge-0.1.0` и `project-knowledge-0.2.0` включает только
восемь явно перечисленных
публичных документов проекта: пять файлов `docs/policies/*.md`,
`docs/expected-configuration.md`, `docs/baseline.md`, `docs/statistical-baseline.md`.
Это внутреннее описание правил и ограничений приложения, не документация вендора,
не утверждённая политика конкретной организации и не доказательство сетевого ущерба.

При сборке wheel архивы включаются по allowlist в
`app/knowledge/versions/<release>/`; исходный checkout читает те же запечатанные
версии из `backend/app/knowledge/versions/`. ТЗ, пользовательские файлы,
конфигурации и произвольные URL не импортируются. Нет runtime-загрузки документов
через API или crawling. Отдельный [офлайн векторный индекс](document-vector-retrieval.md)
с настоящими локальными embeddings реализован; [explicit opt-in semantic context](semantic-explanation-context.md)
подключает его к HTTP/UI, сохраняя mandatory references. Default остаётся explicit.
Подбор следует явной ссылке policy rule; для reference/peer/forest выбраны
конкретные разделы интерпретации и ограничений с проверкой версии детектора.

Ingestion поддерживает простой UTF-8 Markdown с одним H1 и уникальными H2;
заголовки в fenced blocks не превращаются в разделы. Контроли, отсутствующие,
пустые, неоднозначные, несовместимые или слишком большие документы отклоняются.
Лимиты: 64 KiB на документ, 32 раздела, 8 KiB UTF-8 на раздел, 1–4 раздела
на объяснение. Данные не усекаются. Недоступный источник/версия даёт 503 вместо
выдуманной ссылки. Hash каталога учитывает версию алгоритма и hashes всех восьми
файлов; hash документа — исходные байты, hash раздела — нормализованный текст.
Line endings могут изменить document/catalog hash, но не section hash.
Hashes не являются подписью издателя или защитой от привилегированного изменения
приложения. Для существующих версий детекторов сохраняются архивы источников:
20 политик `policy-rules-0.6.0` используют knowledge 0.1.0 (31 раздел), 30 политик
`policy-rules-0.7.0` — knowledge 0.2.0 (41 раздел). Reference/peer/forest версии
0.1.0 закреплены за knowledge 0.1.0. API выбирает архив по записанной версии,
а UI отклоняет несовместимую пару detector/knowledge. Риск и исходное объяснение
не переписываются. См. [формат и границы архива](knowledge-releases.md).

## Граница LLM

Реализованы библиотечный `ExplanationProvider`, минимальный структурированный
контекст, отделённые инструкции, JSON-схема ответа и fail-closed validator.
По умолчанию HTTP-сервис не вызывает provider. `provider=llm` без настройки
возвращает 503 `Language model provider is unavailable.` без скрытой замены на local.
Теперь есть отдельный [opt-in literal-loopback transport](local-model-explanations.md)
с разрешением оператора и запроса, псевдонимизацией, hard deadline и ограниченным
HTTP-ответом. Внешние адреса, фоновая передача и автоматическая загрузка weights
не поддерживаются; `provider=local` всегда остаётся без вызова модели.

Контекст содержит только факты выбранной находки, её evidence/anchors и hashes,
vendor/platform, численные ограничения парсера и выбранные разделы. Полный
снимок, исходный текст, unknown fragments, filename, inventory и итоговый риск
не добавляются. Значения observed/expected всё ещё могут содержать адреса и
другие закрытые данные; этот библиотечный контекст сам по себе не обезличен.
HTTP runtime перед отправкой обязательно заменяет string values/keys, исключает
evidence prose и исходные limitations. Числа/hashes/anchors остаются потенциально
закрытыми; разрешение требуется даже для local endpoint. Подробности — в
[privacy-контракте](local-model-explanations.md). Реальные weights не проверены;
wire tests используют синтетический сервер, не языковую модель.

Ответ требует summary, technical_explanation, possible_impact, recommendation,
assumptions, missing_information, citations, `patch_draft=null` и
`requires_human_review=true`. Лимиты: 64 KiB prompt, 32 KiB ответ, ограниченные
строки и списки. Extra fields (включая risk/severity/verification/approval),
команды в patch_draft, не-JSON/Markdown wrapping, duplicate keys/citations,
невидимые контроли и ссылки вне переданного набора отклоняются. Ошибки provider
обобщаются; отклонённый текст не возвращается. Запрос связывается с exact chunks
до вызова provider. Поддержаны только Cisco IOS и Juniper JunOS.

Проверка структуры и существования citations **не доказывает истинность прозы**,
поддержку каждого утверждения источником или защиту от всех prompt injections.
Модель может ошибиться даже в schema-valid тексте; такой ответ остаётся
недоверенным черновиком для инженера. Команды, генерация патча, изменение оценок,
approval/apply и продвижение verifier status в этой границе отсутствуют.
Реальная модель, её качество и полноценный semantic RAG пока не проверены.
HTTP-ответ модели имеет отдельную версию `model-explanation-0.1.0`, статус `draft`
и не меняет сохранённое детерминированное объяснение. Нет записи model answer в
БД/аудит, авто-retry или fallback на успешный ответ при отказе.

## Интерфейс и проверки

Кнопка «Показать источники объяснения» находится в выбранной находке. Каждый
раздел открывается отдельно с citation и hashes; Markdown/HTML показаны только
как текст, без активных ссылок. UI проверяет IDs, исходное объяснение и hash
текста раздела, игнорирует late responses при смене находки/logout и не сохраняет
материалы в browser storage. LLM по умолчанию помечена недоступной; настроенный
adapter открывает отдельную кнопку только после разрешения. Model prose показана
текстом с предупреждением, без изменения исходных оценок и статусов.

Unit tests проверяют разрешение всех 30 policy references, ingestion/budgets,
provider fakes, защищённую схему и цитаты. API tests проверяют оба вендора,
partial parsing, restart, scope, read-only историю, ошибки и отсутствие fallback.
Desktop/mobile browser tests используют реальный API, проверяют hashes/bindings,
XSS-as-text и late responses; CI повторяет UI против PostgreSQL/Compose.
