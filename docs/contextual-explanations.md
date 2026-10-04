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

Каталог `project-knowledge-0.1.0` включает только восемь явно перечисленных
публичных документов проекта: пять файлов `docs/policies/*.md`,
`docs/expected-configuration.md`, `docs/baseline.md`, `docs/statistical-baseline.md`.
Это внутреннее описание правил и ограничений приложения, не документация вендора,
не утверждённая политика конкретной организации и не доказательство сетевого ущерба.

При сборке wheel эти файлы включаются по allowlist в `app/knowledge/docs/`;
исходный checkout читает те же файлы из `docs/`. ТЗ, пользовательские файлы,
конфигурации и произвольные URL не импортируются. Нет runtime-загрузки документов
через API, crawling, vector database, embeddings или семантического ранжирования.
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
Hashes не являются подписью издателя или защитой от привилегированного изменения.
Исторические версии документов не хранятся: API возвращает текущий каталог,
а старую несовместимую версию детектора не пытается объяснять новым правилом.

## Граница LLM

Реализованы библиотечный `ExplanationProvider`, минимальный структурированный
контекст, отделённые инструкции, JSON-схема ответа и fail-closed validator.
HTTP-сервис не подключает и не вызывает provider. `provider=llm` возвращает
503 `Language model provider is unavailable.` без скрытой замены на local.
Нет внешнего SDK, API key, URL или фоновой передачи конфигурации.

Контекст содержит только факты выбранной находки, её evidence/anchors и hashes,
vendor/platform, численные ограничения парсера и выбранные разделы. Полный
снимок, исходный текст, unknown fragments, filename, inventory и итоговый риск
не добавляются. Значения observed/expected всё ещё могут содержать адреса и
другие закрытые данные; это не обезличивание. Библиотечный вызов явный, будущий
transport adapter должен отдельно получить разрешение, ограничить время/трафик
и обеспечить конфиденциальность. Сейчас используются только тестовые providers.

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
Полноценная LLM/RAG-интеграция и оценка качества пока не завершены.

## Интерфейс и проверки

Кнопка «Показать источники объяснения» находится в выбранной находке. Каждый
раздел открывается отдельно с citation и hashes; Markdown/HTML показаны только
как текст, без активных ссылок. UI проверяет IDs, исходное объяснение и hash
текста раздела, игнорирует late responses при смене находки/logout и не сохраняет
материалы в browser storage. LLM честно помечена недоступной.

Unit tests проверяют разрешение всех 20 policy references, ingestion/budgets,
provider fakes, защищённую схему и цитаты. API tests проверяют оба вендора,
partial parsing, restart, scope, read-only историю, ошибки и отсутствие fallback.
Desktop/mobile browser tests используют реальный API, проверяют hashes/bindings,
XSS-as-text и late responses; CI повторяет UI против PostgreSQL/Compose.
