# Закрытые объяснения сохранённых находок

Отдельный opt-in режим §§17/23.7 ограничивает ответ модели ссылками на записанные
факты и закрытыми кодами. Текст составляет сервер из versioned правил представления.
Это функциональный способ исключить произвольные утверждения модели в новом
сценарии, а не независимое доказательство правильности исходной находки,
семантического качества RAG или безопасности сети.

Прежние v1 DTO, свободный непроверенный текст, инструкции и история не заменяются.
UI сохраняет прежний режим по умолчанию; для нового нужно явно выбрать
«Закрытые факты — серверное объяснение». Старые ответы не переобозначаются как
проверенные. Новый режим не создаёт патч, не запускает детектор повторно и не
меняет риск, оценки, formal status или решение инженера.

## Настройка и запрос

Помимо существующих endpoint/model/local-context настроек из
[описания loopback transport](local-model-explanations.md), оператор независимо
задаёт `NETCONFIG_LLM_ALLOW_GROUNDED_EXPLANATION=1`. Разрешения patch и grounded
patch не включают ordinary explanation и наоборот. Все флаги blank/0 без
настройки провайдера оставляют его выключенным; неполная активная настройка
отклоняется. Модель не загружается и не проверяется при чтении capabilities.

`GET /api/v2/explanation-capabilities` возвращает отдельный envelope
`grounded-explanation-capabilities-0.1.0`, прежние capabilities в `legacy`,
`grounded_explanation=disabled|configured` и `model_health_checked=false`.
Configured обозначает настройку, не проверенное здоровье модели.

```http
POST /api/v2/findings/{finding_id}/explain
Authorization: Bearer <service-token>
Content-Type: application/json

{"analysis_id":"<saved-analysis-uuid>","finding_sha256":"<saved-fingerprint>","provider":"llm","allow_local_model_context":true,"retrieval":"explicit_reference"}
```

Нужны роль с `model_explanation`, independent operator opt-in и точное `true`
в запросе. Проверка роли предшествует чтению тела; предел тела — 16 KiB.
Выбор анализа/находки/source проверяется до передачи модели. Semantic supplement
остаётся отдельным явным выбором с существующими pins/отказами, без fallback.
Unknown fields, caller-selected endpoint/model/path не принимаются.

Новый путь использует тот же literal-loopback transport, deadline и один
nonblocking slot процесса API, что остальные обращения к модели. Конкурентный
вызов получает 429; отсутствующий/выключенный провайдер или отклонённый ответ —
503. Некорректный или слишком большой контекст — 413. Автоматического retry,
исправления JSON и замены ответа заготовкой нет. Модельный `null` отклоняется:
нет принятых закрытых выборов, которые можно представить пользователю.

## Факты и происхождение

Поддерживаются versioned policy findings, reference0.1/0.2, Isolation Forest и
peer0.1/0.2/0.3 для Cisco IOS и JunOS. Используются точные сохранённые Finding,
deterministic explanation, snapshot/parser и только относящиеся к выбранной
находке selection/report сведения. Отсутствующие исторические поля не выдумываются.

- Reference approval остаётся `not_proven`; absent отличается от present/null.
  Reference lines не превращаются в текущие affected lines.
- Forest scores — записанные значения, не вероятность неисправности. Median
  deviations не являются causal/tree attribution; нового ML inference здесь нет.
- Peer0.1 без expanded report сохраняет его отсутствие. Peer0.1/0.2 используют
  confidence-deficit proxy, не измеренную долю строк. Peer0.3 сохраняет настоящий
  numerator/denominator/fraction/adapter и ограничения учёта source lines.
- Данные чужих сравнений в том же анализе не становятся фактами выбранной находки.

Actual prompt содержит pseudonymized observed/expected, allowlisted method,
parser/analysis/invocation facts, текущие anchors, source/finding hashes, sealed
release/chunk pins, required sections и роли источников. Raw titles/remediation,
evidence prose, customer names/labels, filenames, device/analysis IDs, alias map,
unknown fragments и исходный файл модели не передаются. Числа, hashes и номера
строк остаются потенциально конфиденциальными; псевдонимизация не анонимность.

Источники — запечатанные внутренние документы проекта, не vendor manuals или
утверждённая политика организации. Обязательные sections выводятся из выбранного
versioned detector. Semantic supplements дают контекст, не полномочие утверждать
значения находки, approval или результаты verifier.

## Wire и представление

`grounded-model-explanation-0.1.0` содержит прежние source/document bindings и
отдельные `model_answer`, `source_facts_json`, `projection_json`.
Model answer допускает только существующие fact refs, scope-specific recommendation,
missing-information codes, все обязательные citations по порядку,
`patch_draft=null`, точное `requires_human_review=true`. Свободная проза, команды,
новые оценки, status/approval и произвольные источники запрещены.

Нормативны exact UTF-8 JSON strings фактов и представления, связанные отдельными
SHA-256. Их нельзя хешировать после повторной сериализации в JavaScript:
Python и JavaScript различаются в записи float/exponent. Typed properties на
сервере и parsed views в UI производны от этих строк, не второй wire authority.
Отдельно связаны actual context, instructions/schema, typed choices, renderer
version/policy и projection. Повторная проверка заново строит prompt и presentation;
хеши не доказывают истинность фактов, identity инженера или используемые weights.

Server-derived presentation всегда сохраняет unknown/not-run, partial parse,
методические и caller/storage ограничения, даже если модель их не выбрала.
UI сверяет точные строки/SHA и выбранный saved analysis/finding/snapshot/documents,
показывает текст как обычный текст, отдельно от raw closed choices.
Согласие одноразовое и очищается при отправке и смене режима, retrieval, находки,
анализа, клиента или снимка; устаревший ответ не отображается. После потери ответа
автоматического повторного обращения нет.

Model answer не добавляется в сохранённый анализ. Это не обещание отсутствия
хранения клиентом, gateway или сторонними logs. Журнал HTTP фиксирует metadata-only
receipt/completion, IDs и hashes/versions, без значений фактов, choices или текста.
Новой миграции, persisted explanation registry, review/approval/apply перехода нет.

## Границы проверки

Pure unit и искусственные loopback/browser ответы проверяют валидацию, replay,
разрешения и интеграцию. Они не являются actual inference, independent semantic
benchmark или проверкой полного §23. Actual inference и installed qualification
фиксируются отдельно по завершённым запускам, включая отказы, без отбора только
удачных результатов. Representative real-confirmed corpus и независимые
semantic/citation/detection quality остаются отсутствующими.

### Проверки реализации 2026-10-16

Source suite: 3259 passed, 15 явно пропущенных live-engine/PostgreSQL cases,
5 warnings; line coverage 91% (22373 statements, 2080 misses). Ruff и mypy
242 runtime files в default/Linux/win32 modes прошли. Related installed suite —
420 passed на каждом Pydantic2.13.5 и2.14.0, по два dependency warnings,
zero checkout imports. Все242 installed runtime files и3assets совпадают с
source; прежние239installed files и371history hashes сохранены.

UI:596unit tests, typecheck, format и build прошли; прежнее предупреждение о
bundle более500KiB остаётся. Model browser profile:48passed, retries0,
включая12новых desktop/mobile сценариев ordinary explanation; provider искусственный.
Первые новые browser attempts содержали неверные selectors: exact text label
вместо combobox и region вместо aria-labelled div. Они сохранены как неуспешные;
исправлялись selectors теста, а не поведение приложения. Общий initial browser
run дал156pass/2fail: старый тест ожидал повторное использование согласия после
отклонённого ответа. Он обновлён под одноразовое согласие, без его ослабления.
Полный последующий общий browser run:158passed, retries0.

Независимое ревью выявило и проверило исправления двух P2: semantic metadata
больше не затирает renderer version в журнале; UI требует exact Finding member
сохранённого analysis, не только совпадение UUID. Это не независимая оценка
модели или подтверждение всех требований ТЗ.

### Actual installed HTTP diagnostic

[Численный отчёт](evaluation/owned-grounded-explanations.json) фиксирует ровно
четыре обращения к прежней pinned Qwen на ранее созданных Cisco/JunOS Telnet/SSHv1
конфигурациях:4actual backend generations,4accepted closed answers,4точных pure
replays без провайдера. Ни warm-up, ни retry, ни fallback, ни замены входов нет.
Raw ответы, prompts и конфигурации остаются частными. Это не independent test.

Generation заняла18.193/4.638/5.976/4.543s, HTTP18.918/4.826/6.163/4.732s.
Использован явный диагностический HTTP deadline20s; default10s не квалифицирован
и не изменён. Модель возвращала только проверенные refs/codes; показанная проза
выведена server renderer, а не оценена как свободный корректный текст модели.
Actual reference/peer/forest quality этим четырёхслучайным policy run не проверена.

Все request/provider/backend start/completion records сохранены; incomplete0,
drain полный, remaining handlers0, gateway exit0, forced kill отсутствует.
Четыре consent denial, pure replay, reads и новая app instance с выключенным
провайдером не добавили обращений. Restart относится к тому же Python process,
только к сохранённым analyses и disabled-generation refusals: explanation registry
отсутствует. Эфемерный encryption key не сохранялся; backup не заявляется.
Parent140/gateway59 target imports, checkout0; все3bundled assets served exactly.
Outgoing gateway socket connects заблокированы, но это не OS sandbox.
Модельный сервис оператора, рабочая БД, engine/ML/device checks не затрагивались.
