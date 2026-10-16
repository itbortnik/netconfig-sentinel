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
`grounded-explanation-capabilities-0.2.0`, прежние capabilities в `legacy`,
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

Текущий writer `grounded-model-explanation-0.2.0` содержит прежние source/document bindings и
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

### Версионированный scoped prompt 0.2

Новый HTTP writer явно выбирает protocol 0.2. Модель по-прежнему возвращает
`grounded-explanation-answer-0.1.0`: восемь обязательных ключей, включая точный
`version`, перечислены в отдельной инструкции. Context 0.2 также содержит
`required_answer_version` и `required_answer_fields`. JSON Schema в prompt
ограничивает enum ссылок и missing codes текущими доступными значениями,
а recommendation — текущим const. Выборы других детекторов не предлагаются
в этой схеме. Эти ограничения направляют генерацию; фактический raw output
всё равно проходит строгие server-side schema, membership и binding checks.
Ответ без `version`, недоступная ссылка или произвольная проза отклоняются
без исправления JSON, повторной генерации или подстановки ответа.

Старые instructions, static answer schema и context 0.1 сохранены. Библиотечные
`prepare_grounded_explanation` и `grounded_prompt_for_facts` по умолчанию
используют 0.1; новая версия выбирается явным `protocol`.
Prepared inputs сохраняют версию для recheck. Envelope reader восстанавливает
prompt по известной `version`, а не по новейшему default. Изменение одного
discriminator без соответствующих hashes отклоняется. Typed answer, source facts,
renderer policy и exact projection bytes сохраняют прежние контракты.

Native runtime принимает переменную новую schema только после восстановления
целого prompt из typed facts и точных sealed chunks; instructions, context bytes,
context hash и schema должны совпасть. Старый static allowlist остаётся отдельным.
Операторский opt-in, одноразовый request consent, permissions, loopback transport,
deadline, один worker slot и запрет новых detector/formal/approval переходов прежние.
Никакого автоматического включения сервиса или загрузки иных weights нет.

UI читает envelopes и capabilities 0.1/0.2, требует согласованную пару
capabilities version/protocol и отвергает неизвестные версии. API paths и request
body не изменены. Клиентам с reader, ограниченным 0.1, нужен reader 0.2 для новых
ответов; старые responses остаются читаемыми обновлённым reader. Сохранённые
анализы, findings и ранее опубликованные evidence не пересчитываются.

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

### Actual installed reference/peer/forest diagnostic

[Отдельный отчёт](evaluation/owned-grounded-comparison-explanations.json) сохраняет
16 новых actual Qwen generations через installed saved HTTP: обе платформы,
reference 0.1/0.2, peer 0.1 partial proxy, peer 0.2/0.3 property и partial
proxy/measured fraction, Isolation Forest. Это заранее выбранные authored
сценарии, не independent benchmark. Для setup созданы 48 synthetic snapshots
и обучены два небольших vendor forests; новых neural weights/training нет.

Модель завершила 16 ответов, gateway вернул 16 HTTP 200, но API принял только 9:
reference 4/4, peer 5/10, forest 0/2. Остальные 7 получили 503: во всех отсутствует
обязательный `version`. Дополнительный аудит неизменённых raw choices обнаружил
в двух отклонённых peer 0.3 property ответах ссылки `measured_parser_coverage`
и `statistical_record`, отсутствующие в доступных facts. Schema gate сработал
раньше scope gate; добавлением `version` эти два ответа не становятся допустимыми.
Raw не исправлялся, retry/warm-up/fallback и подстановка ответа отсутствуют.
Это evidence фактических отказов, не квалификация успешного forest explanation
или всей матрицы peer selections.

Для 9 принятых ответов проверены exact facts/context/source bindings, required
citations и pure replay представления без модели. Дополнительный pure replay
с пустым списком model missing codes сохраняет обязательные unknown/not-run.
Reference approval остаётся `not_proven`; source anchors относятся к текущему
source; proxy не становится измеренным coverage. Все 16 saved analyses и 48 source
snapshots неизменны; объяснение не вызывает forest fit/predict/score methods.
Полный drain:16 request/provider/backend starts и 16 completions, incomplete 0,
handlers 0, exit 0, без forced kill. Генерация 18.396 s для первого ответа и
4.793–8.304 s для остальных; explicit HTTP deadline 20 s, default 10 s не квалифицирован.

Тот же wheel:242 runtime files и 3 served assets совпали с source,239 прежних
installed files и 375 history hashes сохранены. Parent 132/gateway 59 target imports,
checkout 0. Проверки source related:191 pass/0 skips/3 warnings; installed related:
191 pass/0 skips/2 warnings на каждом Pydantic 2.13.5/2.14.0,141 target imports,
checkout 0. Ruff и 242-file mypy default прошли. Полный suite, UI/browser, live
engine и PostgreSQL повторно не запускались; runtime/UI код не менялся.
Первый preflight не нашёл reference 0.1 finding без interface difference;
это исправлено до любых генераций, failed preflight сохранён отдельно.

Новая app instance в том же процессе повторно прочитала saved analyses/snapshots
и отказала generation при выключенном provider без новых обращений к модели.
Это не fresh-process restart и не persisted explanation registry; эфемерный
encryption key не сохранён. Независимый review проверил helper и bounded raw
choices/support, включая два scope-invalid selections. Independent semantic/
citation quality, реальные данные, calibration, vendor/device/network safety,
approval и полный MVP этим запуском не подтверждены.

### Actual scoped protocol 0.2 diagnostic

[Новый отчёт](evaluation/owned-scoped-grounded-explanations.json) сохраняет
16 новых generations через installed HTTP writer 0.2: reference 4/4, peer 10/10,
Isolation Forest 2/2 приняты. Использованы те же 16 authored scenario definitions
для обеих платформ, но новые run identities, source bindings и context hashes.
Прежний результат 9/16 остаётся неизменным; это наблюдаемое функциональное
улучшение в этих сценариях, без causal attribution или independent quality.
Все ответы включили required `version` и только доступные текущим facts выборы.
Raw output не исправлялся; retry/warm-up/fallback отсутствуют.

Проверены 16 exact typed envelopes, context/schema reconstruction, server-derived
projection и pure replay. Пустые model missing codes не скрывают mandatory
unknown/not-run. Сохранены все 16 analyses и 48 synthetic snapshots; два forest
fits относятся к setup, explanation fit/predict/score reruns отсутствуют.
Все 16 request/provider/backend starts завершены, incomplete 0, drain полный,
remaining handlers 0, exit 0 без forced kill. Device/network/formal/ML checks
и решение инженера этим explanation workflow не выполняются.

Generation заняла 7.039–19.726 s, HTTP 7.279–19.977 s. Использован explicit
deadline 20 s. Три HTTP ответа превысили 10 s: стандартный deadline 10 s
не квалифицирован и не изменён. Новая schema — guidance в prompt, а не constrained
decoding или гарантия соблюдения требований на следующих входах.

Все 242 installed runtime files и 3 served assets совпадают с source; 242 старых
installed runtime files и 379 history hashes сохранены. Обе версии Pydantic
2.13.5/2.14.0 прошли по 466 related installed tests и прочитали те же 13 прежних
actual envelopes 0.1, без checkout imports. 20 frozen family/vendor context hashes
закрепляют старые prompt bytes. Полная source regression: 3309 pass, 15 explicit
live-engine/PostgreSQL skips, 5 warnings, 91% line coverage; Ruff и 242-file mypy
default/Linux/win32 прошли. UI: 606 unit, typecheck/format/build, 48 synthetic
model-browser и 158 regular browser cases, retries 0. Bundle warning >500 KiB прежний.

Первоначальный source run дал 3308 pass/1 fail/15 skips: owned SDK test handler
возвращал redirect, не прочитав POST body, и Windows transport error вызвал retry.
Fixture теперь полностью читает upload и дополнительно сверяет method/length/bytes;
прежние redirect=1/collector=0 assertions и production transport не ослаблены.
Этот failed run сохранён. Первые installed tests дали по 466 pass, но отдельный
private helper postcheck ошибочно выбрал HTTP wrappers вместе с legacy envelopes.
После исправления filename pattern оба qualification runs повторены полностью;
wire data, старые ответы и runtime для этого не менялись.

Независимое read-only ревью проверило код, helper, actual raw support, envelopes,
replay и исторические bindings. Это не independent semantic/citation benchmark
или подтверждение качества исходных facts. Новых neural weights, detector
calibration, real-confirmed данных, engine queries или document encoder calls нет.
Проверка новой app instance по-прежнему относится к тому же Python process,
не fresh-process restart; explanation registry отсутствует, ephemeral key не сохранён.
