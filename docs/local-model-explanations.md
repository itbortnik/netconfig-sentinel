# Черновик объяснения от локальной языковой модели

Экспериментальный opt-in transport дополняет [локальное объяснение с источниками](contextual-explanations.md).
По умолчанию он выключен. Анализ, загрузка, startup, probes и получение источников
не обращаются к языковой модели. Реальные веса не поставляются и не скачиваются
приложением. Интеграционные тесты используют синтетический локальный HTTP-сервер,
а browser tests — подставной ответ поверх реального API сохранённых источников.
Это проверка границ передачи и отказов, не качества объяснений или совместимости
конкретного сервера, checkpoint либо оборудования.
Отдельные [owned проверки настоящей Qwen](local-instruct-runtime.md) выполнены
через явно разрешённый временный gateway; они не активируют сервис оператора и
не доказывают независимое качество. [Новый comparison-context diagnostic](evaluation/owned-expanded-instruct-http.json)
также сохраняет обнаруженные ошибки содержания schema-valid ответов.

## Явное включение

Сначала оператор отдельно запускает доверенный сервер модели и проверяет его
лицензию, хранение prompts, логи, сетевой доступ и ресурсные ограничения.
Поддерживается только буквальный адрес
`http://127.0.0.1:<port>/v1/chat/completions`, порт 1024–65535.
DNS, `localhost`, другие IP, IPv6, credentials в URL, query, fragment и
перенаправления запрещены. Внешние сервисы этим адаптером не поддерживаются.

Перед запуском локального API оператор задаёт в окружении:

```powershell
$env:NETCONFIG_LLM_ENDPOINT = 'http://127.0.0.1:9000/v1/chat/completions'
$env:NETCONFIG_LLM_MODEL = 'reviewed-local-model'
$env:NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT = '1'
```

Alias должен соответствовать `[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`. Это выбранное
оператором имя, не подтверждение фактических weights или идентичности checkpoint.
Необязательный `NETCONFIG_LLM_API_KEY` — отдельный секрет сервера модели;
service token приложения и Fernet key не пересылаются. Не публикуйте credentials.
Запуск и миграции persistent API описаны в [инструкции API](persistent-api.md).
Новой миграции для этого read-only пути нет.

Все четыре переменные пустые/отсутствуют — adapter disabled. Частичная или неверная
настройка останавливает startup вместо скрытого fallback. Переменные читаются при
создании глобального приложения, не при каждом запросе. Для отключения очистите
все четыре и перезапустите API. Автоматической проверки доступности модели нет.

`127.0.0.1` — тот же host/network namespace, что у API. В контейнере это сам
контейнер, не компьютер оператора и не соседний Compose service. Текущий Compose
не передаёт эти переменные: подключение контейнера к host-модели не реализовано.
Не заменяйте адрес на `host.docker.internal` или сетевой IP. Контроль исходящих
соединений и журналов самого сервера модели остаётся задачей оператора: локальный
адрес не доказывает, что сторонний процесс не сохранит или не отправит prompt.

## Отдельное разрешение на каждую находку

Авторизованный `GET /api/v1/explanation-capabilities` сообщает только
`disabled|configured`, transport и требование разрешения. `model_health_checked=false`
всегда: `configured` не означает, что сервер работает или модель пригодна.
Endpoint, ключ и путь модели не возвращаются.
Запрос model draft дополнительно требует role permission `model_explanation`:
[engineer/admin](service-roles.md). Reader/analyst могут получать локальные
источники, но не передавать контекст модели. Role permission не заменяет consent.

В выбранной находке UI показывает отдельное предупреждение и галочку разрешения.
Кнопка модели отключена без галочки; переключение находки или выход очищает
разрешение и видимый ответ. Данные не пишутся в browser storage. Через API нужен
тот же scope, что для источников, плюс явный выбор и строгий JSON boolean:

```json
{
  "analysis_id": "<uuid>",
  "finding_sha256": "<sha256>",
  "provider": "llm",
  "allow_local_model_context": true
}
```

POST выполняется на `/api/v1/findings/{finding_id}/explain`. Binding с сохранённым
анализом проверяется до отправки. Для настроенного adapter отсутствие разрешения
даёт 403; numeric `1` вместо `true` — 400. Disabled adapter даёт 503. Передавать
разрешение с `provider=local` нельзя. Нет фоновых запросов, endpoint из request,
повторного fit, скачивания weights или скрытой замены отклонённого ответа.
Общий service token не удостоверяет личность конкретного инженера.

## Что пересылается

Только выбранная находка и 1–4 точных раздела восьми allowlisted публичных документов.
Полный снимок, исходный файл, unknown fragments, filename, inventory, device UUID
и итоговый risk не добавляются. В observed/expected рекурсивно заменяются все
имена полей и строковые значения на request-local псевдонимы; одинаковые строки
сохраняют равенство только в рамках этого контекста. Таблица соответствий не
экспортируется. Evidence messages/kinds и исходные limitations исключаются.

В контексте модели теперь отдельно передаются строгие
`explanation-analysis-facts-0.1.0`: сохранённый `analysis_status` и, только для
expanded/measured peer finding, версия/статус сохранённого peer report и числа
выбранных peers, profile/compared/skipped features. Строки report limitations,
названия features, inventory и IDs не добавляются. После псевдонимизации эти
allowlisted enums/counts повторно проверяются и сохраняются без замены псевдонимами.
Это дополнительные potentially confidential facts под тем же явным consent,
не разрешение передачи наружу. Числа берутся из сохранённого report, не из нового
анализа, confidence или ответа модели. Legacy peer 0.1 и reference не получают
выдуманного peer report; offline caller без saved context получает `not_supplied`.

`verification_scope` всегда отмечает vendor syntax, network impact, management
access и rollback как `not_checked_in_this_explanation`. Completed относится
только к записанному scoped analysis и не означает успешной проверки сети или
безопасности изменения. Отдельные review/verifier results здесь не потребляются.
Это путь объяснения, не patch/review approval API; его публичный response contract,
privacy algorithm version, sealed documents и сохранённая история не меняются.

Сохраняются числа, booleans, null, порядок массивов, vendor/platform, ID/версия
детектора, публичный policy ID (другие категории обобщены), численные ограничения
парсера, source/finding hashes и line/hash/confidence anchors. Число, номер строки,
структура и hash всё ещё могут быть конфиденциальны. Это псевдонимизация, **не
доказательство анонимности**. Нельзя считать строковую замену достаточным разрешением
на внешнюю передачу. Удалённые имена также ограничивают содержательность ответа.

`finding-context-redaction-0.1.0` и SHA-256 сериализованного контекста возвращаются
с черновиком. Hash — идентификатор payload, не подпись и не независимое доказательство
приватности; UI не получает alias mapping и не пересчитывает redacted context hash.
Текст документов неизменен и не берётся из пользовательских конфигураций.

## Протокол и ограничение работы

Adapter посылает non-streaming chat-completions JSON: `messages` с отделёнными
инструкциями/schema и контекстом, `response_format={"type":"json_object"}`,
`temperature=0`, `max_tokens=4096`. Server должен вернуть HTTP 200 с
`application/json`, ровно один assistant message со строковым `content` и
`finish_reason=stop`. Streaming, compression, tool calls, refusal, незавершённая
генерация и duplicate JSON keys отвергаются. Ответ — JSON-объект по защищённой
[схеме черновика](contextual-explanations.md), не Markdown wrapping.

Prompt ограничен 64 KiB UTF-8, HTTP-envelope ответа — 64 KiB, текст answer —
32 KiB, строки/списки — меньшими контрактными лимитами. Усечение не используется.
Stdlib HTTP worker не использует environment proxies, запускается в изолированном
Python-процессе без унаследованных API credentials и без видимого окна на Windows.
У parent есть hard wall-clock deadline: по умолчанию 10 секунд; библиотечная
настройка допускает 1–20. По истечении worker завершается и reap выполняется до
освобождения slot. Это **не гарантирует отмену генерации на сервере модели**.

Один запрос модели на процесс API; конкурирующий получает 429. Это не глобальная
квота для нескольких процессов/реплик и не защита от последовательного расхода
ресурсов авторизованным клиентом. Очередь, распределённые quotas, health poll и
автоматический retry отсутствуют. Timeout/недоступный сервер/отклонённый answer
дают общий 503, превышение prompt budget — 413. Ошибки не отражают provider body,
URL, headers или traceback. Логи стороннего сервера приложение не контролирует.

## Граница доверия ответа

`model-explanation-0.1.0`, `provider=loopback_language_model`, `llm_status=draft`
включают исходное детерминированное объяснение, привязки, documents и отдельный
`answer`. Citations должны принадлежать exact retrieved chunks; unknown fields,
score/status/approval, исполняемый `patch_draft` и отключение human review запрещены.
Проза показана обычным текстом, без HTML или активных Markdown links.

Проверка JSON и citations не устанавливает истинность утверждений, соответствие
каждого вывода источнику или полную защиту от prompt injection. Даже schema-valid
текст может содержать ложные рекомендации или произвольную прозу; engineer review
обязателен. Приложение не исполняет этот текст и не сохраняет его как новый анализ,
изменение risk, verifier status, feedback, draft или audit event. Генерация команд,
approval/apply и контакты с сетевыми устройствами отсутствуют.

Текущая инструкция просит объяснить конкретную находку, назвать saved status и
точные peer counts, не угадывать interface/storage/privacy и уложиться в 120 слов.
Это **prompt guidance, не semantic validator или enforced word/list limit**.
[Повторная actual диагностика](evaluation/owned-explanation-facts-http.json)
сохраняет обе development итерации на тех же четырёх cases: в каждой 3/4 accepted
drafts и один deadline rejection. Даже после исправления context модель сохраняет
unsupported interface/storage и peer-bias утверждения; semantic quality не пройдена.

### Проверка сохранённых ответов без новой генерации

[Frozen assertion audit](evaluation/owned-frozen-explanation-assertions.json)
проверяет все восемь попыток этих двух development итераций: шесть принятых
ответов повторно прошли schema/citation membership, два deadline имеют
`answer=null` и остаются **unavailable**, не «семантически правильными» или
«семантически ошибочными». Exact prompt/instruction/schema и private report hashes
сверены с исходным evidence; frozen файлы не изменяются. Retrieval, inference,
ML/Batfish, новые inputs и активация сервиса не выполняются.

Это ручная ограниченная проверка конкретных утверждений against software facts
и exact retrieved chunks, **не полная разметка всех claims, human ground truth
или independent accuracy metric**. Проверены следующие наблюдения:

| Выбранное утверждение | Число | Основание оценки |
| --- | ---: | --- |
| Текущий workflow назван CLI-only | 3 | Противоречит измеренному HTTP workflow; исторический library/CLI scope источника не описывает этот caller |
| Текущий workflow объявлен без persistent storage | 2 | Противоречит recorded saved-analysis/restart checks; retrieved limitations также различают standalone и opt-in API storage |
| Числа якобы не передаются в контексте | 1 | В exact redacted prompt числовые значения присутствуют; это не проверка анонимности или утверждение о передаче оригинальных имён |
| Отсутствие bias названо assumption | 1 | Не подтверждено, но не считается доказанно ложным фактом; absence of bias должна оставаться неизвестной |
| Storage отсутствует **без** opt-in API | 1 | Условное library-утверждение поддержано источником и не считается доказательством отсутствия storage у текущего caller |

Итого четыре из шести доступных answers имеют flags в выбранных dimensions:
шесть противоречащих assertions и одно неподтверждённое assumption. Это не число
всех ошибок и не semantic failure rate модели. Два не отмеченных этими checks
reference answers не объявляются полностью правильными. Оба peer summaries
второй итерации используют actual completed/3 peers/19 compared features;
первые generic summaries не объявляются точным воспроизведением этих counts.

Все citations входят в exact retrieved sections, но membership не доказывает
поддержку текущего вывода: описания historical standalone capabilities нельзя
без проверки переносить на saved HTTP analysis. Public report содержит только
counts, dimensions, assessment enums и aggregate bindings; prose, prompts,
per-request identities и exact private annotations остаются локальными.
Semantic validator, qualified output, independent/adversarial quality и §17
целиком этим audit не закрыты; scores/verifier/history не меняются.

### Факты текущего caller, отдельно от исторических документов

`explanation-invocation-facts-0.1.0` — отдельный strict allowlist, не новая версия
saved `analysis_facts` или response DTO. HTTP endpoint формирует его сервером
после consent/source binding: `entrypoint=saved_analysis_http`,
`analysis_storage=stored_analysis`, `model_answer_storage=not_stored_in_analysis`.
Это различает сохранённый детерминированный анализ и возвращённый model draft;
не утверждает отсутствие хранения клиентом, gateway или журналами.

`selected_finding_peer_profile_storage=stored_in_analysis` устанавливается только
для выбранной peer finding с действительно сохранённым profile. Legacy profile
может быть сохранён без нового peer report. Для reference/policy/outlier finding
поле `not_applicable`, даже если тот же analysis содержит другое peer comparison;
отсутствующее metadata остаётся `not_supplied`. Offline caller по умолчанию не
получает выдуманных сведений об interface/storage. HTTP body не управляет этими
полями; redaction повторно валидирует closed object и не переносит private prose,
UUID, database paths или значения profile в этот allowlist.

Инструкция различает historical release descriptions и actual invocation scope,
но не отменяет documented detector limitations. Архивные chunks/mappings,
privacy algorithm и DraftAnswer schema не меняются; новые contexts имеют новые
hash bindings, прежние receipts/answers не пересчитываются. Дополнительные
workflow enums также являются данными под существующим consent, не доказательством
анонимности, семантической истины или deployment readiness.

[Фактический installed повтор](evaluation/owned-invocation-facts-http.json)
выполнил ровно четыре новых Qwen generations на тех же четырёх owned cases.
Все четыре completed/schema-and-citation accepted; четыре consent refusals
произошли до модели, saved/restart analyses не изменились. Веса, detector facts,
observed/expected, source и sealed documents совпадают с фиксированной второй
предыдущей итерацией; finding fingerprints заново привязаны к новым run identities.
Новых независимых случаев, ML fit, Batfish или operator activation нет.

Шесть bounded dimensions перечислены до генерации; labels и выбранные assertions
оценены вручную после неё, не считаются preregistered exhaustive claim taxonomy.
Прежние CLI-only/безусловные nonpersistence claims не наблюдались, оба peer drafts
назвали stored profile и completed/3 peers/19 features/0 skipped. Но отсутствие
фраз не означает правильность всех утверждений: explicit HTTP interface и
различение draft storage в прозе не воспроизведены. Условные library statements
про opt-in storage не классифицируются как current nonpersistence contradictions.

Сохраняются реальные проблемы: два reference drafts отрицают network/syntax issue
без verifier, один предлагает неподтверждённое operational inaction rule; два
peer summaries неоднозначно расширяют nonstorage на target device. Juniper peer
assumes representative selection без evidence. Это unsupported/ambiguous claims,
не установленные ложные факты. Reference summaries пропустили completed; ни один
summary не начинается с literal status. Guidance 120 words/one list item не enforced:
prose counts — 147/180/120/169, у обоих peers largest list length=3.

Полный comparator denominator сохранён: раньше 3 accepted + 1 unavailable deadline,
теперь 4 accepted; unavailable case не считается semantic pass/fail и не выбрасывается
для удобного available-only сравнения. Первый новый HTTP request занял 19.022 s,
остальные 6.256–7.924 s при явном diagnostic budget 20 s; default 10 s не меняется
и не квалифицирован. Это один prompt-development intervention, не causal repair,
independent semantic-quality pass или throughput/SLA. Public evidence содержит
числа, enums и aggregate hashes; prose/contexts/annotations остаются приватными.

Unit/wire/API tests проверяют target/permission, pseudonyms, бюджеты, redirects,
timeout/reap/concurrency, proxy exclusion, schema/citations, неизменность истории
и restart для Cisco/Juniper, включая partial parsing. CI повторяет wire/API cases
на отдельной PostgreSQL test schema. Desktop/mobile tests проверяют consent,
unsafe DTO, plain-text rendering, привязки и late responses. Реальная модель,
качество на эксплуатационных данных, load testing и production deployment не
проверены этим transport test suite. Отдельная
[offline instruct диагностика](local-instruct-runtime.md) уже использует полный
checkpoint и фактические generated drafts, но не квалифицирует этот HTTP service
или семантическую достоверность ответа. Отдельный optional
[semantic document index](semantic-explanation-context.md) уже использует реальные
локальные document embeddings; его tiny owned query checks не доказывают качество
retrieval на независимой vendor/internal библиотеке.
