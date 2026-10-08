# Source-bound черновик патча от локальной модели

Это отдельный **offline library** контракт, а не включение patch generation в
действующий explanation API. HTTP `DraftAnswer` по-прежнему требует
`patch_draft=null`. Нужны два явных разрешения: локальный контекст и
`LocalInstructProvider(..., allow_patch_draft=True)`; default — false.
Применения, подключения, approval или повышения formal status здесь нет.

## Минимальный проверяемый контекст

`build_patch_prompt(before, finding=..., source_sha256=..., reference_id=...,
baseline=..., allow_local_context=True)` принимает точный confidential original
snapshot и заново вычисляет его текущую находку. Поддержан только тот же
[консервативный management slice](vendor-patch-drafts.md): две категории,
Cisco IOS VTY/root и JunOS flat set, без неизвестных/неоднозначных конструкций.
Другие и неполностью разобранные inputs отклоняются до вызова модели.

В context `source-bound-model-patch-0.2.0` попадают:

- vendor/platform, finding/category/detector version и fingerprints;
- все affected anchors, hashes исходных строк и только поддержанные management
  команды с VTY/root контекстом; имеющиеся SSH facts не скрываются;
- явно выбранный baseline того же vendor/platform/hostname, его source hash,
  минимальные management facts и whitelist реально присутствующих команд;
- безопасный structured diff только Telnet/SSH-version, не весь raw diff;
- sealed retrieved documents с release/content hashes и точными citations;
- parser limitations и explicit `formal_verification=not_run`: candidate ещё
  не получен, чужой/выдуманный Batfish pass не подставляется.

Без baseline — `not_supplied`, без diff — `not_available`; отсутствующие inputs
не выдаются за успешные проверки. Baseline approval не доказан. Hostname, users,
пароли/hashes, адреса, неизвестные строки, raw source и reference ID не экспортируются.
Hashes, номера строк, VTY и management facts всё ещё могут быть конфиденциальными:
это минимизация, не доказательство анонимности. Caller обязан подтвердить право
локальной передачи; этот flag не разрешает внешнюю отправку произвольным adapter.

Перед generation всё пересобирается: изменение source/finding/baseline/documents/
instructions/schema/context hashes отклоняется до provider. Из модели принимаются
только bounded bytes, уникальные JSON keys, точная schema, retrieved citations и
`requires_human_review=true`; структура не доказывает смысл текста или citations.

## Candidate, не команда к исполнению

Отдельная `PatchDraftAnswer.patch_draft` — null либо `{edits: [...]}`. Каждый edit
содержит исходный `source_line` и одну replacement configuration command; null
удаляет строку. Нет insertion, произвольного script/diff, других anchors, multi-line,
shell/control characters или execution flags. Edits обязаны покрыть точные anchors
выбранной находки, быть уникальными и упорядоченными.

Предложенные **моделью** replacements переносятся в отдельный candidate с сохранением
остальных исходных байтов, indentation, trailing whitespace/semicolon и CRLF.
Детерминированный vendor draft служит только allowed-edit validator: его готовый
candidate/replacement не отправляется модели и не подставляется вместо отказа
или неверного ответа. Нет repair, hidden retry, template fallback или изменения prose.
Синтаксис реально выбранного baseline, напротив, является явно помеченным входом.

Candidate заново проходит exact source replay, local parser, semantic scope,
policy engine и before/after review. Любая лишняя смена, новый policy finding или
несовпадение разрешённого candidate отклоняет ответ полностью. `patch_draft=null`
остаётся явным `no_candidate`, не становится готовым патчем.

`GeneratedModelPatch` возвращает непроверенный prose, private candidate отдельно
и существующий `VendorDraft/PatchReview`. Confidential поля исключены из repr.
Для сохранения есть отдельный [encrypted model receipt](model-patch-receipts.md)
с completed observation и model/context bindings. `validate_patch_answer` выполняет
только replay уже полученного output, без нового inference/transport permission.
Status остаётся `draft/needs_review`; formal и ML — `not_run`, device syntax/access/
application flags — false. Исчезновение выбранной policy category не доказывает
безопасность доступа или успешное исправление на устройстве.

## Фактическая owned диагностика

```powershell
python -m ml.instruct.patch_smoke --source <trusted-model-root> `
  --expected-source-sha256 4060051515ca2008ca1d43b8179d2ac3332407626cbb19fa6d439d8dbe8e5d26 `
  --allow-owned-context --output <new-private-report.json>
```

Только четыре authored Cisco/JunOS configurations с собственным baseline.
Результаты `locally_checked_draft`, `no_candidate`, `rejected` остаются в знаменателе,
без ремонта или повторного запроса. Output создаётся exclusively, не перезаписывает
старый; accepted prose/private hashes не следует публиковать. Unit fakes проверяют
только контракт и не являются inference evidence.

Действуют те же [fixed source/GPU/decode bounds](local-instruct-runtime.md).
Step deadline 20 секунд — не hard cancellation GPU kernel. Нужен owned isolated
process с parent kill/reap, если необходим жёсткий предел. Диагностика не является
сервером, не меняет окружение оператора, не загружает веса из сети при inference.

[Численный отчёт](evaluation/owned-model-patches.json) содержит все **12 actual
generations** в трёх запусках с одним fixed checkpoint. Исходный минимальный
контекст: 0/4 candidates, три `no_candidate` и один deadline 20.021 секунды.
После добавления реально присутствующих SSH facts/команд baseline и более краткой
инструкции: 2/4 locally checked drafts + два отказа в исходниках и тот же результат
в установленном wheel. Оба принятых вида — SSHv1→SSHv2 для Cisco и JunOS;
Telnet cases по-прежнему `no_candidate`, не подменены templates.

В final source run первый ответ — 18.645 секунды, остальные 6.766–7.840;
installed — 18.783 и 7.993–8.151. Это generation, не cold model load/HTTP throughput.
Первый ответ не укладывается в default 10-second HTTP deadline; default не изменён.
Source/installed checks повторяют те же четыре owned cases; это prompt/context
development, не независимое качество или 12 независимых сетевых конфигураций.

Prose остаётся неподтверждённым даже при accepted edits: выбранный unapproved
baseline называется обязательной политикой, явная SSH-version противоречит фразе
об отсутствии override, отсутствие явной JunOS version интерпретируется как
недостаточная безопасность. Есть неподкреплённые attack/compliance assertions.
Strict schema и exact local edits не устраняют эти реальные семантические ошибки.
Raw answers/context/entity hashes остаются приватными; публичны только численные
observations, contract/model identity и SHA приватных reports.

[Actual ML pre/post supplement](evaluation/owned-model-patch-ml.json) проверил
оба ранее полученных SSH candidates настоящими native/external checkpoint weights:
восемь изолированных review/check процессов, exact source/candidate hashes и
неизменный local review. Новых LLM-вызовов нет: сохранённый actual answer только
локально replay-validated. Два Telnet-отказа остались без candidate/ML supplement.
Оба checkpoint имеют только `telnet_enabled` category head, **не SSHv1**; их
uncalibrated before/after scores не подтверждают качество исправления SSH.
ML evidence не меняет исходный `not_run` в local review и не повышает status.

## Незакрытый полный workflow

Отдельный [exact candidate → scoped network review](model-patch-network-review.md)
добавляет fresh source/answer binding и строит before/after network, не изменяя
исторический review. Есть два новых actual owned model requests на заранее
подготовленных полных toy sources: Cisco candidate, JunOS decline, плюс четыре
actual ML review/check процесса. Это не independent quality или SSH access proof.

Этот slice не заменяет arbitrary vendor patches, полный baseline/previous-config
diff, actual candidate-specific Batfish inputs/results, ML pre/post, engineer
approval transition или связанный API/UI round trip. Приватный candidate можно
передать в существующие отдельные ML/network review contracts только явно, с
точными inputs; они тоже не повышают статус автоматически. Real hardware syntax,
management access/rollback, real-confirmed data, independent semantic/adversarial/
citation evaluation и production deployment остаются открытыми.
