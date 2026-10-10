# Exact model candidate → scoped network review

`app.verification.model_patch` связывает уже полученный `GeneratedModelPatch`
с точным `PreparedPatchPrompt` и явно предоставленной полной сетью. Это library
контракт; HTTP explanation остаётся null-only, автоматического включения нет.

`prepare_model_patch_snapshots(generated, prepared=..., before=...)` заново
проверяет ответ, исходник, finding, prompt и candidate. Устройство выбранной
находки обязано присутствовать в snapshot с **точно теми же исходными байтами**,
что были до generation. Другие устройства сохраняются без изменений. После
замены снова проверяются local parsing, membership и device identity.
Отказ модели, неизвестный input, изменённый source/metadata/candidate не
становятся шаблонным патчем и не доходят до движка. Диагностика ошибки постоянная,
без исходника, model output или путей.

```python
report = check_model_patch_with_batfish(
    generated,
    prepared=prepared,
    before=explicit_before_snapshot,
    scope=ReachabilityScope(start_node="edge", destination="198.51.100.1/32"),
    allow_local_upload=True,  # Только после отдельного разрешения передачи.
    timeout_seconds=120,
)
```

По умолчанию загрузка запрещена. Явный opt-in передаёт только эти два snapshot
в существующий bounded [loopback adapter](batfish-verification.md). Возвращённый
результат заново связывается с обоими snapshot hashes и точным query scope.
`unavailable/error/incomplete/inconclusive/differences_found/no_differences_in_scope`
сохраняются как есть; никакой исход автоматически не повышает patch status.

Отдельный `ModelPatchBatfishReport` сохраняет source/candidate/finding/context
hashes и фактический Batfish result. Status всегда `needs_review`; approval,
device syntax, SSH access, model execution authentication и application — false.
Исторический `VendorDraft.review.preflight` не переписывается. Identifiers/hashes
могут быть конфиденциальными; JSON report не является публичным safe dump.

Нельзя дописать topology к ранее полученному minimal-source answer и объявить
его проверенным. IPv4 data-plane query не моделирует SSH protocol security,
реальную возможность входа, vendor CLI validation или rollback. Отсутствие
различий в одной области не доказывает безопасность всей сети. Последующие
[persistent verification/decisions](saved-model-patch-reviews.md) и
[UI](model-patch-interface.md) реализуют отдельный workflow с этими gates.
Он не является измеренной human identity, device/access/rollback проверкой или
полным actual LLM → ML → engine → approval experiment.

## Фактический owned кандидат

`python -m ml.instruct.patch_smoke ... --network-context --allow-owned-context
--output <new-private-report.json>` выполняет два actual offline model requests
на заранее authored двухузловых Cisco/JunOS sources. Это не реальные сети,
не independent benchmark и не большая обучающая выборка. Приватный output
содержит фактический model prose; не публикуйте его как безопасный отчёт.

При fixed Qwen3-4B revision `cdbee75f17c01a7cc42f958dc650907174af0554`
получен **один Cisco SSHv1→SSHv2 candidate**, JunOS вернул `patch_draft=null`.
Оба запроса сохранены: 18.844/5.945 секунды, 1802/1794 input tokens,
274/240 output tokens. Это generation, не cold load или production latency.
Hidden retries/template fallback не выполнялись. Prose всё ещё приписывает
неодобренному baseline обязательную policy authority и делает unsupported
attack/standards assertions; семантическое качество не подтверждено.

Публичная test fixture `backend/tests/fixtures/owned_model_network_edits.json`
содержит только проекцию **фактически полученных edits**, measured numbers и
hash bindings. Полные answers/context не раскрываются. CI replay использует
фиксированный тестовый prose envelope — это **не** оригинальное объяснение
модели и не новое inference. Hash приватного receipt обеспечивает traceability,
но сам по себе не аутентифицирует GPU execution или model identity.

[Actual ML supplement](evaluation/owned-network-model-ml.json): один Cisco
candidate прошёл два настоящих native/foundation review/check pairs — четыре
изолированных процесса, точные source/candidate bindings, local review неизменен.
JunOS decline не заполнялся и не проверялся как кандидат. У обоих checkpoint
есть только `telnet_enabled` head, не SSHv1; некалиброванные scores не являются
вердиктом о качестве исправления SSH. Никакой risk fusion/approval не выполнен.

Два candidate-specific queries уже выполнены настоящим Linux Batfish:
[измеренный job](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37797853650/job/113381879171)
и [численный отчёт](evaluation/owned-network-model-batfish.json). Для записанного
Cisco edit reachable scope дал 1→1 reachable rows / diff=0
(`no_differences_in_scope`), empty scope — 0→0 / diff=0 (`inconclusive`).
Обе own сети удалены, `needs_review` сохранён. В job прошли 26 tests,
включая эти два queries, прежние шесть engine queries и SDK transport cases.
Это один actual candidate, не два независимых патча. JunOS decline остался
без candidate-specific engine/ML проверки.

Общий CI run этого commit **не был успешным**: отдельное основное задание
остановилось на static type checking с вновь установленной Pydantic 2.14.0.
Успех engine job не подменяет статус всего run. Конструктор tagged training-report
union переведён на named type alias без отключения checking/discriminator и без
смены формата артефактов. Exact issue воспроизведён отдельно на 2.14; исправленный
тип проверен там же, а два actual train/save/load round trips и четыре invalid-tag
cases проходят на новом runtime. Основное локальное окружение 2.13.5 не изменено.

[Installed-wheel replay](evaluation/owned-network-model-installed.json) проверил
оба ранее полученных фактических ответа: exact source/context/candidate bindings,
неизменный review, default upload refusal и отсутствие подстановки JunOS candidate.
Пять runtime files byte-equal исходникам. Новых model/engine calls нет.
После compatibility fix local full suite: **1579 passed, 21 skipped**, четыре
dependency deprecation warnings;
24 binding/outcome tests входят в этот набор. Пропуски — 12 optional SDK,
8 live engine queries и один explicit PostgreSQL test. Ruff/mypy чистые,
187 typed source files на обеих платформах. Пропущенные queries не считаются pass.

Объединение уже полученных ML/formal supplements с exact source replay и
отдельным null-only explanation описано в [candidate review](candidate-review.md).
Проверка целостности общего отчёта не аутентифицирует движок или model execution.
