# Source-bound candidate review facts and optional explanation

`app.patching.candidate_review.build_candidate_review` объединяет local replay,
явно переданный `ModelPatchBatfishReport` и до четырёх `MLChangeReview`.
Это library boundary, не новое HTTP activation и не сертификат выполнения.

Каждая сборка заново проверяет исходный `GeneratedModelPatch`, finding, source,
candidate и оба полных snapshot через existing source-bound replay. Network
result должен совпадать по device/source/candidate/finding/context/snapshot hashes
и точной IPv4 query scope. Каждый ML supplement должен содержать тот же local
review и независимо выбранный model SHA-256. Duplicate selections, foreign
sources/scope, missing pins, stale candidate или status promotion отклоняются
постоянной ошибкой без частных значений. Объект считается конфиденциальным,
даже если содержит только hashes и диагностические числа.

```python
review = build_candidate_review(
    generated,
    prepared=prepared,
    before=explicit_before_snapshot,
    scope=explicit_scope,
    network_result=already_obtained_network_report,
    ml_reviews=(already_obtained_ml_review,),
    expected_model_sha256s=(independently_selected_model_sha256,),
)
```

Функция не запускает модель, не передаёт конфигурацию движку, не пишет файл и
не меняет прежний `preflight.formal_verification=not_run`. Отсутствующие результаты
остаются отсутствующими. Все шесть Batfish outcomes сохраняются; empty scope
остаётся inconclusive, reachability differences требуют review, неизвестный
cleanup не становится успешным. Поддержка нужного category head не доказывает
качество/калибровку модели. `missing_checks` выводится из фактов, а не принимается
как произвольный вердикт. Status всегда `needs_review`, approval/application,
execution authentication и semantic truth — false.

## Separate null-only explanation

`app.explanation.candidate_review` готовит только явный local opt-in контекст
`candidate-review-context-0.2.0`. До вызова provider полностью пересобираются
review и prompt; canonical hash всего report защищает даже не экспортированные
category scores от незамеченного изменения. Hash binding — не authentication.

Original finding и whitelisted management block помечены **before change**,
management facts/actual edits кандидата — **after change**. Diff до выбранного
baseline отделён от patch change; baseline approval не устанавливается.
Предыдущее model prose не повторяется. Node names/IP scope и raw engine version
не экспортируются; scope/engine identity представлены hashes, которые всё ещё
могут быть конфиденциальными. RAG содержит закреплённые внутренние документы,
не внешние vendor manuals или утверждённую организационную политику.

Fixed `ReviewDraftAnswer` null-only schema требует human review, максимум два
пункта в каждом списке и 120 whitespace-delimited words во всех строковых значениях,
включая citations. Duplicate JSON keys, неверные типы, unretrieved/duplicate
citations и превышение bounds отклоняются. Эти ограничения проверяют структуру
и source membership, **не правдивость свободного текста**. Provider вызывается
один раз; retry, repair, template fallback и новый patch запрещены.

`LocalInstructProvider(..., allow_candidate_review=True)` разрешает только эту
fixed instruction/schema пару. Флаг точный boolean и независим от
`allow_patch_draft`; defaults, existing HTTP null-only contract и `.env` не меняются.
Нельзя использовать прежнюю instruction «verification was not run» для review,
к которому действительно приложен scoped verifier result.

## Actual owned diagnostics

[Numeric projection](evaluation/owned-candidate-review.json) сохраняет все четыре
actual offline Qwen review generations: две пары на **одном** ранее полученном
Cisco SSHv1→SSHv2 candidate и его reachable/empty scopes. Два existing ML results
и записанные actual Linux Batfish results повторно связаны с источником; новых
ML inferences, engine queries или patch generations здесь нет. JunOS decline
не заполнен. Это prompt development, не independent test или проверка реальной сети.

Первая версия контекста дала 1 schema-valid / 1 rejected answer. Принятый текст
ошибочно приписал кандидату исходный SSHv1 и SSH category support Telnet-only
моделям. Raw bytes отклонённого первого ответа не были сохранены; точная причина
его отказа неизвестна. Эти результаты не удалены и не переименованы в успех.

Пересмотренный before/after контекст дал **0 accepted / 2 rejected**: оба ответа
превысили review-only list limits; фактические word counts тоже выше 120.
Raw rejected bytes и exact prompts сохранены только в private diagnostics.
При осмотре текст уже различает before SSHv1 и after SSHv2, но по-прежнему делает
необоснованные общие compliance assertions. Это не semantic qualification.
Четыре остающиеся local policy findings и отсутствие baseline approval не исчезают.

Generation timings: первая пара 19.690/11.069 s, вторая 19.291/6.391 s,
не включая cold model load. Explicit diagnostic deadline — 20 s; HTTP default
10 s не повышен. Ни один текст не approved recommendation, статус патча не повышен.
При отказе объяснения deterministic report остаётся доступным, без выдуманного
LLM answer. Full API source handoff, durable workflow и engineer approval остаются
отдельными незавершёнными gates; real confirmed model quality также не доказана.

Local full suite: **1656 passed, 21 skipped**, четыре dependency deprecation
warnings; 82 focused report/provider/runtime cases входят в этот набор.
Optional SDK, live engine и PostgreSQL skips не считаются успешными проверками.
Ruff и mypy проходят для 189 source files на default/win32 platforms.
[Installed-wheel replay](evaluation/owned-candidate-review-installed.json)
восстановил exact prompts/reports для двух actual recorded review outputs,
отклонил оба без retry, проверил byte identity трёх новых/изменённых runtime files
и default upload refusal. Модель/движок не загружались, новых generations нет.
