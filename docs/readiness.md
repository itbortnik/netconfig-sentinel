# Состояние готовности и границы приёмки

На 2026-10-14 реализован лабораторный гибридный workflow. **Полная готовность MVP
и production не подтверждена.** Эта карта связывает текущие возможности с
проверяемыми evidence, не заменяет качество тестов их количеством и не объявляет
неизвестные внешние условия выполненными.

## Минимальные функциональные gates

| Область | Фактическое состояние и evidence | Незакрытая граница |
| --- | --- | --- |
| Cisco/JunOS ingestion и canonical IR | [Поддержанный slice](supported-features.md), включая [numbered standard IPv4 ACL](numbered-standard-acls.md); `backend/tests/golden/test_config_golden.py` | Не все команды/версии платформ, не vendor syntax qualification |
| Синтетические мутации | [Default 0.1 и opt-in hierarchical JunOS 0.2](mutation-engine.md): 15 IOS/14 JunOS классов, до пяти связанных изменений, точный откат и раздельные source/result spans удалений в 0.2 | Offline generator, не remediation или реальные подтверждённые labels; partial unknowns сохранены, device syntax/formal impact и независимое качество не проверены |
| Unknown commands/provenance | Сохраняются anchors/raw hashes/fragments; confidence снижается; partial suppresses risk. Новые uploads сохраняют [измеренное покрытие строк](parser-coverage.md), доступное в API/UI; явный [peer 0.3](baseline.md#measured-parser-coverage) сравнивает долю в library/CLI/API/UI и сохраняет полный report/profile и версионные объяснения | Не универсальный подсчёт vendor-команд или syntax check; исторические снимки без отчёта не пересчитываются. Peer 0.1/0.2 сохраняют confidence-deficit proxy; независимое реальное качество не подтверждено |
| Проверяемые политики | [30 уникальных rules](policy-catalog.md), positive/negative/version tests | Rule pass не доказывает достижимость или полноценную compliance |
| Reference/peers/Isolation Forest | Explicit inputs, persisted 0.1/0.2 comparison manifests, actual numeric scoring; [demo](demo-runbook.md). [Expanded 0.2 comparisons](expanded-comparisons.md) доступны в CLI/API/UI, добавляют management values/VLAN/ACL/routing, explicit partial skips и sealed sources | Не semantic equivalence/effective vendor defaults; authored functional checks не измеряют эксплуатационные false positives |
| Transformer pipeline и контрольные сравнения | Train-only native tokenizer, joint objectives/heads, source binding/save/load; [native transfer](pretraining-transfer.md), [external frozen transfer](foundation-config-transfer.md), [private registry](transformer-model-registry.md), [saved-analysis inference](configuration-model-inference.md), [парное anomaly-only сравнение с forest](paired-detection-comparison.md), [lexical control](lexical-line-baseline.md) | Tiny synthetic validation; недостаточный корпус, независимый paired benchmark/real calibration и qualified operational inference не закрыты |
| Finding evidence | UUID/source hashes/lines/provenance, detector-specific recomputation, golden finding snapshots | Отсутствующая настройка не получает вымышленную строку; статистическая attribution ограничена |
| Объяснение/RAG/LLM | Детерминированное объяснение, sealed versioned sources, actual document encoder, schema/citation-constrained transport, [actual offline instruct](local-instruct-runtime.md); [saved draft/review/decision API/UI](model-patch-interface.md) | Schema-valid outputs всё ещё содержат unsupported claims; independent semantic quality и квалификация полного реального candidate workflow не закрыты; vendor/internal library требует прав и отбора |
| Patch/formal gate | Native/normalized/source-bound model drafts; persisted replayable reviews и append-only decisions; [owned installed Linux queries](evaluation/owned-windows-linux-batfish.json), [standalone Compose](evaluation/owned-standalone-verification-compose.json) и [fresh saved-HTTP Qwen → CPU ML → live engine](evaluation/owned-joint-candidate-live-functional.json); no promotion without complete formal/ML/attestation gates | Один свежий JunOS draft получил actual scoped engine result; status остаётся needs_review, Telnet-only ML не квалифицирует SSHv1. Toy networks/explicit IPv4 scope не доказывают полную topology, management access, device syntax, individual identity или approved real engineer workflow |
| Unit/golden/integration/UI/CI | Actual checks и SQLite/PostgreSQL/Compose jobs; tests в `backend/tests`, `frontend/src`, `frontend/tests/browser`; [owned model browser workflow](evaluation/owned-model-candidate-browser-workflow.json) | Browser provider — synthetic loopback, не real inference. Passing fixture coverage не доказывает все реальные конструкции/деплой/hardware |
| Секреты/access/audit | Sanitization, encrypted at-rest API payload, service RBAC, receipt/completion journal, bounded uploads | Не доказательство отсутствия всех секретов; production secret scan/pentest/SSO/tenant/TLS/backup квалификация открыты |
| Запуск и демонстрация | README, [API](persistent-api.md), [UI](web-interface.md), [автоматический demo](demo-runbook.md) | Local demo — ASGI/SQLite, не production deploy или live network test |
| Раздельные метрики | [Общий evaluator](offline-evaluation.md) и origin/vendor/role/unseen slices; measured synthetic reports | Real-confirmed/independent-test данные отсутствуют; `missing` не означает ноль ошибок или пройденный gate |

## Количественные и модельные ограничения

Новая [explicit 0.4 registry/API/change интеграция](evaluation/owned-balanced-registry.json)
подключает существующий seed17 train-balanced checkpoint, не новый fit или
winning seed. Card 0.3 сохраняет TRAIN counts 32/560/592, coefficient 17.5,
task weight 1 и cost-sensitive/uncalibrated semantics. Complete retained
source/splits/annotations и encoded TRAIN ratio повторно проверяются до
allocation; rehashed metadata не подменяет objective. Actual installed run
выполнил два saved-HTTP CPU workers и четыре CLI review/check processes.
API/CLI parents не импортировали optional runtime; replay/restart после
отключения модели, consent/reader/wrong-pin refusals и удаление ephemeral DB
прошли. 266 старых hashes, OLD231 runtime files и NEW232 source byte equality
сохранены. Native 0.1/0.2/0.3 report/prediction parity и foundation-card parity
проверены; нового foundation inference не было. Все used sources — прежние
own toy inputs; новые реальные данные, calibration/threshold/LLM/engine calls
не добавлены. Telnet-only модель не квалифицирует SSH; needs_review/applied=false
сохраняются. Первый protocol не исполнялся из-за missing historical bindings;
второй завершил prediction parity/enrollment, но helper ошибся в поле upload
response до saved-HTTP ML workers. Эти попытки сохранены отдельно от completed
третьей, не выданы за pass.

Регрессия: 2891 backend pass / 15 skips / 5 warnings / 90% line coverage,
232-file mypy default/Linux/win32 и Ruff pass. Related installed regressions:
330 pass / два live skips на каждом parent Pydantic 2.13.5 и 2.14.0; worker
dependencies не наследуют overlay, checkout imports — zero. UI type/format/build,
503 unit, 158 regular и 22 model-candidate browser cases pass, zero retries.
Browser provider/score fixtures не actual ML quality. Exact-commit CI этой
новой поставки фиксируется отдельно; предшествующий
[c36b4d0 engine/evidence run](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38471600178)
имеет четыре success, но не принимается за CI текущего diff. Эта интеграция
продвигает §11.4/13B/16 функционально, не independent quality или полный MVP.

Последующий [task-rescaling experiment](pretraining-transfer.md#controlled-localization-task-rescaling)
добавляет три фактических fits к шести сохранённым контролям, не новые данные.
CLI позволяет явно настроить существующий `w3` без нового loss/report формата:
592/1120 из TRAIN при прежнем class ratio 17.5. Это нормирует средний row weight,
не градиенты/clipping/Adam или выбор эпохи. Девять исходов показывают неоднозначные
tradeoffs: line recall остаётся 0.75, FP 4/4/12; общий repair или winning coefficient
не подтверждён. Default/explicit 1 protocol/model parity, все пять first components,
173 исторических hashes и 231 installed files сохранены. [Отчёт](evaluation/owned-localization-task-rescaling.json)
раздельно называет candidate/reference в шести paired comparisons; описательные intervals
по двум hypothetical networks не являются independent quality. 2842 full passes /
27 skips, 91 focused + 32 final-module, 293 installed + 293 Pydantic 2.14 parent;
ruff/mypy default/Linux/win32 — pass. Новые local live-engine/БД/browser не запускались;
online workflow неизменён.
§13B/14 продвинуты как functional optimization; representative real labels,
independent test/calibration, модельное качество и полный MVP остаются открытыми.

Предыдущий [train-balanced localization experiment](pretraining-transfer.md#train-balanced-bilateral-line-objective)
добавляет фактически работающий opt-in Stage B loss и отдельный offline формат 0.4.
Шесть заранее фиксированных fits (seeds17/23/41 × unweighted/train-balanced,
20 updates) используют прежние 64 train/16 selection views; новых независимых
данных нет. Train-only коэффициент 560/32=17.5 поднимает line recall 0→0.75 во
всех трёх парах, но добавляет 4/4/8 ложных строк и неоднозначные anomaly/category
tradeoffs. Ни новый default, ни лучший seed, ни приёмка качества не объявлены.
Поддержаны source binding, save/load и общий evaluator; на момент этого
эксперимента registry/HTTP/change selection ещё не принимали 0.4. Последующая
explicit интеграция выше не переписывает эти результаты. Старые formats/policies, seed17 model identity
и 97 исторических файлов сохранены. [Numeric evidence](evaluation/owned-train-balanced-localization.json)
различает собственный weighted selection objective, common unweighted BCE,
AP/PR-AUC и все исходы; descriptive cluster intervals имеют только две authored
сети и не являются независимой оценкой. 2832 full passes/27 skips, 133 focused,
283 installed и 283 Pydantic2.14 parent checks; ruff/mypy default/Linux/win32 — pass,
231 installed runtime files побайтно совпадают. Новые local live-engine/БД/browser
runs не выполнялись. §13B/14 продвинуты в этом functional diagnostic slice;
representative real labels, calibration/test, model quality и полный MVP открыты.

Dataset pipeline проверяет manifest/use authorization, consistency sanitization,
deduplication, network/site/device/time isolation, mutations и фактические counts.
Плановые объёмы не достигаются копиями, форматными views или увеличением UUID.
Owned laboratory scenarios — не независимые реальные сети. Разрешённого большого
корпуса и подтверждённых реальных labels нет; такие метрики не публикуются как
измеренные. Feedback verdict не становится ground truth автоматически.
[Approved public-source intake](dataset-source-review.md) получил разрешение
пользователя на локальные research/training/evaluation/derivative uses без
публикации конфигураций. Получены 508 pinned entries/507 distinct raw blobs;
content preflight пропустил к диагностическому парсеру 411 примеров, из них 386
частичных. Остальные удержаны text/sanitization/residual/parser/file-review gates.
Последующий [v3 prefix-list preflight](evaluation/owned-prefix-list-sanitization.json)
добавил восемь entries: 419 parsed, 393 partial; прежние 422 sanitizable входа
побайтно одинаковы в paired v2/v3 run. Это не imported dataset или новые
независимые сети: capture/entity metadata
неизвестны; на момент этих preflights imported records/dataset bundles/training
runs были 0. Подтверждённые
аномалии и independent-network counts отсутствуют, не подменяются нулями.
Последующая поэкземплярная проверка `dataset-quality-0.3.0` дополнительно
удержала шесть ранее разобранных entries: текущий content preflight — 413 parsed,
387 partial/15 residual refusals. Это распознанные flags, не доказанные disclosures.
Старые preflights и отчёты не перезаписываются. Final scanner учитывает уже
обезличенный `pre-shared-key ascii-text` qualifier: два входа возвращены,
итого 415 parsed/389 partial/13 residual refusals. Значение до marker всё ещё
отклоняется; новые privacy/model-quality гарантии не заявлены.

Следующий [explicit fixture intake](evaluation/owned-source-fixture-intake.json)
фактически импортировал 415 одобренных входов через существующий local importer
и выполнил тот же content deduplication: 415 representatives, 0 найденных
exact/near links, 412 template groups. Это результат ограниченного алгоритма,
не доказательство отсутствия всех похожих файлов. Unknown network/site/device/
capture/role сохранены как `null`; дата acquisition записана отдельно, один
conservative source collection group не выдаётся за независимую сеть.
389 partial/40 warning-bearing inputs сохранены; segmentation принял 412
representatives (3445 structural blocks), три malformed structures отказаны.
Lexical approximation — 30819 tokens, не model tokenizer count. Исторический
manifest/import/dedup/split/quality contract не ослаблен: observed splitter,
full quality metrics, artifact writer и mutation lineage явно отказывают этому
record kind. На этапе intake частные staging JSON не были training-ready corpus;
bundles/train/selection/calibration runs по этому источнику тогда были 0.
Последующая [train-only интеграция](configuration-pretraining.md#train-only-source-fixtures)
повторяет source permissions/inventory/current content/dedup gates, явно удерживает
три malformed structures и обучает тот же движок на 412 fixtures/3445 blocks/
4569 windows/**142500 content BPE tokens**. Это 46610 параметров и две фиксированные
эпохи, не ориентиры большого корпуса или pretrained foundation encoder.
Train weighted loss 19.0544→18.4906; validation/test/real-confirmed metrics остаются
`null`, selection/calibration не выполнялись. Installed replay сохраняет идентичную
model identity; повторный run не добавляет независимых данных. Обычный objective
transfer не принимает этот отдельный train-only bundle. Последующий explicit
[fixture-aware transfer](pretraining-transfer.md#approved-train-only-source-fixtures---supervised-heads)
повторяет retained corpus/targets checks и сравнивает все 415 upstream members с
64 downstream contents: 26560 пар, source/raw/sanitized/normalized/template/near
overlaps не наблюдались. Это audit доступных split representatives/derivatives,
не доказанная физическая изоляция, chronology или потерянная duplicate metadata.
Фактический encoder обучает общие heads: 3993 trainable/50603 total parameters,
48 train/12 selection views исходных 24 owned configs; save/load и installed replay
сохраняют predictions/model identity. Fixed-threshold anomaly/category F1 и line
recall **0**, четыре injected positives пропущены. На момент transfer measurement
новый 0.3 формат был offline-only. С 2026-10-11 explicit private registry admission
повторяет exact retained corpus/annotation/exposure validation и сохраняет
отдельную 0.2 card с неизвестной физической изоляцией. Opt-in saved-analysis API/UI
и source-bound pre/post поддерживают зарегистрированный checkpoint, без risk fusion,
calibration/activation или изменения истории. Independent representative labels,
calibration/test и real operational qualification остаются открытыми.
Исторические intake/Stage A/transfer метрики не переписываются.

Локальная регрессия [fixture registry/API/UI интеграции](evaluation/owned-source-fixture-registry.json):
2667 passed/27 skipped/5 прежних warnings; ruff и mypy default/Linux/win32
229 runtime files — pass. Pydantic 2.14: 176 focused checks; установленный пакет:
68 checks, 229 runtime files побайтно одинаковы, старые artifacts/predictions
не изменились. Выполнены два actual CPU saved-HTTP workers и четыре CLI pre/post
review/check процесса; отдельно прошли 489 frontend unit, 156 desktop/mobile и
22 model-candidate browser tests с synthetic providers. Независимое code review
закрыло linked-input-path и native-only dependency находки; оно не является
независимой оценкой качества ML. Новые локальные live Batfish/PostgreSQL runs
не выполнялись; их skips не засчитаны как pass.

Следующее [fixture-backed paired comparison](paired-detection-comparison.md#fixture-backed-native-03-и-тот-же-контрольный-лес)
фактически сравнивает тот же 0.3 checkpoint с двумя vendor forests на полной
общей таблице из 12 authored selection views. Forest fit использует только
16 original train parents; оба детектора пропустили четыре injected positives,
F1=0. Новый route сохраняет retained source/exposure binding, а не переносит
несовместимый старый external checkpoint на другую truth table. Это закрывает
функциональный control-comparison разрыв этой версии, не independent benchmark,
calibration, реальные labels, unknown-site quality или приёмку всего MVP.
Регрессия comparison slice: 2677 full passes/27 skips/5 прежних warnings,
40 source и 40 installed targeted checks, 130 Pydantic 2.14 checks;
ruff/mypy default/Linux/win32 — pass. Установленный runtime побайтно совпадает
с исходниками; новый двухмодельный сценарий и старый трёхмодельный сохраняют
numeric parity без требования равенства measured timings. Исторические отчёты,
веса и Stage35 predictions не изменены. Scope и hashes — в
[отдельном evidence](evaluation/owned-source-fixture-comparison.json).

Exact registry-integration commit `01b06e002c499c7266c313ec3723edc8fa97d563`
имеет [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38124186294).
Следующий exact comparison commit `fefa9c61d61815a4d9bace4dba0aeb60124c812f`
также имеет [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38124970228).
Эти runs не являются CI следующей parser-поставки или independent quality evidence.

Последующий [numbered standard IPv4 ACL slice](numbered-standard-acls.md) добавляет
global IOS permit/deny facts в существующий IR/30-policy catalog. На тех же 415
retained approved inputs paired old/new installed census распознал ещё 23 строки
в девяти входах: accepted 1387→1410, unparsed 3738→3715 при неизменном command
denominator 5125; partial inputs 389→388. Один другой вход получил только явный
warning для неподдержанной ACL-команды; всего изменились десять fresh parse results,
405 сохранили те же canonical/coverage/features/findings.
Добавился один configured `acl.unrestricted_permit` finding с точной строкой;
это не подтверждённая реальная аномалия, attachment или effective traffic verdict.
Старые reports/snapshots/coverage/модельные файлы не переписываются. Retained corpus
audit и exact source/annotation/exposure validation существующего 0.3 checkpoint
сохраняются без нового inference/обучения. Границы: extended numbered ACL,
noncontiguous wildcards, options и mixed numeric named/global edits остаются unknown.
Локальная регрессия [parser-slice evidence](evaluation/owned-numbered-standard-acls.json):
2749 full passes/27 skips/5 прежних warnings, 170 source и 170 installed targeted
checks, 118 Pydantic 2.14 checks; ruff/mypy default/Linux/win32 — pass. Установленные
229 runtime files побайтно совпадают с исходниками; четыре golden inputs неизменны.
Независимое ревью выявило numeric-name alias, исправление повторно проверено.
Новые local live Batfish/PostgreSQL/browser runs не выполнялись. Позднее exact parser
commit `26241441643e5bb38fa3bb72c6842bf99402a04d` получил
[все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38126586501).
Это не CI следующей LLM-поставки и не полная vendor/ML/MVP приёмка.

Следующий [saved-analysis explanation context](local-model-explanations.md) передаёт
модели actual saved status и explicit peer report counts, сохраняет их через strict
redaction allowlist и помечает отсутствующие syntax/network/access/rollback checks.
Старой истории, sealed knowledge и risk/verifier state изменения не приписываются.
[Actual повтор Qwen](evaluation/owned-explanation-facts-http.json) сохраняет две
development итерации на тех же четырёх authored случаях: 8 measured attempts,
6 completed/schema-and-citation accepted, 2 deadline rejections. Два peer summaries
финальной инструкции теперь называют actual completed/3 peers/19 features, но
unsupported CLI/storage/peer-bias claims остаются. Semantic quality и default
ten-second budget не квалифицированы; новое factual context не закрывает §17
целиком, independent LLM/RAG evaluation или весь MVP.
Локальная регрессия: 2777 passed/27 skipped/5 прежних warnings, 225 installed
targeted checks и 225 Pydantic 2.14 parent checks; ruff/mypy default/Linux/win32
230 runtime files — pass. Все 230 files побайтно совпали с installed target;
actual API и GPU imports исключают checkout. Live Batfish/PostgreSQL/browser
локально не запускались; предыдущий parser CI не считается CI этой поставки.
Позднее exact explanation commit `48c40f4eb11c8237bb70eb9a293272c233ff48c1`
получил [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38129428779),
включая PostgreSQL, Compose/browser и owned live-engine scenarios. Это evidence
точной поставки, не semantic quality или CI следующего ML diagnostic report.

Следующая [диагностика бюджета Stage B](pretraining-transfer.md#fixed-optimizer-budget-diagnostic)
фактически обучила шесть заранее заданных моделей на прежних 48 train/12 selection
views: seeds 17/23/41 × 20/200 full-batch updates, без изменения source, labels,
весов компонентов loss или strict 0.5 thresholds. Первые 20 losses каждой пары совпали точно;
исходная seed-17 модель побайтно воспроизведена. Все шесть исходов сохранены.
При 200 шагах selected epochs 38/68/42 дают anomaly/category F1 0/0.4/0 и line
recall 1/1/0.5; тот же rescored forest имеет F1 0. Это sensitivity diagnostic,
не выбранный лучший checkpoint, уникальная причина отказа или quality pass.
Метрики относятся к restored selected epochs, не последнему шагу 200; к нему
validation loss выросла до 6.129/3.129/4.353 при падающей train loss.
Один длинный run обнаружил только один из четырёх positives, остальные — ни одного.
Cisco-positive support всё ещё отсутствует; generator/vendor/line imbalance,
calibration и independent real test остаются открытыми. Новые 132 связанные
regression checks прошли; шесть actual fits/save-load round trips использовали
230 byte-equal installed runtime files. Runtime contracts и история не менялись;
новые local live-engine/БД/browser прогоны не выполнялись.

Позднее exact optimizer-report commit `60c13146100cb674dbb99a1fac69981b5fa380c4`
получил [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38130301367).
Это CI предыдущей публикации, не новой bilateral поставки и не quality gate.

Следующий [explicit bilateral Telnet scenario](pretraining-transfer.md#explicit-bilateral-telnet-scenario)
добавляет Cisco-positive supervision без изменения default legacy и истории.
Те же 24 authored parents и entity/capture/split memberships дают 64 train/16
selection views с positive/negative support обоих vendors; это не новые
независимые конфигурации или физические сети. Новый source ID и raw hashes
привязаны к действительно изменённому authored тексту до sanitizer. Generic
dedup/split/exposure/annotation checks сохранены; reserved test не размечается.

Фактический [installed run](evaluation/owned-bilateral-fixture-transfer.json)
на default seed17/20 steps выбрал epoch20: anomaly F1 0.85714 (6/8 positives,
0 false positives), category F1 0.66667, line recall **0** (0/8). Cisco обнаружил
4/4 positives, JunOS 2/4; новый forest control пропустил 8/8 на той же полной
truth table. Parent context и баланс изменились вместе, поэтому это не causal
shortcut repair или paired improvement относительно старых 12 views. Selection
переиспользуется; real-confirmed, independent-test и calibration fit отсутствуют.
80 исторических файлов неизменны; оба installed packages совпали по полному
legacy input и всем 60 predictions старой модели. Source encoder сохранён,
80 новых predictions прошли save/load. 34860 полных content comparisons не
доказывают физическую независимость upstream fixtures. Online activation,
production quality и formal/vendor-syntax acceptance не заявлены.

Локальная регрессия bilateral slice: 2790 passed/27 skipped/5 warnings,
coverage 18871/20883 lines, 113 installed checks и 113 Pydantic 2.14 parent checks.
Два последних model/admission mismatch случая включены в full/installed suites;
ранний source-focused run содержит 111 checks до их добавления. Все 230 runtime
files побайтно совпадают с installed package; parent каждого свежего installed
targeted run загрузил 101 app/ml modules из выбранного target, без checkout. Проверяющий обнаружил,
что исходные targeted children брали checkout: эти первые runs подтверждали
installed origin только parent. Исправленные четыре fixture children выбирают
roots фактически импортированных app/ml packages и проверяют каждый module file;
свежие installed/compat runs повторены с этими guards. Isolated subprocesses
используют default dependencies, не наследуют Pydantic override. Ruff и mypy
default/Linux/win32 — pass. Новый local live Batfish/PostgreSQL/browser run не
выполнялся; 27 explicit skips не считаются успехом, exact-commit CI ожидается
отдельно после публикации.

Позднее exact bilateral commit `c2d5f15b62c4c06ffb1ff795782fe5fa5ef19977`
получил [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38154444968),
включая PostgreSQL, Compose/browser и owned live-engine checks. Это evidence
точной runtime-поставки, не следующего diagnostic report или real/model quality.

Последующая [диагностика строковой головы](evaluation/owned-bilateral-line-localization.json)
использует тот же selected bilateral checkpoint без нового обучения: все 32 train
и 8 selection positive anchors попадают в encoder features и positive targets;
batch/single scores согласованы, selected validation loss component воспроизведён.
Положительные targets — лишь 32/592 и 8/148 строк (5.405%), несмотря на баланс
конфигурационных классов. Все положительные line scores ниже 0.069 при strict 0.5:
recall остаётся 0 даже на train. Line AP train/selection — 0.34029/0.42500,
Cisco/JunOS selection — 0.20000/0.66667. Selection BCE 0.18160 ниже train-prevalence
constant reference 0.21028, но обе decision rules пропускают все positives.
Отсутствие targets/score mapping drift в этом сценарии исключено; единственная
причина, приемлемое качество, calibration или исправление imbalance не доказаны.
94 retained source/model/report files неизменны; no new fit/threshold/activation,
reserved test features/labels не используются. Требования §13B/14 остаются
частично выполненными, не закрываются более низким loss или существованием heads.
Независимый numerical review обнаружил повторный sigmoid на vendor-shaped slices:
ULP tie changes меняли Cisco AP, несмотря на allclose. Report исправлен до публикации:
все ranking slices используют одни single-record scores без пересчёта sigmoid,
BCE остаётся на original full-batch logits. Оба private attempts сохранены;
это исправление diagnostic metric path, не модели, truth или нулевого recall.

[Frozen explanation audit](evaluation/owned-frozen-explanation-assertions.json)
сохраняет полный denominator восьми прежних попыток: шесть accepted rechecked
schema/citations, два deadline — content unavailable. В ограниченных dimensions
четыре доступных answers имеют flags: три CLI-only claims, два отсутствия
persistence и одно отрицание передачи чисел противоречат actual workflow/context;
одно bias assumption не подтверждено, но не названо доказанно ложным фактом.
Отдельное условное storage-утверждение без opt-in поддержано и не включено в
contradictions. Exact citations membership не подтверждает перенос historical
library scope на текущий saved HTTP workflow. Это не exhaustive claim labels,
human ground truth, semantic error rate или независимое качество; два неотмеченных
reference answers не объявлены правильными. Новых inference/retrieval/fit/Batfish
нет; frozen inputs и история сохранены, runtime semantic gate не добавлен.
§17 остаётся частично выполненным, model prose не повышает фактические статусы.

Exact diagnostic commit `f61579d78188d5646718a845831f577ce6804bc8` позднее получил
[все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38155973374).
Это CI прежних audits, не следующего invocation-context изменения и не model quality.

Следующий [caller-context slice](local-model-explanations.md) вводит отдельные
strict server-derived facts текущего saved HTTP invocation: stored analysis,
selected peer profile и model draft, не сохраняемый в analysis. Это не storage
guarantee для client/gateway/logs. Offline/historical missing metadata остаются
unknown; выбранная reference/policy finding не получает storage другой peer
finding. Redaction повторно проверяет closed allowlist; consent/response schemas,
sealed documents, сохранённые analyses и прежние audit/context bindings не меняются.

[Actual installed repeat](evaluation/owned-invocation-facts-http.json) сохранил
4/4 completed/schema-and-citation accepted Qwen drafts на тех же четырёх owned
cases; comparator retained 3 accepted/1 unavailable deadline, без missing-case
intersection. Веса/source/observed/expected/docs и saved status/counts прежние,
finding fingerprints связаны с новыми run identities. Прежние CLI-only/безусловные
nonpersistence assertions не наблюдаются, оба peers называют stored profile и
completed/3/19/0. Это не causal repair или semantic-quality gate: два references
категорично исключают network/syntax issue без verifier, один добавляет unsupported
operational inaction rule; два peers расширяют nonstorage на target с ambiguous
scope, Juniper assumes representative selection без evidence. Qualified opt-in
library storage statements не названы current nonpersistence contradictions.
Шесть dimensions перечислены до generation, labels выбраны вручную после неё;
не exhaustive или human ground truth. Omission of old claims не делает draft правильным.

Четыре consent refusals до модели, saved/restart reads неизменны; gateway завершён,
временная owned БД удалена. Первый request 19.022 s не укладывается в default 10 s;
diagnostic 20 s не меняет default, retries/warm-up/activation отсутствуют. Новых
weights, independent cases, ML fit, Batfish и пересчёта старых answers нет.
§17/independent LLM/RAG quality/production остаются частично выполненными.

Регрессия этого slice: 2810 passed/27 skipped/5 warnings, coverage 18898/20906;
138 nearest checks, 245 installed и 245 Pydantic 2.14 parent checks — pass.
Все 230 runtime files побайтно совпали с installed target, actual API 123/GPU 57
и targeted parent 130 imports происходят из target без checkout. Isolated child
dependencies не наследуют Pydantic override. Ruff/mypy default/Linux/win32 — pass.
Новый local live Batfish/PostgreSQL/browser run не выполнялся; 27 skips не pass,
exact-commit CI этой поставки фиксируется отдельно после публикации.

Локальная проверка [этой интеграции](evaluation/owned-source-fixture-pretraining.json):
2575 full passes/27 skips/5 warnings, 156 nearest regression и 156 Pydantic 2.14
checks; ruff/default+win32 mypy 225 runtime files — pass. Installed wheel побайтно
совпадает с runtime: два isolated children, 35 old/38 new app/ml target imports,
51 новая проверка и actual source retraining с той же model identity. Сохранены
старый полный six-record quality JSON, семь файлов dataset artifact и четыре
файла actual objective bundle; прежний native train/validation run дал идентичные
полный report и веса. Новые local live engine/DB/browser проверки не запускались.
Точный предыдущий fixture-intake commit `1b11c06abdea95af6dd0dae713b63d2b9b01b84d`
имеет [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38046558911);
это не exact-commit CI новой train-only поставки и не independent model quality.
Позже exact train-only commit `9959397e33f5709bea3ae604b763d1314f28ee3e`
получил [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38048804671).
Это не CI новой fixture-transfer поставки и не real model/source qualification.

Исторический actual joint transfer использует 24 owned configs/12 hypothetical network labels,
16 train/4 validation/4 reserved test configs. Stage A — 52,725 параметров;
Stage B — 3,993 trainable параметра, 48/12 derived train/validation views.
Measured anomaly/category F1 и line recall равны **0** на selection diagnostics.
Это работающий pipeline, но не приемлемое качество детектора; reserved test не
переиспользуется для поиска лучшего решения. Severity в этом запуске выключен.
Есть tokenizer/window/source alignment, все пять head interfaces и configurable
loss; нет оправдания переносить scores в production risk или считать их calibrated.

Multilingual MiniLM фактически загружен и используется для **документного** поиска.
Он не выдается за Config Transformer, instruct LLM или config-pretrained foundation.
Отдельный external transfer использует настоящие hidden token features этих
замороженных весов для конфигурационных adapter/heads: 114521 trainable,
20 epochs, F1/line recall=0. Это не документные cosine vectors, attention LoRA
или независимое качество; внешняя pretraining exposure явно неизвестна.
Раздельный temperature/threshold fitting реализован, но нужен независимый
размеченный calibration cohort, а не epoch-selection validation.

## Какие evidence ещё нужны

[Source-intake evidence](evaluation/owned-batfish-source-intake.json) фиксирует
human approval, pinned blob/size/hash checks и локальный premetadata content
preflight. Общий scanner не ослабляет полный dataset gate: 2370 full passes/
27 skips/5 warnings, 32 final focused и 32 actual Pydantic 2.14 checks; ruff/mypy
223 files на обеих платформах. Installed wheel: 223 runtime файла побайтно,
13 target imports в каждом из двух isolated children, восемь content checks и
неизменный полный quality report шести authored legacy records. Новые live
engine/DB/browser/model checks для этого slice не выполнялись. Для upstream
collection всё ещё нужны metadata-aware import, дедупликация, допустимая изоляция
и репрезентативный размеченный корпус; content preflight не закрывает эти gates.

Explicit [v3 CIDR preprocessing](dataset-ingestion.md#sanitization) покрывает
positive IOS/XE prefix-list entries, не новые команды парсера; v1/v2 не меняются.
Отдельная поставка: 2435 full passes/27 skips/5 warnings, 149 focused и 149
Pydantic 2.14 passes, ruff/default+win32 mypy 223 files. Installed wheel сверяет
223 runtime файла и все 29 app/ml imports нового child; 65 authored checks,
включая шесть import/parse/segment/mutate/reverse/quality/artifact round trips.
Два isolated children сохранили прежний полный quality report. Actual upstream
preflight не пишет bodies/keys и не создаёт fake network/capture metadata;
независимое качество, source corpus import и реальные метки остаются открыты.
Для предыдущей поставки shared scanner commit
`ec3b202992a116e090254030fb997b6026e5d8b8` все четыре
[CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38043151359)
успешны. Это не новый exact-commit CI для v3 preprocessing.

[Per-occurrence residual gate](evaluation/owned-residual-content-gate.json)
закрывает authored mixed-redaction bypass и повторяет текущий content check до
новой записи даже при hash-bound legacy report. Новые отчёты имеют версию 0.3;
старые 0.2 читаются без переоценки/изменения истории. Проверены 2480 full passes/
27 skips/5 warnings, 142 focused и 142 Pydantic 2.14 checks, ruff/mypy 223 files
на обеих платформах. Installed wheel: 223 runtime файла, 13 old/29 new target
imports в двух children, 45 новых и 65 prefix-list authored проверок; фактически
созданный старым пакетом учебный артефакт прочитан новым без изменения семи файлов.
Current upstream preflight допускает 415 entries, не корпус/ground truth.
Preceding prefix-list commit `d487e30b8ee5cfcff059907f39cccdfe027e6d62` имеет
[все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38044023526):
2435 backend passes/27 skips, 35 main Batfish + два saved-HTTP checks, 282 PG
passes/2 skips/4 deselected, 478 frontend unit/154 regular/22 synthetic/154 Compose
browser checks. Это не exact-commit CI для нового residual gate или source data
network qualification; сырые/обезличенные upstream configs остаются локально.

Позже exact residual commit `2907f9497a2602fc06abdd9b07f01f5c315e9ff4`
получил [все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38045127858):
2480 backend passes/27 skips, 35 owned Batfish + два saved-HTTP checks,
282 PG passes/2 skips/4 deselected, 478 frontend unit/154 regular/22 synthetic/
154 Compose browser. Эти проверки не загружают upstream corpus в движок и не
квалифицируют новый fixture-intake commit или качество реальных данных.

[Explicit unknown-metadata intake](evaluation/owned-source-fixture-intake.json)
проверен сквозным локальным source run, 44 новыми authored cases и 161 nearest
regression/Pydantic 2.14 cases. Final frozen suite: 2524 passes/27 skips/5 warnings;
ruff/default+win32 mypy 223 runtime files — pass. Installed wheel побайтно
совпадает с рабочим runtime: два isolated children, все app/ml imports из
выбранного target, 44 fixture cases + повторная проверка 415 approved records.
Полный six-record quality JSON предыдущего пакета побайтно неизменен, настоящий
старый artifact прочитан без изменения семи файлов. Это functional compatibility
и local content intake, не независимая оценка модели. Новые CI на момент записи
этого отчёта ещё не запускались; предыдущие зелёные jobs не выдаются за новые.

[Hierarchical JunOS mutation evidence](evaluation/owned-hierarchical-junos-mutations.json)
проверяет opt-in offline 0.2: 14 классов, связанные изменения, source preservation,
точный откат и корректные final source/result spans удалений. Локально: 2314 full
passes/23 skips/5 warnings, 173 связанных проверки, 173 focused Pydantic 2.14 checks,
ruff/mypy 223 files на обеих платформах. Frontend 478 unit/typecheck/format/build
прошёл; local browser для offline изменения не перезапускался. Installed wheel:
68 генераций/откатов/JSON round trips, 16 отказов, 29 исторических flat образцов
с неизменной полной сериализацией; imports проверены в каждом из пяти children.
Это один authored parent в четырёх форматных views, не рост независимого корпуса.
Синтетическая метка не становится real-confirmed, а пустые result lines при
удалении — здоровым line target. Новые sample-specific Batfish/device checks и
обучение на этих примерах не выполнялись; существующий review engine не запускается
генератором автоматически. Независимое качество и quantitative gates открыты.
Отдельные [owned network integration cases](batfish-verification.md#сгенерированное-удаление-hierarchical-junos-маршрута)
подготовлены для именно generated hierarchical route deletion, reachable baseline,
direct peer и empty scope. Local no-upload checks не считаются выполненными
network queries; требуется новый exact-commit `batfish-live` run. Исторический
formal status образца остаётся `not_run`, даже при отдельном последующем query.
Локальная поставка network cases: 2318 full passes/27 skips/5 warnings,
226 связанных passes/10 live skips и 53 focused Pydantic 2.14 passes/10 live skips;
ruff/mypy на обеих платформах чистые. Четыре no-upload сценария выполнены также
через прежний installed wheel: все 223 runtime файла побайтно прежние, imports
31 app/ml модуля проверены из установленного target. Authored test functions
исполнялись из checkout; это не independent test или live engine evidence.
Первый [live job этой интеграции](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38039746950/job/114177442737)
на `a74eba03752f9dcc38e9d02688b19e32d481c249` неуспешен: все четыре generated/control
попытки вернули `incomplete / initialization_issues` до reachability queries.
Очистка собственных сетей подтверждена, счётчики запросов отсутствуют, не равны
нулю. Это не инфраструктурный pull-limit и не formal pass. Диагностический
[повтор](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38040115561/job/114178500349)
показал fatal warning: v1 sanitization оставлял ненулевые host bits в static
network CIDR. Ограниченная [v2 CIDR policy](dataset-ingestion.md#sanitization)
выбирается явно, не пересчитывает старые данные или model defaults. Исправленный
сценарий использует её для configs и query destinations. Последующий
[actual job](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38041061060/job/114181229521)
измерил route loss 1→0/diff=1, unchanged/direct-peer 1→1/diff=0, empty scope
0→0/inconclusive; cleanup всех четырёх сетей успешен. Это одна toy topology,
не 14 qualified классов, device syntax или независимое качество. История отказов
сохранена в [report](evaluation/owned-generated-route-batfish.json).
Неизвестные CIDR роли и separate IPv4 masks в v2 отклоняются,
а полная топологическая эквивалентность обезличивания не доказана.
Локальная регрессия исправления: 2362 passes/27 skips/5 warnings, 255 связанных
passes/4 live skips, 193 focused Pydantic 2.14 passes/4 live skips; ruff и mypy
223 files на обеих платформах чистые. Новый installed wheel проверяет все 223
runtime файла, 33 loaded imports, четыре no-upload случая и import/segment/
generate/reverse round trip. Отдельная installed regression повторила 68
hierarchical samples/undo/JSON round trips и 29 flat serializations с прежним
полным checksum; это не 68 независимых parent или измерение detector quality.

[Измеренное покрытие исходных строк](evaluation/owned-parser-coverage.json)
добавлено вне canonical IR: новые uploads/API/история/UI используют фактические
source units и явный знаменатель, не `1 - parser_confidence`. Проверены 2044 full
backend passes/23 skips/5 warnings, 416 frontend unit checks, 134 обычных и 22
synthetic-model browser cases; installed wheel — четыре upload/analysis/restart
сценария, один legacy snapshot и четыре неизменных golden canonical пары.
Принятость адаптером не равна полной семантике или vendor syntax validation.
Явная peer 0.3 реализация сравнивает эту долю в library/CLI/API/UI, сохраняя 19 property
templates, partial skips и полный source-bound report/profile в encrypted history;
корректный подсчёт строк не доказывает качество на независимом реальном корпусе.
[Отдельный local report](evaluation/owned-measured-peer-local.json): 2113 full
backend passes/23 skips/5 warnings, 82 связанных проверки, 28 actual installed
CLI процессов с проверкой imports в каждом child. UI regression: 416 unit checks,
typecheck/format/build; browser не перезапускался для library/CLI изменения.

[Отдельный API/UI report](evaluation/owned-measured-api-comparisons.json): 2175 full
backend passes/23 skips/5 warnings, 37 связанных API checks, 135 focused Pydantic
2.14 checks, 478 frontend unit tests и 154 regular browser scenarios. Отдельные
22 model-browser cases используют synthetic provider, не настоящую LLM.
Installed wheel проверяет 12 analysis/restart scenarios, legacy refusal без
переразбора, reference-only без coverage и шесть исторических explanation replays.
Knowledge 0.4 запечатан из published 5cb7cd1; старые 24 документа не меняются.
Три actual installed API → CPU document-worker requests используют настоящий
44-row индекс. Шесть повторно использованных authored queries дают hit@1/hit@4
5/6, не independent retrieval quality. Diagnostic deadline 40 s не квалифицирует
default 20 s или SLA; child import introspection не выполнялся. Эти local checks
не заменяют PostgreSQL/Compose/live-engine прогон точной новой поставки.
Для точного API/UI commit `20c5b26f378d8725578d69371b4f6bd465c1edce`
[все четыре CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37999329652)
завершились успешно, включая PostgreSQL, Compose/browser и owned live-engine scope.
Это подтверждение этой поставки, не последующих мутаций, полной реальной сети
или независимого качества модели.

Предыдущий library/CLI commit `5cb7cd1fa1ad7d26b156526ad0e978418aeb8962` имеет
[все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37995756443),
включая PostgreSQL, Compose/browser и owned live-engine scope. Это evidence этого
точного предыдущего commit, не новых API/UI изменений или полной реальной сети.

Поставка coverage `216e785afe0a8d553e175231c0a05ec182db642e` имеет неуспешный
[CI run](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37993422878):
основной test успешен; PostgreSQL service pull остановился на auth timeout и
unauthenticated Docker Hub rate limit. Frontend прошёл unit/build/134 обычных и
22 synthetic-model browser checks, но Compose остановился на auth timeout при
загрузке PostgreSQL. Batfish service pull встретил auth timeout и тот же rate
limit. Это не успешные
PostgreSQL/Compose/live проверки текущей поставки; причины service pull не
подменяются результатом теста приложения.

Предыдущий commit `ffea49008ba75ec09d21d4282bda7bc7361e5bdd` имеет неуспешный
[CI run](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37989882251),
включая повтор failed jobs: основной test прошёл, PostgreSQL/Batfish не смогли
загрузить services из-за unauthenticated Docker Hub rate limit. Frontend прошёл
unit/build/локальные browser checks, но Compose также остановился на pull.
Это не pass внешних сред и не подтверждение текущего изменения старым зелёным CI.

Actual model candidate теперь имеет [отдельный bound network review](model-patch-network-review.md):
два свежих owned Qwen requests (Cisco candidate/JunOS decline), четыре actual ML
review/check процесса и два actual Linux Batfish queries именно Cisco edit.
Data-plane scope не подтверждает SSH security/access, device syntax или approval.
Теперь есть отдельный [сохранённый API/UI workflow](model-patch-interface.md):
выбор exact source/baseline/network, consent, durable local/formal/ML reports,
replay и решения инженера. [Browser evidence](evaluation/owned-model-candidate-browser-workflow.json)
использует synthetic provider, не новые Qwen/ML/Batfish вызовы; pending projection
в одном сценарии также synthetic. [Saved HTTP live evidence](evaluation/owned-saved-model-review-live.json)
проверяет настоящим Linux engine только два authored scopes с synthetic provider,
а [installed ML evidence](evaluation/owned-installed-saved-patch-review.json) —
два actual CPU workers на неизменном старом recorded answer. Это функциональные
проверки разных частей, не совместная независимая квалификация реального патча,
полной topology, approved baseline, личной identity или эксплуатационного доступа.
Independent quality остаётся открытым. Исторический network-review report сохраняет
type-check failure своего общего run отдельно от успешного engine job; последующие
[четыре CI jobs UI-поставки](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37962285379)
успешны для commit `acececd3a324e0fb5ad350e07c44977cbf1e729c`.

Следующий [fresh saved-HTTP functional run](evaluation/owned-joint-candidate-functional.json)
связывает новые четыре Qwen outputs непосредственно с durable generation/review,
а не replay старого ответа: один Cisco SSHv1 draft и три declines (Cisco Telnet,
JunOS SSHv1/Telnet), без retries или fallback. Для принятого exact candidate
выполнен один actual installed CPU ML worker; native модель только Telnet не
квалифицирует SSHv1. Local SDK отсутствует: formal `unavailable/sdk_missing`,
counts/cleanup неизвестны, engine executions — ноль. Approval заблокирован даже
при всех synthetic attestations; диагностическое `needs_more_information` не
является решением установленного человека. Replay/restart/consent/encryption/
неизменность source/analysis прошли, 231 runtime files byte-equal и 226 прежних
hashes сохранены. Четыре reused cases — производные двух toy networks, не
independent test и не прирост корпуса. Полный actual engine/human workflow,
device syntax/access/rollback, ML calibration и semantic/citation quality открыты.

[Bounded source-support audit](evaluation/owned-joint-candidate-source-support.json)
отдельно воспроизвёл неподтверждённое утверждение модели об одобрении baseline;
во входе было `approval=not_proven`. Null/schema validity не доказывают truth.
Сохранённая UI-подпись теперь явно отделяет baseline selection/unknown approval
от model prose, доступна reader и не меняется от несохранённого выбора формы.
Это не автоматический semantic verifier. Related installed checks: 223 pass и
два live skips на каждом parent Pydantic 2.13.5/2.14.0, 166 target imports,
без checkout imports. UI: typecheck/format/build, 489 unit и 22 synthetic model
browser и 156 regular browser pass, без retries. После первоначального прерывания
по ресурсу read-only follow-up завершил независимые binding/projection/UI checks
и bounded source-support audit всех четырёх ответов; прежняя receipt сохранена.
Более слабое baseline-as-obligation interpretation и ambiguous removal limitation
не считаются равно доказанными ошибками. Unsupported не означает доказанно false;
exhaustive semantic review и independent quality gate по-прежнему не заявлены.

На следующем разрешённом этапе per-user Docker Desktop 4.95.0 / WSL2 запущен
без новых admin actions или reboot. [Installed Linux run](evaluation/owned-windows-linux-batfish.json)
с pinned Batfish 2026.08.27.3685 дал 25 pass / 88 deselected / zero skips:
14 real verifier attempts, 3 differences / 6 no differences / 5 inconclusive,
14 successful SDK network cleanup. Два saved HTTP случая здесь используют
synthetic provider, не новую модель. [Отдельный standalone Compose run](evaluation/owned-standalone-verification-compose.json)
не требует API/DB credentials и не запускает их сервисы: 10 pass / шесть real
queries (по два differences/no differences/inconclusive), затем zero own
container/network/volume resources. Старые own diagnostic resources тоже
удалены после ID/label проверки; unrelated resources не удалялись. Это не secure
disk erasure или air-gap: actual bridge `internal=false`, host bind loopback.
Общий application Compose profile этим отдельным запуском не квалифицирован.

[Новый fresh Qwen/CPU ML/live-engine run](evaluation/owned-joint-candidate-live-functional.json)
сохраняет четыре новых model generations: один Cisco SSH API failure, два
Telnet declines и один JunOS SSH draft, без retries/fallback. Неуспешный raw
output не принят. Только draft получил actual CPU rerun и actual IPv4 Batfish:
1→1 reachable / diff=0 / cleanup=true. Raw uncalibrated anomaly score вырос
0.3296065629→0.3307287693; Telnet-only модель не поддерживает SSHv1. Approval
заблокирован, status needs_review, applied=false. Device syntax/access/rollback
не объявлены выполненными, diagnostic service-role decision не human identity.
Все 231 runtime files byte-equal, 240 прежних hashes сохранены; источники старше
generation, но topology_pinned_at_generation=false. Предыдущий sdk_missing run
остаётся историческим unavailable, не переписан. Новый [bounded support audit](evaluation/owned-joint-candidate-live-source-support.json)
снова подтвердил unsupported baseline approval claim; последующая engine
проверка не исправляет model truth. Independent review проверил bindings,
projection и bounded claims, не независимое качество моделей или новых сетей.

Локальный backend regression run с установленным optional SDK: 2855 pass /
15 skips / 5 warnings, total line coverage 90%, 343.68 s. Live opt-in и PostgreSQL
skips не считаются pass; отдельные разрешённые engine runs перечислены выше.
Full run собран до добавления трёх optional-Compose regression cases; отдельный
финальный config-only набор дал 4 pass. Ruff и mypy (231 source files) прошли.
UI-код не менялся; новый local browser или PostgreSQL run не выполнялся.
Это проверки функциональной поставки, не independent quality; новый exact-commit
CI следует проверять отдельно после публикации.

Runtime/test commit `5ff1c8fab24f7b8719d07c93be0579c1e0369438` имеет
[все четыре успешных CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38357446237).
Предыдущий `58b88f97e20e5bc76a23741620cffb76d17d6e87` сохраняет
[frontend failure](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38354602394):
browser history читала тело HTTP response после навигации. Узкая test-only правка
подписывает waiter после `goto` и читает body сразу, без retries/timeout увеличения
или ослабления ML/history assertions. Этот CI относится к указанному commit,
не переносится на последующие UI/evidence изменения.

[Expanded local comparison evidence](evaluation/owned-expanded-local-comparisons.json)
фиксирует новую opt-in 0.2 реализацию management/VLAN/ACL/routing comparisons,
1903 full local passes/23 skips/5 warnings и 12 actual installed CLI processes.
Следующая [API/UI/installed поставка](evaluation/owned-expanded-api-comparisons.json)
добавляет явный выбор версии, encrypted profile/evaluation, historical replay и
sealed knowledge 0.3. Локально: 1952 full passes/23 skips/5 warnings, 370 UI unit
tests, 116 обычных и 22 synthetic-model browser сценария. В installed package
проверены 14 analyses/restart round trips и четыре настоящих isolated document
worker requests; новых instruct/Batfish вызовов в этом workflow нет. Новый index
даёт hit@1 и hit@4 по 5/6 на прежних authored queries, не independent quality.
Production, реальные подтверждённые labels и calibration не закрыты.

Поставка comparisons `37ee1192cd61070211c351a01c7e710f59760960` и PostgreSQL follow-up
`67460e21823c7043c07201692282d8631bd460d2` имеют все четыре успешных CI jobs
([comparison run](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37984221007),
[PostgreSQL run](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37984627396)).
Во втором отдельная PostgreSQL-задача включает expanded scenarios: 222 passes,
два live-engine skips, два deselected native-worker cases; это не новое качество моделей.
[Четыре actual Qwen comparison explanations](evaluation/owned-expanded-instruct-http.json)
приняты структурно, но содержат неподтверждённые safety/partial-status утверждения.
Модельные scores, semantic truth, стандартный десятисекундный deadline и production
по этим authored cases не квалифицированы; анализы сохранены неизменными.

- Авторизованные обезличиваемые конфигурации, provenance/license/allowed uses,
  реальные подтверждённые annotations и entity-isolated networks/sites/time cohorts.
- Квалифицированный instruct service, independent/adversarial/semantic/citation
  evaluation actual outputs: pinned checkpoint и owned генерации уже доступны,
  но schema validity не устраняет наблюдённые неподтверждённые утверждения.
- Доверенный deployment Batfish engine и разрешение явно выбранных loopback uploads;
  полные реальные network inputs/scope, candidate-specific before/after results
  и representative failure coverage. Локальный Windows/WSL2 Linux engine и один
  свежий scoped candidate теперь фактически проверены, но не заменяют эти условия.
- Разрешённая vendor/internal документация и reviewed ingestion, retrieval quality
  на независимых queries; project policies не заменяют vendor corpus.
- Representative model/baseline evaluation, неизвестные площадки, обе платформы,
  роли/реальные labels, calibration/latency/parser coverage на целевых ресурсах.
- Отдельные production deployment, TLS/identity/tenant, secret management,
  backup/restore/pentest и hardware/access/rollback испытания.

GNN/temporal не активируются вместо этих gates: это post-MVP расширения,
сейчас явно ограниченные interfaces. Автоматическое подключение/применение
production-команд не входит в этот workflow и не добавляется ради демонстрации.

## Как проверять следующую поставку

Проверяйте конкретный commit и все его CI jobs, а не наличие старого зелёного run.
Повторите lint/type checks, связанные unit/golden/integration тесты, UI/browser
проверки и installed-wheel сценарий. Сопоставьте measured outputs с hashes
точной модели/корпуса/thresholds и источников. Артефакты/checksums — evidence
целостности, не издательская подпись, label truth или успешная внешняя проверка.

Для published external-transfer этапа
[CI всех трёх jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37641564421)
успешен. Local baseline этого этапа: 1319 backend tests passed, live Batfish и
explicit local PostgreSQL test skipped; PostgreSQL/Compose проверены отдельно
этим CI. External pre/post review также имеет
[успешные три CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37642765987).
Local full suite с paired comparison: 1363 passed, те же два explicit skips;
ruff и mypy на обеих платформах чистые, 13 installed-wheel сценариев пройдены.
Published paired comparison имеет
[успешные три CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37646999268).
Local full suite с private Transformer registry: 1398 passed, те же два skips;
ruff/mypy чистые, все 14 installed-wheel сценариев пройдены. Registry не закрывает
online deployment, calibration или quality gates. Published registry имеет
[успешные три CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37677295661).
Demo имеет свои integration tests и [измеренный отчёт](evaluation/owned-workflow.json).
Эти факты не закрывают перечисленные недостающие evidence.

Local full suite с explicit instruct runtime: 1451 passed, те же два skips;
ruff и mypy на обеих платформах чистые, все 15 installed-wheel сценариев пройдены.
Полные Qwen weights проверены; 16 actual
owned generations в четырёх source/installed runs отражены в
[numeric report](evaluation/owned-instruct.json), включая неудачные исходные
запуски. Последние schema-valid 4/4 + 4/4 не доказывают factual/citation quality:
принятые drafts всё ещё содержат unsupported claims. Online model activation,
MVP acceptance, vendor patch generation и production quality не заявлены.

Отдельный [actual owned HTTP report](evaluation/owned-instruct-http.json) фиксирует
четыре ответа настоящей модели через установленный пакет, четыре отказа без
consent до модели и неизменность сохранённых analysis. Временный gateway принимал
только точные owned contexts; deadline 20 секунд был явным параметром диагностики,
не изменением default 10 секунд или активацией сервиса оператора. Это functional
evidence простого explanation пути, не semantic quality или полного patch workflow.
Published instruct runtime имеет
[успешные три CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37686408823).

Отдельный [offline model patch slice](model-patch-drafts.md) добавляет actual
affected command context, выбранный baseline и строгую проверку model-generated
edits. Он не меняет null-only explanation HTTP schema. Последующие
[saved generation](saved-model-patches.md), [reviews/decisions](saved-model-patch-reviews.md)
и [UI](model-patch-interface.md) реализованы отдельно; раздельные actual LLM/ML/
engine measurements не доказывают semantic quality или полный actual chain
с подтверждённым инженером, device syntax, management access и rollback.

Local full suite этого slice: 1497 passed, два explicit skips; ruff и mypy на
обеих платформах чистые. [12 actual model-patch generations](evaluation/owned-model-patches.json)
и все 16 installed-wheel сценариев проверены на той же сборке. Measured runs
содержат исходный deadline/отказы и два final source/installed runs по 2/4 accepted
SSH drafts + 2/4 `no_candidate`. Все четыре cases повторяются при разработке
контекста, не являются independent test. Наблюдённые prose contradictions и
unsupported claims сохраняются; локально проверенный edit не равен semantic truth.
Published actual explanation HTTP evidence имеет
[успешные три CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37687171335).
Published source-bound model patch также имеет
[успешные три CI jobs](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37732025615).

Для двух actual SSH candidates выполнены восемь native/external ML review/check
процессов ([отчёт](evaluation/owned-model-patch-ml.json)); scores не калиброваны,
SSH category отсутствует в этих trained heads. Это functional pre/post evidence,
не ML repair verdict. Два Telnet-отказа не заменены патчами.

[Encrypted private model receipts](model-patch-receipts.md) сохраняют exact
answer/candidate/context/model bindings и обязательный `needs_review` либо отказ.
Есть [installed four-output round trip](evaluation/owned-encrypted-model-receipts.json)
без нового inference и с отказом по неверному ключу; key был diagnostic ephemeral,
не production backup. Local full suite: 1520 passed, прежние два explicit skips;
ruff/mypy на обеих платформах чистые. API activation, identity authentication,
semantic truth, engineer approval и production key management не заявлены.
Все 17 installed-wheel сценариев этого этапа пройдены: 16 регрессионных и
encrypted receipt round trip; они не заменяют оставшиеся quality/external gates.
