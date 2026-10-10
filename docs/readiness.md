# Состояние готовности и границы приёмки

На 2026-10-10 реализован лабораторный гибридный workflow. **Полная готовность MVP
и production не подтверждена.** Эта карта связывает текущие возможности с
проверяемыми evidence, не заменяет качество тестов их количеством и не объявляет
неизвестные внешние условия выполненными.

## Минимальные функциональные gates

| Область | Фактическое состояние и evidence | Незакрытая граница |
| --- | --- | --- |
| Cisco/JunOS ingestion и canonical IR | [Поддержанный slice](supported-features.md), `backend/tests/golden/test_config_golden.py` | Не все команды/версии платформ, не vendor syntax qualification |
| Синтетические мутации | [Default 0.1 и opt-in hierarchical JunOS 0.2](mutation-engine.md): 15 IOS/14 JunOS классов, до пяти связанных изменений, точный откат и раздельные source/result spans удалений в 0.2 | Offline generator, не remediation или реальные подтверждённые labels; partial unknowns сохранены, device syntax/formal impact и независимое качество не проверены |
| Unknown commands/provenance | Сохраняются anchors/raw hashes/fragments; confidence снижается; partial suppresses risk. Новые uploads сохраняют [измеренное покрытие строк](parser-coverage.md), доступное в API/UI; явный [peer 0.3](baseline.md#measured-parser-coverage) сравнивает долю в library/CLI/API/UI и сохраняет полный report/profile и версионные объяснения | Не универсальный подсчёт vendor-команд или syntax check; исторические снимки без отчёта не пересчитываются. Peer 0.1/0.2 сохраняют confidence-deficit proxy; независимое реальное качество не подтверждено |
| Проверяемые политики | [30 уникальных rules](policy-catalog.md), positive/negative/version tests | Rule pass не доказывает достижимость или полноценную compliance |
| Reference/peers/Isolation Forest | Explicit inputs, persisted 0.1/0.2 comparison manifests, actual numeric scoring; [demo](demo-runbook.md). [Expanded 0.2 comparisons](expanded-comparisons.md) доступны в CLI/API/UI, добавляют management values/VLAN/ACL/routing, explicit partial skips и sealed sources | Не semantic equivalence/effective vendor defaults; authored functional checks не измеряют эксплуатационные false positives |
| Transformer pipeline и контрольные сравнения | Train-only native tokenizer, joint objectives/heads, source binding/save/load; [native transfer](pretraining-transfer.md), [external frozen transfer](foundation-config-transfer.md), [private registry](transformer-model-registry.md), [saved-analysis inference](configuration-model-inference.md), [парное anomaly-only сравнение с forest](paired-detection-comparison.md), [lexical control](lexical-line-baseline.md) | Tiny synthetic validation; недостаточный корпус, независимый paired benchmark/real calibration и qualified operational inference не закрыты |
| Finding evidence | UUID/source hashes/lines/provenance, detector-specific recomputation, golden finding snapshots | Отсутствующая настройка не получает вымышленную строку; статистическая attribution ограничена |
| Объяснение/RAG/LLM | Детерминированное объяснение, sealed versioned sources, actual document encoder, schema/citation-constrained transport, [actual offline instruct](local-instruct-runtime.md); [saved draft/review/decision API/UI](model-patch-interface.md) | Schema-valid outputs всё ещё содержат unsupported claims; independent semantic quality и квалификация полного реального candidate workflow не закрыты; vendor/internal library требует прав и отбора |
| Patch/formal gate | Native/normalized/source-bound model drafts; persisted replayable reviews и append-only decisions; [six owned Linux queries](evaluation/owned-batfish.json) и [saved HTTP candidate live scope](evaluation/owned-saved-model-review-live.json); no promotion without complete formal/ML/attestation gates | Live evidence — игрушечные сети/explicit IPv4 scope с synthetic provider; отдельные actual ML workers — replay старого draft. Не полная топология, management access, device syntax, individual identity или approved real engineer workflow |
| Unit/golden/integration/UI/CI | Actual checks и SQLite/PostgreSQL/Compose jobs; tests в `backend/tests`, `frontend/src`, `frontend/tests/browser`; [owned model browser workflow](evaluation/owned-model-candidate-browser-workflow.json) | Browser provider — synthetic loopback, не real inference. Passing fixture coverage не доказывает все реальные конструкции/деплой/hardware |
| Секреты/access/audit | Sanitization, encrypted at-rest API payload, service RBAC, receipt/completion journal, bounded uploads | Не доказательство отсутствия всех секретов; production secret scan/pentest/SSO/tenant/TLS/backup квалификация открыты |
| Запуск и демонстрация | README, [API](persistent-api.md), [UI](web-interface.md), [автоматический demo](demo-runbook.md) | Local demo — ASGI/SQLite, не production deploy или live network test |
| Раздельные метрики | [Общий evaluator](offline-evaluation.md) и origin/vendor/role/unseen slices; measured synthetic reports | Real-confirmed/independent-test данные отсутствуют; `missing` не означает ноль ошибок или пройденный gate |

## Количественные и модельные ограничения

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
неизвестны, imported records/dataset bundles/training runs пока 0. Подтверждённые
аномалии и independent-network counts отсутствуют, не подменяются нулями.
Последующая поэкземплярная проверка `dataset-quality-0.3.0` дополнительно
удержала шесть ранее разобранных entries: текущий content preflight — 413 parsed,
387 partial/15 residual refusals. Это распознанные flags, не доказанные disclosures.
Старые preflights и отчёты не перезаписываются. Final scanner учитывает уже
обезличенный `pre-shared-key ascii-text` qualifier: два входа возвращены,
итого 415 parsed/389 partial/13 residual refusals. Значение до marker всё ещё
отклоняется; новые privacy/model-quality гарантии не заявлены.

Actual joint transfer использует 24 owned configs/12 hypothetical network labels,
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
  evaluation actual outputs: pinned checkpoint уже выбран и 16 owned генераций
  выполнены, но schema validity не устраняет наблюдённые неподтверждённые утверждения.
- Доверенный deployment Batfish engine и разрешение явно выбранных loopback uploads;
  полные реальные network inputs/scope, candidate-specific before/after results
  и representative failure coverage. Шесть owned Linux queries подтверждены,
  но не заменяют эти условия.
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
