# Состояние готовности и границы приёмки

На 2026-10-09 реализован лабораторный гибридный workflow. **Полная готовность MVP
и production не подтверждена.** Эта карта связывает текущие возможности с
проверяемыми evidence, не заменяет качество тестов их количеством и не объявляет
неизвестные внешние условия выполненными.

## Минимальные функциональные gates

| Область | Фактическое состояние и evidence | Незакрытая граница |
| --- | --- | --- |
| Cisco/JunOS ingestion и canonical IR | [Поддержанный slice](supported-features.md), `backend/tests/golden/test_config_golden.py` | Не все команды/версии платформ, не vendor syntax qualification |
| Unknown commands/provenance | Сохраняются anchors/raw hashes/fragments; confidence снижается; partial suppresses risk | Unknown text остаётся конфиденциальным, не интерпретируется как безопасный |
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
edits. Он не меняет null-only HTTP schema и не закрывает полный patch workflow,
semantic quality, actual ML/formal recheck или engineer approval.

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
