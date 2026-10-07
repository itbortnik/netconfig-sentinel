# Состояние готовности и границы приёмки

На 2026-10-07 реализован лабораторный гибридный workflow. **Полная готовность MVP
и production не подтверждена.** Эта карта связывает текущие возможности с
проверяемыми evidence, не заменяет качество тестов их количеством и не объявляет
неизвестные внешние условия выполненными.

## Минимальные функциональные gates

| Область | Фактическое состояние и evidence | Незакрытая граница |
| --- | --- | --- |
| Cisco/JunOS ingestion и canonical IR | [Поддержанный slice](supported-features.md), `backend/tests/golden/test_config_golden.py` | Не все команды/версии платформ, не vendor syntax qualification |
| Unknown commands/provenance | Сохраняются anchors/raw hashes/fragments; confidence снижается; partial suppresses risk | Unknown text остаётся конфиденциальным, не интерпретируется как безопасный |
| Проверяемые политики | [30 уникальных rules](policy-catalog.md), positive/negative/version tests | Rule pass не доказывает достижимость или полноценную compliance |
| Reference/peers/Isolation Forest | Explicit inputs, persisted manifests, actual numeric scoring; [demo](demo-runbook.md) | Synthetic functional checks не измеряют эксплуатационные false positives |
| Transformer pipeline и контрольные сравнения | Train-only native tokenizer, joint objectives/heads, source binding/save/load; [native transfer](pretraining-transfer.md), [external frozen transfer](foundation-config-transfer.md), [private registry](transformer-model-registry.md), [парное anomaly-only сравнение с forest](paired-detection-comparison.md), [lexical control](lexical-line-baseline.md) | Tiny synthetic validation; недостаточный корпус, независимый paired benchmark/real calibration и qualified HTTP inference не закрыты |
| Finding evidence | UUID/source hashes/lines/provenance, detector-specific recomputation, golden finding snapshots | Отсутствующая настройка не получает вымышленную строку; статистическая attribution ограничена |
| Объяснение/RAG/LLM | Детерминированное объяснение, sealed versioned sources, actual optional document encoder, schema/citation-constrained provider transport | Настоящая instruct-модель и её качество не проверены; vendor/internal source library требует прав и отбора |
| Patch/formal gate | Native source-bound draft и normalized API draft; replayable local checks; no status promotion without formal inputs | Live Batfish не подтверждён; безопасный management access/device syntax/engineer approval не реализованы как квалифицированный end-to-end переход |
| Unit/golden/integration/UI/CI | Actual checks и SQLite/PostgreSQL/Compose jobs; tests в `backend/tests`, `frontend/src`, `frontend/e2e` | Passing fixture coverage не доказывает все реальные конструкции/деплой/hardware |
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

- Авторизованные обезличиваемые конфигурации, provenance/license/allowed uses,
  реальные подтверждённые annotations и entity-isolated networks/sites/time cohorts.
- Выбранный доверенный instruct checkpoint/server, права использования и ресурсы;
  schema/adversarial/citation evaluation actual outputs, не synthetic wire response.
- Доверенный Batfish engine и разрешение явно выбранных loopback uploads;
  поддержанные network inputs/scope, actual before/after results и failure coverage.
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
online deployment, calibration или quality gates.
Demo имеет свои integration tests и [измеренный отчёт](evaluation/owned-workflow.json).
Эти факты не закрывают перечисленные недостающие evidence.
