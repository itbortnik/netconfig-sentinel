# NetConfig Sentinel

Система обнаружения аномалий в конфигурациях сетевых устройств на стадии
разработки. Поддерживает ограниченный набор конструкций Cisco IOS и JunOS,
детерминированные политики, сравнение с эталоном и лабораторные ML-эксперименты.
Неподдержанные команды сохраняются с provenance. Готовность к production,
формальная проверка достижимости и автоматическое применение не заявляются.

## Реализовано

- FastAPI с `GET /health` и `GET /ready`;
- строгие Pydantic-контракты `CanonicalConfig`, `SourceLocation` и `Finding`;
- независимый интерфейс `VendorParser` и явный registry адаптеров;
- Cisco IOS/IOS-XE: hostname, version, AAA, SSH/Telnet, SNMP, NTP и Syslog;
- JunOS в hierarchical и `set`-формате: hostname, AAA, SSH/Telnet, SNMP, NTP и Syslog;
- типизированные интерфейсы, logical units, IPv4/IPv6 CIDR, описание и явно
  заданное административное состояние;
- типизированные VLAN и access/trunk-параметры с разрешением JunOS VLAN-имён;
- типизированные Cisco ACL/prefix-list и JunOS firewall filter/prefix-list с
  адресами, протоколами, портами, действиями и provenance;
- типизированные IPv4/IPv6 static routes с next-hop, выходным интерфейсом,
  preference/administrative distance и discard-маршрутами;
- типизированный BGP-процесс и IPv4/IPv6-соседи с local/remote AS, router ID,
  iBGP/eBGP, группами, update source и административным состоянием;
- типизированный OSPFv2 с router ID, нормализованными area ID, Cisco network
  statements и JunOS interface membership, passive state и metric;
- детерминированный policy engine с воспроизводимыми ID находок;
- двадцать политик для management plane, наблюдаемости, ACL, маршрутизации и
  L2;
- детерминированный peer-group baseline с явным ключом группы, порогом
  консенсуса и проверяемыми отклонениями;
- сравнение с явно выбранной конфигурацией того же устройства;
- локальная проверка изменений до/после: новые, сохраняющиеся и исчезнувшие
  нарушения политик, отклонения от эталона и отдельная оценка риска по политикам;
- черновики изменений с привязкой к hashes снимков, закрытые локальные
  JSON-артефакты без перезаписи и повторная проверка их актуальности;
- экспериментальный opt-in адаптер Batfish для пары многодевайсных снимков
  и заданной области IPv4; живой запуск пока не подтверждён;
- привязка сетевого результата к черновику с проверкой всех входных fingerprints
  и повторным локальным анализом до загрузки в движок;
- воспроизводимый Isolation Forest на версионированной схеме из 33
  структурированных признаков;
- прозрачный risk fusion v1 с явными весами, статусами доступности и
  ограничителями для критических формальных результатов;
- строгий manifest происхождения, лицензии и разрешённых способов использования
  для локальных источников датасета;
- ограниченный безопасный импорт UTF-8 конфигураций и детерминированное
  обезличивание секретов, идентификаторов и IP-адресов до передачи дальше;
- многоуровневая дедупликация по исходному, обезличенному и нормализованному
  SHA-256 с проверяемым MinHash-поиском близких копий и группами шаблонов;
- детерминированное train/validation/test-разбиение с изоляцией сетей,
  площадок, устройств и duplicate-кластеров и явным аудитом времени;
- воспроизводимый отчёт качества с проверкой provenance, остаточных секретов,
  распределений, утечек между выборками и фактической готовности к PoC;
- детерминированный генератор 15 классов синтетических аномалий с точными
  строковыми изменениями, отдельными метками и обратными операциями;
- неперезаписываемые каталоги обезличенных датасетов с каноническим JSON,
  полным реестром файлов и проверкой SHA-256 при загрузке;
- provenance для нормализованных значений;
- сегментация Cisco IOS и JunOS на смысловые блоки с сохранением всех строк;
- локальный BPE-токенизатор: обучение только на train, версионированный словарь,
  окна до 1024 токенов и привязка токенов к исходным строкам;
- воспроизводимое CPU-обучение небольшого Transformer на задаче восстановления
  маскированных токенов, выбор эпохи по validation и проверяемые checkpoint;
- unit-тесты и полные golden JSON snapshots для четырёх безопасных конфигураций.

Неподдержанные строки не игнорируются: они попадают в `unparsed_fragments` и
снижают `parser_confidence`.

## Локальный запуск

Требуется Python 3.12–3.14.

Для проверки двух локальных конфигураций без запуска API доступна
[команда preflight](docs/change-preflight.md). Она выдаёт JSON-отчёт,
не изменяет файлы и не объявляет изменение формально проверенным.
Для сохранения и повторной проверки результата есть
[локальный сценарий черновиков](docs/patch-drafts.md).
Подготовка сетевых снимков, ограничения и включение внешнего локального
движка описаны в [Batfish-проверках](docs/batfish-verification.md).

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
uvicorn app.main:app --app-dir backend --reload
```

Для Linux/macOS отличается только активация окружения:

```bash
source .venv/bin/activate
```

После запуска доступны:

- API: <http://127.0.0.1:8000>
- OpenAPI: <http://127.0.0.1:8000/docs>
- liveness: <http://127.0.0.1:8000/health>
- readiness: <http://127.0.0.1:8000/ready>

## Проверки

```powershell
ruff check .
mypy backend/app ml
pytest --cov=app --cov=ml --cov-report=term-missing
```

## Docker Compose

```powershell
docker compose up --build
```

API будет доступно на `http://127.0.0.1:8000`. На этом этапе контейнеры БД,
Redis и Batfish не добавлены: текущему функциональному срезу они не нужны.

## Структура

```text
backend/app/
  api/                 HTTP endpoints
  domain/              канонические публичные контракты
  parsers/             определение вендора и независимые адаптеры
  ingestion/           будущий безопасный приём конфигураций
  normalization/       будущая нормализация расширенных объектов
  policies/            декларативный версионированный каталог политик
  detection/           policy engine, будущие детекторы и risk fusion
  verification/        будущая формальная проверка
  explanation/         будущие объяснения и RAG
  patching/            будущие предложения патчей
  audit/               будущий аудит
ml/
  datasets/            импорт, дедупликация, разбиение, качество и артефакты
  mutation/            обратимые синтетические аномалии и разметка
  training/            маскирование, encoder, CPU-обучение и checkpoint
  preprocessing/       детерминированное обезличивание конфигураций
```

Поддерживаемая синтаксическая область и ограничения перечислены в
[`docs/supported-features.md`](docs/supported-features.md).

Реализованные требования безопасности описаны в
[`docs/policies/management-plane.md`](docs/policies/management-plane.md) и
[`docs/policies/observability.md`](docs/policies/observability.md), а проверки
ACL — в [`docs/policies/access-control.md`](docs/policies/access-control.md).
Маршрутные проверки описаны в [`docs/policies/routing.md`](docs/policies/routing.md).
Проверки VLAN и switchport описаны в [`docs/policies/layer2.md`](docs/policies/layer2.md).
Модель сравнения сопоставимых устройств описана в
[`docs/baseline.md`](docs/baseline.md).
Сравнение параметров с явно выбранным эталоном того же устройства описано в
[`docs/expected-configuration.md`](docs/expected-configuration.md).
Статистическая контрольная модель описана в
[`docs/statistical-baseline.md`](docs/statistical-baseline.md).
Формула объединения риска описана в
[`docs/risk-fusion.md`](docs/risk-fusion.md).
Контракт источников данных и граница обезличивания описаны в
[`docs/dataset-ingestion.md`](docs/dataset-ingestion.md).
Алгоритм дедупликации и правила подсчёта уникальных конфигураций описаны в
[`docs/dataset-deduplication.md`](docs/dataset-deduplication.md).
Правила формирования изолированных обучающих выборок описаны в
[`docs/dataset-splitting.md`](docs/dataset-splitting.md).
Проверки качества и честный учёт готовности к PoC описаны в
[`docs/dataset-quality.md`](docs/dataset-quality.md), а формат сохраняемого
обезличенного набора — в
[`docs/dataset-artifacts.md`](docs/dataset-artifacts.md).
Контракт и границы генератора синтетических аномалий описаны в
[`docs/mutation-engine.md`](docs/mutation-engine.md).
Подготовка блоков и токенизатора для Config Transformer описана в
[`docs/config-tokenization.md`](docs/config-tokenization.md).
Первый тренировочный цикл и команда демонстрационного запуска описаны в
[`docs/mlm-training.md`](docs/mlm-training.md).
Классификатор синтетических мутаций поверх замороженного encoder описан в
[`docs/mutation-classification.md`](docs/mutation-classification.md).
Локализация добавленных и изменённых строк, включая ограничения для удалений,
описана в [`docs/line-localization.md`](docs/line-localization.md).
Диагностика ложных срабатываний и чувствительности к форматированию описана в
[`docs/localization-diagnostics.md`](docs/localization-diagnostics.md).
Экспериментальный порог по обучающим конфигурациям и измеренный компромисс между
ложными срабатываниями и пропусками описаны в
[`docs/line-operating-point.md`](docs/line-operating-point.md).
Эксперимент с расширением обучающих контекстов и его ограничения описаны в
[`docs/reference-context-experiment.md`](docs/reference-context-experiment.md).
Структурно разные лабораторные сценарии Cisco/JunOS, их происхождение и
результаты проверки описаны в [`docs/laboratory-dataset.md`](docs/laboratory-dataset.md).
Сравнение локализатора с простой TF-IDF-моделью описано в
[`docs/lexical-line-baseline.md`](docs/lexical-line-baseline.md).
Границы переноса на незнакомые типы изменений проверяются в
[`docs/unseen-mutation-diagnostics.md`](docs/unseen-mutation-diagnostics.md).
