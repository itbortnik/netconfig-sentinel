# NetConfig Sentinel

Минимальная основа системы обнаружения аномалий в конфигурациях сетевых
устройств. Текущая итерация намеренно ограничена: она определяет Cisco IOS и
Juniper JunOS по содержимому, нормализует hostname и часть management plane и
сохраняет каждую неподдержанную команду вместе с номером строки и SHA-256.

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
- пятнадцать политик для management plane, наблюдаемости, ACL и маршрутизации;
- provenance для нормализованных значений;
- unit-тесты и полные golden JSON snapshots для четырёх безопасных конфигураций.

Неподдержанные строки не игнорируются: они попадают в `unparsed_fragments` и
снижают `parser_confidence`.

## Локальный запуск

Требуется Python 3.12–3.14.

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
mypy backend/app
pytest --cov=app --cov-report=term-missing
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
```

Поддерживаемая синтаксическая область и ограничения перечислены в
[`docs/supported-features.md`](docs/supported-features.md).

Реализованные требования безопасности описаны в
[`docs/policies/management-plane.md`](docs/policies/management-plane.md) и
[`docs/policies/observability.md`](docs/policies/observability.md), а проверки
ACL — в [`docs/policies/access-control.md`](docs/policies/access-control.md).
Маршрутные проверки описаны в [`docs/policies/routing.md`](docs/policies/routing.md).
