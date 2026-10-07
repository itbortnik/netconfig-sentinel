# Воспроизводимая демонстрация

Это проверка работы реализованных границ на собственных синтетических fixtures,
не реальный dataset, квалификация модели или подтверждение готовности MVP.
Конфигурации реальных устройств, внешние API и сетевое оборудование не нужны.

## Автоматический локальный сценарий

После `python -m pip install -e ".[dev]"` из корня репозитория:

```powershell
python -m app.demo.cli --output artifacts/owned-demo-v1
```

Родительский каталог должен существовать, выбранный output — отсутствовать.
Команда создаёт **свою новую SQLite**, временные service keys/Fernet key и
собственные конфигурации Cisco/JunOS. Она не мигрирует рабочую БД, не выбирает
клиентские файлы и не наследует operator storage/model/provider settings:
фиксированный child-процесс запускается с минимальным OS environment и `-I`.
Токены/ключи существуют только в памяти и не выводятся/не сохраняются.
Deadline — 60 секунд; таймаут/ошибка дают обобщённый отказ, не успех.
Это изоляция настроек, не OS sandbox или доказательство отсутствия любых
возможностей сторонних Python-зависимостей.

Через настоящие ASGI endpoints, но **без TCP-сервера/браузера**, для каждого
вендора выполняются:

1. Миграция собственной БД, health/ready, восемь разных owned training snapshots.
2. Actual Isolation Forest training и его явный выбор вместе с эталоном/тремя peers.
3. Policy/peer находка Telnet и отдельное различие access VLAN с выбранным эталоном.
4. Локальное объяснение, finding fingerprint и hash-bound project citations.
5. Запрос недоступной instruct-модели → 503; оценка инженера и идемпотентный повтор.
6. Exact сохранённая policy finding → native candidate → source-rebuilding recheck.
7. Загрузка candidate того же устройства, нормализованный diff и объектный draft.
8. Reader write → 403; инженерный local review и его идемпотентный повтор.
9. Явная недоступная formal-проверка → 503, без фиктивного `validated` или новой
   успешной VerificationRun. Изменение остаётся `draft/needs_review/not_run`.
10. Неизвестная команда → `partial`, raw unknown fragment сохранён, risk отсутствует.
11. Новый экземпляр приложения читает неизменную историю analysis/draft/review/model/feedback.
12. Admin проверяет receipts/completions всех выбранных запросов, включая отказы;
    хранилище содержит аутентифицируемые encrypted payload, не их plaintext.

Local/native/API drafts остаются разными representations: API хранит IR и не
восстанавливает raw source; native генератор читает exact original. Telnet recipe
не исправляет отдельное отклонение VLAN или оставшиеся policy findings.
Отсутствие выбранной находки после изменения не доказывает безопасную сеть.

## Результат и повторный запуск

В новом каталоге остаются:

- `report.json` — только счётчики/наблюдения и явные false-flags качества;
- `demo.sqlite3` — isolated encrypted fixture history, без сохранённого Fernet key;
- `cisco/` и `juniper/` — owned original и private native draft с candidate/export.

SQLite payload намеренно нельзя повторно расшифровать после завершения без
временного ключа, который не сохраняется: это одноразовая демонстрация,
**не** рабочее хранение/backup.
Не используйте такую стратегию для настоящих данных. Ключ рабочей БД нужно
сохранять по [runbook API](persistent-api.md), не генерировать при каждом запуске.

Код 0 — успешная функциональная демонстрация, не MVP acceptance; stdout — маленький
JSON без raw content, ключей и paths. Код 2 — отказ. При ошибке могут остаться
созданные owned-файлы и `.incomplete`; это не успешный отчёт и автоматически не
очищается. Новый запуск требует нового output, не overwrite/повторную миграцию.
Создание output со linked/junction-parent отклоняется. Общая защита пути не
заменяет OS access control или защиту от privileged TOCTOU.

Измеренный [пример отчёта](evaluation/owned-workflow.json) получен 2026-10-07:
две vendor-ветви, 61 проверенный operation record и 180 encrypted payload.
Собственные UUID/токены/Fernet ciphertext/timestamps отличаются между runs;
проверяемые действия и количество fixtures фиксированы. Новые UUID/варианты
не являются независимыми сетями или подтверждёнными реальными аномалиями.

## Интерактивный UI и отдельные экспериментальные ветви

Для браузера настройте свою БД/service-role keys по [API runbook](persistent-api.md),
соберите [UI](web-interface.md) и откройте `http://127.0.0.1:8000/ui/`.
Начните с `samples/cisco_ios/access-legacy.cfg` и
`samples/juniper_junos/access-set.conf`: изучите evidence и неизвестные команды.
Эти samples намеренно могут иметь нарушения/partial parsing; их нельзя считать
health baseline или конфигурациями для deployment. Следующая версия должна
сохранять UUID/vendor/platform/hostname. UI не запускает native raw generator.

Автоматические [браузерные проверки](web-interface.md#проверки) отдельно используют
Chromium desktop/mobile и настоящую API; CI повторяет их с SQLite и Compose
PostgreSQL. Этот локальный demo не заявляет выполнение UI/TCP/Compose/PostgreSQL.

Для обучения/повторной проверки вне API используйте отдельные явные сценарии:

- [joint pretraining → supervised heads](pretraining-transfer.md): actual owned
  native weights и diagnostics, без independent/real quality claims;
- [ML pre/post review](ml-change-review.md): pinned trusted модель, in-memory
  sanitization и отдельные numeric outputs, без изменения риска/status;
- [document embeddings](document-vector-retrieval.md) и
  [semantic HTTP supplement](semantic-explanation-context.md): approved sealed
  project sources, не лицензированная vendor library или instruct LLM;
- [loopback instruct transport](local-model-explanations.md): отдельный выбранный
  checkpoint/server и explicit consent; без них provider остаётся unavailable;
- [Batfish](batfish-verification.md): exact network/scope и explicit local upload,
  только при наличии готового доверенного engine.

Документы [готовности](readiness.md) и [угроз](threat-model.md) перечисляют
незакрытые gates. Зелёные функциональные тесты не заменяют ни один из них.
