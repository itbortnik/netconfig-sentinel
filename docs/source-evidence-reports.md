# Совместный отчёт по сохранённым результатам

Для [частичной диагностики политик](source-partial-diagnostics.md) request/report0.5
принимает только завершённый диагностический child0.2. Другие виды результатов
в этом режиме не выбираются; общая квалификация остаётся `not_proven`.

Версия request/report0.4 сохраняет
[наблюдения точек входа](source-ingress-observations.md) из выбранного child.
Описанные ниже0.1 и отдельные0.2/0.3 остаются историческими протоколами.

Для ordinary [draft](persistent-patches.md) можно явно выбрать уже сохранённые
результаты и записать отдельный неизменяемый отчёт (§16.7). Обязателен
[детерминированный повтор исходного анализа](source-deterministic-rechecks.md).
[Isolation Forest](source-forest-rechecks.md), [нейросетевой повтор](source-ml-rechecks.md)
и сетевая проверка выбираются отдельно. Сервер проверяет совместимость входов,
сохраняет компактные проекции и fingerprints; новые вычисления не запускаются.

| Операция | Путь |
| --- | --- |
| Сохранить выбранные результаты | `POST /api/v2/patches/<patch UUID>/evidence-reports` |
| История | `GET /api/v2/patches/<patch UUID>/evidence-reports?limit=20&offset=0` |
| Полный отчёт | `GET /api/v2/patches/<patch UUID>/evidence-reports/<report UUID>` |

POST, включая replay, требует engineer/admin с permission `verify`; роль
проверяется до чтения тела. GET/list доступны read-ролям. Тело версии
`source-evidence-request-0.1.0`:

```json
{
  "report_id": "00000000-0000-0000-0000-000000000010",
  "draft_sha256": "<saved draft SHA-256>",
  "deterministic": {
    "record_id": "<selected deterministic recheck UUID>",
    "review_sha256": "<selected review SHA-256>"
  },
  "forest": null,
  "neural": null,
  "network": null
}
```

Все четыре поля выбора обязательны. У необязательных результатов null означает
«не выбрано»; выбранная запись задаётся UUID и SHA-256. Автоматического выбора
последней записи нет. Новый consent не запрашивается: операция читает сохранённые
результаты и не получает originals, документы, новые конфигурации или модель.
Согласия на исходные вычисления остаются в их отдельных исторических requests.

Сервер сверяет draft, точные before/after snapshot UUID, device/source/canonical
SHA-256 и время. Детерминированный результат и Forest обязаны ссылаться на один
before analysis UUID и fingerprint. Выбранные записи должны иметь completed
execution и полный результат: `pending_unknown` и `failed` не принимаются.
Завершённая сетевая проверка с результатом `error`, `differences_found` или
`inconclusive` остаётся допустимым свидетельством именно такого исхода.

Проекции сохраняют исходные версии и blockers. Политики содержат отдельные
policy/reference/peer counts, reference/profile pins и partition изменений;
невыбранное сравнение остаётся null. Forest сохраняет model/artifact/schema/library,
decision offset и обе исходные числовые оценки. Нейросеть сохраняет model/card,
training report/encoder/tokenizer SHA, classes/heads, semantics, runtime version,
source/sanitization pins и scores без embedding vectors. Сетевой результат
сохраняет реальные status/reason/scope/engine/counts/cleanup и ограничения.
Исторический network0.1 не записывал SDK version: проекция явно содержит null.
Его собственный `ml_status=not_run` не меняется при выборе отдельной нейросети.

Если исходный анализ содержал статистику, отсутствие выбранного Forest отмечено
blocker. Наличие Forest или нейросети не подтверждает независимое качество или
пригодность модели для конкретного изменения. Успешная IPv4 query в выбранной
области не подтверждает всю сеть, syntax на устройстве или доступ управления.
Отчёт всегда `needs_review`, общая `formal_qualification=not_proven`;
`risk_fused`, `calibrated`, `quality_proven`, `approved`, `applied` всегда false.
Фактический статус выбранной сетевой проверки показывается отдельно.

Миграция `0015_source_evidence_reports` добавляет таблицу `patch_evidence_reports`.
Перед явным upgrade нужны backup и прежний encryption key. Startup не мигрирует
БД. Отчёт и domain audit `patch.evidence_report_created` записываются одной
транзакцией; envelope связан с типом и UUID. Отдельных intent/outcome для этой
операции нет: вычисления не выполняются. Operation journal хранит allowlisted
IDs/hashes/versions, без raw source, observations или scores.

Новая запись возвращает201; идентичный POST с тем же UUID возвращает200 и прежний
отчёт. Другой request с тем же UUID даёт409. Отсутствующий draft/child даёт404,
несовместимые pins409, неверное тело/повторённые JSON keys400, бюджет413,
повреждённая сохранённая запись503. Body ≤16KiB, суммарные полные selected child
DTOs вместе с proof ≤32MiB, report payload/proof ≤4MiB, ciphertext/outer response
≤16MiB. Нет усечения результатов для прохождения бюджета.

GET/list/replay заново проверяют сохранённые child records и их проекции в одной
read session. Они не читают originals, модель, текущий каталог, reference snapshot
или peers и не запускают inference/engine. Нужны неизменные draft, target snapshots,
исходный analysis и выбранные дочерние записи. Удаление обязательной исторической
зависимости считается недоступностью данных, а не поводом пересчитать историю.

В панели draft откройте «Совместный отчёт», явно загрузите нужные истории и выберите
результаты. Списки поддерживают страницы; pending/failed недоступны для выбора.
Перед показом отчёта клиент проверяет proof и заново читает выбранные полные
child records, независимо сверяя каждую проекцию. В частности, normative Python
JSON для model card сохраняет исходные float bytes. Несовпадение скрывает отчёт.
После потери POST используйте same-ID GET; автоматического повторного POST нет.
503 и неизвестный исход остаются замороженными до восстановления. Service token
не удостоверяет личность отдельного инженера.

[Функциональный HTTP report](evaluation/owned-source-evidence-functional.json)
содержит два actual совместных отчёта для двух authored Cisco/JunOS target pairs,
выбирающих шесть ранее сохранённых actual sibling reports. Подготовка выполнила
две CPU neural пары/четыре side reports существующей модели без нового fit;
само объединение выполнило ноль detector/model/engine calls. Класс нейросети
только `telnet_enabled`; изменения адресов этими результатами не квалифицированы.
Сетевой движок в этом прогоне не выбран. Проверены additive0014→0015, неизменность
старых строк и selected children, GET/list/replay после удаления originals,
моделей и эталонов на отдельной копии БД. Сохранены583 frozen historical files,
276 прежних installed runtime files и3assets. Independent quality denominator
отсутствует; binding доказывает согласованность записей, а не истинность labels,
безопасность изменения или approval инженера.
