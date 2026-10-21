# Сохранённое решение по совместному отчёту

Для ordinary [совместного отчёта](source-evidence-reports.md) engineer/admin может
записать `rejected` или `needs_more_information` с комментарием. Это доступная
часть §16.8: сохраняется решение **сервисной роли**, а не подтверждённая личность
инженера. Текущий отчёт имеет `formal_qualification=not_proven`; `approved` и
`applied` недоступны. Решение не изменяет draft, отчёт, дочерние проверки или
их статусы и не запускает новые вычисления.

| Операция | Путь |
| --- | --- |
| Записать решение | `POST /api/v2/patches/<patch UUID>/evidence-reports/<report UUID>/decisions` |
| История решений отчёта | `GET /api/v2/patches/<patch UUID>/evidence-reports/<report UUID>/decisions?limit=20&offset=0` |
| Полная запись | `GET /api/v2/patches/<patch UUID>/evidence-reports/<report UUID>/decisions/<decision UUID>` |

POST, включая replay, требует engineer/admin с permission `verify`; проверка
роли выполняется до чтения тела. GET/list доступны read-ролям. Request версии
`source-evidence-decision-request-0.1.0`:

```json
{
  "decision_id": "00000000-0000-0000-0000-000000000011",
  "report_sha256": "<selected report SHA-256>",
  "verdict": "needs_more_information",
  "comment": "Нужны дополнительные сведения для рассмотрения изменения."
}
```

Второй допустимый verdict — `rejected`. Comment обязателен:1–1200 Unicode code
points, не только whitespace; разрешены printable text, newline и tab. UUID и SHA
отчёта выбираются явно. Поля роли, подтверждения личности, approval и применения
не принимаются из тела. Свободный комментарий остаётся недоверенным текстом:
интерфейс выводит его как текст, operation audit его не сохраняет.

Сервер читает integrity-checked parent report с его draft, analysis и child
records в той же session. Сверяются report UUID/SHA/version, draft SHA, точные
before/after snapshot/device/source/canonical pins и исходный analysis UUID/SHA.
Решение содержит исходный request, aware timestamp, полученную из авторизации
`service_role`, normative JSON и SHA-256. Простая валидация DTO не заменяет
повторную сверку с сохранённым родителем. Никакие raw sources, модель, reference,
peers, inference или Batfish для этой операции не нужны.

`individual_identity_verified`, `approved`, `applied` всегда strict false.
Service token удостоверяет только роль. Комментарий и verdict не становятся
ground truth, human attestation или evidence качества модели. Более позднее
решение добавляет новую запись в историю; оно не заменяет прежнюю запись и
не повышает статус отчёта автоматически.

Миграция `0016_source_evidence_decisions` добавляет `patch_evidence_decisions` с
зашифрованным payload, связанным с типом и UUID. Перед явным upgrade сохраните
backup и прежний encryption key. Startup не меняет схему. Decision и domain audit
`patch.evidence_decision_recorded` сохраняются одной транзакцией; отдельных
computation intent/outcome нет. Operation journal сохраняет allowlisted UUID,
hashes, versions, verdict и исходную recorded role без comment/proof/model data.

Новый POST возвращает201. Идентичный request с тем же UUID возвращает200 и
**первоначальные роль, время и proof**, даже если replay выполнила другая
разрешённая сервисная роль. Другой intent/parent с тем же UUID даёт409.
Отсутствующий родитель или decision —404; несовместимые pins —409; неверное
тело, повторённые JSON keys или недопустимый verdict —400; бюджет —413;
повреждённая сохранённая запись или её историческая зависимость —503.

Body ≤16KiB, plaintext payload/proof ≤32KiB, ciphertext/outer response ≤128KiB.
Ничего не усекается ради бюджета. Summary версии
`source-evidence-decision-summary-0.1.0` содержит IDs, SHA, time, verdict и
recorded role; комментарий и полный proof доступны в detail, а не в списке.
History/replay проверяют неизменные зависимости; удаление original/model/reference
после завершения не требует их восстановления и не вызывает новый анализ.

Откройте полный совместный отчёт и панель решения. Явно выберите verdict,
введите комментарий и сохраните запись. Списки имеют страницы; разрешённые
read-роли читают историю без кнопки записи. Клиент проверяет точный Python proof
и заново читает полный parent report через проверку всех selected children.
Подписанная заново ложная проекция не принимается по одному совпавшему SHA
ссылки на родителя. Parent GET failure после POST остаётся неизвестным исходом.
После потери ответа используйте same-ID GET без автоматического повторного POST.
503 или неизвестный исход с GET404 остаётся замороженным; известный отказ с404
разрешает явный reset. Пока исход неизвестен, навигация к другому отчёту ограничена.
Комментарий и попытка не сохраняются в local storage.

[Функциональный HTTP report](evaluation/owned-source-evidence-decisions-functional.json)
фиксирует восемь actual software dispositions: два authored Cisco/JunOS отчёта ×
две сервисные роли × два verdict. Это две исходные пары, а не восемь независимых
сетей или инженеров. В этом прогоне0 detector/model/engine calls,0 fits и0 новых
весов. Проверены additive0015→0016, прежние физические строки, неизменность
родителей/детей, сохранение роли/времени и GET/list/replay после удаления originals,
моделей и двух эталонов на копии БД. Сохранены634 frozen historical files,
282 прежних installed runtime files и3assets. Реальное подтверждение инженера,
независимое качество, calibration, общий formal status и безопасность изменения
этим не доказаны.

Служебная дата SQL нормализуется в UTC; исходный offset в encrypted payload и proof
сохраняется. Отдельные регрессии `±03:00` подтвердили чтение/replay и порядок
истории в SQLite. Предыдущий функциональный прогон и сборка сохранены отдельно;
финальный прогон включает исправление этой библиотечной ошибки.
