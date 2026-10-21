# Повтор исходных политик, эталона и профиля соседей

Отдельная проверка ordinary [draft](persistent-patches.md) повторяет детерминированную
часть явно выбранного before analysis. Обе стороны используют **его исходный каталог
политик, его эталон и его сохранённый peer profile**. Новый консенсус не строится,
after не становится новым эталоном. Версии comparison0.1/0.2/0.3 и policy-only
сохраняют собственную семантику. Это часть §16.3–4,7; общий qualified rerun всех
детекторов и проверка безопасности этим не закрываются.

| Операция | Путь |
| --- | --- |
| Выбрать исходный анализ | `GET /api/v2/patches/<patch UUID>/deterministic-selection/<analysis UUID>` |
| Запустить | `POST /api/v2/patches/<patch UUID>/deterministic-rechecks` |
| История | `GET /api/v2/patches/<patch UUID>/deterministic-rechecks?limit=20&offset=0` |
| Полная запись | `GET /api/v2/patches/<patch UUID>/deterministic-rechecks/<recheck UUID>` |

Selection возвращает fingerprint анализа, исходный детерминированный контекст и
canonical fingerprint выбранного эталона. Чтение metadata не проверяет наличие
retained originals и не запускает детекторы. Эталону достаточно сохранённого
canonical snapshot; для обеих target sides нужны точные retained originals.
Read-роли читают selection/history; POST, включая replay, требует engineer/admin
с permission `verify`. Проверка роли предшествует чтению тела.

Тело `source-deterministic-request-0.1.0`:

```json
{
  "recheck_id": "00000000-0000-0000-0000-000000000008",
  "draft_sha256": "<saved draft fingerprint>",
  "before_analysis_id": "00000000-0000-0000-0000-000000000009",
  "before_analysis_sha256": "<selected analysis fingerprint>",
  "reference_canonical_sha256": null,
  "allow_local_analysis_context": true
}
```

`reference_canonical_sha256` обязателен: SHA из selection, если выбран эталон,
иначе null. Consent default false; строки и числа не превращаются в bool.
HTTP не принимает исходники, каталог правил, новый профиль или reference projection.
Неверное тело/дубли JSON keys дают400, отсутствие согласия403, отсутствующая
запись404, stale pins/ineligible context409, превышение бюджета413.

Перед reservation сервер заново разбирает оба retained originals и проверяет их
canonical/source/device bindings, полный поддержанный разбор и доступность исходного
алгоритма/каталога. Выбранный reference projection и peer profile фиксируются в
intent. Исходный before повторяется первым: **все** поля findings и отдельного
peer report должны совпасть с сохранённым анализом в нормативном JSON. Затем теми
же входными настройками анализируется after. Различия policy findings сохраняются
как resolved/introduced/persistent с полной проверкой их partition.

В отчёте null означает «сравнение не выбрано», пустой массив — «выбрано и выполнено
без findings». У peer0.1 отдельного evaluation report нет по исходному контракту.
Нейросеть и Isolation Forest не запускаются; если исходный анализ включал Forest,
это отмечается blocker `original_statistical_not_rerun`. Их отдельные
[ML](source-ml-rechecks.md) и [Forest](source-forest-rechecks.md) проверки сохраняют
собственные результаты и не объединяются автоматически.

Миграция `0014_deterministic_rechecks` добавляет только отдельные таблицы
`patch_deterministic_recheck_intents`/`patch_deterministic_recheck_outcomes`.
Перед явным [upgrade](persistent-api.md) сохраните backup и прежний encryption key.
Startup не мигрирует БД. Intent и audit `patch.deterministic_recheck_requested`,
затем outcome и `patch.deterministic_recheck_completed` записываются атомарными
парами. Encrypted envelope связан с типом и UUID. Operation journal сохраняет
allowlisted IDs/hashes/status, без observations, значений эталона или raw source.

Новая попытка возвращает201. Идентичный POST200 читает прежний результат; другой
request с тем же UUID даёт409. Только победитель reservation запускает детекторы.
Intent без outcome — `pending_unknown`; это не подтверждение живого процесса.
Автоматического resume нет. Ошибка вычисления или несовпадение исходного before
сохраняет `failed`, report=null и общий код
`original_context_or_deterministic_result_unavailable`, без частичных findings.
GET/list/replay не читают originals/reference/peer snapshots, не загружают модели
и не вычисляют детекторы. История связывается с неизменными draft/targets/analysis
и сохранённым proof; удаление эталона после завершения не вызывает новый анализ.

Body ≤16 KiB, combined inputs ≤32 MiB, report ≤2 MiB, intent/outcome/proof ≤4 MiB,
outer response ≤16 MiB. Intent оставляет2 MiB+8192 bytes для completion до reserve.
Proof сохраняет Python compact sorted JSON и SHA-256; hash binding не подтверждает
истинность findings, качество или личность инженера.

В панели draft откройте «Перепроверка исходного анализа», введите UUID before
analysis и загрузите selection. Просмотрите исходные версии/эталон/профиль,
затем дайте отдельное согласие. Смена или refresh selection сбрасывает согласие.
После потери POST используйте same-ID GET: автоматического повторного запуска нет.
Известный отказ вместе с GET404 разрешает явный reset и новое согласие; lost
response плюс404 оставляет попытку замороженной. После reload сначала проверьте
сохранённую историю. Read-роли не получают кнопки запуска.

[Функциональный HTTP report](evaluation/owned-source-deterministic-functional.json)
фиксирует18 completed повторов: две authored Cisco/JunOS пары × три версии × три
cohorts. Это две исходные пары, а не18 независимых сетей. Анализы выбраны
ретроспективно, после сохранения обеих target versions. В прогоне0 model runs,
0 новых fit и0 новых peer profiles. Проверены точные before findings, additive
0013→0014 с сохранением прежних строк, GET/list/replay после удаления reference,
raw sources и models на диагностической копии. Сохранены558 зафиксированных
historical files. Independent quality denominator/metrics отсутствуют.

Результат всегда `needs_review`, formal `not_run`; quality_proven/calibrated/
risk_fused/approved/applied false. Не подтверждены vendor syntax, полная сеть,
management access, operational false positives, independent real quality,
calibrated risk, квалификация ML для изменения и individual engineer approval.
