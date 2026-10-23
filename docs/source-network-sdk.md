# Наблюдаемая версия SDK в сетевых результатах

Явный source network request `source-patch-request-0.2.0` сохраняет результат
изолированного worker вместе с наблюдением distribution metadata `pybatfish`.
Проверка по-прежнему использует точные retained before/after, выбранные companion
configurations и явный IPv4 scope. Автоматическое применение отсутствует.

Worker импортирует SDK, затем читает distribution metadata до создания session.
`BatfishExecution` версии `batfish-execution-0.2.0` содержит прежний `BatfishResult`,
`sdk_version` и отдельное `sdk_observation`:

| Наблюдение | Значение версии | Значение |
| --- | --- | --- |
| `observed` | Ограниченная непустая строка | Metadata прочитана внутри worker. |
| `metadata_unavailable` | `null` | SDK импортирован, metadata недоступна; query result сохраняется отдельно. |
| `not_observed` | `null` | Подтверждённого наблюдения worker нет. |

Ошибка engine после наблюдения не удаляет SDK metadata. Отказ в consent,
отсутствующий SDK, timeout и невалидный/неполный ответ worker не получают версию
из пакета родительского процесса. Worker response должен совпадать с точными
before/after digests, scope и собственной временной сетью. Metadata distribution
не удостоверяет байты импортированного кода и не доказывает качество проверки.

Старый request без версии сохраняет протокол 0.1. Его immutable proof, timestamps,
GET и replay не пересчитываются; SDK version в старом сетевом evidence остаётся
`null`, без нового поля наблюдения. Один UUID нельзя повторно использовать с
другим протоколом. Новые payload versions используют прежние encrypted tables и
audit kinds; отдельной SQL migration для них нет. При новых записях SQL timestamp
нормализуется в UTC, исходный offset payload/proof сохраняется.

Совместный request/report 0.2 принимает явно выбранный старый network 0.1, новый
network 0.2 либо отсутствие network. Новый projection включает SDK metadata из
сохранённого child и его UUID/SHA; при чтении весь child/parent chain проверяется
повторно без вычислений. Пересчитанный hash ложной проекции не заменяет child.
Report 0.1 отказывает новому network 0.2 с 409; несовместимая сохранённая зависимость
считается повреждением истории и возвращает 503.

Decision request/record 0.2 относится только к report 0.2; прежний 0.1 — к report
0.1. Сохраняются явные `rejected`/`needs_more_information`, первоначальные сервисная
роль, время и proof. Эти записи не удостоверяют individual identity и не дают
approval. UI отправляет новые source/report requests явно как 0.2, выбирает
версию решения по выбранному отчёту, проверяет полную цепочку proofs и сохраняет
неопределённый результат запроса до явного восстановления через GET.

[Фактический HTTP-прогон](evaluation/owned-source-sdk-functional.json) использовал
две прежние authored пары: два новых SDK вызова, два совместных отчёта и восемь
software dispositions. Выбранные deterministic/Forest/neural outputs существовали
раньше; новых model calls, fits или весов нет. Neural inventory остаётся только
`telnet_enabled`; другие изменения не квалифицированы. На копии БД проверено
чтение/replay после удаления originals, моделей и двух reference configurations;
прежние физические строки сохранены.

Отдельные шесть actual SDK/engine API scenarios Cisco/JunOS проверили route loss,
reachable control и empty scope с SDK `2026.8.19.3660` и engine
`2026.08.27.3685`. Результаты differences, отсутствие differences в выбранном scope
и inconclusive сохраняются раздельно. Это authored integration, не независимая
оценка реальных сетей. `formal_qualification=not_proven`, quality/calibration,
individual identity, approval и applied этим не повышаются. Parser reparse не
заменяет vendor syntax validation, IPv4 scope не доказывает management access,
SSH/AAA, IPv6, полноту topology или безопасность всей сети.
