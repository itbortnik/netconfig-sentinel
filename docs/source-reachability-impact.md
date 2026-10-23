# Примеры потери и появления достижимости

Явный source network request `source-patch-request-0.3.0` добавляет к сохранённому
результату SDK ограниченные свидетельства направления изменения IPv4-доставки.
Проверяются точные retained before/after, выбранные companion configurations и
явный исходный узел/префикс назначения. Новые совместные отчёты и решения используют
версию0.3; request без версии сохраняет прежний протокол0.1.

Движок возвращает примеры конкретных flows. Для каждого примера сравниваются
**полные** наборы trace dispositions до и после: успешная доставка до и отсутствие
успеха после дают свидетельство потери; обратное — появления. Найденные оба вида
показываются отдельно. Общие счётчики reachability не вычитаются: одинаковые числа
могут соответствовать разным flows.

`reachability_impact` версии `reachability-impact-0.1.0` хранит:

| Состояние | Смысл |
| --- | --- |
| `observed` | Полностью интерпретированы возвращённые ограниченные примеры. |
| `inconclusive` | Пустая достижимая область не позволяет положительный вывод. |
| `not_observed` | Соответствующие queries не были выполнены. |
| `unknown` | Ответ нельзя полно интерпретировать либо cleanup не подтверждён. |

Для `observed` направление — `loss_found`, `gain_found`, `loss_and_gain_found`
либо `no_witnesses_returned`; счётчики относятся к сохранённым примерам. Для других
состояний направление/счётчики равны `null`, witnesses пусты. Это не нулевое
воздействие. Прежний общий `BatfishResult` сохраняется отдельно, включая ошибки,
доступные счётчики и результат очистки.

Адаптер принимает не более64witnesses и16traces на сторону одного flow. Число
traces должно точно совпадать с неусечённым набором; скрытый ECMP success нельзя
объявить потерей. Неизвестные dispositions, `INSUFFICIENT_INFO`, неоднозначность,
дубликаты, неверная форма и переполнение дают `unknown`, без частичного pass.
Исходные scalar types проверяются до преобразований SDK. Поддержана фактически
наблюдённая legacy-пара raw Flow `state=NEW`, `tag=tag`; она включена в версионный
hash identity. Другие значения или неизвестные поля не игнорируются молча.
Parent transport0.3 ограничен128KiB UTF-8; старые протоколы сохраняют32KiB.

В записи остаются flow SHA, dispositions/counts и ограничения; raw trace hops,
маршруты и конфигурации не публикуются как directional output. SDK observation,
engine version и exact source/snapshot/scope/network bindings входят в прежнюю
проверяемую цепочку. Hash удостоверяет связь данных, а не истинность движка.

Source → encrypted immutable record/audit → joint report → UI сохраняют
полный выбранный child; decision хранит parent UUID/SHA и проверяет всю цепочку.
Пересчитанный parent hash с ложным направлением не заменяет
исходный child. GET/list/replay не запускают queries. Старые0.1/0.2 proofs/defaults
не пересчитываются; новый report0.3 может явно выбрать старый network result.
Старый report не принимает новый0.3 child; decision соответствует версии parent.
SQL tables и encrypted kinds сохраняются, отдельной migration нет.

Десять actual локальных API/engine сценариев на собственных Cisco/JunOS inputs
проверили loss, gain, reachable control, empty scope и противоположные изменения
при before=after=1 и двух разных witnesses. Пройдены сохранение source/joint/
service-role decision и restart/replay после удаления исходных текстов, без SDK
или raw-source reads. SDK `2026.8.19.3660`, engine `2026.08.27.3685`. Новых model
calls/fits в этом прогоне нет. Это authored functional integration, не новые
независимые сети или оценка качества.

[Сквозной HTTP report](evaluation/owned-source-direction-functional.json) отдельно
повторно использует две прежние authored пары и шесть сохранённых detector/model
результатов без rerun. Два actual SDK calls суммарно дали два immutable source/joint
reports; первый completed source повторно выбран после прерванной попытки.
Восемь решений сервисных ролей сохраняют выбранные parent proofs. На копии БД
проверена история после удаления originals/models/двух references. Оба scoped
результата — `no_witnesses_returned`; реальные потери/появления проверены отдельными
десятью сценариями выше. Model calls/fits0; independent quality не измерялось.

Область запроса использует ingress locations, присутствующие и active в обоих
snapshots; source-IP inference использует after. Исчезнувшие ingress locations
этим не покрыты. Отсутствие возвращённых witnesses не доказывает неизменность всех
flows или безопасность всей сети. `DELIVERED_TO_SUBNET`/`EXITS_NETWORK` не доказывают
доставку реальному внешнему устройству. Management/SSH/AAA, IPv6, vendor syntax,
rollback, полнота topology и operational state не квалифицированы.

Сохраняются `needs_review` и общий formal `not_proven`. Severity, calibrated risk,
качество моделей, individual identity, approval и application не выводятся из
этих примеров. Service-role решения не удостоверяют подтверждение человеком.
