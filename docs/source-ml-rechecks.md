# Парная ML-диагностика исходников обычного draft

Отдельный workflow выполняет два прохода выбранной config-модели по точным
retained before/after исходникам [обычного object draft](persistent-patches.md).
Finding, модельное предложение или сохранённый analysis для этого не нужны.
Результат не изменяет draft, risk, findings, прежние network reviews или decisions.
Это экспериментальные scores, а не доказательство исправления или безопасности.

## Настройка и запуск

Используется тот же operator-selected registry и independent pin, что у
[single-source inference](configuration-model-inference.md):
`NETCONFIG_CONFIG_MODEL_REGISTRY`, `NETCONFIG_CONFIG_MODEL_SHA256` и, только для
foundation, `NETCONFIG_CONFIG_MODEL_FOUNDATION_SOURCE`. Default disabled;
startup/configured не означает проверку весов или здоровья worker. HTTP не
принимает paths, endpoints, команды, веса или новый source text.

| Операция | Путь |
| --- | --- |
| Настройка без probing | `GET /api/v2/patches/ml-capabilities` |
| Новая парная попытка | `POST /api/v2/patches/<patch UUID>/ml-rechecks` |
| История | `GET /api/v2/patches/<patch UUID>/ml-rechecks?limit=20&offset=0` |
| Полный результат | `GET /api/v2/patches/<patch UUID>/ml-rechecks/<recheck UUID>` |

POST требует engineer/admin (`configuration_model`), включая replay. Все read-роли
читают историю. Строгое тело `source-ml-request-0.1.0`:

```json
{
  "recheck_id": "00000000-0000-0000-0000-000000000007",
  "draft_sha256": "<saved draft fingerprint>",
  "model_sha256": "<operator-selected full lowercase SHA-256>",
  "allow_local_model_context": true
}
```

Согласие отдельное от retention и сетевого upload; default false, числа/строки
не приводятся к bool. Сервер сверяет draft, оба snapshots, source/canonical hashes,
device/vendor identity и заново разбирает originals. Нужен полный разбор обеих
сторон; полный canonical1.2 допускается независимо от network adapter. Это не
vendor syntax validation. Нет оригинала/partial/иной pin дают409 до reservation;
без согласия403, disabled503, занятый slot429, неверное тело400, бюджет413.

Обе стороны используют один экземпляр API runtime/его slot, один bounded child,
одну загрузку модели, один ephemeral private key и один device scope. Single-source
и pair inference взаимно исключают друг друга в этом процессе API. Между replicas
нет общей очереди или распределённого лимита. Оба job envelopes проверяются до
reservation: job ≤32 MiB, paired result ≤2 MiB. Intent/outcome/proof ≤4 MiB;
canonical intent заранее оставляет2 MiB+8192 байта для completion. Outer response
≤16 MiB с учётом escaping. Body ≤16 KiB. Deadline общий на две стороны, default60s;
timeout убивает/reaps child. Allowlisted child environment отключает downloads и
telemetry; trusted operator pipeline не является sandbox для враждебного кода.

## Хранение, восстановление и UI

Миграция0012 добавляет `patch_ml_recheck_intents` и `patch_ml_recheck_outcomes`,
не переписывая старую историю. Payload зашифрован с type/UUID binding. Intent и
`patch.ml_recheck_requested`, затем outcome и `patch.ml_recheck_completed`
сохраняются отдельными атомарными транзакциями. Журнал операций хранит только
IDs/hashes/status, не raw source, private key, paths или scores.

Только победитель reservation запускает worker. Если обе стороны прошли numeric,
card/runtime/sanitizer и source/model/own-line-count проверки, сохраняется
`completed` с двумя `ConfigurationInferenceReport`. Сбой любой стороны даёт
`failed`, report=null и общий код `worker_failed_or_unavailable`; частичный
результат не выдаётся. Новая durable запись возвращает201, идентичный replay200.
Другой intent с прежним UUID409. Pending intent без outcome — `pending_unknown`,
не доказательство живого процесса. Replay возвращает прежние bytes даже при
disabled/busy runtime; GET не читает originals, не запускает модель или policies.
Parent snapshots и hashes всё ещё проверяются. Автоматического resume нет.

Ответ `source-ml-recheck-0.1.0` содержит exact Python compact sorted JSON proof и
его SHA-256. Browser проверяет typed equality, outer proof и raw nested intent
hash, сохраняя Python float representation. Это binding, не удостоверение truth
или личности инженера. Число raw строк записывается producer при запуске и
связано с MAC/result length; само по себе не выводится из canonical IR с комментариями.

В панели обычного draft откройте «Парный ML-пересчёт исходников». UI показывает
pin, классы, enabled heads, обе стороны и собственные координаты строк. Новое
намерение требует нового согласия; refresh pin сбрасывает согласие. Reader/analyst
получают только историю. После потери POST доступен same-ID GET, новый POST
заблокирован. Явный HTTP-отказ вместе с GET404 разрешает отдельный reset/new UUID;
lost response плюс404 не разрешает повтор. Reload теряет intent memory: сначала
изучите серверную историю. Browser timeout не отменяет серверную попытку.

## Что подтверждено и что остаётся открытым

[Actual CPU functional report](evaluation/owned-source-ml-functional.json)
содержит2 completed pairs/4 side reports на двух authored controls, с существующей
native моделью, без новых весов или обучения. Один control меняет Telnet, другой
маршрут вне inventory выбранной модели. Runtime2.14.0+cpu; обе HTTP-попытки,
включая subprocess/load, заняли примерно4.1–4.2s. Pure replay и неизменность
snapshots проверены. Numeric/browser fixtures отдельно проверяют протокол и сбои,
не функционирование encoder. CI также проверяет actual paired worker на маленьких
authored native test bundles; это отдельные функциональные входы.

Выбранная существующая модель имеет только `telnet_enabled`. Card/heads не
доказывают поддержку произвольного изменения. Disabled heads остаются null;
localization scores относятся к собственному исходнику, удалённой строки в after
нет. Между новыми попытками private key меняется, поэтому равенство sanitized
hashes/scores не обещается. Падение anomaly score не является remediation pass.

Итог всегда `needs_review`, formal `not_run`, risk_fused/calibrated/quality_proven/
approved/applied false. Change-specific ML qualification, повтор всех исходных
детекторов, независимый корпус/качество, calibration, device syntax, management
access, rollback, approved baseline и individual engineer gates остаются открытыми.
Network0.1 продолжает сохранять ML `not_run`: новый ML record не повышает его
статус и не создаёт общий qualified verification автоматически.
