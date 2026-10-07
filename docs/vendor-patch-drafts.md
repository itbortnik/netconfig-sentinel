# Ограниченные vendor-specific черновики

`app.patching.vendor_drafts` готовит новый текстовый кандидат из явно выбранного
исходного файла и текущей точной находки policy engine. Это отдельный
детерминированный генератор, не свободный текст LLM и не восстановление исходной
конфигурации из IR. Он не подключается к устройствам, не выполняет команды,
не устанавливает `validated/approved/applied` и не запускает Batfish по умолчанию.

## Две поддержанные операции

| Текущая категория | Cisco IOS/IOS-XE в поддержанном IOS slice | JunOS |
| --- | --- | --- |
| `management.telnet_enabled` | В явно заданном VTY-диапазоне заменить только `transport input ssh telnet` либо обратный порядок протоколов на SSH-only | Удалить единственную точную flat-set строку включения Telnet, сохранив явно заданный SSH |
| `management.ssh_version_1` | Заменить единственную явную root-строку выбора SSHv1 на SSHv2 | Заменить единственную точную flat-set строку выбора SSHv1 на SSHv2 |

Контекст и список протоколов сверены с
[Cisco transport input command reference](https://www.cisco.com/c/en/us/td/docs/ios/termserv/command/reference/tsv_book/tsv_s1.html).
Это line-mode настройка, а доступность SSH и деталей синтаксиса зависит от
образа/версии устройства. Генератор не подтверждает существование ключей,
аутентификацию, работоспособность SSH или совместимость клиентов.

Для JunOS используются область
[Telnet services](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/telnet-edit-system.html),
[SSH services](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/ssh-edit-system.html)
и семантика удаления одной ветви из
[официального руководства по изменению конфигурации](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/modifying-configuration.html).
Наличие инструкции в документации не подтверждает её безопасность на конкретном
оборудовании: изменение разрешённых протоколов может лишить инженера доступа
или нарушить зависимые сценарии. Нужны отдельные испытания доступа и rollback.

Не поддерживаются произвольные рекомендации, ACL/маршрутизация, создание SSH/AAA,
исправление отсутствующих значений, удаление локальных аккаунтов или секретов.
`transport input all`, Telnet-only, другие протоколы, неизвестные команды,
перекрывающиеся/повторные VTY-диапазоны и неоднозначные повторные настройки
отклоняются. Уже отключённый неперекрывающийся VTY-диапазон остаётся нетронутым.
Cisco VTY-заголовок должен быть root-строкой, transport — вложенной строкой.
JunOS поддержан только как flat `set`, не иерархические блоки, группы, наследование
или Telnet-подопции. При недостатке данных нет шаблонного fallback.

## Привязки и локальные проверки

`create_vendor_draft(before, finding=..., source_sha256=..., reference_id=...)`:

- проверяет лимиты 2 MiB / 10 000 строк и SHA-256 точного исходного текста;
- требует полный локальный разбор и точную текущую находку `policy-rules-0.7.0`,
  включая UUID, категорию, доказательства и fingerprint; старую находку не переименовывает;
- изменяет только поддержанные строки, совпадающие со всеми anchors этой находки;
- сохраняет остальные байты декодированного текста, включая CRLF, пробелы и секреты;
- заново разбирает кандидат и проверяет, что нормализованно изменилось только
  целевое management-свойство; новые нарушения политик недопустимы;
- создаёт существующие `PatchProposal` и `PatchReview` с hashes обеих сторон.

Полнота локального parser означает только полноту его ограниченного slice,
не платформенную проверку синтаксиса или корректность сети. Отчёт всегда
`needs_review`, formal — `not_run`, application/device-syntax/access flags — false.
Даже исчезновение выбранной находки и отсутствие новых нарушений не разрешают
применение. Другие текущие нарушения сохраняются в preflight и его блокерах.

`VendorDraft` хранит типизированные edits, hashes строк, VTY-контекст, fingerprint
выбранной находки, версию генератора/политик и связанный local review. Raw-кандидат
возвращается отдельно, исключён из repr контейнера. `native_commands` строится
только из фиксированных поддержанных операций и числовых VTY-диапазонов; никакой
пользовательский prose/LLM-output не становится исполняемой командой.

`check_vendor_draft()` регенерирует разрешённое изменение из точного original
snapshot и сравнивает кандидат и весь metadata/review. Изменение исходника,
каталога правил, anchors, строк или результатов проверок требует нового черновика.
Hash/finding UUID не аутентифицирует физическое устройство или инженера.

## Private artifact и CLI

До запуска сохраните original snapshot в закрытом каталоге для проверки/rollback.
Hash — UTF-8 текста после снятия возможного BOM при чтении, с сохранёнными CRLF.
Передайте hash выбранной версии, не placeholder:

```powershell
python -m app.patching.vendor_cli generate --before private-before.cfg --source-sha256 <selected-decoded-source-sha256> --device-id 7f64381c-fda8-48f9-8e8a-fb772b2f64dc --reference-id selected-v1 --category management.telnet_enabled --output private-draft-v1
python -m app.patching.vendor_cli check --before private-before.cfg --artifact private-draft-v1
```

Генерация создаёт только новый явно выбранный каталог; родители не создаются,
существующие файлы/каталоги не перезаписываются. Внутри:

- `candidate.cfg` — полный конфиденциальный кандидат;
- `metadata.json` — bounded, checksummed metadata и local preflight;
- `native-commands.txt` — inspection-only команды с предупреждением и контекстом,
  без автоматического перехода в режим, сохранения/commit или подключения.
- `local-review.json` — тот же `PatchReview` в существующем формате артефакта,
  пригодный для явного `--patch-review` offline Batfish CLI; сам экспорт не
запускает движок и не является формальным результатом.

Для exact original/candidate можно отдельно выполнить
[ML-перепроверку выбранной native модели](ml-change-review.md). Она использует
`local-review.json`, обезличивает входы в памяти и сохраняет отдельные numeric
diagnostics; local review/formal/status не повышаются и файлы draft не меняются.

При сбое записи может остаться неполный каталог с `.incomplete`: загрузчик его
отклоняет. Для повторной генерации нужен новый путь; автоматической очистки нет.
Загрузчик требует точный inventory, бюджеты, уникальные JSON-ключи, checksum,
совпадение candidate hash и текста native commands с типизированным metadata.
Симлинки, junctions и такие родители отклоняются, но проверки путей не являются
OS sandbox или защитой от привилегированной подмены между проверкой и чтением.
`check` дополнительно пересчитывает всё по original snapshot, а не доверяет
самостоятельно пересчитанной checksum. Hash не является подписью издателя.

Код 0 — успешная генерация/совпадение локальной перепроверки, не formal pass или
approval. Код 2 — отказ с обобщённой диагностикой. Stdout содержит только hashes,
идентификаторы и состояния; конфиги, имена файлов, команды и секреты не печатаются.
Команд `apply`, `approve`, `validate`, `commit`, overwrite-флагов нет.

Артефакты содержат сырой конфиг и сетевые значения. Они не обезличены и не
зашифрованы этим offline-модулем: храните в закрытом каталоге ОС, вне публичного
Git и внешних сервисов. Service RBAC и operation journal не удостоверяют
действия отдельного offline CLI-процесса. [API/UI object drafts](persistent-patches.md)
остаются отдельным путём: там нет original raw text и эта генерация не выдумывается.
Связанный [network review](batfish-verification.md#привязка-к-существующему-черновику) принимает явные before/after
snapshots, но его экспериментальный Batfish-результат также не повышает статус.

Все проверки этого этапа используют owned fixtures. Живой Batfish, реальное
оборудование, безопасный management access и реальные deployment-испытания
не подтверждены.
