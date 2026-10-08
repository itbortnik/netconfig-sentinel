# Зашифрованная запись model patch

`app.explanation.patch_receipts` сохраняет output выбранной instruct-модели,
численное observation, exact candidate и local review в новом private `.ncp`.
Это отдельный offline artifact, не database migration, API activation или
согласование патча. Используется уже имеющаяся зависимость `cryptography`.

## Контракт записи

`create_patch_receipt(generated, prepared=..., identity=..., observation=...,
expected_inventory_sha256=...)`:

- заново проверяет answer, exact source/finding/baseline/documents/schema bindings;
- требует completed observation для того же context, finite generation ≤20 секунд
  и token budgets, без deadline/incomplete/control refusal;
- связывает модель/revision/inventory, instructions/schema, policy/doc versions,
  исходник/находку и private candidate с существующим local review;
- не подменяет отказ: null answer сохраняется как `no_candidate`, без candidate;
- оставляет `needs_review/not_run`, no apply/activation/semantic truth flags.

Identity/observation обязан предоставить caller из своего selected runtime.
Их запись не аутентифицирует физический GPU процесс, model publisher, training
exposure, source consent или истинность prose: `model_identity_authenticated=false`.
Для происхождения нужны отдельные actual-run evidence. Receipt не загружает веса
заново и не запускает модель; independent inventory pin проверяет declared binding,
не новое qualification текущих файлов checkpoint.

## Сохранение и проверка

`save_patch_receipt(receipt, path, key=..., prepared=...,
expected_inventory_sha256=...)` сначала пересчитывает все local bindings, затем
создаёт один новый `.ncp` только в существующем выбранном каталоге. Не создаёт
parents, не перезаписывает старый файл и не использует plaintext fallback.
Payload защищён authenticated Fernet encryption; ключ передаётся явно и не
попадает в receipt, filename, stdout или журнал. Его хранение/backup/rotation
в secret store остаётся ответственностью оператора.

`load_patch_receipt(path, key=..., prepared=...,
expected_inventory_sha256=...)` bounded-read/decrypts, проверяет type/schema,
уникальные JSON keys и заново replay-validates модельные edits относительно
сохранённых оператором точных before/baseline inputs и текущей находки. Неверный
ключ, изменённый ciphertext, authenticated invalid payload, другой pin/source/
context/candidate, linked path или превышение budget дают обобщённый отказ.
Generation/transport/network при load не вызываются.

Plaintext budget — 8 MiB, encrypted — 12 MiB. Links/junctions и такие absolute
parents запрещены. Это не OS sandbox и не защита от привилегированной race-подмены.
ACL выбранного каталога/ключа, отдельный доступ к before/baseline и защиту памяти
caller обеспечивает сам. Неудачная запись может оставить неполный **encrypted**
файл; он отклоняется, автоматического удаления нет, для повтора нужен новый путь.

`repr` скрывает raw answer/candidate/metadata/identity, но явный `model_dump_json()`
остаётся конфиденциальным plaintext: не публикуйте его и не отправляйте наружу.
Standalone функции не удостоверяют отдельного инженера и не заменяют API RBAC,
operation journal, signed provenance или production key-management qualification.

## Границы полного workflow

Local replay проверяет допустимые bytes/scope/parser/policy, не device syntax,
SSH access, rollback, formal reachability или semantic/citation truth. Даже
authenticated artifact с accepted edit не получает `validated/approved/applied`.
Persistent API/UI handoff, candidate-specific formal/model review context и
engineer approval остаются отдельными незавершёнными требованиями.

## Installed owned evidence

[Численный round-trip report](evaluation/owned-encrypted-model-receipts.json)
фиксирует четыре actual outputs из ранее выполненного instruct run: два SSH
candidates и два `no_candidate`. Каждый зашифрован установленным wheel, прочитан
с тем же diagnostic key и replay-checked по точному source/context; другой key
отклонён. Новых LLM-вызовов или GPU loads не было. Confidential fragments/key
не обнаружены в этих четырёх ciphertext files — это fixture check, не доказательство
универсального отсутствия утечек или production cryptography qualification.

Diagnostic key был ephemeral и не сохранён; лабораторные `.ncp` не являются
deployment backup и не предназначены для восстановления после завершения процесса.
Исторический actual-inference report сохранён отдельно. Production caller обязан
сам обеспечивать долговременное защищённое хранение/backup ключа и exact inputs.
