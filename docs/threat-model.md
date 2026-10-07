# Граница доверия текущего API

Конфигурации считаются конфиденциальными и недоверенными. Этот документ описывает
текущий development-срез, а не сертификацию безопасности или production-ready статус.

## Что защищено

- Все persistent endpoints проверяют service bearer-token и разрешения роли до
  чтения write body; LLM permission — после bounded selection, до передачи.
  [Фиксированные роли](service-roles.md) не принимаются из request body.
  Нет demo-token, fallback-пароля или открытого business endpoint.
- Текст имеет бюджеты bytes/lines, JSON — общий byte budget. Пути файлов,
  control characters, архивы, сжатые тела и неизвестные поля не принимаются.
  Filename никогда не используется как путь записи. SQL-значения параметризованы.
- Identity устройства, канонические снимки и анализы хранятся как
  [аутентифицированные Fernet-payload](https://cryptography.io/en/latest/fernet/).
  Envelope связывает payload с типом и UUID записи; чтение валидирует контракт
  и основные связи с metadata. Неверный ключ, повреждение и подмена ciphertext
  другой записью дают общий 503, не успешный результат.
- Создание снимка/анализа и audit-event происходит в одной транзакции. При
  ошибке аудита результат не сохраняется. Через API нельзя изменить или удалить
  историю. Конфликт UUID/identity устройства отвергается.
- Feedback имеет зашифрованный payload, обязательные analysis/finding bindings
  и content hash. Оценка и `finding.feedback_recorded` атомарны; одинаковый ID
  при одинаковом намерении, включая параллельные повторы, возвращает исходную
  запись без повторного audit-event. Другой scope/text/verdict под тем же ID — 409.
  Comment ограничен 2000 символами, body — 16 KiB. Оценка не меняет анализ,
  не согласует патч и не становится проверенной training label.
- Модели и обучающие паспорта тоже зашифрованы и атомарны с `model.trained`.
  Registry хранит ограниченные числовые деревья, не исполняемые Python-объекты;
  проверяет граф, schema, finite values и artifact hash. API не импортирует внешние
  модели и не обучает заново при inference. Входы обучения/анализа проверяются
  по группе, полноте разбора, distinct devices и отсутствию target/future snapshots.
  Эти проверки не удостоверяют физические устройства или качество датасета.
- В собственных логах API нет конфигураций, секретов или SQL-параметров;
  ошибки валидации не отражают исходный input. HTTP-ответы имеют `no-store` и
  `nosniff`. В Docker build context исключены `.env`, ТЗ и локальные artifacts.
- API не вызывает внешние ML/LLM-сервисы, не загружает модели из запроса,
  не подключается к устройствам и не применяет изменения.
  Отдельный opt-in LLM adapter обращается только к буквальному loopback после
  разрешения оператора/запроса; строковые keys/values заменены, evidence prose
  исключена. Числа/hashes/anchors могут быть закрытыми. Один bounded worker на
  процесс и hard deadline не заменяют общие quotas или контроль сервера модели.
- Snapshot diff читает только явно выбранную пару сохранённых версий того же
  устройства с проверкой времени. Неоднозначные keys и превышенные бюджеты
  отвергаются, не превращаются в пустой clean report. Unknown fragments исключены
  с partial coverage; source/projection hashes и anchors сторон сохраняются.
  Diff не обезличивает значения, не запускает детекторы и не меняет историю/риск.
- Черновик сохраняет именно этот diff, не команды. Draft/review payload
  зашифрованы, привязаны к UUID/снимкам/fingerprint и атомарны с аудитом.
  Параллельные повторы одного намерения возвращают одну исходную запись;
  чтение пересчитывает diff из родителей, но не переоценивает исторический
  отчёт новым каталогом. Локальная проверка не может стать formal pass:
  `mode=batfish` в HTTP возвращает 503 без fallback.
- Reference/peer inputs выбираются только по сохранённым IDs, до анализа
  проверяются identity, группа, distinct devices, порядок приёма и полнота
  парсинга. Результат хранит профиль/версии/hashes внутри encrypted payload.
  Неверный выбор не создаёт ни анализа, ни успешного audit-event. Роль и
  метки задаёт оператор; UUID/hostname не удостоверяют физическое устройство.
- UI и API работают на одном origin. Токен используется только в Authorization,
  не в URL/cookies/localStorage/sessionStorage; logout, pagehide и восстановление
  страницы очищают сессию и видимые данные. Ошибки не отражают response body.
  Конфигурации и citations рендерятся текстом, не HTML/ссылками от входных данных.
  Built UI имеет CSP без inline scripts/styles, запрет framing, no-referrer и no-store.

## Что остаётся открытым или ограниченным

Service key — роль, не индивидуальный пользователь/tenant. Его владелец видит
все устройства, включая конфиденциальный canonical/raw-unparsed text. Ограничение
операций по роли реализовано, отзыв/ротация — только через настройки и restart
всех процессов. Individual identity, пользовательские sessions, hot-revocation,
SSO, expiry и разделение tenants отсутствуют.
Без reverse proxy нет TLS; наружу этот development API открывать нельзя.
Секреты и файл SQLite требуют ограниченных OS permissions.
Любой исполняемый скрипт того же origin, вредоносное расширение браузера или
компрометация endpoint может получить токен из памяти и видимые конфигурации.
Очищение ссылок при logout не является гарантированным стиранием памяти браузера.
Dev Vite server не имеет production CSP и доступен только на loopback.

UUID, source hashes, timestamps, связи и типы действий открыты в БД; Fernet
также раскрывает timestamp создания ciphertext. Секреты существуют в памяти
процесса и доверенной среде запуска. Потеря ключа делает историю нечитаемой;
сохранение ключа отдельно от backups и безопасная rotation ещё не автоматизированы.
Компрометация процесса/ключа не защищена шифрованием payload.

Audit сейчас фиксирует только успешные создания snapshot/analysis/model/feedback/draft/local-review, не чтения,
не попытки доступа и не конкретного человека. DB-admin может переписать или
удалить metadata, audit и ciphertext. Нет append-only внешнего аудита,
защиты от отката всей БД, подписей результатов, retention policy или backup UI.
Fernet выявляет подмену прочитанных payload, но не гарантирует выявление удаления
или переноса metadata, скрывающего строку от scoped query. Feedback actor —
`shared_service_token`, не удостоверенная личность человека.

Лимиты отдельного запроса не заменяют rate limit, concurrency quotas и общей
квоты диска: авторизованный клиент способен заполнить историю. Анализ синхронный,
очередь задач и отмена отсутствуют. Пагинация offset может смещаться при новых
записях. Одновременное первое создание одного UUID может дать повторяемый 503
из-за DB-constraint; клиент вправе безопасно повторить запрос с той же identity.
Отмена fetch в UI прекращает ожидание клиента, но не откатывает возможную запись
или работу backend. После таймаута надо проверить историю до повторного POST.
Обучение ограничено 8–100 снимками, 16 MiB суммарного canonical JSON и одним
запуском на процесс; это не распределённая quota или защита от заполнения реестра.
Локальный registry не утверждает, не калибрует и не продвигает модели в production.

Общий `/ready` проверяет схему, а не все зашифрованные строки и не пригодность
ключа для старой БД. API сохраняет canonical snapshot, не полный raw file;
восстановить original для формальной проверки по нему нельзя.

Production-проверки PostgreSQL, deployment, TLS, roles, backup/restore и
penetration testing ещё не выполнены. Static checks и SQLite integration tests
не заменяют этих проверок.
## Retrieved explanation sources

The authenticated read-only `explain` endpoint retrieves only allowlisted internal
project documents, not arbitrary URLs or uploaded configuration fragments.
Local retrieval never calls an LLM. An explicit LLM request defaults to unavailable;
an opt-in literal-loopback adapter requires separate context permission. Scores,
verification and saved analysis cannot be changed by an answer. UI renders source
content as text and checks bindings/chunk hashes, which are not publisher signatures.
The provider boundary rejects extra fields, executable patch drafts and unretrieved
citations; schema validity does not establish semantic truth or eliminate prompt
injection. Model prose remains untrusted and is never executed or saved as an analysis.
String pseudonyms and omission of evidence prose do not establish anonymity:
numeric facts, hashes and line anchors can still be confidential. Remote addresses,
redirects and environment proxies are prohibited, but the local server's own logging,
storage and outgoing network access require operator control. Worker termination
does not prove remote computation was cancelled. No actual instruct-language
weights or explanation quality have been validated. See [contextual explanations](contextual-explanations.md) and
[local-model limits](local-model-explanations.md).

## Offline prediction and calibration artifacts

Explanation source releases are pinned to supported recorded detector versions.
The application anchors manifest hashes, checks archived file/parent boundaries,
inventory and document hashes, and never substitutes mutable current documents.
Backend and frontend reject incompatible detector/knowledge versions. This is
content integrity and version isolation, not publisher signatures, external
license approval or protection from an actor who can rewrite application code.

The separate offline vector index uses a fixed, checksum-pinned public document
encoder, never pickle or remote Python. Acquisition is an explicit operator CLI,
not API startup; encoding/index loading performs no network requests. Model and
index directories must remain trusted and immutable during reads. Exact model,
pipeline/runtime and complete sealed-source bindings reject incompatible inputs;
finite unit-vector validation does not prove that a privileged artifact author
computed vectors honestly. An optional externally recorded index hash can pin
the artifact beyond its own manifest. Query rankings cannot approve patches,
change detector scores, or make retrieved prose authoritative. Opt-in HTTP
retrieval uses an isolated deadline-bound worker with stripped environment and
public detector metadata only, never customer values/source text. Parent validates
the returned release/model/index/query/source bindings, mandatory references stay
in context and a failed semantic request never silently becomes explicit-only.
The worker runs trusted local code; it is not an OS sandbox or network firewall.
Six authored diagnostic queries do not
establish independent retrieval quality or prompt-injection robustness.

Local prediction files must not contain configuration text or secrets. Opaque
grouping keys, source/annotation/model hashes and calibration exposure can still
be confidential and linkable; hashing does not grant evaluation or publication
permission. The evaluator bounds JSON/arrays, rejects duplicate keys/nonfinite
values, checks supplied grouping/exposure and suppresses raw input in CLI errors.
It cannot attest operator-provided annotations, source authorization, deduplication
or model identity. Keep files in trusted access-controlled storage.

Calibration refuses test/selection reuse for fitting and records its exact
model/corpus/exposure binding; a valid artifact is not a production calibration
or data-quality pass. Generic reports and SVG never alter online risk or approve
a patch. Missing real data and undefined metrics remain explicit. Only reviewed
synthetic aggregate diagnostics are published in the demonstration report;
real predictions and calibration inputs are not automatically uploaded.

## Supervised encoder outputs

The joint model consumes sanitized source-aligned features and explicit labels.
Training rechecks original split membership, entity isolation, tokenizer/corpus
binding and annotation hashes; these integrity checks cannot verify a human's
source authorization or factual labels. Similarity groups and embeddings can be
confidential. Inference returns no score for explicitly disabled/untrained tasks.
Neural severity is a prediction, not a policy override or formal consequence.
The local model bundle is loaded only from trusted storage, with bounded files,
inventory/checksum/tensor/report checks. Hashes do not authenticate model authors.
The synthetic full-batch training/evaluation path does not promote weights into
the API, alter online risk, approve a patch or replace live verification.

The joint pretraining path likewise consumes already approved/sanitized records
and treats semantic pair reviews as operator-supplied declarations, not proof.
Original/derived views, hashes and embeddings remain confidential. Pair scope
is explicit: a match in a narrow routing slice cannot establish full-config
equivalence, management safety or reachability. Synthetic replacement labels do
not certify anomalies or syntax validity. Offline bundle integrity, construction
budgets and tensor-only loading do not establish source consent or model quality.
