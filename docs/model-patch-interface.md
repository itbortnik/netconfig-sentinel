# Модельное исправление в веб-интерфейсе

В деталях сохранённой находки откройте «Модельные исправления». Это отдельный
source-line workflow, не переименование существующего черновика нормализованных
объектов. Все роли чтения могут изучать историю; создание требует `draft` и
`model_explanation`, проверка — `verify`, решение — `feedback`. Сервер проверяет
права независимо от интерфейса.

## Порядок работы

1. Точный исходник должен быть ранее сохранён с original-retention opt-in.
   Старые файлы не восстанавливаются из canonical IR. Поддержаны только
   `management.telnet_enabled` / `management.ssh_version_1` policy findings
   Cisco/JunOS, без автоматической подстановки патча при отказе модели.
2. Обновите историю. При желании явно выберите более ранний снимок **того же
   устройства** как контекст генерации. Его утверждение не установлено.
3. Если оператор настроил generation, отдельно разрешите минимальный
   псевдонимизированный контекст локальной модели. Согласие unchecked,
   действует на одну отправку и сбрасывается при смене эталона/находки.
   Генерация сохраняет одну попытку под новым UUID; результат `declined`,
   `failed` или `generating` не превращается в готовый кандидат.
4. Для `draft` выберите сеть: исходный снимок обязателен, дополнительные
   snapshots не позднее generation и не более одного на устройство.
   Limit — 32 устройства. Заголовки снимков не подтверждают наличие retained
   originals; сервер проверяет их перед выполнением. Файлы не скачиваются в UI.
5. Задайте существующий начальный hostname и canonical IPv4 destination CIDR.
   При выключенных workers выполняется только local preflight. Для Batfish
   и Transformer нужны **раздельные** unchecked согласия и разрешение оператора.
   Изменение сети/области сбрасывает оба согласия. Batfish получает полные
   confidential sources; ML-worker псевдонимизирует стороны до инференса.
6. Изучите локальный разбор, политики, изменённые диапазоны, отдельные
   formal/ML/statistical results, approval blockers и оставшиеся ограничения.
   Пустой formal scope, ошибка, незавершённый запуск или неподтверждённая
   очистка никогда не отображаются как successful verification.
7. Для terminal review инженер/администратор добавляет неизменяемое решение:
   отклонить, запросить сведения либо утвердить. Approval недоступно без
   server gates, всех limitation acknowledgements и отдельных подтверждений
   device syntax, management access и rollback. Эти подтверждения — заявления
   роли service key, не независимое измерение и не удостоверение человека.
8. После нового входа откройте сохранённый анализ, находку, историю черновиков,
   затем явно выберите review/decision. Страницы содержат до 20 записей.
   Ни одно действие не применяет конфигурацию на устройстве.

Исходный анализ, риск и proposal не переписываются после проверки или решения.
`approved` относится к отдельной записи reviewer, не изменяет `applied=false`
и не доказывает безопасность всей сети или качество модели.

## Сбой и привязки

У каждого POST свой UUID, intent живёт только в памяти формы. Сетевой сбой,
таймаут, 5xx, неверный успешный response или pending result блокируют новую
отправку в этой форме. «Прочитать сохранённую попытку» выполняет только GET
с прежним ID; модель, engine и ML не запускаются повторно. 404 при чтении
не доказывает отсутствие исполнения. После закрытия формы/logout найдите
показанный ID в сохранённой истории до нового намерения.

Strict browser schemas и selection checks связывают analysis/finding/source,
baseline, exact candidate, scope, network, model pins и review decision.
Late response после смены finding/logout игнорируется. Hashes projection
авторитетно рассчитывает и заново проверяет сервер; UI сопоставляет их с
выбранным intent. Это **не** цифровая подпись и не независимое удостоверение
исполнения. Клиент не подменяет Python JSON hashing своим JSON serializer.
Comment/answer показываются React-текстом, без HTML или активных untrusted links.
Токен, context consent и IDs не записываются в browser storage.

## Настройки без исполнения

`GET /api/v1/model-patches/capabilities` доступен всем read roles. Возвращает
только `configured` / `disabled` для generation, network engine, Transformer
и независимый model SHA-256, если модель выбрана оператором. Endpoint/path/key
не возвращаются. Этот GET не вызывает provider/workers, не загружает checkpoint
и не проверяет readiness/quality. Поэтому `configured` не означает «проверка
пройдена» или «модель доступна». Operation audit сохраняет только explicit
status/pin/version metadata, без operator paths или конфигураций.

## Проверки и ограничения

```powershell
cd frontend
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:e2e
npm run test:e2e:model-patches
```

Отдельный model-patch profile всегда создаёт owned loopback backend на 8302,
fresh encrypted temporary SQLite и **фиксированный synthetic provider**.
Все `NETCONFIG_*` из родительского процесса исключаются. Он не использует
рабочую БД, deployed base URL, настоящую LLM, Transformer или Batfish.
Junit report сохраняется в ignored `artifacts`, CI публикует только этот report.
Default profile на 8301 по-прежнему имеет выключенную модель.

Browser tests проверяют реальные HTTP uploads, durable draft/local review,
append-only decisions, unchanged analysis/proposal, explicit baseline/network,
RBAC чтения после reconnect, declined/missing-original paths, response tamper,
late response, lost result/decision и pending reconciliation. Pending projection
в одном сценарии синтетическая; её нельзя считать измерением фонового worker.
Контрактные tests отдельно проверяют synthetic formal/ML approval gates, но не
доказывают исполнение этих моделей через браузер. Реальные owned engine/installed
ML measurements описаны отдельно в [saved review evidence](saved-model-patch-reviews.md).

[Локальный результат](evaluation/owned-model-candidate-browser-workflow.json):
1805 backend tests passed / 23 environment-dependent skipped, 349 frontend unit
tests, 104 default и 22 model-candidate desktop/mobile browser scenarios passed.
Typecheck/format/build и оба backend typecheck targets также прошли.
Изолированный installed-package smoke проверил четыре изменённых runtime files,
три bundled/served assets byte-for-byte, CSP/no-store, default-disabled
capabilities и отказ unauthenticated чтения. Модели не импортировались/не вызывались.

Это workflow test, не новые model-quality metrics, не production topology test
и не human identity verification. Firefox/Safari, production TLS/SSO, нагрузка,
изоляция tenants и independent real-data quality остаются отдельными требованиями.
