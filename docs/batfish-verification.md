# Экспериментальный адаптер Batfish

Реализованы подготовка пары многодевайсных снимков, отдельный SDK-процесс и
ограниченный запрос изменения достижимости. **Успешные живые запросы подтверждены
в отдельном Linux CI job** на commit `c32c89f`: шесть actual запросов к двум
собственным Cisco/JunOS топологиям, восемь tests passed. Проверены реальная
потеря достижимости, неизменённая достижимая сеть и пустой scope без ложного pass,
а также удаление каждой собственной сети. См.
[конкретный job](https://github.com/itbortnik/netconfig-sentinel/actions/runs/37735135977/job/113172859364)
и [извлечённый числовой отчёт](evaluation/owned-batfish.json).
Это узкий diagnostic integration, не квалификация production или модельного патча.

На 2026-10-08 временный официальный JAR
`2026.08.27.3685` запущен на уже установленной Java 21 в Windows. Проверено,
что его единственный listener — `127.0.0.1:9996`; после проверки собственный
процесс завершён и listener отсутствует. Но SDK initialization собственных
двух Cisco-конфигураций вернул `No valid configurations found in snapshot`.
Это реальный отрицательный результат, не formal pass. Установка службы,
Docker/WSL или загрузка пользовательских данных не выполнялась.

В [закреплённом исходнике FileBasedStorage](https://github.com/batfish/batfish/blob/329c14bf712f81b1522147abb00419c8e34e8f4a/projects/common/src/main/java/org/batfish/storage/FileBasedStorage.java)
ключи формируются через native `Path.toString()`, а `keyInDir` требует `/`.
Это вероятная причина Windows отказа, установленная по исходнику, а не
подтверждённая исправленной сторонней сборкой. JAR не патчился; Windows-native
поддержка движка и любые обходы не квалифицированы.

В CI job `batfish-live` используется фиксированный официальный контейнер и
шесть собственных сценариев Cisco/JunOS. Совместимость нужно повторять для
конкретного нового commit; старый успешный job не подтверждает ещё не запущенный
код. Тестовый клиент unit tests проверяет только порядок вызовов и отказобезопасность.

## Область проверки

Снимок включает явно переданные конфигурации 1–32 устройств, до 8 MiB суммарно;
каждая конфигурация ограничена 2 MiB и 10 000 строк. Требуется полный локальный
разбор, уникальные hostname и UUID. Набор UUID/vendor-platform/hostname должен
совпадать до/после; добавление/удаление устройств пока не поддерживается.
Имена файлов генерируются из UUID. Обход каталогов и автообнаружение файлов
не выполняются. Hash снимка учитывает все входные конфигурации.

Scope ограничен исходным узлом и IPv4-префиксом назначения, без пользовательских
выражений specifier. Источник обязан присутствовать в обоих снимках. Все
протоколы рассматриваются в этой области; произвольные ACL-политики, обратный
трафик, аварии оборудования и полноценный topology inventory не проверяются.
Движок выводит связи из предоставленных конфигураций. Полнота физической сети
не доказана; результат относится только к этой модели.

Адаптер использует `fileParseStatus`, `initIssues` и `parseWarning` перед
запросами: каждый ожидаемый файл и hostname должен быть найден ровно один раз,
статус должен быть PASSED, предупреждений не должно быть. Неизвестные/пустые
результаты не считаются успешным разбором. См.
[официальные рекомендации инициализации](https://batfish.readthedocs.io/en/latest/notebooks/interacting.html).

Затем выполняются `reachability(actions="success")` для обеих сторон и
`differentialReachability(snapshot="after", reference_snapshot="before")`.
В scope без достижимых потоков нельзя получить положительный вывод только
на основании пустого diff. Направление вызова и поля вопроса приведены в
[документации differentialReachability](https://batfish.readthedocs.io/en/latest/notebooks/differentialQuestions.html).

## Безопасность запуска

По умолчанию нет загрузок и подключений: результат `unavailable` с причиной
`upload_not_authorized`. Опция `--allow-local-upload` разрешает передать сырые
конфигурации **только локальному Batfish на 127.0.0.1**. Удалённый host через
CLI не задаётся. Движок следует запускать отдельно в доверенном окружении.
SDK-процесс запускается без унаследованных HTTP/HTTPS/ALL_PROXY и с NO_PROXY=*,
чтобы не маршрутизировать локальную загрузку через внешний прокси.
SDK — необязательная зависимость: `pip install -e ".[verification]"`.
Зафиксирован [официальный pybatfish 2026.8.19.3660](https://pypi.org/project/pybatfish/2026.8.19.3660/).
Ранее указанная `0.36.0` отсутствует в каталоге пакетов; эта ошибка исправлена
после реального отказа установки. Новый SDK установлен в отдельную лабораторную
среду; основной CPU/ML environment не изменён. SHA256 wheel опубликован на
PyPI: `6ce1d0c2346a67b27665f341e69837ee7711734a7859cd12259b6e08c5c19621`.

Python worker получает только минимальные OS/runtime переменные и не наследует
API/model tokens, credentials или Python import/startup overrides. Он запускается
в isolated mode, без пользовательского site и видимого Windows окна. Permission
обязан быть boolean; truthy строки/числа не разрешают upload. Timeout — integer
1–300, не boolean/float. Эти ограничения не являются OS sandbox.

SDK получает literal host/port `127.0.0.1:9996`, без SSL и proxy overrides.
Redirect following отключён для всех запросов; response hook дополнительно
отклоняет весь диапазон HTTP 3xx до интерпретации ответа. Поэтому redirect не
перенаправляет upload и не считается подтверждением создания/очистки сети.
Отказ возвращается как generic engine error, без URL, body или исходных строк.
Двенадцать actual optional-SDK проверок 302/307/308 × GET/POST/PUT/DELETE на
двух собственных loopback HTTP fixtures подтвердили: вторичный endpoint не
получил запрос. См. [installed SDK transport report](evaluation/owned-batfish-transport.json).
Это реальные transport tests, но не Batfish/formal queries.

## Отдельный контейнер

Опциональный Compose profile не активирует verifier в HTTP и не передаёт входы
самостоятельно. Только после решения оператора запустить доверенный движок:

```powershell
docker compose --profile verification up -d batfish
```

Контейнер закреплён official release digest
`sha256:7909378197c5a3974f2e8180af58cef0ca17b74d1cd9ba39f2d1fddb64737e55`
(tag `2026.08.27.3685`), порт хоста — только `127.0.0.1:9996`.
Лимиты — 4 GiB RAM и два CPU, root filesystem read-only, `/tmp` временный,
`/data` отдельный volume. Внутренний контейнерный listener не равен ограничению
host networking: доверие к сети/контейнеру остаётся обязанностью оператора.
Volume может сохранять сырые снимки при сбое/timeout. Compose profile локально
не запускался, поскольку Docker CLI отсутствует; его hardening ещё не квалифицирован.
Registry/layer digests проверяют целостность, не publisher signature, эксплуатационную
безопасность или корректность сети. JAR из этого image не заменяет контейнер:
нативный Windows запуск получил описанный выше отказ.

## Лимиты и удаление собственных снимков

Запросы выполняются в дочернем процессе с общим лимитом 60 секунд (допустимо
1–300). При тайм-ауте SDK-процесс завершается, временные файлы родителя удаляются.
Временные снимки содержат сырой текст и защищены только средствами ОС;
шифрование временного каталога модулем не реализовано.

Для каждого запуска создаётся уникальная сеть `sentinel-<uuid>`, снимки
загружаются без overwrite. В конце удаляется только созданная этим запуском
сеть. Коллизия имени — отказ, существующая сеть не удаляется. При тайм-ауте,
обрыве или сбое очистки на сервере могут остаться сырые снимки. `network_name`
и `cleanup_complete` позволяют установить необходимость ручной очистки;
`null` не подтверждает очистку. Автоматического удаления других сетей нет.
Успех очистки не является частью оценки достижимости.

Сообщения SDK, trace и строки диагностик не возвращаются в отчёте: только
версии, hashes, scope, счётчики, статусы и ограничения. Ошибки обобщаются без
текста конфигураций. Отчёт всё равно содержит hostname и адрес назначения и
должен храниться закрыто.

## Manifest и команда

Все пути задаются относительно manifest и должны оставаться внутри его
каталога после разрешения ссылок. UUID одного устройства одинаков на обеих
сторонах. Минимальный пример:

```json
{
  "version": "network-check-0.1.0",
  "devices": [{
    "device_id": "7f64381c-fda8-48f9-8e8a-fb772b2f64dc",
    "before": "before/edge.cfg",
    "after": "after/edge.cfg"
  }],
  "scope": {"start_node": "edge", "destination": "198.51.100.1/32"}
}
```

```powershell
.venv\Scripts\python.exe -m app.verification.batfish_cli --manifest private-network.json
# Только после настройки доверенного локального движка и разрешения загрузки:
.venv\Scripts\python.exe -m app.verification.batfish_cli --manifest private-network.json --allow-local-upload --timeout 120
```

| Статус | Значение | Код CLI |
|---|---|---|
| no_differences_in_scope | Есть достижимые потоки на обеих сторонах, diff пуст | 0 |
| differences_found | Найдены примеры изменившейся достижимости | 1 |
| error | Сбой процесса/движка либо тайм-аут | 2 |
| unavailable | Нет разрешения загрузки или SDK | 3 |
| incomplete | Не все файлы распознаны либо есть диагностика | 3 |
| inconclusive | Пустой diff при пустой достижимой области | 3 |

Невалидный manifest/вход даёт код 2 без отчёта. Счётчики — количество строк
ответа, не число всех потоков. Изменения могут означать как потерю, так и
появление достижимости; им не назначается severity автоматически.
Код 0 не подтверждает безопасность всей сети и не повышает статус PatchProposal.

## Проверка реализации

Обычные тесты используют fake SDK и не выполняют сетевых запросов. Отдельный
live smoke tests с двумя собственными узлами каждого вендора запускаются только явно:

```powershell
$env:NETCONFIG_LIVE_BATFISH='1'
.venv\Scripts\python.exe -m pytest backend/tests/integration/test_live_batfish.py -q
Remove-Item Env:NETCONFIG_LIVE_BATFISH
```

Проверяются потеря достижимости при замене static next-hop на discard,
неизменённая достижимая сеть и пустой scope без ложного положительного вывода
для Cisco IOS и JunOS. Это шесть запросов к двум игрушечным топологиям, а не
шесть независимых сетей или реальных аномалий. Каждый запрос должен завершить
удаление собственной сети. Эти шесть тестов уже пройдены в указанном Linux job.
Undefined ACL ссылки в двух дополнительных owned fixtures отклоняются ещё
локальным parser gate, до upload; этот отказ не выдаётся за live initIssues
coverage. Общая поддержка платформ и operational state всё ещё не установлены.
Адаптер остаётся экспериментальным; связь с
утверждением черновика и интеграция в итоговый risk fusion намеренно отсутствуют.

### Сгенерированное удаление hierarchical JunOS маршрута

`backend/tests/integration/test_live_mutation_batfish.py` связывает существующий
адаптер с точным результатом `config-mutation-0.2.0`, а не заменяет генерацию
похожим ручным edit. Два собственных multiline JunOS устройства проходят
sanitization с одним topology scope; генератор удаляет единственный static route
на edge. Соседний узел остаётся побайтно прежним, весь parent восстанавливается
точным inverse, source/candidate hashes проверяются до network query.

Четыре отдельных scope проверяют generated route loss, unchanged reachable
baseline, сохранение directly connected peer и empty unreachable scope без
ложного pass. Параметр `candidate_selected` явно отличает unchanged control от
запроса именно generated candidate. Каждый live output содержит mutation ID,
source/candidate и full snapshot hashes, scope, engine/SDK versions, реальные
счётчики, status/reason и cleanup. Старый `sample.formal_validation=not_run`
остаётся неизменным: последующий network result не переписывает историю мутации.

Обычный запуск проверяет подготовку и отказ без upload, но пропускает четыре
live-запроса. Owned Linux CI включает этот файл в существующий `batfish-live`
job. До успешного нового exact-commit job это только проверяемые сценарии,
не evidence выполненных запросов. Даже успешные запросы квалифицируют лишь одну
authored двухузловую модель, один класс мутации и выбранные IPv4 scopes; не все
14 классов, vendor device syntax, management access, реальную сеть или обучение.
Первый [owned job](https://github.com/itbortnik/netconfig-sentinel/actions/runs/38039746950/job/114177442737)
на `a74eba0` получил `incomplete / initialization_issues` во всех четырёх попытках,
включая неизменённый parent. Reachability counts не получены; cleanup успешен.
Строгий gate остаётся прежним. Test-only диагностический повтор выводит только
ограниченные Type/Details для точных публичных authored inputs; Line_Text и полные
строки ответа не выводятся, production worker по-прежнему не раскрывает diagnostics.

## Привязка к существующему черновику

Дополнительный параметр `--patch-review private-review.json` принимает локальный
артефакт, созданный командой `app.patching.cli create`. На stdout возвращается
`NetworkPatchReview`: исходный локальный отчёт, fingerprints всех устройств
обоих снимков и отдельный результат сетевого запроса.

До любой загрузки проверяются хеши устройства из черновика, состав и идентичность
снимков. В этом режиме изменяться может только целевое устройство; изменения
соседей требуют отдельного набора предложений, который пока не поддерживается.
Локальный preflight пересчитывается: сохранённый, но устаревший/изменённый отчёт
отклоняется до обращения к SDK. Существующий артефакт никогда не переписывается.

`status=needs_review` и `requires_human_review=true` остаются обязательными даже
при `no_differences_in_scope`. Исторический `local_review.preflight` сохраняет
своё `formal_verification=not_run`, поскольку это результат локального этапа;
позднейший сетевой запрос находится в отдельном поле `network_result`.
Scope не считается полным набором критериев приёмки. Вывод не является подписью
и не может использоваться как разрешение на применение.

Для завершённых запросов обязательна версия движка и целочисленные счётчики
(boolean не принимается за число). Некорректный JSON-ответ worker, в том числе
`null` или массив, даёт `error/worker_failed` без traceback и исходных данных.

Для untrusted source-bound model answers есть отдельный
[exact model candidate → network review](model-patch-network-review.md):
fresh replay original answer/metadata, exact source in supplied full snapshot,
только одна замена и сохранение остальных устройств. Opt-in и status не меняются.
Raw model prose/receipt не передаются движку; передаются только explicit network
snapshots. Записанный decline не получает substitute candidate.
