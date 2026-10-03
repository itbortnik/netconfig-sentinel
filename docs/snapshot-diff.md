# Сравнение сохранённых снимков

Этот просмотр сравнивает нормализованные объекты двух явно выбранных версий
одного устройства. БД не хранит полный исходный файл, поэтому результат **не raw
text diff**, не список команд для применения и не восстановление original file.
Сравнение не запускает детекторы/обучение/Batfish/LLM, не меняет risk, не создаёт
анализ, оценку или событие успешного создания в audit. Дополнительная миграция
для него не нужна; постоянный API по-прежнему требует актуальную схему.

## API

```text
GET /api/v1/configurations/<current_id>/diff?reference_configuration_id=<before_id>
Authorization: Bearer <service-token>
```

Оба UUID обязательны. Current и reference должны быть разными снимками с тем же
UUID устройства, vendor, platform и hostname. Reference не должен быть принят
позже current; используется серверный `created_at`, не дата сбора из файла.
Ранний снимок выбирается оператором, автоматически не подбирается и не становится
approved baseline. Частичный разбор допускается, но покрытие будет `partial`.

Ответ `snapshot-diff-0.1.0` имеет `representation="normalized_objects"`:

- `before`, `after`: UUID снимка/устройства, исходный SHA-256, время приёма,
  vendor/platform/hostname, confidence и counts диагностик, `projection_sha256`;
- `coverage`: `supported_complete` только при confidence=1 и отсутствии
  warnings/unparsed у обоих входов; иначе `partial`;
- `source_changed`: сравнение SHA-256 исходных текстов, не нормализованных объектов;
- `added_count`, `removed_count`, `modified_count`: точные counts объектов;
- `changes`: отсортированные уникальные `section`/`object_key`, kind,
  JSON `before_value`/`after_value` и отдельные `before_locations`/`after_locations`;
- `limitations`: границы сравнения, без статуса verified/validated или оценки ущерба.

На отсутствующей стороне value — null, locations — пустой массив. Строки старого
объекта не объявляются строками current. Anchors покрывают объект, не точный
диапазон отредактированных строк; provenance-only перенос строк не создаёт change.
Projection hash — SHA-256 канонически упорядоченного списка section/key/value,
без source metadata и anchors. Это привязка к сравнению, не цифровая подпись.

| HTTP | Значение |
| --- | --- |
| 200 | Полный результат в заявленной поддерживаемой области, без усечения |
| 401 / 503 | Нет токена / недоступная схема, БД или повреждённый payload |
| 404 / 422 | Снимок не найден / обязательный UUID отсутствует или некорректен |
| 409 | Текущий/чужой/более поздний reference либо неоднозначный object key |
| 413 | Превышен бюджет сравнения; это отказ, не пустой результат |

Бюджеты: 16 MiB суммарного сериализованного JSON входов, до 500 изменений,
до 2 MiB JSON ответа. Усечения/скрытой фильтрации нет. Лимиты не заменяют rate
limit, общую concurrency quota или защиту от авторизованного перегруза. GET
возвращает конфиденциальные значения владельцу общего токена с `no-store`;
само сравнение не обезличивает данные и не предназначено для внешней передачи.

## Что и как сравнивается

| Section | Граница объекта / порядок |
| --- | --- |
| `device` | Metadata включая OS version и operator inventory labels; provenance исключён |
| `management` | Все разобранные параметры; списки SNMP/NTP/Syslog нормализуются по порядку |
| `interfaces` | Name + unit; все параметры; порядок адресов и VLAN memberships нормализуется |
| `vlans` | VLAN ID, либо имя при отсутствии ID; изменение имени известного ID — modified |
| `acls` | Family + kind + name; полный объект, порядок rules сохранён |
| `prefix_lists` | Family + name; полный объект, порядок rules сохранён |
| `static_routes` | Family + destination; список forwarding targets сохраняет дубликаты, нормализует порядок |
| `bgp` | Global параметры без neighbors; собственные anchors процесса |
| `bgp_neighbors` | Адрес соседа, все разобранные параметры и его anchors |
| `ospf` | Process ID; весь процесс, порядок network statements сохранён |

Одинаковые ключи интерфейсов/VLAN/ACL/prefix-list/OSPF не схлопываются: сравнение
отказывается от неоднозначного входа. Семантические vendor defaults не добавляются.
Это консервативное сравнение объектов parser schema 1.0, не доказательство
эквивалентности сетевого поведения. ACL и другие сохранённые порядки — порядки
канонической модели, не реконструкция original file.

Не сравниваются raw unknown fragments, текст диагностик, filename, collected_at,
номера строк, raw-text hashes provenance и parser confidence как настройка.
Их количества/confidence доступны в bindings. Поэтому zero changes при разных
source hashes допустимы: например, переставлены независимые объекты, пробелы,
комментарии, строки provenance или неизвестные команды. Изменение inventory
metadata, наоборот, может дать change при одинаковом исходном тексте.

## Интерфейс

1. Откройте ранний снимок и нажмите «Выбрать для diff». Выбор разрешён и при
   частичном разборе; он отдельный от reference/peers для анализа.
2. Откройте более поздний снимок этого же устройства или загрузите следующую
   версию с прежним UUID/hostname. Нажмите «Показать различия объектов».
3. Изучите counts, coverage, две стороны объекта, собственные строки/hashes.
   При partial неизвестные изменения могут быть пропущены; нулевой count не
   объявляется равенством исходного текста или безопасностью сети.
4. Список отображается страницами по 20 из полного bounded результата. Кнопка
   «Убрать снимок для diff» очищает выбор и результат.

Current/foreign/future reference отклоняется локально и повторно сервером.
Клиент проверяет version, representation, counts, отсутствие anchors у удалённой
стороны и все bindings выбранной пары. Смена пары очищает результат; logout,
reload и page restoration очищают selection. Запоздалый ответ после закрытия
панели/сессии не отображается. Никакие данные сравнения не пишутся в browser
storage. Значения показываются React-текстом и JSON, не HTML или ссылками.

Unit/API tests проверяют все object sections, anchors, чувствительные порядки,
отсутствие provenance noise, partial scope, bindings, budgets, corrupt payload,
restart consistency и отсутствие новых analyses/audit writes. Desktop/mobile
Chromium проверяет реальные Cisco/JunOS uploads, selection, pagination,
XSS-as-text, layout, отклонение подменённого ответа и logout. PostgreSQL и тот же
браузерный сценарий против Compose проверяются в CI. Эти тесты не являются
формальной сетевой проверкой или production security audit.
