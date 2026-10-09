# Локальный векторный поиск по запечатанным документам

Реализован отдельный ограниченный cosine index для approved внутренних разделов
knowledge 0.1.0, 0.2.0 и 0.3.0. Его библиотека не импортирует PyTorch/Transformers и
не меняет findings, risk, confidence, feedback, patches или сохранённые анализы.
HTTP `explain` по умолчанию использует `explicit_reference`; отдельный
[opt-in semantic context](semantic-explanation-context.md) подключает индекс
к API/UI и разрешённому LLM draft, не меняя mandatory references или оценки.

## Реальный локальный encoder

Используется [многоязычная MiniLM издателя Sentence Transformers](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2),
revision `e8f8c211226b894fcb81acc59f3b34ba3efd5f42`. Model card декларирует
Apache-2.0; это не аудит происхождения обучающего корпуса и не подтверждение
пригодности для закрытых данных. Исходная карточка сохраняется рядом с weights.
Список всех десяти допустимых файлов, точные размеры и SHA-256 закреплены в
`ml/retrieval/minilm.py`; посторонние файлы, pickle weights и custom Python
отклоняются. Автоматической загрузки при импорте/старте API нет.

Фактически загружены 117653760 параметров и `model.safetensors` размером
470641600 байт. Это document embedding model на 384 координаты, не instruct-LLM,
не ConfigTransformer и не обученный детектор аномалий конфигурации.
`BertModel` создаётся из hash-pinned config, все learned tensors загружаются
строго. Единственный compatibility adapter проверяет сохранённый старым BERT
buffer `embeddings.position_ids` на точное `arange(512)`, затем исключает его
из state dict: текущая библиотека не хранит этот buffer. Другие неизвестные или
отсутствующие tensors не игнорируются. Weights заморожены; inference — CPU/eval,
без gradients, сетевого запроса, AutoModel или remote code.

Pipeline `minilm-all-content-window128-mean-l2-0.1.0` использует native tokenizer
и окна по 126 content tokens + CLS/SEP. Весь текст покрывается непересекающимися
окнами, без скрытого truncation. Padding исключается attention mask; суммы всех
token vectors делятся на общее число attention tokens, затем L2-нормализуются.
CLS/SEP учитываются для каждого окна. Это явно собственное расширение pooling
для длинных разделов, не тождественный publisher recipe с усечением на 128 tokens.
Исходные control-token literals обрабатываются как обычный текст.

Лимиты encoder: 256 texts, 16 KiB UTF-8/text, 1024 windows/call, batch 8.
Они ограничивают работу, но не гарантируют время/RAM на любом hardware.
Library inference не меняет общий RNG или число threads; отдельный CLI-процесс
выбирает один CPU thread. Model directory должен быть доверенным, закрытым от
параллельной записи и не writable для HTTP пользователей. SHA-256 не защищает
от администратора, способного заменить приложение или файлы во время чтения.

## Индекс и поиск

`build_document_index` принимает только полный каталог, побайтово совпадающий
с встроенным sealed release. Embedding input — document title, section title
и полный content. Numeric-only artifact содержит citation и document/content
hashes для каждого раздела, knowledge version/hash, identity encoder с revision,
aggregate file hash, pipeline и версиями runtime. Индекс другой версии документов,
неполный каталог или runtime identity отклоняются, без current-doc fallback.

Format `sealed-document-vectors-0.1.0`: canonical JSON, 1–256 уникальных отсортированных
rows, 1–1024 finite dimensions, unit vectors, не более 8 MiB. Рядом — checksum
manifest. Загрузка проверяет inventory, duplicate JSON keys, canonical bytes,
ссылки/junctions файлов и родителей, hashes и полную привязку к каталогу.
Сохранение создаёт новый каталог и никогда не перезаписывает существующий.
`load_document_index(..., expected_sha256=...)` позволяет оператору закрепить
trusted hash вне изменяемого manifest. Manifest сам по себе не доказывает, что
vectors вычислены заявленной моделью; trust включает владельца артефакта.

`search_documents` принимает query до 4096 UTF-8 bytes и limit 1–4, считает cosine
и возвращает сами sealed chunks с hashes. Одинаковые scores упорядочиваются по
citation. Similarity — средство ранжирования, не detector confidence, вероятность,
семантическая истина или доказательство сетевого воздействия. Retrieval не
выполняет инструкции из текста и не разрешает добавлять произвольные документы,
URL, vendor manuals, конфигурации или ТЗ в индекс.

## Повторить локально

Дополнительные библиотеки устанавливаются явно; для CPU можно сначала выбрать
официальный CPU wheel PyTorch, затем optional extra:

```bash
python -m pip install torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu
python -m pip install -e '.[retrieval]'
python -m ml.retrieval.acquire --output-root artifacts/minilm-public
python -m ml.retrieval.smoke --model-root artifacts/minilm-public --output-root artifacts/document-search-run
```

Acquisition — отдельная явная команда: только fixed public repository/revision,
без private configs, API keys или caller-selected URLs. Она скачивает примерно
480 MB в новый каталог, проверяет размеры/SHA и не выполняет downloaded code.
Connect/read timeout 30 s, проверяемый общий бюджет 600 s; это не изолированный
hard process deadline. При ошибке остаётся непроверенный частичный каталог,
не пригодный к inference. Для повтора нужно выбрать другой новый путь.
Каталоги `artifacts/` исключены из Git; wheel не содержит weights или vectors.

CLI строит оба release indexes, сохраняет их, загружает обратно и выполняет
шесть authored EN/RU запросов.

Для новых comparison sources используйте `--knowledge-version project-knowledge-0.3.0`.
Этот повторяемый параметр выбирает точные releases; default двухрелизный run и
исторические отчёты не меняются. Knowledge 0.3 содержит 43 sections; собственный
pin для HTTP описан в [настройке semantic context](semantic-explanation-context.md).

Библиотечный поиск можно вызвать так:

```python
from pathlib import Path
from app.explanation.knowledge import load_knowledge_catalog
from app.explanation.vector_index import load_document_index, search_documents
from ml.retrieval.minilm import LocalDocumentEncoder

catalog = load_knowledge_catalog('project-knowledge-0.2.0')
encoder = LocalDocumentEncoder(Path('artifacts/minilm-public'))
index = load_document_index(Path('artifacts/document-search-run') / catalog.version, catalog)
results = search_documents(index, catalog, encoder, 'Почему следует отключить Telnet?')
```

## Фактическая диагностическая проверка

[Отчёт](evaluation/document-retrieval.json) получен на настоящих pinned weights,
без customer configurations, на одном CPU thread. Два последовательных прогона
дали одинаковые index hashes. Для обоих releases hit@1 — 5/6, hit@4 — 6/6;
русский запрос про peer baseline limitations не занял первое место. Query latency
в сохранённом прогоне — около 19–21 ms, построение 31/41 rows — 1.84/2.81 s;
это измерение данного процесса, не SLA или нагрузочный benchmark.

Expected citations и queries написаны вместе с реализацией. Шесть запросов не
являются independent held-out dataset, реальной оценкой RAG/LLM, cross-domain
качеством или production acceptance. [API/workflow integration](semantic-explanation-context.md)
реализована отдельно; ещё нужны независимые query labels и проверенные разрешённые vendor sources. Реальный
локальный instruct-LLM и его explanations этой моделью не заменяются.
