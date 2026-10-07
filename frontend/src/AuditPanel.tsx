import { useEffect, useRef, useState } from "react";
import { ApiClient } from "./api";
import type { OperationPage, OperationRecord } from "./audit";
import { date, shortId } from "./format";

const outcomes = {
  pending: "Итог не подтверждён",
  successful_response: "Успешный ответ API",
  rejected_response: "Запрос отклонён",
  failed_response: "Ошибка ответа API",
};
const authorizations = {
  allowed: "Разрешено ролью",
  denied: "Недостаточно прав",
  not_authenticated: "Без подтверждённого ключа",
  not_checked: "Решение о правах не зафиксировано",
};
export function AuditPanel({
  client,
  onError,
}: {
  client: ApiClient;
  onError: (problem: unknown) => void;
}) {
  const [page, setPage] = useState<OperationPage | null>(null);
  const [selected, setSelected] = useState<OperationRecord | null>(null);
  const [cursor, setCursor] = useState<string | undefined>();
  const [prior, setPrior] = useState<(string | undefined)[]>([]);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const locked = useRef(false);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, [client]);
  async function load(
    before?: string,
    direction: "newest" | "next" | "back" = "newest",
  ) {
    if (locked.current || !client.permits("read_audit")) return;
    locked.current = true;
    setBusy(true);
    try {
      const received = await client.operationAudit(before);
      if (!alive.current) return;
      setPage(received);
      setSelected(null);
      setPrior((values) =>
        direction === "next"
          ? [...values, cursor]
          : direction === "back"
            ? values.slice(0, -1)
            : [],
      );
      setCursor(before);
    } catch (problem) {
      if (alive.current) {
        setPage(null);
        setSelected(null);
        onError(problem);
      }
    } finally {
      locked.current = false;
      if (alive.current) setBusy(false);
    }
  }
  async function detail(item: OperationRecord) {
    if (locked.current) return;
    locked.current = true;
    setBusy(true);
    setSelected(null);
    try {
      const received = await client.operation(item.receipt.operation_id);
      if (alive.current) setSelected(received);
    } catch (problem) {
      if (alive.current) onError(problem);
    } finally {
      locked.current = false;
      if (alive.current) setBusy(false);
    }
  }
  const result = selected?.completion?.result;
  return (
    <section className="panel audit-panel" aria-label="Журнал операций">
      <div className="section-heading split">
        <div>
          <span className="eyebrow">ДОСТУП АДМИНИСТРАТОРА</span>
          <h2>Журнал операций</h2>
        </div>
        <button
          className="button secondary compact"
          disabled={busy}
          onClick={() => void load()}
        >
          {busy
            ? "Загрузка журнала…"
            : page
              ? "Обновить журнал"
              : "Открыть журнал"}
        </button>
      </div>
      <p className="hint">
        Роль service-ключа — не личность пользователя. Записан итог ответа API,
        а не его доставка клиенту, применение изменений или формальная проверка.
        Отсутствующий итог остаётся неподтверждённым.
      </p>
      {page && (
        <>
          <div className="audit-records">
            {page.records.length === 0 && <p>Нет более ранних операций.</p>}
            {page.records.map((item) => (
              <button
                className="button secondary audit-record"
                key={item.receipt.operation_id}
                disabled={busy}
                onClick={() => void detail(item)}
                aria-label={`Операция ${item.receipt.operation_id}`}
              >
                <strong>{item.receipt.operation}</strong>
                <span>
                  {date(item.receipt.started_at)} ·{" "}
                  {shortId(item.receipt.operation_id)}
                </span>
                <span>
                  {item.receipt.service_role ?? "Ключ не подтверждён"} ·{" "}
                  {outcomes[item.outcome]}
                </span>
              </button>
            ))}
          </div>
          <div className="pager">
            <button
              className="button secondary compact"
              disabled={busy || !prior.length}
              onClick={() => void load(prior.at(-1), "back")}
            >
              Новые записи
            </button>
            <span className="hint">Показано: {page.records.length}</span>
            <button
              className="button secondary compact"
              disabled={busy || !page.next_before}
              onClick={() => void load(page.next_before ?? undefined, "next")}
            >
              Более ранние
            </button>
          </div>
        </>
      )}
      {selected && (
        <section className="audit-detail" aria-label="Детали операции">
          <h3>{outcomes[selected.outcome]}</h3>
          <p>
            UUID: <code>{selected.receipt.operation_id}</code>
          </p>
          <p>
            {selected.receipt.method} · {selected.receipt.operation} ·{" "}
            {authorizations[selected.authorization]}
          </p>
          {selected.completion ? (
            <>
              <p>
                HTTP {selected.completion.status_code} ·{" "}
                {selected.completion.duration_ms} мс ·{" "}
                {date(selected.completion.completed_at)}
              </p>
              <ul>
                {selected.completion.permissions.map((item) => (
                  <li key={item.permission}>
                    {item.permission}: {item.granted ? "разрешено" : "отказ"}
                  </li>
                ))}
              </ul>
              {result && (
                <>
                  <p>
                    Результатов: {result.result_count}. UUID в журнале —
                    ограниченный список, не весь ответ.
                  </p>
                  <p>
                    Версии:{" "}
                    {result.versions.length
                      ? result.versions.join(", ")
                      : "Версия в результате не предоставлена"}
                  </p>
                  {result.resource_ids.map((id) => (
                    <p key={id}>
                      <code>{id}</code>
                    </p>
                  ))}
                  <p>
                    SHA метаданных: <code>{result.metadata_sha256}</code>
                  </p>
                  {result.knowledge_sha256 && (
                    <p>
                      SHA источников: <code>{result.knowledge_sha256}</code>
                    </p>
                  )}
                  {result.document_index_sha256 && (
                    <p>
                      SHA индекса: <code>{result.document_index_sha256}</code>
                    </p>
                  )}
                  {result.document_encoder_sha256 && (
                    <p>
                      SHA идентификатора энкодера:{" "}
                      <code>{result.document_encoder_sha256}</code>
                    </p>
                  )}
                </>
              )}
            </>
          ) : (
            <p className="notice">
              Нет подтверждённого завершения. Изменение могло сохраниться;
              проверьте предметную историю перед повтором.
            </p>
          )}
          <p className="hint">
            Журнал не содержит конфигурации, токены, промпты, эмбеддинги,
            комментарии или текст ответа модели. Проверка привязки и шифрования
            не доказывает полноту истории и не защищает от удаления
            привилегированным владельцем БД.
          </p>
        </section>
      )}
    </section>
  );
}
