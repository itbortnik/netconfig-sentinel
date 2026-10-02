import type { SelectedSnapshot } from "./comparison";

export function ComparisonSelection({
  reference,
  peers,
  busy,
  onClearReference,
  onRemovePeer,
}: {
  reference: SelectedSnapshot | null;
  peers: SelectedSnapshot[];
  busy: boolean;
  onClearReference: () => void;
  onRemovePeer: (id: string) => void;
}) {
  return (
    <section className="panel comparison-panel" aria-label="Выбор сравнений">
      <h3>Сравнения для следующего анализа</h3>
      <p className="hint">
        Откройте ранние снимки в истории и добавьте эталон или 3–20 peers. Затем
        выберите текущий снимок и нажмите «Анализировать снимок». Ничего не
        выбирается автоматически.
      </p>
      <p>
        Эталон:{" "}
        {reference
          ? `${reference.hostname ?? "Без hostname"} · ${reference.id}`
          : "Не выбран"}
      </p>
      {reference && (
        <button
          className="button secondary compact"
          disabled={busy}
          onClick={onClearReference}
        >
          Убрать эталон
        </button>
      )}
      <p>Группа: {peers.length} из максимум 20 устройств</p>
      <ul>
        {peers.map((peer) => (
          <li key={peer.id}>
            {peer.hostname ?? "Без hostname"} ·{" "}
            <span className="mono">{peer.id}</span>{" "}
            <button
              className="button secondary compact"
              disabled={busy}
              onClick={() => onRemovePeer(peer.id)}
              aria-label={`Убрать peer ${peer.hostname ?? peer.id}`}
            >
              Убрать
            </button>
          </li>
        ))}
      </ul>
      <p className="hint">
        Различия с эталоном показываются отдельно и не входят в риск. Совпадение
        с группой не доказывает безопасность. ML запускается только при явном
        выборе модели ниже. Batfish не запускается.
      </p>
    </section>
  );
}
