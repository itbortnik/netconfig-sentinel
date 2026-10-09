import type { SelectedSnapshot } from "./comparison";

export function ComparisonSelection({
  reference,
  peers,
  version,
  onVersion,
  busy,
  onClearReference,
  onRemovePeer,
}: {
  reference: SelectedSnapshot | null;
  peers: SelectedSnapshot[];
  version: "0.1.0" | "0.2.0" | "0.3.0";
  onVersion: (value: "0.1.0" | "0.2.0" | "0.3.0") => void;
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
      <label htmlFor="comparison-version">Область сравнения</label>
      <select
        id="comparison-version"
        disabled={busy}
        value={version}
        onChange={(event) =>
          onVersion(
            event.target.value === "0.3.0"
              ? "0.3.0"
              : event.target.value === "0.2.0"
                ? "0.2.0"
                : "0.1.0",
          )
        }
      >
        <option value="0.1.0">0.1 — прежний набор признаков</option>
        <option value="0.2.0">
          0.2 — значения management, VLAN, ACL и routing
        </option>
        <option value="0.3.0">
          0.3 — те же свойства и измеренная доля неразобранных строк
        </option>
      </select>
      {version !== "0.1.0" && (
        <p className="hint">
          При неполном разборе текущего снимка сравнение свойств peers
          пропускается целиком. Отсутствие находок не означает, что эти свойства
          проверены.
        </p>
      )}
      {version === "0.3.0" && (
        <p className="hint">
          Для peers нужны сохранённые измерения с ненулевым знаменателем.
          Считаются исходные строки адаптера, не универсальные команды. Форматы
          set и blocks могут иметь разные знаменатели; это не проверка
          синтаксиса или безопасности. Эталонное сравнение остаётся версией 0.2
          и не требует отчёта покрытия.
        </p>
      )}
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
