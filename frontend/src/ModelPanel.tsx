import type { ModelSummary } from "./contracts";
import type { SelectedSnapshot } from "./comparison";
import { date, shortId } from "./format";

export function ModelPanel({
  models,
  training,
  selected,
  offset,
  busy,
  onTrain,
  onRemove,
  onSelect,
  onOffset,
}: {
  models: ModelSummary[];
  training: SelectedSnapshot[];
  selected: ModelSummary | null;
  offset: number;
  busy: boolean;
  onTrain: () => void;
  onRemove: (id: string) => void;
  onSelect: (model: ModelSummary | null) => void;
  onOffset: (offset: number) => void;
}) {
  return (
    <section className="panel comparison-panel" aria-label="Реестр моделей">
      <h3>Isolation Forest · экспериментальный контроль</h3>
      <p className="notice warning">
        Модели не калиброваны и не подтверждают безопасность сети. Для обучения
        откройте и добавьте 8–100 снимков разных устройств одной группы.
        Обучение и выбор модели выполняются явно.
      </p>
      <details open={training.length > 0}>
        <summary>Обучающие снимки: {training.length}</summary>
        <ul>
          {training.map((item) => (
            <li key={item.id}>
              {item.hostname} · <span className="mono">{item.id}</span>{" "}
              <button
                className="button secondary compact"
                disabled={busy}
                onClick={() => onRemove(item.id)}
                aria-label={`Убрать из обучения ${item.hostname ?? item.id}`}
              >
                Убрать
              </button>
            </li>
          ))}
        </ul>
        <button
          className="button secondary"
          disabled={busy || training.length < 8}
          onClick={onTrain}
        >
          Обучить и сохранить модель
        </button>
        <p className="hint">
          200 деревьев, seed 42, contamination 0.1. Это параметр алгоритма, не
          измеренная доля реальных аномалий. Изменения на устройства не
          отправляются.
        </p>
      </details>
      <p>
        Модель следующего анализа:{" "}
        {selected
          ? `${shortId(selected.model_id)} · ${selected.metadata.sample_count} снимков`
          : "Не выбрана — ML не запускается"}
      </p>
      {selected && (
        <button
          className="button secondary compact"
          disabled={busy}
          onClick={() => onSelect(null)}
        >
          Убрать модель
        </button>
      )}
      <ul>
        {models.map((model) => (
          <li key={model.model_id}>
            <span className="mono">{model.model_id}</span> ·{" "}
            {date(model.created_at)} · {model.metadata.sample_count} снимков ·
            experimental{" "}
            <button
              className="button secondary compact"
              disabled={busy}
              onClick={() => onSelect(model)}
              aria-pressed={selected?.model_id === model.model_id}
            >
              Выбрать модель {shortId(model.model_id)}
            </button>
            <details>
              <summary>Паспорт модели {shortId(model.model_id)}</summary>
              <pre className="json-view">{JSON.stringify(model, null, 2)}</pre>
            </details>
          </li>
        ))}
      </ul>
      {models.length === 0 && (
        <p className="empty">На этой странице реестра моделей нет.</p>
      )}
      <div className="pager">
        <button
          className="button secondary compact"
          disabled={busy || offset === 0}
          onClick={() => onOffset(Math.max(0, offset - 20))}
        >
          Предыдущие модели
        </button>
        <button
          className="button secondary compact"
          disabled={busy || models.length < 20 || offset >= 10000}
          onClick={() => onOffset(offset + 20)}
        >
          Следующие модели
        </button>
      </div>
    </section>
  );
}
