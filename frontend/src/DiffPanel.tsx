import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import { PatchPanel } from "./PatchPanel";
import type {
  ConfigurationSnapshot,
  ObjectChange,
  SnapshotDiff,
} from "./contracts";
import { diffBound, diffInput, diffSelection } from "./diff";
import type { DiffSelection } from "./diff";
import { date } from "./format";

const sectionNames: Record<ObjectChange["section"], string> = {
  device: "Метаданные устройства",
  management: "Управление и наблюдаемость",
  local_users: "Локальные пользователи устройства",
  interfaces: "Интерфейсы",
  vlans: "VLAN",
  acls: "ACL / фильтры",
  prefix_lists: "Prefix lists",
  static_routes: "Статические маршруты",
  bgp: "BGP",
  bgp_neighbors: "BGP-соседи",
  ospf: "OSPF",
};
const kindNames: Record<ObjectChange["kind"], string> = {
  added: "Добавлен",
  removed: "Удалён",
  modified: "Изменён",
};
function Side({
  item,
  side,
}: {
  item: ObjectChange;
  side: "before" | "after";
}) {
  const value = side === "before" ? item.before_value : item.after_value;
  const anchors =
    side === "before" ? item.before_locations : item.after_locations;
  return (
    <div className="diff-side">
      <h4>{side === "before" ? "До" : "После"}</h4>
      {value === null ? (
        <p className="hint">Объект отсутствует в этом снимке.</p>
      ) : (
        <pre>{JSON.stringify(value, null, 2)}</pre>
      )}
      {anchors.length > 0 && (
        <details>
          <summary>Строки объекта и hashes ({anchors.length})</summary>
          <p className="hint">
            Строки только этого снимка, не точный диапазон отредактированных
            строк.
          </p>
          <ul>
            {anchors.map((anchor, index) => (
              <li key={index}>
                Строки {anchor.source_lines.join(", ")} ·{" "}
                <span className="mono">{anchor.raw_text_hash}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
export function DiffPanel({
  client,
  snapshot,
  before,
  busy,
  onClear,
  onCompare,
  onError,
}: {
  client: ApiClient;
  snapshot: ConfigurationSnapshot;
  before: DiffSelection | null;
  busy: boolean;
  onClear: () => void;
  onError: (problem: unknown) => void;
  onCompare: (
    current: string,
    reference: string,
  ) => Promise<SnapshotDiff | null>;
}) {
  const [report, setReport] = useState<SnapshotDiff | null>(null);
  const [offset, setOffset] = useState(0);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const after = diffSelection(snapshot);
  async function compare() {
    if (!before || busy) return;
    setReport(null);
    setOffset(0);
    let reference: string;
    try {
      reference = diffInput(before, after);
    } catch (problem) {
      onError(
        new ApiError(
          400,
          problem instanceof Error
            ? problem.message
            : "Выбор снимков не принят.",
        ),
      );
      return;
    }
    const received = await onCompare(after.configuration_id, reference);
    if (!alive.current || !received) return;
    if (!diffBound(received, before, after)) {
      onError(
        new ApiError(0, "Сравнение не соответствует выбранной паре снимков."),
      );
      return;
    }
    setReport(received);
  }
  return (
    <section className="panel diff-panel" aria-label="Сравнение снимков">
      <h3>Сравнение разобранных объектов</h3>
      <p className="hint">
        Откройте ранний снимок, нажмите «Выбрать для diff», затем откройте
        следующий снимок этого устройства. Этот выбор не задаёт эталон для
        анализа.
      </p>
      <p>
        До:{" "}
        {before
          ? `${before.hostname ?? "Без hostname"} · ${before.configuration_id} · ${date(before.created_at)}`
          : "Не выбран"}
      </p>
      <p>
        После: {after.configuration_id} · {date(after.created_at)}
      </p>
      <p className="notice">
        Сравниваются нормализованные объекты, не исходные файлы. Неизвестные
        команды исключены. Это не проверка сети, не согласование патча и не
        изменение риска.
      </p>
      <div className="button-row">
        <button
          className="button secondary"
          disabled={busy || !before}
          onClick={() => {
            void compare();
          }}
        >
          Показать различия объектов
        </button>
        <button
          className="button secondary compact"
          disabled={busy || !before}
          onClick={onClear}
        >
          Убрать снимок для diff
        </button>
      </div>
      {report && (
        <div className="diff-result" aria-label="Результат сравнения">
          <p>
            {report.coverage === "partial"
              ? "Неполная область сравнения"
              : "Сравнена поддерживаемая область"}
          </p>
          {report.coverage === "partial" && (
            <p className="notice warning">
              Хотя бы один снимок разобран не полностью. Изменения неизвестных
              команд не показаны.
            </p>
          )}
          <p>
            Добавлено: {report.added_count} · Удалено: {report.removed_count} ·
            Изменено: {report.modified_count}
          </p>
          <p className="hint">
            Исходные SHA-256{" "}
            {report.source_changed ? "различаются" : "совпадают"}. Равенство
            разобранных объектов не доказывает равенство исходного текста или
            поведения сети.
          </p>
          {report.changes.length === 0 && (
            <p>В сравниваемых объектах различий нет.</p>
          )}
          {report.changes.slice(offset, offset + 20).map((item) => (
            <article
              className="diff-change"
              key={JSON.stringify([item.section, item.object_key])}
            >
              <h4>
                {kindNames[item.kind]} · {sectionNames[item.section]} ·{" "}
                {item.object_key.filter(Boolean).join(" / ")}
              </h4>
              <div className="diff-columns">
                <Side item={item} side="before" />
                <Side item={item} side="after" />
              </div>
            </article>
          ))}
          {report.changes.length > 20 && (
            <div className="pager">
              <button
                className="button secondary compact"
                disabled={busy || offset === 0}
                onClick={() => setOffset(Math.max(0, offset - 20))}
              >
                Предыдущие различия
              </button>
              <span className="hint">
                {offset + 1}–{Math.min(offset + 20, report.changes.length)} /{" "}
                {report.changes.length}
              </span>
              <button
                className="button secondary compact"
                disabled={busy || offset + 20 >= report.changes.length}
                onClick={() => setOffset(offset + 20)}
              >
                Следующие различия
              </button>
            </div>
          )}
          <details>
            <summary>Привязка сравнения и ограничения</summary>
            <pre>
              {JSON.stringify(
                {
                  version: report.version,
                  representation: report.representation,
                  before: report.before,
                  after: report.after,
                  limitations: report.limitations,
                },
                null,
                2,
              )}
            </pre>
          </details>
        </div>
      )}
      <PatchPanel
        client={client}
        snapshot={snapshot}
        diff={report}
        busy={busy}
        onError={onError}
      />
    </section>
  );
}
