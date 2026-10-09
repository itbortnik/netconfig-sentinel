import { useEffect, useRef } from "react";
import type { ConfigurationSnapshot } from "./contracts";
import { date, percent } from "./format";
import { ParserCoverageView } from "./ParserCoverageView";

export function SnapshotView({
  snapshot,
  busy,
  canAnalyze,
  canTrain,
  onAnalyze,
  onDevice,
  onReference,
  onPeer,
  onTraining,
  onDiffReference,
}: {
  snapshot: ConfigurationSnapshot;
  busy: boolean;
  canAnalyze: boolean;
  canTrain: boolean;
  onAnalyze: () => void;
  onDevice: () => void;
  onReference: () => void;
  onPeer: () => void;
  onTraining: () => void;
  onDiffReference: () => void;
}) {
  const config = snapshot.canonical;
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [snapshot.configuration_id]);
  const partial =
    config.parser_confidence < 1 ||
    config.parse_warnings.length > 0 ||
    config.unparsed_fragments.length > 0;
  return (
    <section
      className="panel snapshot-panel"
      aria-labelledby="snapshot-heading"
    >
      <div className="section-heading split">
        <div>
          <span className="eyebrow">ВЫБРАННЫЙ СНИМОК</span>
          <h2 ref={heading} tabIndex={-1} id="snapshot-heading">
            {config.device.hostname ?? "Без hostname"}
          </h2>
        </div>
        <span className={`badge ${partial ? "medium" : "neutral"}`}>
          {partial ? "Неполный разбор" : "Разобран"}
        </span>
      </div>
      <p className="muted">
        {config.device.vendor.toUpperCase()} / {config.device.platform} ·{" "}
        {config.source.filename} · {date(snapshot.created_at)}
      </p>
      <dl className="metrics">
        <div>
          <dt>Доверие к разбору</dt>
          <dd>{percent(config.parser_confidence)}</dd>
        </div>
        <div>
          <dt>Интерфейсы</dt>
          <dd>{config.interfaces.length}</dd>
        </div>
        <div>
          <dt>VLAN</dt>
          <dd>{config.vlans.length}</dd>
        </div>
        <div>
          <dt>Неизвестные фрагменты</dt>
          <dd>{config.unparsed_fragments.length}</dd>
        </div>
      </dl>
      <ParserCoverageView report={snapshot.parser_coverage} />
      <dl className="identifiers">
        <dt>Устройство</dt>
        <dd>{snapshot.device_id}</dd>
        <dt>Снимок</dt>
        <dd>{snapshot.configuration_id}</dd>
        <dt>SHA-256</dt>
        <dd>{config.source.sha256}</dd>
      </dl>
      {partial && (
        <p className="notice warning">
          Неподдержанные команды могут изменить вывод. Итоговый риск для этого
          снимка не рассчитывается.
        </p>
      )}
      <div className="button-row">
        <button
          className="button secondary"
          disabled={busy}
          onClick={onDiffReference}
        >
          Выбрать для diff
        </button>
        <button
          className="button primary"
          disabled={busy || !canAnalyze}
          onClick={onAnalyze}
        >
          Анализировать снимок
        </button>
        <button className="button secondary" disabled={busy} onClick={onDevice}>
          Использовать UUID устройства
        </button>
        <button
          className="button secondary"
          disabled={busy || partial || !canAnalyze}
          onClick={onReference}
        >
          Выбрать как эталон
        </button>
        <button
          className="button secondary"
          disabled={
            busy ||
            !canAnalyze ||
            partial ||
            !config.device.role ||
            !config.device.site_class ||
            !config.device.service_profile
          }
          onClick={onPeer}
        >
          Добавить в группу сравнения
        </button>
        <button
          className="button secondary"
          disabled={
            busy ||
            !canTrain ||
            partial ||
            !config.device.hostname ||
            !config.device.role ||
            !config.device.site_class ||
            !config.device.service_profile
          }
          onClick={onTraining}
        >
          Добавить в обучение модели
        </button>
      </div>
      {config.schema_version === "1.1" && (
        <details>
          <summary>
            Пользователи устройства ({config.local_users?.length ?? 0})
          </summary>
          <p className="hint">
            Только явно разобранные параметры. Пароли, их значения и ключи здесь
            не хранятся; фактические права и возможность входа не проверены.
          </p>
          <div className="fragment-list">
            {config.local_users?.map((user) => (
              <div key={user.name}>
                <strong>{user.name}</strong>
                <p>
                  Privilege: {user.privilege ?? "Не задан"} · Класс:{" "}
                  {user.login_class ?? "Не задан"}
                  {user.uid !== null && ` · UID: ${user.uid}`}
                </p>
                <p>
                  Аутентификация:{" "}
                  {user.authentication.length
                    ? user.authentication
                        .map(
                          (item) =>
                            `${item.kind} / ${item.encoding ?? "без пароля (явно)"}`,
                        )
                        .join(", ")
                    : "Не задана в поддержанном фрагменте"}
                </p>
                <span className="muted">
                  Строки{" "}
                  {user.provenance.name?.source_lines.join(", ") ?? "не заданы"}
                </span>
              </div>
            ))}
          </div>
        </details>
      )}
      {config.schema_version === "1.0" && (
        <p className="hint">Снимок старой схемы: пользователи не разобраны.</p>
      )}
      {config.parse_warnings.length > 0 && (
        <details>
          <summary>
            Предупреждения парсера ({config.parse_warnings.length})
          </summary>
          <ul>
            {config.parse_warnings.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </details>
      )}
      {config.unparsed_fragments.length > 0 && (
        <details>
          <summary>
            Неподдержанные фрагменты ({config.unparsed_fragments.length})
          </summary>
          <div className="fragment-list">
            {config.unparsed_fragments.map((item, index) => (
              <div key={index}>
                <span className="muted">
                  Строки {item.location.source_lines.join(", ")}
                </span>
                <pre>{item.raw_text}</pre>
              </div>
            ))}
          </div>
        </details>
      )}
      <details>
        <summary>Каноническая модель</summary>
        <p className="hint">
          Это нормализованные данные и provenance, не восстановленный исходный
          файл.
        </p>
        <pre className="json-view">{JSON.stringify(config, null, 2)}</pre>
      </details>
    </section>
  );
}
