import { useEffect, useRef, useState } from "react";
import type {
  AnalysisResult,
  FeedbackRecord,
  FeedbackSubmission,
  Finding,
  Severity,
} from "./contracts";
import type { ApiClient } from "./api";
import { FeedbackPanel } from "./FeedbackPanel";
import {
  date,
  numericScore,
  percent,
  severityLabel,
  sourceLabel,
} from "./format";

function JsonValues({
  title,
  values,
}: {
  title: string;
  values: Finding["observed"];
}) {
  return Object.keys(values).length > 0 ? (
    <div>
      <h4>{title}</h4>
      <pre>{JSON.stringify(values, null, 2)}</pre>
    </div>
  ) : null;
}

export function AnalysisView({
  result,
  client,
  busy,
  onError,
  onFeedback,
}: {
  result: AnalysisResult;
  client: ApiClient;
  busy: boolean;
  onError: (problem: unknown) => void;
  onFeedback: (
    finding: string,
    submission: FeedbackSubmission,
  ) => Promise<FeedbackRecord | null>;
}) {
  const [selected, setSelected] = useState(
    result.findings[0]?.finding_id ?? null,
  );
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [result.analysis_id]);
  const matches = result.findings.filter(
    (item) =>
      (severity === "all" || item.severity === severity) &&
      `${item.title} ${item.category}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const finding =
    matches.find((item) => item.finding_id === selected) ?? matches[0];
  const explanation = finding
    ? result.explanations.find((item) => item.finding_id === finding.finding_id)
    : undefined;
  const critical = result.findings.filter(
    (item) => item.severity === "critical",
  ).length;
  return (
    <section className="analysis-area" aria-labelledby="analysis-heading">
      <div className="panel analysis-summary">
        <div className="section-heading split">
          <div>
            <span className="eyebrow">02 / РЕЗУЛЬТАТ АНАЛИЗА</span>
            <h2 ref={heading} tabIndex={-1} id="analysis-heading">
              Находки и доказательства
            </h2>
          </div>
          <span
            className={`badge ${result.status === "partial" ? "medium" : "neutral"}`}
          >
            {result.status === "partial"
              ? "Частичный результат"
              : "Политики проверены"}
          </span>
        </div>
        <p className="muted">
          {date(result.created_at)} · {result.policy_catalog_version}
        </p>
        <dl className="metrics">
          <div>
            <dt>Итоговый риск</dt>
            <dd>
              {result.risk ? numericScore(result.risk.score) : "Недоступен"}
            </dd>
            {result.risk && (
              <span className={`badge ${result.risk.level}`}>
                {severityLabel[result.risk.level]}
              </span>
            )}
          </div>
          <div>
            <dt>Находки</dt>
            <dd>{result.findings.length}</dd>
          </div>
          <div>
            <dt>Критические</dt>
            <dd>{critical}</dd>
          </div>
          <div>
            <dt>Формальная проверка</dt>
            <dd className="metric-text">Не запускалась</dd>
          </div>
        </dl>
        <p className="notice">
          Выполнены политики
          {result.comparison?.reference
            ? ", сравнение с выбранным эталоном"
            : ""}
          {result.comparison?.peer_baseline
            ? " и сравнение с выбранной группой"
            : ""}
          {result.statistical
            ? ", экспериментальный Isolation Forest. Transformer и Batfish не запускались."
            : ". ML и Batfish не запускались."}{" "}
          Оценки не калиброваны; требуется проверка инженером.
        </p>
        {result.comparison && (
          <details>
            <summary>Входы сравнения и профиль группы</summary>
            <p className="hint">
              Различия с эталоном не входят в итоговый риск. Метки и снимки
              выбраны оператором, не утверждены автоматически.
            </p>
            <pre className="json-view">
              {JSON.stringify(result.comparison, null, 2)}
            </pre>
          </details>
        )}
        {result.statistical && (
          <details>
            <summary>Модель и статистический результат</summary>
            <p className="hint">
              Модель: {result.statistical.model.model_id}.{" "}
              {result.statistical.prediction === -1
                ? "Вектор отмечен как выброс."
                : "Вектор не отмечен как выброс — это не доказательство безопасности."}
            </p>
            <pre className="json-view">
              {JSON.stringify(result.statistical, null, 2)}
            </pre>
          </details>
        )}
        {result.status === "partial" && (
          <p className="notice warning">
            Разбор неполный. Находки частичные, итоговый риск недоступен.
          </p>
        )}
        {result.risk && (
          <details>
            <summary>Состав оценки риска</summary>
            <ul className="risk-components">
              {result.risk.components.map((item) => (
                <li key={item.source}>
                  <span>{sourceLabel[item.source]}</span>
                  <strong>
                    {item.status === "completed" && item.raw_score !== null
                      ? numericScore(item.raw_score)
                      : "Не запускался"}
                  </strong>
                  <small>Вес: {numericScore(item.effective_weight)}</small>
                </li>
              ))}
            </ul>
            <ul>
              {[...result.risk.guardrails, ...result.risk.limitations].map(
                (item, index) => (
                  <li key={index}>{item}</li>
                ),
              )}
            </ul>
          </details>
        )}
        <details>
          <summary>Идентификаторы и ограничения</summary>
          <dl className="identifiers">
            <dt>Анализ</dt>
            <dd>{result.analysis_id}</dd>
            <dt>SHA-256</dt>
            <dd>{result.source_sha256}</dd>
          </dl>
          <ul>
            {result.limitations.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </details>
      </div>
      <div className="finding-workspace">
        <section className="panel findings-list" aria-label="Список находок">
          <div className="section-heading">
            <h3>
              Находки <span className="count">{matches.length}</span>
            </h3>
          </div>
          <label htmlFor="finding-search">Поиск по находкам</label>
          <input
            id="finding-search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Название или правило"
          />
          <label htmlFor="severity-filter">Уровень ущерба</label>
          <select
            id="severity-filter"
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value as Severity | "all")
            }
          >
            <option value="all">Все уровни</option>
            {(Object.keys(severityLabel) as Severity[]).map((item) => (
              <option key={item} value={item}>
                {severityLabel[item]}
              </option>
            ))}
          </select>
          <div className="finding-buttons">
            {matches.map((item) => (
              <button
                key={item.finding_id}
                className={`finding-button ${finding?.finding_id === item.finding_id ? "selected" : ""}`}
                disabled={busy}
                aria-pressed={finding?.finding_id === item.finding_id}
                onClick={() => setSelected(item.finding_id)}
              >
                <span className={`badge ${item.severity}`}>
                  {severityLabel[item.severity]}
                </span>
                <strong>{item.title}</strong>
                <span className="mono small">{item.category}</span>
                <span className="muted">
                  {item.affected_lines.length
                    ? `Строки ${item.affected_lines.join(", ")}`
                    : "Нет привязки к текущим строкам"}
                </span>
              </button>
            ))}
          </div>
          {matches.length === 0 && (
            <p className="empty">
              {result.findings.length
                ? "Находок по этому фильтру нет."
                : "Находок выполненных проверок нет. Это не доказательство безопасности сети."}
            </p>
          )}
        </section>
        <section className="panel finding-detail" aria-label="Детали находки">
          {finding && explanation ? (
            <>
              <span className={`badge ${finding.severity}`}>
                {severityLabel[finding.severity]}
              </span>
              <h3>{finding.title}</h3>
              <p className="mono muted">
                {finding.detector} · {finding.category}
              </p>
              <dl className="metrics small-metrics">
                <div>
                  <dt>Уверенность детектора</dt>
                  <dd>{percent(finding.confidence)}</dd>
                </div>
                <div>
                  <dt>Оценка отклонения</dt>
                  <dd>{numericScore(finding.anomaly_score)}</dd>
                </div>
              </dl>
              <h4>Доказательства</h4>
              {finding.evidence.map((item, index) => (
                <div className="evidence" key={index}>
                  <p>{item.message}</p>
                  {item.source_location ? (
                    <>
                      <span className="line-label">
                        Строки {item.source_location.source_lines.join(", ")}
                      </span>
                      <p className="hash">
                        Hash команды: {item.source_location.raw_text_hash}
                      </p>
                    </>
                  ) : (
                    <p className="hint">
                      Доказательство не привязано к строке текущего снимка;
                      строки не выдуманы.
                    </p>
                  )}
                </div>
              ))}
              <JsonValues
                title="Наблюдаемое значение"
                values={finding.observed}
              />
              <JsonValues
                title="Ожидаемое значение"
                values={finding.expected}
              />
              <div className="explanation">
                <span className="eyebrow">ЛОКАЛЬНОЕ ОБЪЯСНЕНИЕ / БЕЗ LLM</span>
                <h4>{explanation.summary}</h4>
                <p>{explanation.technical_explanation}</p>
                <h4>Рекомендация</h4>
                <p>{explanation.recommendation}</p>
              </div>
              <h4>Источники</h4>
              <ul className="citations">
                {explanation.citations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
              <details>
                <summary>Привязка доказательств к снимку</summary>
                <p className="hash">
                  SHA-256 снимка: {explanation.source_sha256}
                </p>
                {explanation.anchors.map((item, index) => (
                  <div key={index}>
                    <p>Строки {item.lines.join(", ")}</p>
                    <p className="hash">
                      Hash команды: {item.statement_sha256}
                    </p>
                  </div>
                ))}
              </details>
              <details>
                <summary>Ограничения этой находки</summary>
                <ul>
                  {explanation.limitations.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              </details>
              <p className="notice warning">
                Никакие изменения не применяются. Рекомендация требует проверки
                инженером.
              </p>
              <FeedbackPanel
                key={`${result.analysis_id}:${finding.finding_id}`}
                analysis={result}
                finding={finding}
                client={client}
                busy={busy}
                onError={onError}
                onSubmit={onFeedback}
              />
            </>
          ) : (
            <p className="empty">
              Выберите находку для просмотра доказательств.
            </p>
          )}
        </section>
      </div>
    </section>
  );
}
