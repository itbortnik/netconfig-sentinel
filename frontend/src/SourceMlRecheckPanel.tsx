import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type { PatchDraft } from "./patches";
import type { ConfigurationInferenceReport } from "./configurationModels";
import { date, numericScore, shortId } from "./format";
import type {
  RunSourceMlRecheck,
  SourceMlCapabilities,
  SourceMlRecheck,
  SourceMlSummary,
} from "./sourceMlRecheck";

const blockers: Record<string, string> = {
  formal_verification_not_run: "Формальная проверка не запускалась",
  change_specific_ml_quality_not_proven:
    "Качество ML-проверки этого изменения не подтверждено",
  selected_model_independent_quality_not_proven:
    "Независимое качество выбранной модели не подтверждено",
  baseline_approval_not_proven: "Одобрение раннего снимка не установлено",
  individual_engineer_review_required:
    "Требуется отдельное рассмотрение инженером",
  device_syntax_not_verified: "Синтаксис на устройстве не проверен",
  management_access_not_verified: "Доступ управления не проверен",
  rollback_not_verified: "Откат не проверен",
  ml_execution_unknown: "Исполнение ML-запроса не подтверждено",
  selected_ml_unavailable: "Принятых результатов выбранной модели нет",
};
const statusNames = {
  pending_unknown: "исполнение не подтверждено",
  completed: "отчёт сохранён",
  failed: "попытка завершилась отказом",
};
function InferenceReport({
  report,
  label,
}: {
  report: ConfigurationInferenceReport;
  label: string;
}) {
  const { model, prediction } = report;
  return (
    <article aria-label={label}>
      <h5>{label}</h5>
      <p className="mono">
        Model SHA-256: {model.model_sha256}
        <br />
        SHA-256 исходника: {prediction.raw_source_sha256}
        <br />
        SHA-256 обезличенного текста: {prediction.sanitized_source_sha256}
      </p>
      <p>
        Строк исходника: {prediction.total_lines}. Runtime:{" "}
        {report.runtime_torch_version}. Sanitizer: {report.sanitization_version}
        .
      </p>
      <p>
        Карточка: {model.version} · {model.kind} · {model.status}. Target
        semantics: {model.target_semantics}.
      </p>
      <p>Классы: {model.classes.join(", ")}.</p>
      <ul aria-label={`Головы: ${label}`}>
        {Object.entries(model.enabled_heads).map(([head, enabled]) => (
          <li key={head}>
            {head}: {enabled ? "включена" : "отключена"}
          </li>
        ))}
      </ul>
      <p>
        Некалиброванный anomaly score:{" "}
        {prediction.anomaly_score === null
          ? "голова отключена"
          : numericScore(prediction.anomaly_score)}
        .
      </p>
      <p>
        Категории:{" "}
        {prediction.category_scores === null
          ? "голова отключена"
          : Object.entries(prediction.category_scores)
              .map(([name, score]) => `${name}: ${numericScore(score)}`)
              .join("; ")}
        .
      </p>
      <p>
        Severity distribution:{" "}
        {prediction.severity_scores === null
          ? "голова отключена"
          : Object.entries(prediction.severity_scores)
              .map(([name, score]) => `${name}: ${numericScore(score)}`)
              .join("; ")}
        . Это не severity находки.
      </p>
      {model.version !== "config-model-card-0.1.0" && (
        <p className="notice warning">
          Энкодер обучен на тестовых конфигурациях. Физическая изоляция
          pretraining-данных и качество на реальных аномалиях не подтверждены.
        </p>
      )}
      {model.version === "config-model-card-0.3.0" && (
        <p className="notice warning">
          Локализация обучена с разной стоимостью классов строк; scores не
          являются калиброванными вероятностями. Вес положительных строк:{" "}
          {model.localization_objective.positive_weight}; вес задачи:{" "}
          {model.localization_task_weight}.
        </p>
      )}
      <details>
        <summary>Строки, attention и полная карточка: {label}</summary>
        <p>
          Локализация:{" "}
          {model.enabled_heads.localization
            ? prediction.line_scores
                .map(
                  (value, index) =>
                    `${index + 1}: ${value === null ? "нет значения" : numericScore(value)}`,
                )
                .join("; ")
            : "голова отключена"}
          .
        </p>
        <p>
          Attention не является причинным объяснением. Embedding хранится как
          hash и размерность: {prediction.embedding_dimensions}.
        </p>
        <pre className="json-view">{JSON.stringify(report, null, 2)}</pre>
      </details>
    </article>
  );
}
export function SourceMlRecheckPanel({
  client,
  draft,
  busy: outerBusy,
  onError,
}: {
  client: ApiClient;
  draft: PatchDraft;
  busy: boolean;
  onError: (problem: unknown) => void;
}) {
  const [open, setOpen] = useState(false);
  const [capabilities, setCapabilities] = useState<SourceMlCapabilities | null>(
    null,
  );
  const [capabilitiesFailed, setCapabilitiesFailed] = useState(false);
  const [working, setWorking] = useState(false);
  const [history, setHistory] = useState<SourceMlSummary[]>([]);
  const [offset, setOffset] = useState(0);
  const [consent, setConsent] = useState(false);
  const [attempt, setAttempt] = useState<RunSourceMlRecheck | null>(null);
  const [view, setView] = useState<SourceMlRecheck | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [rejected, setRejected] = useState(false);
  const [rejectedNotStored, setRejectedNotStored] = useState(false);
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<RunSourceMlRecheck | null>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const busy = outerBusy || working;
  async function operation(action: () => Promise<void>) {
    if (lock.current || outerBusy) return;
    lock.current = true;
    setWorking(true);
    try {
      await action();
    } catch (problem) {
      if (alive.current) onError(problem);
    } finally {
      lock.current = false;
      if (alive.current) setWorking(false);
    }
  }
  async function loadHistory(next: number) {
    const rows = await client.sourceMlRechecks(draft, next);
    if (alive.current) {
      setHistory(rows);
      setOffset(next);
    }
  }
  async function openPanel() {
    setOpen(true);
    setConsent(false);
    try {
      const caps = await client.sourceMlCapabilities();
      if (alive.current) {
        setCapabilities(caps);
        setCapabilitiesFailed(false);
      }
    } catch (problem) {
      if (alive.current) {
        setCapabilities(null);
        setCapabilitiesFailed(true);
        onError(problem);
      }
    }
    await loadHistory(0);
  }
  async function launch() {
    if (
      intent.current ||
      !client.permits("configuration_model") ||
      capabilities?.inference !== "configured" ||
      !capabilities.model_sha256 ||
      !consent
    )
      return;
    const request: RunSourceMlRecheck = {
      version: "source-ml-request-0.1.0",
      recheck_id: crypto.randomUUID(),
      draft_sha256: draft.draft_sha256,
      model_sha256: capabilities.model_sha256,
      allow_local_model_context: true,
    };
    intent.current = request;
    setAttempt(request);
    setView(null);
    setConsent(false);
    setUncertain(true);
    setRejected(false);
    setRejectedNotStored(false);
    try {
      const row = await client.runSourceMlRecheck(draft, request);
      if (!alive.current) return;
      setView(row);
      setUncertain(row.execution_status === "pending_unknown");
      await loadHistory(0);
    } catch (problem) {
      if (alive.current) {
        setUncertain(true);
        setRejected(
          problem instanceof ApiError &&
            [400, 403, 404, 409, 413, 422, 429, 503].includes(problem.status),
        );
      }
      throw problem;
    }
  }
  async function reconcile() {
    const request = intent.current;
    if (!request) return;
    try {
      const row = await client.sourceMlRecheck(
        draft,
        request.recheck_id,
        request,
      );
      if (alive.current) {
        setView(row);
        setUncertain(row.execution_status === "pending_unknown");
        setRejectedNotStored(false);
      }
    } catch (problem) {
      if (
        alive.current &&
        rejected &&
        problem instanceof ApiError &&
        problem.status === 404
      )
        setRejectedNotStored(true);
      throw problem;
    }
    await loadHistory(0);
  }
  async function detail(summary: SourceMlSummary) {
    const row = await client.sourceMlRecheck(
      draft,
      summary.recheck_id,
      undefined,
      summary,
    );
    if (alive.current) {
      setView(row);
      setConsent(false);
    }
  }
  function reset(rejectedOnly = false) {
    if (busy || !attempt) return;
    if (
      rejectedOnly
        ? !(rejected && rejectedNotStored)
        : uncertain ||
          view?.recheck_id !== attempt.recheck_id ||
          view.execution_status === "pending_unknown"
    )
      return;
    intent.current = null;
    setAttempt(null);
    setView(null);
    setUncertain(false);
    setRejected(false);
    setRejectedNotStored(false);
    setConsent(false);
  }
  return (
    <section className="patch-panel" aria-label="Парный ML-пересчёт исходников">
      <h4>Парный ML-пересчёт исходников</h4>
      <p className="notice warning">
        Экспериментальные scores до и после не подтверждают исправление или
        безопасность. Снижение anomaly score не заменяет формальную проверку.
        Независимое качество модели и качество проверки этого изменения не
        доказаны; риск не пересчитывается.
      </p>
      <p className="hint">
        Сервер использует точные сохранённые исходники двух снимков этого
        черновика и обезличивает их перед локальным inference. Модель выбрана
        оператором. Чтение истории не запускает inference.
      </p>
      <button
        className="button secondary"
        disabled={busy}
        onClick={() => void operation(openPanel)}
      >
        {open ? "Обновить парные ML-пересчёты" : "Открыть парный ML-пересчёт"}
      </button>
      {open && (
        <>
          {working && <p role="status">Ожидание парного ML-пересчёта…</p>}
          {capabilitiesFailed && (
            <p className="notice warning">
              Возможности парного inference недоступны. Запуск заблокирован.
            </p>
          )}
          {capabilities && (
            <p>
              {capabilities.inference === "configured"
                ? "Парная модель настроена оператором; её работоспособность этим не проверена."
                : "Парный inference отключён. Запуск недоступен."}
            </p>
          )}
          {capabilities?.model_sha256 && (
            <p className="mono">
              Текущий model pin оператора: {capabilities.model_sha256}
            </p>
          )}
          <p className="mono">
            Исходник до: {draft.diff.before.configuration_id} · SHA-256:{" "}
            {draft.diff.before.source_sha256}
            <br />
            Исходник после: {draft.diff.after.configuration_id} · SHA-256:{" "}
            {draft.diff.after.source_sha256}
          </p>
          {client.permits("configuration_model") && (
            <>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={consent}
                  disabled={
                    busy ||
                    !!attempt ||
                    capabilities?.inference !== "configured"
                  }
                  onChange={(event) => setConsent(event.target.checked)}
                />
                Разрешаю отдельный парный локальный inference сохранённых
                исходников
              </label>
              <button
                className="button secondary"
                disabled={
                  busy ||
                  !!attempt ||
                  !consent ||
                  capabilities?.inference !== "configured"
                }
                onClick={() => void operation(launch)}
              >
                Пересчитать ML до и после
              </button>
            </>
          )}
          {attempt && (
            <div aria-label="Запрос парного ML-пересчёта">
              <p className="mono">
                ID парной ML-попытки: {attempt.recheck_id}
                <br />
                Model pin запроса: {attempt.model_sha256}
              </p>
              {uncertain && (
                <p className="notice warning">
                  {rejected
                    ? "Сервер отклонил ML-запрос. Проверьте наличие записи этой попытки."
                    : "Итог ML-запроса не подтверждён."}{" "}
                  Новый запуск заблокирован; повторной отправки POST нет.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void operation(reconcile)}
              >
                Прочитать парную ML-попытку
              </button>
              {rejectedNotStored && (
                <>
                  <p>
                    После явного отказа сервера чтение этой попытки вернуло 404.
                    Сбросьте отклонённый запрос, затем отдельно разрешите новый
                    запуск.
                  </p>
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={() => reset(true)}
                  >
                    Сбросить отклонённый парный ML-запрос
                  </button>
                </>
              )}
              {!uncertain &&
                view?.recheck_id === attempt.recheck_id &&
                view.execution_status !== "pending_unknown" && (
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={() => reset()}
                  >
                    Подготовить новый парный ML-пересчёт
                  </button>
                )}
            </div>
          )}
          <ul aria-label="История парных ML-пересчётов">
            {history.map((row) => (
              <li key={row.recheck_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => void operation(() => detail(row))}
                >
                  Открыть парный ML-пересчёт {shortId(row.recheck_id)} ·{" "}
                  {date(row.created_at)} · {statusNames[row.execution_status]}
                </button>
              </li>
            ))}
          </ul>
          {(offset > 0 || history.length === 20) && (
            <div className="pager">
              <button
                className="button secondary compact"
                disabled={busy || offset === 0}
                onClick={() => void operation(() => loadHistory(offset - 20))}
              >
                Предыдущие парные ML-пересчёты
              </button>
              <button
                className="button secondary compact"
                disabled={busy || history.length < 20 || offset >= 10000}
                onClick={() => void operation(() => loadHistory(offset + 20))}
              >
                Следующие парные ML-пересчёты
              </button>
            </div>
          )}
          {view && (
            <div aria-label="Результат парного ML-пересчёта">
              <h4>
                Парный ML: {statusNames[view.execution_status]} (
                {view.execution_status})
              </h4>
              <p>
                Статус: needs_review. Формальная проверка: not_run. Качество
                доказано: нет. Калибровка: нет. Согласовано: нет. Применено:
                нет.
              </p>
              {view.execution_status === "pending_unknown" && (
                <p className="notice warning">
                  pending_unknown не доказывает работу фонового процесса.
                  Результаты модели отсутствуют; POST не повторяется.
                </p>
              )}
              {view.execution_status === "failed" && (
                <p className="notice warning">
                  Попытка завершилась отказом: worker_failed_or_unavailable.
                  Принятых scores нет; отсутствующие результаты не заменены
                  нулями.
                </p>
              )}
              {view.outcome?.report && (
                <>
                  <InferenceReport
                    report={view.outcome.report.before}
                    label="ML до изменения"
                  />
                  <InferenceReport
                    report={view.outcome.report.after}
                    label="ML после изменения"
                  />
                </>
              )}
              <ul>
                {view.validation_blockers.map((value) => (
                  <li key={value}>{blockers[value] ?? value}</li>
                ))}
              </ul>
              <p className="mono">
                Model SHA-256 попытки: {view.model_sha256}
                <br />
                SHA-256 записи: {view.review_sha256}
              </p>
              <p className="hint">
                Хеш связывает содержимое записи; он не удостоверяет личность
                инженера или истинность результата. Сетевые проверки и их
                история сохраняются отдельно.
              </p>
              <details>
                <summary>
                  Полная сохранённая запись парного ML-пересчёта
                </summary>
                <pre className="json-view">{JSON.stringify(view, null, 2)}</pre>
              </details>
            </div>
          )}
        </>
      )}
    </section>
  );
}
