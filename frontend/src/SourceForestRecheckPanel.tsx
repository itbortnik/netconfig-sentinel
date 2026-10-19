import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type { PatchDraft } from "./patches";
import { date, shortId } from "./format";
import type {
  RunSourceForestRecheck,
  SourceForestRecheck,
  SourceForestSelection,
  SourceForestSummary,
} from "./sourceForestRecheck";

const blockers: Record<string, string> = {
  formal_verification_not_run: "Формальная проверка не запускалась",
  original_statistical_quality_not_proven:
    "Независимое качество исходного Forest не подтверждено",
  all_original_detectors_not_rerun: "Все исходные детекторы не пересчитаны",
  baseline_approval_not_proven: "Одобрение раннего снимка не установлено",
  individual_engineer_review_required:
    "Требуется отдельное рассмотрение инженером",
  device_syntax_not_verified: "Синтаксис на устройстве не проверен",
  management_access_not_verified: "Доступ управления не проверен",
  rollback_not_verified: "Откат не проверен",
  statistical_execution_unknown: "Исполнение Forest-запроса не подтверждено",
  original_statistical_unavailable: "Принятых результатов исходного Forest нет",
};
const statusNames = {
  pending_unknown: "исполнение не подтверждено",
  completed: "отчёт сохранён",
  failed: "попытка завершилась отказом",
};
export function SourceForestRecheckPanel({
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
  const [analysisId, setAnalysisId] = useState("");
  const [selection, setSelection] = useState<SourceForestSelection | null>(
    null,
  );
  const [working, setWorking] = useState(false);
  const [history, setHistory] = useState<SourceForestSummary[]>([]);
  const [offset, setOffset] = useState(0);
  const [consent, setConsent] = useState(false);
  const [attempt, setAttempt] = useState<RunSourceForestRecheck | null>(null);
  const [view, setView] = useState<SourceForestRecheck | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [rejected, setRejected] = useState(false);
  const [rejectedNotStored, setRejectedNotStored] = useState(false);
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<RunSourceForestRecheck | null>(null);
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
    const rows = await client.sourceForestRechecks(draft, next);
    if (alive.current) {
      setHistory(rows);
      setOffset(next);
    }
  }
  async function openPanel() {
    setOpen(true);
    setConsent(false);
    setSelection(null);
    await loadHistory(0);
  }
  async function loadSelection() {
    setConsent(false);
    setSelection(null);
    const row = await client.sourceForestSelection(draft, analysisId.trim());
    if (alive.current) setSelection(row);
  }
  async function launch() {
    if (
      intent.current ||
      !client.permits("configuration_model") ||
      !selection ||
      !consent
    )
      return;
    const request: RunSourceForestRecheck = {
      version: "source-forest-request-0.1.0",
      recheck_id: crypto.randomUUID(),
      draft_sha256: draft.draft_sha256,
      before_analysis_id: selection.before_analysis_id,
      before_analysis_sha256: selection.before_analysis_sha256,
      model_id: selection.original.model.model_id,
      artifact_sha256: selection.original.model.artifact_sha256,
      allow_local_model_context: true,
    };
    intent.current = request;
    setAttempt(request);
    setView(null);
    setConsent(false);
    setUncertain(true);
    setRejected(false);
    setRejectedNotStored(false);
    let row: SourceForestRecheck;
    try {
      row = await client.runSourceForestRecheck(draft, request, selection);
    } catch (problem) {
      if (alive.current)
        setRejected(
          problem instanceof ApiError &&
            [400, 403, 404, 409, 413, 422, 429, 503].includes(problem.status),
        );
      throw problem;
    }
    if (!alive.current) return;
    setView(row);
    setUncertain(row.execution_status === "pending_unknown");
    await loadHistory(0);
  }
  async function reconcile() {
    const request = intent.current;
    if (!request) return;
    try {
      const row = await client.sourceForestRecheck(
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
  async function detail(summary: SourceForestSummary) {
    const row = await client.sourceForestRecheck(
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
    if (
      busy ||
      !attempt ||
      (rejectedOnly
        ? !(rejected && rejectedNotStored)
        : uncertain ||
          view?.recheck_id !== attempt.recheck_id ||
          view.execution_status === "pending_unknown")
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
    <section className="patch-panel" aria-label="Пересчёт исходного Forest">
      <h4>Пересчёт исходного Forest</h4>
      <p className="notice warning">
        Повторный расчёт выбранного исходного Isolation Forest экспериментален.
        Scores не являются вероятностью, severity или доказательством
        исправления. Снижение score не заменяет формальную проверку; риск и
        статус черновика не меняются.
      </p>
      <p className="hint">
        Выберите сохранённый анализ снимка «до» явно по UUID. Используется его
        исходная числовая модель и точные сохранённые исходники обоих снимков.
        Чтение выбора и истории не запускает модель.
      </p>
      <button
        className="button secondary"
        disabled={busy}
        onClick={() => void operation(openPanel)}
      >
        {open ? "Обновить пересчёты Forest" : "Открыть пересчёт Forest"}
      </button>
      {open && (
        <>
          {working && <p role="status">Ожидание пересчёта исходного Forest…</p>}
          <p className="mono">
            Исходник до: {draft.diff.before.configuration_id} · SHA-256:{" "}
            {draft.diff.before.source_sha256}
            <br />
            Исходник после: {draft.diff.after.configuration_id} · SHA-256:{" "}
            {draft.diff.after.source_sha256}
          </p>
          {client.permits("configuration_model") && (
            <>
              <label>
                UUID сохранённого анализа до изменения
                <input
                  value={analysisId}
                  disabled={busy || !!attempt}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => {
                    setAnalysisId(event.target.value);
                    setSelection(null);
                    setConsent(false);
                  }}
                />
              </label>
              <button
                className="button secondary"
                disabled={busy || !!attempt || !analysisId.trim()}
                onClick={() => void operation(loadSelection)}
              >
                Загрузить исходный анализ Forest
              </button>
              {!selection && (
                <p>
                  Исходный анализ Forest не выбран. Автоматического выбора
                  последней модели нет.
                </p>
              )}
              {selection && (
                <div aria-label="Выбранный исходный Forest">
                  <p className="mono">
                    Анализ до: {selection.before_analysis_id}
                    <br />
                    SHA-256 анализа: {selection.before_analysis_sha256}
                    <br />
                    Model UUID: {selection.original.model.model_id}
                    <br />
                    Artifact SHA-256: {selection.original.model.artifact_sha256}
                  </p>
                  <p>
                    Исходный анализ:{" "}
                    {date(selection.before_analysis_created_at)}. Модель:
                    experimental. Порог offset_:{" "}
                    {selection.original.model.decision_offset}.
                  </p>
                </div>
              )}
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={consent}
                  disabled={busy || !!attempt || !selection}
                  onChange={(event) => setConsent(event.target.checked)}
                />
                Разрешаю отдельный локальный пересчёт исходного Forest на
                сохранённых исходниках
              </label>
              <button
                className="button secondary"
                disabled={busy || !!attempt || !consent || !selection}
                onClick={() => void operation(launch)}
              >
                Пересчитать исходный Forest до и после
              </button>
            </>
          )}
          {attempt && (
            <div aria-label="Запрос пересчёта Forest">
              <p className="mono">
                ID Forest-попытки: {attempt.recheck_id}
                <br />
                Исходный анализ: {attempt.before_analysis_id}
                <br />
                Model UUID запроса: {attempt.model_id}
                <br />
                Artifact SHA-256 запроса: {attempt.artifact_sha256}
              </p>
              {uncertain && (
                <p className="notice warning">
                  {rejected
                    ? "Сервер отклонил Forest-запрос. Проверьте наличие записи этой попытки."
                    : "Итог Forest-запроса не подтверждён."}{" "}
                  Новый запуск заблокирован; повторной отправки POST нет.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void operation(reconcile)}
              >
                Прочитать Forest-попытку
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
                    Сбросить отклонённый Forest-запрос
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
                    Подготовить новый пересчёт Forest
                  </button>
                )}
            </div>
          )}
          <ul aria-label="История пересчётов Forest">
            {history.map((row) => (
              <li key={row.recheck_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => void operation(() => detail(row))}
                >
                  Открыть пересчёт Forest {shortId(row.recheck_id)} ·{" "}
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
                Предыдущие пересчёты Forest
              </button>
              <button
                className="button secondary compact"
                disabled={busy || history.length < 20 || offset >= 10000}
                onClick={() => void operation(() => loadHistory(offset + 20))}
              >
                Следующие пересчёты Forest
              </button>
            </div>
          )}
          {view && (
            <div aria-label="Результат пересчёта Forest">
              <h4>
                Исходный Forest: {statusNames[view.execution_status]} (
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
                  Попытка завершилась отказом:
                  original_baseline_or_numeric_result_unavailable. Принятых
                  scores нет; отсутствующие результаты не заменены нулями.
                </p>
              )}
              {view.outcome?.report && (
                <>
                  <p>
                    Исходная модель: experimental. Порог offset_:{" "}
                    {view.outcome.report.model.decision_offset}.
                    decision_function = score_samples − offset_; prediction: −1
                    при decision_function &lt; 0, иначе +1.
                  </p>
                  <div className="forest-scores">
                    <table aria-label="Числовые результаты исходного Forest">
                      <thead>
                        <tr>
                          <th>Снимок</th>
                          <th>score_samples</th>
                          <th>decision_function</th>
                          <th>prediction (±1)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(["before", "after"] as const).map((side) => {
                          const scores = view.outcome!.report!.scores;
                          return (
                            <tr key={side}>
                              <th>
                                {side === "before"
                                  ? "До изменения"
                                  : "После изменения"}
                              </th>
                              <td>{String(scores[`${side}_score_samples`])}</td>
                              <td>
                                {String(scores[`${side}_decision_function`])}
                              </td>
                              <td>{scores[`${side}_prediction`]}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
              <ul>
                {view.validation_blockers.map((value) => (
                  <li key={value}>{blockers[value] ?? value}</li>
                ))}
              </ul>
              <p className="mono">
                Анализ до: {view.before_analysis_id}
                <br />
                SHA-256 анализа: {view.before_analysis_sha256}
                <br />
                Model UUID: {view.model_id}
                <br />
                Artifact SHA-256: {view.artifact_sha256}
                <br />
                SHA-256 записи: {view.review_sha256}
              </p>
              <p className="hint">
                Хеш связывает содержимое записи; он не удостоверяет личность
                инженера или истинность результата. Сетевые проверки и их
                история сохраняются отдельно.
              </p>
              <details>
                <summary>Полная сохранённая запись пересчёта Forest</summary>
                <pre className="json-view">{JSON.stringify(view, null, 2)}</pre>
              </details>
            </div>
          )}
        </>
      )}
    </section>
  );
}
