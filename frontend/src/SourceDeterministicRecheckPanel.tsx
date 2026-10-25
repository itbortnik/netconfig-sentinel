import { useEffect, useRef, useState } from "react";
import { PartialPolicyDiagnosticView } from "./PartialPolicyDiagnosticView";
import { runSourceDeterministicRecheckSchema } from "./sourceDeterministicRecheck";
import { ApiClient, ApiError } from "./api";
import type { PatchDraft } from "./patches";
import { date, shortId } from "./format";
import type {
  RunSourceDeterministicRecheck,
  SourceDeterministicRecheck,
  SourceDeterministicSelection,
  SourceDeterministicSummary,
} from "./sourceDeterministicRecheck";

const blockers: Record<string, string> = {
  formal_verification_not_run: "Формальная проверка не запускалась",
  deterministic_evidence_not_combined_with_qualified_verification:
    "Результаты не объединены с квалифицированной проверкой изменения",
  deterministic_quality_not_proven: "Независимое качество метода не доказано",
  baseline_approval_not_proven:
    "Согласование исходного эталона и профиля не подтверждено",
  individual_engineer_review_required:
    "Требуется отдельное рассмотрение инженером",
  device_syntax_not_verified: "Синтаксис на устройстве не проверен",
  management_access_not_verified: "Доступ управления не проверен",
  rollback_not_verified: "Откат не проверен",
  original_statistical_not_rerun:
    "Исходная статистическая модель не пересчитана",
  deterministic_execution_unknown:
    "Исполнение запроса перепроверки не подтверждено",
  original_deterministic_unavailable:
    "Принятых результатов исходного анализа нет",
};
const statusNames = {
  pending_unknown: "исполнение не подтверждено",
  completed: "отчёт сохранён",
  failed: "попытка завершилась отказом",
};
export function SourceDeterministicRecheckPanel({
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
  const [partialMode, setPartialMode] = useState(false);
  const [analysisId, setAnalysisId] = useState("");
  const [selection, setSelection] =
    useState<SourceDeterministicSelection | null>(null);
  const [working, setWorking] = useState(false);
  const [history, setHistory] = useState<SourceDeterministicSummary[]>([]);
  const [offset, setOffset] = useState(0);
  const [consent, setConsent] = useState(false);
  const [attempt, setAttempt] = useState<RunSourceDeterministicRecheck | null>(
    null,
  );
  const [view, setView] = useState<SourceDeterministicRecheck | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [rejected, setRejected] = useState(false);
  const [rejectedNotStored, setRejectedNotStored] = useState(false);
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<RunSourceDeterministicRecheck | null>(null);
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
    const rows = await client.sourceDeterministicRechecks(draft, next);
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
    const row = await client.sourceDeterministicSelection(
      draft,
      analysisId.trim(),
    );
    if (alive.current) setSelection(row);
  }
  async function launch() {
    if (intent.current || !client.permits("verify") || !selection || !consent)
      return;
    const request = runSourceDeterministicRecheckSchema.parse({
      ...(partialMode
        ? {
            version: "source-deterministic-request-0.2.0" as const,
            mode: "policy_only_partial_diagnostic" as const,
          }
        : { version: "source-deterministic-request-0.1.0" as const }),
      recheck_id: crypto.randomUUID(),
      draft_sha256: draft.draft_sha256,
      before_analysis_id: selection.before_analysis_id,
      before_analysis_sha256: selection.before_analysis_sha256,
      reference_canonical_sha256: partialMode
        ? null
        : (selection.reference?.canonical_sha256 ?? null),
      allow_local_analysis_context: true,
    });
    intent.current = request;
    setAttempt(request);
    setView(null);
    setConsent(false);
    setUncertain(true);
    setRejected(false);
    setRejectedNotStored(false);
    let row: SourceDeterministicRecheck;
    try {
      row = await client.runSourceDeterministicRecheck(
        draft,
        request,
        selection,
      );
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
      const row = await client.sourceDeterministicRecheck(
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
  async function detail(summary: SourceDeterministicSummary) {
    const row = await client.sourceDeterministicRecheck(
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
    <section
      className="patch-panel"
      aria-label="Перепроверка исходного анализа"
    >
      <h4>Перепроверка исходного анализа</h4>
      <p className="notice warning">
        Отдельная перепроверка политик и сравнений использует исходный каталог,
        сохранённый эталон и профиль соседей выбранного анализа. Результаты не
        подтверждают качество метода, согласование эталона или безопасность
        изменения. Риск и статус черновика не меняются.
      </p>
      <p className="hint">
        Явно выберите сохранённый анализ снимка «до» по UUID. Оба снимка заново
        разбираются из точных сохранённых исходников. Новый профиль соседей не
        строится. Чтение выбора и истории не запускает детекторы.
      </p>
      <button
        className="button secondary"
        disabled={busy}
        onClick={() => void operation(openPanel)}
      >
        {open
          ? "Обновить перепроверки анализа"
          : "Открыть перепроверку анализа"}
      </button>
      {open && (
        <>
          {working && (
            <p role="status">Ожидание пересчёта исходного анализа…</p>
          )}
          <p className="mono">
            Исходник до: {draft.diff.before.configuration_id} · SHA-256:{" "}
            {draft.diff.before.source_sha256}
            <br />
            Исходник после: {draft.diff.after.configuration_id} · SHA-256:{" "}
            {draft.diff.after.source_sha256}
          </p>
          {client.permits("verify") && (
            <>
              <label>
                Режим перепроверки анализа
                <select
                  aria-label="Режим перепроверки анализа"
                  value={partialMode ? "partial" : "complete"}
                  disabled={busy || !!attempt}
                  onChange={(e) => {
                    setPartialMode(e.target.value === "partial");
                    setSelection(null);
                    setConsent(false);
                  }}
                >
                  <option value="complete">
                    Полная перепроверка политик и сравнений
                  </option>
                  <option value="partial">
                    Явная частичная диагностика только политик
                  </option>
                </select>
              </label>
              {partialMode && (
                <p className="notice warning">
                  Выбран отдельный режим частичной диагностики. Требуется
                  исходный анализ без эталона, peers и Forest. Частичная
                  диагностика не устанавливает успешность изменения. После
                  отказа полной перепроверки режим автоматически не меняется.
                </p>
              )}
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
                Загрузить исходный анализ политик и сравнений
              </button>
              {!selection && (
                <p>
                  Исходный анализ политик и сравнений не выбран. Автоматического
                  выбора последнего анализа нет.
                </p>
              )}
              {selection && (
                <div aria-label="Выбранный исходный анализ">
                  <p className="mono">
                    Анализ до: {selection.before_analysis_id}
                    <br />
                    SHA-256 анализа: {selection.before_analysis_sha256}
                    <br />
                    Каталог политик: {selection.original.policy_catalog_version}
                    <br />
                    Эталон:{" "}
                    {selection.reference?.configuration_id ?? "не выбран"}
                    <br />
                    SHA-256 эталона:{" "}
                    {selection.reference?.canonical_sha256 ?? "не выбран"}
                  </p>
                  <p>
                    Исходный анализ:{" "}
                    {date(selection.before_analysis_created_at)}. Профиль
                    соседей:{" "}
                    {selection.original.comparison?.peer_baseline
                      ?.model_version ?? "не выбран"}
                    .
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
                Разрешаю отдельную локальную перепроверку исходного анализа на
                сохранённых исходниках
              </label>
              <button
                className="button secondary"
                disabled={busy || !!attempt || !consent || !selection}
                onClick={() => void operation(launch)}
              >
                Пересчитать исходный анализ до и после
              </button>
            </>
          )}
          {attempt && (
            <div aria-label="Запрос перепроверки анализа">
              <p className="mono">
                ID попытки перепроверки: {attempt.recheck_id}
                <br />
                Исходный анализ: {attempt.before_analysis_id}
                <br />
                SHA-256 эталона запроса:{" "}
                {attempt.reference_canonical_sha256 ?? "не выбран"}
              </p>
              {uncertain && (
                <p className="notice warning">
                  {rejected
                    ? "Сервер отклонил запрос перепроверки. Проверьте наличие записи этой попытки."
                    : "Итог запроса перепроверки не подтверждён."}{" "}
                  Новый запуск заблокирован; повторной отправки POST нет.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void operation(reconcile)}
              >
                Прочитать попытку перепроверки
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
                    Сбросить отклонённый запрос перепроверки
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
                    Подготовить новую перепроверку анализа
                  </button>
                )}
            </div>
          )}
          <ul aria-label="История перепроверок анализа">
            {history.map((row) => (
              <li key={row.recheck_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => void operation(() => detail(row))}
                >
                  Открыть перепроверку анализа {shortId(row.recheck_id)} ·{" "}
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
                Предыдущие перепроверки анализа
              </button>
              <button
                className="button secondary compact"
                disabled={busy || history.length < 20 || offset >= 10000}
                onClick={() => void operation(() => loadHistory(offset + 20))}
              >
                Следующие перепроверки анализа
              </button>
            </div>
          )}
          {view && (
            <div aria-label="Результат перепроверки анализа">
              <h4>
                Исходный анализ: {statusNames[view.execution_status]} (
                {view.execution_status})
              </h4>
              <p>
                Статус: needs_review. Формальная проверка: not_run. Качество
                доказано: нет. Калибровка: нет. Согласовано: нет. Применено:
                нет.
              </p>
              {view.version === "source-deterministic-recheck-0.2.0" && (
                <p className="notice warning">
                  Явная частичная диагностика только политик. Покрытие: partial.
                  Статус completed подтверждает завершение вычисления
                  диагностики; полнота проверки и успешность изменения не
                  установлены.
                </p>
              )}
              {view.execution_status === "pending_unknown" && (
                <p className="notice warning">
                  pending_unknown не доказывает работу фонового процесса.
                  Результаты детекторов отсутствуют; POST не повторяется.
                </p>
              )}
              {view.execution_status === "failed" && (
                <p className="notice warning">
                  Попытка завершилась отказом:
                  original_context_or_deterministic_result_unavailable. Принятых
                  результатов нет; отсутствующие результаты не заменены нулями.
                </p>
              )}
              {view.outcome?.report?.version ===
                "source-deterministic-report-0.2.0" && (
                <PartialPolicyDiagnosticView report={view.outcome.report} />
              )}
              {view.outcome?.report?.version ===
                "source-deterministic-report-0.1.0" && (
                <>
                  <p>
                    Каталог политик:{" "}
                    {view.outcome.report.policy_catalog_version}. Версия
                    сравнений: {view.outcome.report.comparison_version}.
                  </p>
                  <table aria-label="Результаты исходных политик и сравнений">
                    <thead>
                      <tr>
                        <th>Проверка</th>
                        <th>До изменения</th>
                        <th>После изменения</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(
                        [
                          ["Политики", "policy_findings"],
                          ["Исходный эталон", "reference_findings"],
                          ["Исходный профиль соседей", "peer_findings"],
                        ] as const
                      ).map(([label, field]) => (
                        <tr key={field}>
                          <th>{label}</th>
                          {(["before", "after"] as const).map((side) => {
                            const report = view.outcome!.report!;
                            const findings =
                              report.version ===
                              "source-deterministic-report-0.1.0"
                                ? report[side][field]
                                : null;
                            return (
                              <td key={side}>
                                {findings === null
                                  ? "Не выбрано"
                                  : `Выполнено · замечаний: ${findings.length}`}
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p>
                    Политики: исчезло наблюдений{" "}
                    {view.outcome.report.policy_changes.resolved.length},
                    появилось{" "}
                    {view.outcome.report.policy_changes.introduced.length},
                    сохранилось{" "}
                    {view.outcome.report.policy_changes.persistent.length}.
                  </p>
                  <p className="mono">
                    SHA-256 исходного профиля:{" "}
                    {view.outcome.report.peer_profile_sha256 ?? "не выбран"}
                  </p>
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
                SHA-256 эталона:{" "}
                {view.reference_canonical_sha256 ?? "не выбран"}
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
                  Полная сохранённая запись перепроверки анализа
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
