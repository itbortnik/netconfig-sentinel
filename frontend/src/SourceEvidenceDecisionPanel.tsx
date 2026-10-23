import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import { date, shortId } from "./format";
import type { PatchDraft } from "./patches";
import type { SourceEvidenceReport } from "./sourceEvidenceReports";
import {
  evidenceCommentLength,
  sourceEvidenceCommentSchema,
} from "./sourceEvidenceDecisions";
import type {
  ReviewSourceEvidenceReport,
  SourceEvidenceDecision,
  SourceEvidenceDecisionSummary,
} from "./sourceEvidenceDecisions";

const verdictNames = {
  rejected: "Отклонено",
  needs_more_information: "Нужны дополнительные сведения",
};
export function SourceEvidenceDecisionPanel({
  client,
  draft,
  report,
  busy: outerBusy,
  onError,
  onGuardChange,
}: {
  client: ApiClient;
  draft: PatchDraft;
  report: SourceEvidenceReport;
  busy: boolean;
  onError: (problem: unknown) => void;
  onGuardChange: (guarded: boolean) => void;
}) {
  const [open, setOpen] = useState(false),
    [working, setWorking] = useState(false);
  const [verdict, setVerdict] = useState<
    ReviewSourceEvidenceReport["verdict"] | ""
  >("");
  const [comment, setComment] = useState("");
  const [history, setHistory] = useState<SourceEvidenceDecisionSummary[]>([]),
    [offset, setOffset] = useState(0);
  const [attempt, setAttempt] = useState<ReviewSourceEvidenceReport | null>(
      null,
    ),
    [view, setView] = useState<SourceEvidenceDecision | null>(null);
  const [uncertain, setUncertain] = useState(false),
    [rejected, setRejected] = useState(false),
    [notStored, setNotStored] = useState(false);
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<ReviewSourceEvidenceReport | null>(null);
  const busy = outerBusy || working;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      onGuardChange(false);
    };
  }, [onGuardChange]);
  useEffect(() => {
    onGuardChange(working || uncertain);
  }, [working, uncertain, onGuardChange]);
  async function operation(action: () => Promise<void>) {
    if (lock.current || outerBusy) return;
    lock.current = true;
    setWorking(true);
    onGuardChange(true);
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
    const rows = await client.sourceEvidenceDecisions(report, next);
    if (alive.current) {
      setHistory(rows);
      setOffset(next);
    }
  }
  async function openPanel() {
    setOpen(true);
    await loadHistory(0);
  }
  async function save() {
    if (
      intent.current ||
      !client.permits("verify") ||
      !verdict ||
      !sourceEvidenceCommentSchema.safeParse(comment).success
    )
      return;
    const request: ReviewSourceEvidenceReport = {
      version:
        report.version === "source-evidence-report-0.2.0"
          ? "source-evidence-decision-request-0.2.0"
          : "source-evidence-decision-request-0.1.0",
      decision_id: crypto.randomUUID(),
      report_sha256: report.review_sha256,
      verdict,
      comment,
    };
    intent.current = request;
    setAttempt(request);
    setView(null);
    setUncertain(true);
    setRejected(false);
    setNotStored(false);
    let row: SourceEvidenceDecision;
    try {
      row = await client.reviewSourceEvidenceReport(draft, report, request);
    } catch (problem) {
      if (alive.current)
        setRejected(
          problem instanceof ApiError &&
            [400, 403, 404, 409, 413, 422, 429].includes(problem.status),
        );
      throw problem;
    }
    if (!alive.current) return;
    setView(row);
    setUncertain(false);
    await loadHistory(0);
  }
  async function reconcile() {
    const request = intent.current;
    if (!request) return;
    try {
      const row = await client.sourceEvidenceDecision(
        draft,
        report,
        request.decision_id,
        request,
      );
      if (!alive.current) return;
      setView(row);
      setUncertain(false);
      setNotStored(false);
    } catch (problem) {
      if (
        alive.current &&
        rejected &&
        problem instanceof ApiError &&
        problem.status === 404
      )
        setNotStored(true);
      throw problem;
    }
    await loadHistory(0);
  }
  async function detail(summary: SourceEvidenceDecisionSummary) {
    const expected =
      intent.current?.decision_id === summary.decision_id
        ? intent.current
        : undefined;
    const row = await client.sourceEvidenceDecision(
      draft,
      report,
      summary.decision_id,
      expected,
      summary,
    );
    if (!alive.current) return;
    setView(row);
    if (expected) {
      setUncertain(false);
      setNotStored(false);
    }
  }
  function reset() {
    if (
      busy ||
      !attempt ||
      (uncertain
        ? !(rejected && notStored)
        : view?.decision_id !== attempt.decision_id)
    )
      return;
    intent.current = null;
    setAttempt(null);
    setView(null);
    setUncertain(false);
    setRejected(false);
    setNotStored(false);
    setVerdict("");
    setComment("");
  }
  const commentValid = sourceEvidenceCommentSchema.safeParse(comment).success;
  return (
    <section
      className="patch-panel"
      aria-label="Рассмотрение совместного отчёта"
    >
      <h4>Рассмотрение совместного отчёта</h4>
      <p className="notice warning">
        Доступны отклонение или запрос дополнительных сведений. Согласование
        недоступно: формальная квалификация отчёта not_proven. Решение
        сохраняется отдельно и не меняет отчёт, его результаты или статус
        needs_review.
      </p>
      <p className="hint">
        Записывается сервисная роль токена, а личность инженера не удостоверена.
        Комментарий и вердикт не являются независимой разметкой качества.
      </p>
      <button
        className="button secondary"
        disabled={busy}
        onClick={() => void operation(openPanel)}
      >
        {open
          ? "Обновить решения по отчёту"
          : "Открыть рассмотрение этого отчёта"}
      </button>
      {open && (
        <>
          {working && (
            <p role="status">Чтение или сохранение решения по отчёту…</p>
          )}
          <p className="mono">
            Рассматриваемый отчёт: {report.report_id}
            <br />
            Версия отчёта: {report.version}
            <br />
            SHA-256 отчёта: {report.review_sha256}
          </p>
          {client.permits("verify") && (
            <>
              <label>
                Вердикт по совместному отчёту
                <select
                  aria-label="Вердикт по совместному отчёту"
                  value={verdict}
                  disabled={busy || !!attempt}
                  onChange={(event) =>
                    setVerdict(event.target.value as typeof verdict)
                  }
                >
                  <option value="">Выберите вердикт</option>
                  <option value="rejected">Отклонено</option>
                  <option value="needs_more_information">
                    Нужны дополнительные сведения
                  </option>
                </select>
              </label>
              <label>
                Комментарий к решению
                <textarea
                  aria-label="Комментарий к решению"
                  value={comment}
                  disabled={busy || !!attempt}
                  rows={4}
                  autoComplete="off"
                  onChange={(event) => setComment(event.target.value)}
                />
              </label>
              <p className="hint">
                Символов Unicode: {evidenceCommentLength(comment)} / 1200.
                Разрешены печатные символы, перенос строки и табуляция.
              </p>
              {comment && !commentValid && (
                <p className="notice warning">
                  Нужен непустой комментарий до 1200 символов Unicode без
                  непечатных символов.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy || !!attempt || !verdict || !commentValid}
                onClick={() => void operation(save)}
              >
                Сохранить решение по отчёту
              </button>
            </>
          )}
          {attempt && (
            <div aria-label="Запрос решения по отчёту">
              <p className="mono">ID решения: {attempt.decision_id}</p>
              {uncertain && (
                <p className="notice warning">
                  {rejected
                    ? "Сервер отклонил запрос решения. Проверьте наличие записи этого ID."
                    : "Итог сохранения решения не подтверждён."}{" "}
                  Поля и выбор другого отчёта заморожены; повторной отправки
                  POST нет.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void operation(reconcile)}
              >
                Прочитать решение по ID запроса
              </button>
              {rejected && notStored && (
                <>
                  <p>
                    После явного отказа чтение вернуло 404. Можно явно сбросить
                    отклонённый запрос.
                  </p>
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={reset}
                  >
                    Сбросить отклонённый запрос решения
                  </button>
                </>
              )}
              {!uncertain && view?.decision_id === attempt.decision_id && (
                <button
                  className="button secondary"
                  disabled={busy}
                  onClick={reset}
                >
                  Подготовить новое решение по отчёту
                </button>
              )}
            </div>
          )}
          <ul aria-label="История решений по отчёту">
            {history.map((row) => (
              <li key={row.decision_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => void operation(() => detail(row))}
                >
                  Открыть решение {shortId(row.decision_id)} ·{" "}
                  {date(row.created_at)} · {verdictNames[row.verdict]} ·
                  сервисная роль: {row.service_role}
                </button>
              </li>
            ))}
          </ul>
          <p className="hint">
            Решений на странице: {history.length}; смещение: {offset}. Каждая
            запись самостоятельна; последняя запись не повышает статус отчёта.
          </p>
          {(offset > 0 || history.length === 20) && (
            <div className="pager">
              <button
                className="button secondary compact"
                disabled={busy || offset === 0}
                onClick={() => void operation(() => loadHistory(offset - 20))}
              >
                Предыдущие решения по отчёту
              </button>
              <button
                className="button secondary compact"
                disabled={busy || history.length < 20 || offset >= 10000}
                onClick={() => void operation(() => loadHistory(offset + 20))}
              >
                Следующие решения по отчёту
              </button>
            </div>
          )}
          {view && (
            <div aria-label="Сохранённое решение по отчёту">
              <h4>Решение сохранено: {verdictNames[view.request.verdict]}</h4>
              <p>
                Сервисная роль при записи: {view.service_role}. Личность
                инженера не удостоверена. Согласовано: нет. Применено: нет.
                Статус отчёта: needs_review.
              </p>
              <p className="mono">
                Отчёт: {view.report_id} · SHA-256: {view.report_sha256}
                <br />
                ID решения: {view.decision_id} · {date(view.created_at)}
                <br />
                SHA-256 решения: {view.decision_sha256}
              </p>
              <p>Сохранённый комментарий:</p>
              <pre
                className="json-view"
                aria-label="Сохранённый комментарий решения"
              >
                {view.request.comment}
              </pre>
              <p className="hint">
                Хеш связывает запись с отчётом; он не подтверждает личность
                автора или истинность комментария.
              </p>
              <details>
                <summary>Полная сохранённая запись решения</summary>
                <pre className="json-view">{JSON.stringify(view, null, 2)}</pre>
              </details>
            </div>
          )}
        </>
      )}
    </section>
  );
}
