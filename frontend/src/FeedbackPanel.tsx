import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiClient, ApiError } from "./api";
import type {
  AnalysisResult,
  FeedbackRecord,
  FeedbackSubmission,
  FeedbackVerdict,
  Finding,
} from "./contracts";
import {
  feedbackMatches,
  feedbackTarget,
  prepareFeedback,
  sameSubmission,
  verdictLabels,
} from "./feedback";
import { date } from "./format";

export function FeedbackPanel({
  analysis,
  finding,
  client,
  busy,
  onError,
  onSubmit,
}: {
  analysis: AnalysisResult;
  finding: Finding;
  client: ApiClient;
  busy: boolean;
  onError: (error: unknown) => void;
  onSubmit: (
    finding: string,
    submission: FeedbackSubmission,
  ) => Promise<FeedbackRecord | null>;
}) {
  const target = useMemo(
    () => feedbackTarget(analysis, finding),
    [analysis, finding],
  );
  const [records, setRecords] = useState<FeedbackRecord[]>([]);
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(false);
  const [comment, setComment] = useState("");
  const [verdict, setVerdict] = useState<FeedbackVerdict>(
    "needs_investigation",
  );
  const [notice, setNotice] = useState<string | null>(null);
  const pending = useRef<FeedbackSubmission | null>(null);
  const draft = useRef({ verdict, comment });
  draft.current = { verdict, comment };
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      pending.current = null;
    };
  }, []);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setRecords([]);
    void client
      .feedback(finding.finding_id, analysis.analysis_id, offset)
      .then((items) => {
        if (!alive) return;
        if (
          items.some((record) => !feedbackMatches(record, target)) ||
          new Set(items.map((record) => record.feedback_id)).size !==
            items.length
        )
          throw new ApiError(
            0,
            "История обратной связи не соответствует выбранной находке.",
          );
        setRecords(items);
        const attempt = pending.current;
        const stored = attempt
          ? items.find((item) => item.feedback_id === attempt.feedback_id)
          : undefined;
        if (stored && attempt) {
          if (!sameSubmission(stored, attempt))
            throw new ApiError(
              0,
              "Сохранённая запись не соответствует отправленной оценке.",
            );
          pending.current = null;
          if (
            draft.current.verdict === attempt.verdict &&
            draft.current.comment.trim() === attempt.comment
          )
            setComment("");
          setNotice("Отправленная оценка найдена в истории.");
        }
      })
      .catch((problem: unknown) => {
        if (alive) onError(problem);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [
    client,
    analysis.analysis_id,
    finding.finding_id,
    offset,
    refresh,
    target,
    onError,
  ]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setNotice(null);
    let request: FeedbackSubmission;
    try {
      request = prepareFeedback(target, verdict, comment, pending.current);
    } catch (problem) {
      onError(
        new ApiError(
          400,
          problem instanceof Error ? problem.message : "Оценка не принята.",
        ),
      );
      return;
    }
    pending.current = request;
    const record = await onSubmit(finding.finding_id, request);
    if (!mounted.current) return;
    if (!record) {
      setNotice(
        "Отправка не подтверждена. Сначала обновите историю; повтор той же оценки использует прежний ID. Изменённый текст или вердикт создаст новую запись.",
      );
      return;
    }
    if (!feedbackMatches(record, target) || !sameSubmission(record, request)) {
      onError(
        new ApiError(
          0,
          "Сохранённая запись не соответствует отправленной оценке.",
        ),
      );
      setNotice("Отправка не подтверждена. Обновите историю перед повтором.");
      return;
    }
    pending.current = null;
    setComment("");
    setNotice("Оценка сохранена. Исходный анализ и риск не изменены.");
    setOffset(0);
    setRefresh((value) => value + 1);
  }

  return (
    <section className="feedback-panel" aria-label="Обратная связь по находке">
      <h4>Оценка инженера</h4>
      <p className="hint">
        Оценка владельца общего service-токена: личность не подтверждается. Это
        не исправление, не согласование патча и не проверенная метка датасета.
        Не вписывайте секреты.
      </p>
      <form
        onSubmit={(event) => {
          void submit(event);
        }}
      >
        <label htmlFor="feedback-verdict">Вердикт по находке</label>
        <select
          id="feedback-verdict"
          value={verdict}
          disabled={busy}
          onChange={(event) =>
            setVerdict(event.target.value as FeedbackVerdict)
          }
        >
          {(Object.keys(verdictLabels) as FeedbackVerdict[]).map((value) => (
            <option key={value} value={value}>
              {verdictLabels[value]}
            </option>
          ))}
        </select>
        <label htmlFor="feedback-comment">Комментарий к оценке</label>
        <textarea
          id="feedback-comment"
          value={comment}
          disabled={busy}
          maxLength={4000}
          rows={4}
          required
          autoComplete="off"
          onChange={(event) => setComment(event.target.value)}
        />
        <p className="hint">{Array.from(comment).length} / 2000 символов</p>
        <button
          className="button secondary"
          disabled={busy || !comment.trim()}
          type="submit"
        >
          Сохранить оценку
        </button>
      </form>
      {notice && (
        <p role="status" className="hint">
          {notice}
        </p>
      )}
      <h4>История оценок</h4>
      <p className="hint">
        Записи не переписываются. Изменение мнения добавляйте отдельной оценкой.
      </p>
      <button
        className="button secondary compact"
        disabled={busy || loading}
        onClick={() => setRefresh((value) => value + 1)}
      >
        Обновить историю оценок
      </button>
      {loading ? (
        <p role="status">Загрузка оценок…</p>
      ) : records.length === 0 ? (
        <p className="hint">На этой странице оценок нет.</p>
      ) : (
        <ul className="feedback-history">
          {records.map((record) => (
            <li key={record.feedback_id}>
              <strong>{verdictLabels[record.verdict]}</strong> ·{" "}
              {date(record.created_at)}
              <p className="feedback-comment">{record.comment}</p>
              <details>
                <summary>Привязка оценки</summary>
                <pre>{JSON.stringify(record, null, 2)}</pre>
              </details>
            </li>
          ))}
        </ul>
      )}
      <div className="pager">
        <button
          className="button secondary compact"
          disabled={busy || loading || offset === 0}
          onClick={() => setOffset(Math.max(0, offset - 20))}
        >
          Предыдущие оценки
        </button>
        <button
          className="button secondary compact"
          disabled={busy || loading || records.length < 20 || offset >= 10000}
          onClick={() => setOffset(offset + 20)}
        >
          Следующие оценки
        </button>
      </div>
    </section>
  );
}
