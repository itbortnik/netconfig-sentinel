import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type { ConfigurationSnapshot, SnapshotDiff } from "./contracts";
import {
  patchBound,
  patchIntent,
  reviewBound,
  summaryBound,
  summaryMatchesDraft,
} from "./patches";
import type {
  CreatePatch,
  PatchDraft,
  PatchSummary,
  VerificationRun,
  VerificationSummary,
  VerifyPatch,
} from "./patches";
import { date, shortId } from "./format";

const blockerNames: Record<string, string> = {
  formal_verification_not_run: "Формальная проверка не запускалась",
  human_review_required: "Требуется проверка человеком",
  incomplete_parsing: "Не все команды разобраны",
  reference_comparison_unavailable: "Сравнение с ранним снимком недоступно",
  current_policy_findings: "В новом снимке остались нарушения политик",
  introduced_policy_findings: "Появились новые нарушения политик",
};
const conflict = () =>
  new ApiError(0, "Запись не соответствует выбранному снимку или черновику.");
export function PatchPanel({
  client,
  snapshot,
  diff,
  busy: outerBusy,
  onError,
}: {
  client: ApiClient;
  snapshot: ConfigurationSnapshot;
  diff: SnapshotDiff | null;
  busy: boolean;
  onError: (problem: unknown) => void;
}) {
  const [drafts, setDrafts] = useState<PatchSummary[]>([]);
  const [draft, setDraft] = useState<PatchDraft | null>(null);
  const [runs, setRuns] = useState<VerificationSummary[]>([]);
  const [run, setRun] = useState<VerificationRun | null>(null);
  const [draftOffset, setDraftOffset] = useState(0);
  const [runOffset, setRunOffset] = useState(0);
  const [working, setWorking] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [historyReady, setHistoryReady] = useState(false);
  const alive = useRef(true);
  const locked = useRef(false);
  const createIntent = useRef<CreatePatch | null>(null);
  const reviewIntent = useRef<VerifyPatch | null>(null);
  const busy = outerBusy || working;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  async function operation(action: () => Promise<void>, write = false) {
    if (locked.current || outerBusy) return;
    locked.current = true;
    setWorking(true);
    try {
      await action();
      if (alive.current && write) setUncertain(false);
    } catch (error) {
      if (alive.current) {
        if (write) setUncertain(true);
        onError(error);
      }
    } finally {
      locked.current = false;
      if (alive.current) setWorking(false);
    }
  }
  async function refreshDrafts(offset: number) {
    const items = await client.patches(snapshot.configuration_id, offset);
    if (
      items.some((item) => !summaryBound(item, snapshot)) ||
      new Set(items.map((item) => item.patch_id)).size !== items.length
    )
      throw conflict();
    if (alive.current) {
      setDrafts(items);
      setDraftOffset(offset);
      setHistoryReady(true);
    }
  }
  async function refreshRuns(selected: PatchDraft, offset: number) {
    const items = await client.verifications(selected.patch_id, offset);
    if (
      items.some(
        (item) =>
          item.patch_id !== selected.patch_id ||
          item.draft_sha256 !== selected.draft_sha256 ||
          Date.parse(item.created_at) < Date.parse(selected.created_at),
      ) ||
      new Set(items.map((item) => item.verification_id)).size !== items.length
    )
      throw conflict();
    if (alive.current) {
      setRuns(items);
      setRunOffset(offset);
    }
  }
  async function save() {
    if (!diff || !diff.source_changed || diff.changes.length === 0) return;
    createIntent.current ??= patchIntent(diff, crypto.randomUUID());
    const received = await client.createPatch(createIntent.current);
    if (
      received.patch_id !== createIntent.current.patch_id ||
      !patchBound(received, snapshot, diff)
    )
      throw conflict();
    if (!alive.current) return;
    setDraft(received);
    setRun(null);
    setRuns([]);
    reviewIntent.current = null;
    await refreshDrafts(0);
    await refreshRuns(received, 0);
  }
  async function select(item: PatchSummary) {
    const received = await client.patch(item.patch_id);
    if (!summaryMatchesDraft(item, received) || !patchBound(received, snapshot))
      throw conflict();
    if (!alive.current) return;
    setDraft(received);
    setRun(null);
    setRuns([]);
    setUncertain(false);
    reviewIntent.current = null;
    await refreshRuns(received, 0);
  }
  async function review() {
    if (!draft) return;
    reviewIntent.current ??= {
      verification_id: crypto.randomUUID(),
      draft_sha256: draft.draft_sha256,
      mode: "local_preflight",
    };
    const received = await client.verifyPatch(
      draft.patch_id,
      reviewIntent.current,
    );
    if (
      received.verification_id !== reviewIntent.current.verification_id ||
      !reviewBound(received, draft)
    )
      throw conflict();
    if (!alive.current) return;
    setRun(received);
    await refreshRuns(draft, 0);
    if (alive.current) reviewIntent.current = null;
  }
  async function openRun(item: VerificationSummary) {
    if (!draft) return;
    const received = await client.verification(
      draft.patch_id,
      item.verification_id,
    );
    if (
      received.verification_id !== item.verification_id ||
      !reviewBound(received, draft) ||
      received.preflight.policy_catalog_version !==
        item.policy_catalog_version ||
      received.preflight.after_policy_findings.length !==
        item.current_policy_finding_count ||
      received.preflight.before.complete !== item.before_complete ||
      received.preflight.after.complete !== item.after_complete ||
      (received.preflight.policy_changes?.introduced.length ?? null) !==
        item.introduced_count ||
      (received.preflight.policy_changes?.resolved.length ?? null) !==
        item.resolved_count
    )
      throw conflict();
    if (alive.current) {
      setRun(received);
      if (reviewIntent.current?.verification_id === received.verification_id) {
        reviewIntent.current = null;
        setUncertain(false);
      }
    }
  }
  return (
    <section aria-label="Черновики изменений" className="patch-panel">
      <h3>Черновики изменений</h3>
      <p className="notice">
        Черновик сохраняет различия объектов, не команды для устройства.
        Согласование и применение недоступны. Локальная проверка не заменяет
        проверку поведения сети.
      </p>
      <div className="button-row">
        <button
          className="button secondary"
          disabled={busy || !diff?.source_changed || diff.changes.length === 0}
          onClick={() => {
            void operation(save, true);
          }}
        >
          Сохранить черновик объектов
        </button>
        <button
          className="button secondary"
          disabled={busy}
          onClick={() => {
            void operation(() => refreshDrafts(0));
          }}
        >
          Обновить черновики
        </button>
      </div>
      {working && <p role="status">Загрузка черновика или истории…</p>}
      {uncertain && (
        <p className="notice warning">
          Запись могла сохраниться, даже если ответ не получен. Проверьте
          историю. Повтор кнопки в этой сессии использует тот же ID.
        </p>
      )}
      {historyReady && drafts.length === 0 && (
        <p>Черновиков на этой странице нет.</p>
      )}
      <ul>
        {drafts.map((item) => (
          <li key={item.patch_id}>
            <button
              className="button secondary compact"
              disabled={busy}
              onClick={() => {
                void operation(() => select(item));
              }}
            >
              Открыть черновик {shortId(item.patch_id)} ·{" "}
              {date(item.created_at)} · {item.change_count} изменений
            </button>
          </li>
        ))}
      </ul>
      {(draftOffset > 0 || drafts.length === 20) && (
        <div className="pager">
          <button
            className="button secondary compact"
            disabled={busy || draftOffset === 0}
            onClick={() => {
              void operation(() => refreshDrafts(draftOffset - 20));
            }}
          >
            Предыдущие черновики
          </button>
          <button
            className="button secondary compact"
            disabled={busy || drafts.length < 20 || draftOffset >= 10000}
            onClick={() => {
              void operation(() => refreshDrafts(draftOffset + 20));
            }}
          >
            Следующие черновики
          </button>
        </div>
      )}
      {draft && (
        <div aria-label="Сохранённый черновик">
          <h4>
            Черновик {shortId(draft.patch_id)} — требуется проверка человеком
          </h4>
          <p className="mono">
            До: {draft.diff.before.configuration_id}
            <br />
            После: {draft.diff.after.configuration_id}
            <br />
            SHA-256 черновика: {draft.draft_sha256}
          </p>
          <p>
            {draft.diff.coverage === "partial"
              ? "Неполный разбор: неизвестные команды не включены."
              : "Различия только в поддерживаемых объектах."}
          </p>
          <details>
            <summary>Сохранённые различия объектов</summary>
            <pre>{JSON.stringify(draft.diff, null, 2)}</pre>
          </details>
          <div className="button-row">
            <button
              className="button secondary"
              disabled={busy}
              onClick={() => {
                void operation(review, true);
              }}
            >
              Локальная проверка черновика
            </button>
            <button
              className="button secondary"
              disabled={busy}
              onClick={() => {
                void operation(() => refreshRuns(draft, 0));
              }}
            >
              Обновить проверки
            </button>
          </div>
          <p className="notice warning">
            Формальная проверка: не запускалась. Статус черновика не меняется
            после локальной проверки.
          </p>
          <ul>
            {runs.map((item) => (
              <li key={item.verification_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => {
                    void operation(() => openRun(item));
                  }}
                >
                  Открыть проверку {shortId(item.verification_id)} ·{" "}
                  {date(item.created_at)} · нарушений:{" "}
                  {item.current_policy_finding_count}
                </button>
              </li>
            ))}
          </ul>
          {(runOffset > 0 || runs.length === 20) && (
            <div className="pager">
              <button
                className="button secondary compact"
                disabled={busy || runOffset === 0}
                onClick={() => {
                  void operation(() => refreshRuns(draft, runOffset - 20));
                }}
              >
                Предыдущие проверки
              </button>
              <button
                className="button secondary compact"
                disabled={busy || runs.length < 20 || runOffset >= 10000}
                onClick={() => {
                  void operation(() => refreshRuns(draft, runOffset + 20));
                }}
              >
                Следующие проверки
              </button>
            </div>
          )}
          {run && (
            <div aria-label="Локальная проверка">
              <h4>Локальная проверка — требуется рассмотрение</h4>
              <p>Каталог политик: {run.preflight.policy_catalog_version}</p>
              <p>
                Нарушения до: {run.preflight.before_policy_findings.length} ·
                после: {run.preflight.after_policy_findings.length}
              </p>
              <p>
                {run.preflight.policy_changes
                  ? `Новых: ${run.preflight.policy_changes.introduced.length} · исчезнувших: ${run.preflight.policy_changes.resolved.length} · сохранившихся: ${run.preflight.policy_changes.persistent.length}`
                  : "Изменения нарушений недоступны: неполный разбор."}
              </p>
              <p className="hint">
                Исчезновение находки не доказывает исправление или безопасность
                сети. Сохранённые анализы и риск не изменены.
              </p>
              <ul>
                {run.validation_blockers.map((item) => (
                  <li key={item}>{blockerNames[item] ?? item}</li>
                ))}
              </ul>
              <details>
                <summary>Полный отчёт локальной проверки</summary>
                <pre>{JSON.stringify(run, null, 2)}</pre>
              </details>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
