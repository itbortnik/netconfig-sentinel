import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type { ConfigurationSummary } from "./contracts";
import type { PatchDraft } from "./patches";
import { date, shortId } from "./format";
import {
  sourceCompanionEligible,
  sourceNetworkStatusNames,
  verifySourcePatchSchema,
} from "./sourcePatchVerification";
import type {
  SourcePatchCapabilities,
  SourcePatchVerification,
  SourcePatchVerificationSummary,
  VerifySourcePatch,
} from "./sourcePatchVerification";

const blockers: Record<string, string> = {
  device_syntax_not_verified: "Синтаксис на устройстве не проверен",
  management_access_not_verified: "Доступ управления не проверен",
  rollback_not_verified: "Откат не проверен",
  selected_ml_not_run: "ML не запускался",
  baseline_approval_not_proven: "Одобрение раннего снимка не установлено",
  individual_engineer_review_required:
    "Требуется отдельное рассмотрение инженером",
  network_execution_unknown: "Исполнение сетевого запроса не подтверждено",
  formal_scope_not_passed:
    "Сетевая область не получила положительного результата",
  engine_cleanup_not_confirmed: "Удаление временной сети не подтверждено",
  policy_regression_or_missing_comparison:
    "Есть новые нарушения политик или сравнение недоступно",
};
const cleanup = (value: boolean | null) =>
  value === true
    ? "подтверждено"
    : value === false
      ? "не выполнено"
      : "неизвестно";
export function SourcePatchVerificationPanel({
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
  const [capabilities, setCapabilities] =
    useState<SourcePatchCapabilities | null>(null);
  const [capabilitiesFailed, setCapabilitiesFailed] = useState(false);
  const [working, setWorking] = useState(false);
  const [history, setHistory] = useState<SourcePatchVerificationSummary[]>([]);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [pool, setPool] = useState<ConfigurationSummary[]>([]);
  const [poolOffset, setPoolOffset] = useState(0);
  const [poolCount, setPoolCount] = useState(0);
  const [companions, setCompanions] = useState<ConfigurationSummary[]>([]);
  const [startNode, setStartNode] = useState("");
  const [destination, setDestination] = useState("");
  const [consent, setConsent] = useState(false);
  const [attempt, setAttempt] = useState<VerifySourcePatch | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [rejected, setRejected] = useState(false);
  const [rejectedNotStored, setRejectedNotStored] = useState(false);
  const [view, setView] = useState<SourcePatchVerification | null>(null);
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<VerifySourcePatch | null>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const busy = outerBusy || working;
  const frozen = busy || !!attempt;
  const ready = verifySourcePatchSchema.safeParse({
    verification_id: "00000000-0000-0000-0000-000000000001",
    draft_sha256: draft.draft_sha256,
    companions: companions.map(({ configuration_id, source_sha256 }) => ({
      configuration_id,
      source_sha256,
    })),
    scope: { start_node: startNode, destination },
    allow_local_engine_upload: consent,
  });
  const knownHost = [
    draft.diff.before.hostname,
    ...companions.map((row) => row.hostname),
  ].includes(startNode);
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
  async function loadHistory(offset: number) {
    const rows = await client.sourcePatchVerifications(draft, offset);
    if (alive.current) {
      setHistory(rows);
      setHistoryOffset(offset);
    }
  }
  async function openPanel() {
    setOpen(true);
    try {
      const value = await client.sourcePatchCapabilities();
      if (alive.current) {
        setCapabilities(value);
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
  async function loadPool(offset: number) {
    const rows = await client.configurations(offset);
    if (alive.current) {
      setPool(
        rows.filter((row) => row.device_id !== draft.diff.before.device_id),
      );
      setPoolOffset(offset);
      setPoolCount(rows.length);
    }
  }
  async function launch() {
    if (
      intent.current ||
      !client.permits("verify") ||
      capabilities?.network_engine !== "configured" ||
      !consent ||
      !knownHost ||
      !ready.success
    )
      return;
    const request = { ...ready.data, verification_id: crypto.randomUUID() };
    intent.current = request;
    setAttempt(request);
    setConsent(false);
    setView(null);
    setUncertain(true);
    setRejected(false);
    setRejectedNotStored(false);
    try {
      const received = await client.verifySourcePatch(draft, request);
      if (!alive.current) return;
      setView(received);
      setUncertain(received.execution_status !== "completed");
      await loadHistory(0);
    } catch (problem) {
      // A lost response never authorizes another POST. Reconcile this exact ID by GET.
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
    let received: SourcePatchVerification;
    try {
      received = await client.sourcePatchVerification(
        draft,
        request.verification_id,
        request,
      );
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
    if (alive.current) {
      setView(received);
      setUncertain(received.execution_status !== "completed");
    }
    await loadHistory(0);
  }
  async function detail(summary: SourcePatchVerificationSummary) {
    const received = await client.sourcePatchVerification(
      draft,
      summary.verification_id,
      undefined,
      summary,
    );
    if (alive.current) {
      setView(received);
      setConsent(false);
    }
  }
  function newAttempt() {
    if (
      !attempt ||
      uncertain ||
      view?.verification_id !== attempt.verification_id ||
      view.execution_status !== "completed"
    )
      return;
    intent.current = null;
    setAttempt(null);
    setView(null);
    setConsent(false);
  }
  function clearRejected() {
    if (!rejectedNotStored || !rejected || working || !attempt) return;
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
      aria-label="Сетевая проверка сохранённых исходников"
      className="patch-panel"
    >
      <h4>Сетевая проверка сохранённых исходников</h4>
      <p className="hint">
        Проверка использует точные сохранённые тексты двух снимков этого
        черновика и выбранных соседей. Сырые конфигурации передаются локальному
        Batfish только с отдельного разрешения. Проверяется явная область IPv4;
        согласование и применение недоступны.
      </p>
      <button
        className="button secondary"
        disabled={busy}
        onClick={() => void operation(openPanel)}
      >
        {open
          ? "Обновить сетевые проверки"
          : "Открыть сетевые проверки исходников"}
      </button>
      {open && (
        <>
          {working && <p role="status">Загрузка сетевой проверки…</p>}
          {capabilitiesFailed && (
            <p className="notice warning">
              Возможности сетевой проверки недоступны. Запуск заблокирован.
            </p>
          )}
          {capabilities && (
            <p className="notice warning">
              {capabilities.network_engine === "configured"
                ? "Локальный сетевой движок настроен; его доступность не проверена."
                : "Локальный сетевой движок отключён. Запуск недоступен."}{" "}
              ML не запускается.
            </p>
          )}
          {client.permits("verify") && (
            <>
              <p className="mono">
                Исходник до: {draft.diff.before.source_sha256}
                <br />
                Исходник после: {draft.diff.after.source_sha256}
              </p>
              <button
                className="button secondary compact"
                disabled={frozen}
                onClick={() => void operation(() => loadPool(0))}
              >
                Показать снимки соседних устройств
              </button>
              <p className="hint">
                Выберите по одному снимку каждого соседа; без выбора проверяется
                только целевое устройство. Наличие точного сохранённого
                исходника проверит сервер.
              </p>
              {pool.map((row) => (
                <label className="checkbox" key={row.configuration_id}>
                  <input
                    type="checkbox"
                    checked={companions.some(
                      (item) => item.configuration_id === row.configuration_id,
                    )}
                    disabled={
                      frozen || !sourceCompanionEligible(row, draft, companions)
                    }
                    onChange={(event) => {
                      setConsent(false);
                      setCompanions((items) =>
                        event.target.checked
                          ? [...items, row]
                          : items.filter(
                              (item) =>
                                item.configuration_id !== row.configuration_id,
                            ),
                      );
                    }}
                  />
                  {row.hostname ?? "Без имени"} · {row.configuration_id} ·{" "}
                  {date(row.created_at)}
                </label>
              ))}
              {(poolOffset > 0 || poolCount === 20) && (
                <div className="pager">
                  <button
                    className="button secondary compact"
                    disabled={frozen || poolOffset === 0}
                    onClick={() =>
                      void operation(() => loadPool(poolOffset - 20))
                    }
                  >
                    Предыдущие снимки соседей
                  </button>
                  <button
                    className="button secondary compact"
                    disabled={frozen || poolCount < 20 || poolOffset >= 10000}
                    onClick={() =>
                      void operation(() => loadPool(poolOffset + 20))
                    }
                  >
                    Следующие снимки соседей
                  </button>
                </div>
              )}
              <ul aria-label="Выбранные соседи">
                {companions.map((row) => (
                  <li key={row.configuration_id}>
                    <span className="mono">
                      {row.hostname} · {row.configuration_id} · SHA-256
                      исходника: {row.source_sha256}
                    </span>
                    <button
                      className="button secondary compact"
                      disabled={frozen}
                      onClick={() => {
                        setCompanions((items) =>
                          items.filter(
                            (item) =>
                              item.configuration_id !== row.configuration_id,
                          ),
                        );
                        setConsent(false);
                      }}
                    >
                      Убрать {row.hostname}
                    </button>
                  </li>
                ))}
              </ul>
              <label>
                Начальный узел сетевой проверки
                <input
                  value={startNode}
                  disabled={frozen}
                  maxLength={128}
                  onChange={(event) => {
                    setStartNode(event.target.value);
                    setConsent(false);
                  }}
                  placeholder="Укажите hostname выбранного устройства"
                />
              </label>
              <label>
                Назначение IPv4 сетевой проверки
                <input
                  value={destination}
                  disabled={frozen}
                  maxLength={18}
                  onChange={(event) => {
                    setDestination(event.target.value);
                    setConsent(false);
                  }}
                  placeholder="Например, 198.51.100.1/32"
                />
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={consent}
                  disabled={
                    frozen || capabilities?.network_engine !== "configured"
                  }
                  onChange={(event) => setConsent(event.target.checked)}
                />
                Разрешаю передачу выбранных исходников локальному сетевому
                движку
              </label>
              <button
                className="button secondary"
                disabled={
                  frozen ||
                  capabilities?.network_engine !== "configured" ||
                  !consent ||
                  !knownHost ||
                  !ready.success
                }
                onClick={() => void operation(launch)}
              >
                Проверить сохранённые исходники в сети
              </button>
            </>
          )}
          {attempt && (
            <div aria-label="Сохранённый запрос сетевой проверки">
              <p className="mono">
                ID сетевой попытки: {attempt.verification_id}
              </p>
              {uncertain && (
                <p className="notice warning">
                  {rejected
                    ? "Сервер отклонил запрос. Проверьте наличие записи этой попытки."
                    : "Итог не подтверждён."}{" "}
                  Новый запуск заблокирован. Прочитайте сохранённую попытку;
                  повторная отправка не выполняется.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void operation(reconcile)}
              >
                Прочитать сетевую попытку
              </button>
              {rejectedNotStored && (
                <>
                  <p className="notice warning">
                    Сервер отклонил запрос; чтение этой попытки вернуло 404.
                    Можно сбросить отклонённый запрос, исправить параметры и
                    отдельно разрешить новый запуск.
                  </p>
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={clearRejected}
                  >
                    Сбросить отклонённый сетевой запрос
                  </button>
                </>
              )}
              {!uncertain &&
                view?.verification_id === attempt.verification_id &&
                view.execution_status === "completed" && (
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={newAttempt}
                  >
                    Подготовить новую сетевую проверку
                  </button>
                )}
            </div>
          )}
          <ul aria-label="История сетевых проверок">
            {history.map((row) => (
              <li key={row.verification_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => void operation(() => detail(row))}
                >
                  Открыть сетевую проверку {shortId(row.verification_id)} ·{" "}
                  {date(row.created_at)} ·{" "}
                  {row.network_status
                    ? sourceNetworkStatusNames[row.network_status]
                    : "Исполнение не подтверждено"}
                </button>
              </li>
            ))}
          </ul>
          {(historyOffset > 0 || history.length === 20) && (
            <div className="pager">
              <button
                className="button secondary compact"
                disabled={busy || historyOffset === 0}
                onClick={() =>
                  void operation(() => loadHistory(historyOffset - 20))
                }
              >
                Предыдущие сетевые проверки
              </button>
              <button
                className="button secondary compact"
                disabled={busy || history.length < 20 || historyOffset >= 10000}
                onClick={() =>
                  void operation(() => loadHistory(historyOffset + 20))
                }
              >
                Следующие сетевые проверки
              </button>
            </div>
          )}
          {view && (
            <div aria-label="Результат проверки исходников">
              <h4>Требуется рассмотрение: needs_review</h4>
              <p>Согласовано: нет. Применено: нет. ML: не запускался.</p>
              <p>Локальный preflight: формальная проверка не запускалась.</p>
              {view.execution_status === "pending_unknown" ? (
                <p className="notice warning">
                  pending_unknown: исполнение не подтверждено. Этот статус не
                  доказывает работу фонового процесса.
                </p>
              ) : (
                view.outcome && (
                  <>
                    <p>
                      {
                        sourceNetworkStatusNames[
                          view.outcome.network_result.status
                        ]
                      }{" "}
                      ({view.outcome.network_result.status})
                    </p>
                    <p>
                      Причина: {view.outcome.network_result.reason}. Версия
                      движка:{" "}
                      {view.outcome.network_result.engine_version ??
                        "не получена"}
                      .
                    </p>
                    <p>
                      Строк ответа до:{" "}
                      {view.outcome.network_result.before_reachable_count ??
                        "не получены"}{" "}
                      · после:{" "}
                      {view.outcome.network_result.after_reachable_count ??
                        "не получены"}{" "}
                      · различий:{" "}
                      {view.outcome.network_result.difference_count ??
                        "не получены"}
                    </p>
                    <p>
                      Удаление временной сети:{" "}
                      {cleanup(view.outcome.network_result.cleanup_complete)}.
                    </p>
                    {view.outcome.network_result.cleanup_complete !== true && (
                      <p className="notice warning">
                        На движке могли остаться исходники. Сеть:{" "}
                        {view.outcome.network_result.network_name ??
                          "имя не получено"}
                        .
                      </p>
                    )}
                  </>
                )
              )}
              <p>
                Область: {view.intent.request.scope.start_node} →{" "}
                {view.intent.request.scope.destination}. Счётчики показывают
                строки ответа в выбранной области, а не безопасность всей сети.
              </p>
              <p className="mono">
                SHA-256 сети до: {view.intent.before_network_sha256}
                <br />
                SHA-256 сети после: {view.intent.after_network_sha256}
                <br />
                SHA-256 записи: {view.review_sha256}
              </p>
              <p className="hint">
                Хеш связывает содержимое записи; он не удостоверяет личность
                инженера или истинность результата. Проверка не доказывает
                синтаксис устройства, доступ управления, откат и поведение вне
                выбранной области.
              </p>
              <ul>
                {view.validation_blockers.map((value) => (
                  <li key={value}>{blockers[value] ?? value}</li>
                ))}
              </ul>
              <details>
                <summary>Полная сохранённая сетевая проверка</summary>
                <pre>{JSON.stringify(view, null, 2)}</pre>
              </details>
            </div>
          )}
        </>
      )}
    </section>
  );
}
