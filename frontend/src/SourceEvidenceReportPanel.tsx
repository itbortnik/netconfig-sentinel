import { IngressScopeView } from "./IngressScopeView";
import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import { SourceRiskAssessmentPanel } from "./SourceRiskAssessmentPanel";
import { SourceEvidenceDecisionPanel } from "./SourceEvidenceDecisionPanel";
import { ReachabilityImpactView } from "./ReachabilityImpactView";
import type { PatchDraft } from "./patches";
import { date, shortId } from "./format";
import type { SourceDeterministicSummary } from "./sourceDeterministicRecheck";
import type { SourceForestSummary } from "./sourceForestRecheck";
import type { SourceMlSummary } from "./sourceMlRecheck";
import {
  sourceNetworkStatusNames,
  sdkObservationNames,
} from "./sourcePatchVerification";
import type { SourcePatchVerificationSummary } from "./sourcePatchVerification";
import type {
  CreateSourceEvidenceReport,
  SourceEvidenceKind,
  SourceEvidenceReport,
  SourceEvidenceSummary,
} from "./sourceEvidenceReports";

const kinds = ["deterministic", "forest", "neural", "network"] as const;
const names = {
  deterministic: "Исходные политики и сравнения",
  forest: "Исходный Forest",
  neural: "Нейросетевая модель",
  network: "Сетевая проверка",
};
type ChildSummary =
  | SourceDeterministicSummary
  | SourceForestSummary
  | SourceMlSummary
  | SourcePatchVerificationSummary;
type Pages = Record<
  SourceEvidenceKind,
  { rows: ChildSummary[]; offset: number }
>;
type Selections = Record<SourceEvidenceKind, ChildSummary | null>;
const emptySelections = (): Selections => ({
  deterministic: null,
  forest: null,
  neural: null,
  network: null,
});
const emptyPages = (): Pages => ({
  deterministic: { rows: [], offset: 0 },
  forest: { rows: [], offset: 0 },
  neural: { rows: [], offset: 0 },
  network: { rows: [], offset: 0 },
});
const identity = (row: ChildSummary) =>
  "recheck_id" in row ? row.recheck_id : row.verification_id;
const refusal = (problem: unknown) =>
  problem instanceof ApiError &&
  [400, 403, 404, 409, 413, 422, 429].includes(problem.status);
const missing = (value: number | null) =>
  value === null ? "не выбрано / недоступно" : String(value);
const blockerNames: Record<string, string> = {
  baseline_approval_not_proven: "Одобрение исходного эталона не подтверждено",
  device_syntax_not_verified: "Синтаксис на устройстве не проверен",
  management_access_not_verified: "Доступ управления не проверен",
  rollback_not_verified: "Откат не проверен",
  individual_engineer_review_required:
    "Требуется отдельное рассмотрение инженером",
  independent_quality_not_proven: "Независимое качество не подтверждено",
  calibration_not_proven: "Калибровка не подтверждена",
  formal_qualification_not_proven:
    "Общая формальная квалификация не подтверждена",
  deterministic_quality_not_proven:
    "Независимое качество политик и сравнений не подтверждено",
  original_statistical_not_selected: "Исходный Forest не выбран",
  original_statistical_quality_not_proven:
    "Независимое качество исходного Forest не подтверждено",
  neural_not_selected: "Нейросетевой результат не выбран",
  network_not_selected: "Сетевая проверка не выбрана",
  change_specific_ml_quality_not_proven:
    "Качество ML для изменений не подтверждено",
  selected_model_independent_quality_not_proven:
    "Независимое качество выбранной модели не подтверждено",
  network_scope_not_overall_formal_qualification:
    "Сетевая область не доказывает общую формальную квалификацию",
  formal_scope_not_passed:
    "В выбранной сетевой области нет подтверждения успешной проверки",
  engine_cleanup_not_confirmed: "Очистка ресурсов движка не подтверждена",
};

export function SourceEvidenceReportPanel({
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
  const [open, setOpen] = useState(false),
    [working, setWorking] = useState(false);
  const [decisionGuard, setDecisionGuard] = useState(false);
  const [riskGuard, setRiskGuard] = useState(false);
  const [pages, setPages] = useState<Pages>(emptyPages),
    [selected, setSelected] = useState<Selections>(emptySelections);
  const [history, setHistory] = useState<SourceEvidenceSummary[]>([]),
    [historyOffset, setHistoryOffset] = useState(0);
  const [attempt, setAttempt] = useState<CreateSourceEvidenceReport | null>(
      null,
    ),
    [view, setView] = useState<SourceEvidenceReport | null>(null);
  const [uncertain, setUncertain] = useState(false),
    [rejected, setRejected] = useState(false),
    [notStored, setNotStored] = useState(false);
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<CreateSourceEvidenceReport | null>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const busy = outerBusy || working || decisionGuard || riskGuard;
  async function operation(action: () => Promise<void>) {
    if (lock.current || outerBusy || decisionGuard || riskGuard) return;
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
  function children(
    kind: SourceEvidenceKind,
    offset: number,
  ): Promise<ChildSummary[]> {
    if (kind === "deterministic")
      return client.sourceDeterministicRechecks(draft, offset);
    if (kind === "forest") return client.sourceForestRechecks(draft, offset);
    if (kind === "neural") return client.sourceMlRechecks(draft, offset);
    return client.sourcePatchVerifications(draft, offset);
  }
  async function loadChild(kind: SourceEvidenceKind, offset: number) {
    const rows = await children(kind, offset);
    if (alive.current)
      setPages((current) => ({ ...current, [kind]: { rows, offset } }));
  }
  async function loadHistory(offset: number) {
    const rows = await client.sourceEvidenceReports(draft, offset);
    if (alive.current) {
      setHistory(rows);
      setHistoryOffset(offset);
    }
  }
  async function openPanel() {
    setOpen(true);
    await Promise.all([
      loadHistory(0),
      ...kinds.map((kind) => loadChild(kind, 0)),
    ]);
  }
  async function save() {
    if (intent.current || !client.permits("verify") || !selected.deterministic)
      return;
    const pin = (row: ChildSummary | null) =>
      row
        ? { record_id: identity(row), review_sha256: row.review_sha256 }
        : null;
    const request: CreateSourceEvidenceReport = {
      version: "source-evidence-request-0.4.0",
      report_id: crypto.randomUUID(),
      draft_sha256: draft.draft_sha256,
      deterministic: pin(selected.deterministic)!,
      forest: pin(selected.forest),
      neural: pin(selected.neural),
      network: pin(selected.network),
    };
    intent.current = request;
    setAttempt(request);
    setUncertain(true);
    setRejected(false);
    setNotStored(false);
    setView(null);
    let row: SourceEvidenceReport;
    try {
      row = await client.createSourceEvidenceReport(draft, request);
    } catch (problem) {
      if (alive.current) setRejected(refusal(problem));
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
      const row = await client.sourceEvidenceReport(
        draft,
        request.report_id,
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
  async function detail(summary: SourceEvidenceSummary) {
    const row = await client.sourceEvidenceReport(
      draft,
      summary.report_id,
      undefined,
      summary,
    );
    if (!alive.current) return;
    setView(row);
    if (intent.current?.report_id === row.report_id) {
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
        : view?.report_id !== attempt.report_id)
    )
      return;
    intent.current = null;
    setAttempt(null);
    setView(null);
    setUncertain(false);
    setRejected(false);
    setNotStored(false);
    setSelected(emptySelections());
  }
  return (
    <section
      className="patch-panel"
      aria-label="Совместный отчёт по сохранённым результатам"
    >
      <h4>Совместный отчёт по сохранённым результатам</h4>
      <p className="notice warning">
        Отчёт объединяет явно выбранные сохранённые записи. Составление не
        запускает детекторы, модель или сетевой движок. Статус остаётся
        needs_review; общая формальная квалификация не подтверждена.
      </p>
      <button
        className="button secondary"
        disabled={busy}
        onClick={() => void operation(openPanel)}
      >
        {open
          ? "Обновить совместные отчёты и результаты"
          : "Открыть совместный отчёт"}
      </button>
      {open && (
        <>
          {working && (
            <p role="status">Чтение или сохранение совместного отчёта…</p>
          )}
          <p className="hint">
            Выберите исходные политики и сравнения обязательно, остальные
            результаты — по необходимости. Автоматического выбора последних
            записей нет. Forest должен ссылаться на тот же исходный анализ и его
            SHA-256. Pending и failed недоступны; завершённая сетевая ошибка
            остаётся доступным свидетельством ошибки.
          </p>
          {kinds.map((kind) => {
            const page = pages[kind],
              choice = selected[kind];
            const rows =
              choice &&
              !page.rows.some((row) => identity(row) === identity(choice))
                ? [choice, ...page.rows]
                : page.rows;
            return (
              <div key={kind} aria-label={`Выбор: ${names[kind]}`}>
                <label>
                  {names[kind]}
                  {kind === "deterministic"
                    ? " (обязательно)"
                    : " (необязательно)"}
                  <select
                    aria-label={names[kind]}
                    disabled={busy || !!attempt}
                    value={choice ? identity(choice) : ""}
                    onChange={(event) => {
                      setSelected((current) => ({
                        ...current,
                        [kind]:
                          rows.find(
                            (row) => identity(row) === event.target.value,
                          ) ?? null,
                      }));
                    }}
                  >
                    <option value="">Не выбрано</option>
                    {rows.map((row) => (
                      <option
                        key={identity(row)}
                        value={identity(row)}
                        disabled={row.execution_status !== "completed"}
                      >
                        {shortId(identity(row))} · {date(row.created_at)} ·{" "}
                        {row.execution_status}
                        {"network_status" in row && row.network_status
                          ? ` · ${sourceNetworkStatusNames[row.network_status]}`
                          : ""}
                        {"before_analysis_id" in row
                          ? ` · анализ ${shortId(row.before_analysis_id)}`
                          : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <p className="hint">
                  На странице: {page.rows.length}; смещение: {page.offset}.
                  Выбрано: {choice ? identity(choice) : "не выбрано"}.
                </p>
                {(page.offset > 0 || page.rows.length === 20) && (
                  <div className="pager">
                    <button
                      className="button secondary compact"
                      disabled={busy || page.offset === 0}
                      onClick={() =>
                        void operation(() => loadChild(kind, page.offset - 20))
                      }
                    >
                      Предыдущие: {names[kind]}
                    </button>
                    <button
                      className="button secondary compact"
                      disabled={
                        busy || page.rows.length < 20 || page.offset >= 10000
                      }
                      onClick={() =>
                        void operation(() => loadChild(kind, page.offset + 20))
                      }
                    >
                      Следующие: {names[kind]}
                    </button>
                  </div>
                )}
              </div>
            );
          })}
          {selected.deterministic &&
            selected.forest &&
            "before_analysis_id" in selected.deterministic &&
            "before_analysis_id" in selected.forest &&
            selected.deterministic.before_analysis_id !==
              selected.forest.before_analysis_id && (
              <p className="notice warning">
                Выбранные записи относятся к разным исходным анализам. Сервер
                проверяет точные UUID и SHA-256; этот выбор может быть отклонён
                с 409.
              </p>
            )}
          {client.permits("verify") && (
            <button
              className="button secondary"
              disabled={busy || !!attempt || !selected.deterministic}
              onClick={() => void operation(save)}
            >
              Сохранить совместный отчёт
            </button>
          )}
          {attempt && (
            <div aria-label="Запрос совместного отчёта">
              <p className="mono">ID отчёта: {attempt.report_id}</p>
              {uncertain && (
                <p className="notice warning">
                  {rejected
                    ? "Сервер отклонил запрос совместного отчёта. Проверьте наличие записи этого ID."
                    : "Итог сохранения совместного отчёта не подтверждён."}{" "}
                  Выбор заморожен; повторной отправки POST нет.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void operation(reconcile)}
              >
                Прочитать отчёт по ID запроса
              </button>
              {rejected && notStored && (
                <>
                  <p>
                    После явного отказа чтение вернуло 404. Можно явно сбросить
                    отклонённый запрос и выбрать результаты заново.
                  </p>
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={reset}
                  >
                    Сбросить отклонённый запрос отчёта
                  </button>
                </>
              )}
              {!uncertain && view?.report_id === attempt.report_id && (
                <button
                  className="button secondary"
                  disabled={busy}
                  onClick={reset}
                >
                  Подготовить новый совместный отчёт
                </button>
              )}
            </div>
          )}
          <ul aria-label="История совместных отчётов">
            {history.map((row) => (
              <li key={row.report_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => void operation(() => detail(row))}
                >
                  Открыть совместный отчёт {shortId(row.report_id)} ·{" "}
                  {date(row.created_at)} · выбранных видов:{" "}
                  {row.selected_kinds.length}
                </button>
              </li>
            ))}
          </ul>
          {history.length === 0 && (
            <p>Совместных отчётов на этой странице нет.</p>
          )}
          <p className="hint">
            Отчётов на странице: {history.length}; смещение: {historyOffset}.
          </p>
          {(historyOffset > 0 || history.length === 20) && (
            <div className="pager">
              <button
                className="button secondary compact"
                disabled={busy || historyOffset === 0}
                onClick={() =>
                  void operation(() => loadHistory(historyOffset - 20))
                }
              >
                Предыдущие совместные отчёты
              </button>
              <button
                className="button secondary compact"
                disabled={busy || history.length < 20 || historyOffset >= 10000}
                onClick={() =>
                  void operation(() => loadHistory(historyOffset + 20))
                }
              >
                Следующие совместные отчёты
              </button>
            </div>
          )}
          {view && (
            <>
              <EvidenceView view={view} />
              <SourceRiskAssessmentPanel
                key={`risk-${view.report_id}-${view.review_sha256}`}
                client={client}
                draft={draft}
                report={view}
                busy={outerBusy || working || decisionGuard}
                onError={onError}
                onGuardChange={setRiskGuard}
              />
              <SourceEvidenceDecisionPanel
                key={`${view.report_id}-${view.review_sha256}`}
                client={client}
                draft={draft}
                report={view}
                busy={outerBusy || working || riskGuard}
                onError={onError}
                onGuardChange={setDecisionGuard}
              />
            </>
          )}
        </>
      )}
    </section>
  );
}

function EvidenceView({ view }: { view: SourceEvidenceReport }) {
  const deterministic = view.deterministic;
  return (
    <div aria-label="Результат совместного отчёта">
      <h4>Совместный отчёт сохранён — требуется рассмотрение</h4>
      <p>
        Статус: needs_review. Общая формальная квалификация: not_proven.
        Качество доказано: нет. Калибровка: нет. Объединение риска в этой
        записи: нет; экспериментальный приоритет сохраняется отдельно.
        Согласовано: нет. Применено: нет.
      </p>
      <p className="mono">
        До: {view.before.configuration_id} · source SHA-256:{" "}
        {view.before.source_sha256} · canonical SHA-256:{" "}
        {view.before.canonical_sha256}
        <br />
        После: {view.after.configuration_id} · source SHA-256:{" "}
        {view.after.source_sha256} · canonical SHA-256:{" "}
        {view.after.canonical_sha256}
        <br />
        Исходный анализ: {view.before_analysis_id} · SHA-256:{" "}
        {view.before_analysis_sha256}
      </p>
      <h4>Исходные политики и сравнения</h4>
      <p>
        Каталог: {deterministic.policy_catalog_version}. Версия сравнения:{" "}
        {deterministic.comparison_version}. Peers: {deterministic.peer_count}.
      </p>
      <table aria-label="Количество замечаний совместного отчёта">
        <thead>
          <tr>
            <th>Проверка</th>
            <th>До</th>
            <th>После</th>
          </tr>
        </thead>
        <tbody>
          {(
            [
              ["policy", "Политики"],
              ["reference", "Эталон"],
              ["peer", "Peers"],
            ] as const
          ).map(([field, title]) => (
            <tr key={field}>
              <th>{title}</th>
              <td>{missing(deterministic.before[field])}</td>
              <td>{missing(deterministic.after[field])}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        Новых замечаний политик: {deterministic.policy_changes.introduced};
        исчезнувших: {deterministic.policy_changes.resolved}; сохранившихся:{" "}
        {deterministic.policy_changes.persistent}. Исчезновение замечания не
        доказывает исправление или безопасность сети.
      </p>
      {deterministic.reference && (
        <p className="mono">
          Эталон: {deterministic.reference.configuration_id} · canonical
          SHA-256: {deterministic.reference.canonical_sha256}
        </p>
      )}
      {deterministic.peer_profile_sha256 && (
        <p className="mono">
          Профиль peers SHA-256: {deterministic.peer_profile_sha256}
        </p>
      )}
      <h4>Исходный Forest</h4>
      {view.forest ? (
        <>
          <p className="mono">
            Модель: {view.forest.model_id} · artifact SHA-256:{" "}
            {view.forest.artifact_sha256}
          </p>
          <p>
            {view.forest.model_version} · {view.forest.feature_schema_version} ·{" "}
            {view.forest.library} {view.forest.library_version}. Порог offset_:{" "}
            {view.forest.decision_offset}. Scores экспериментальны, не
            вероятность или severity.
          </p>
          <table aria-label="Forest в совместном отчёте">
            <thead>
              <tr>
                <th>Снимок</th>
                <th>score_samples</th>
                <th>decision_function</th>
                <th>prediction</th>
              </tr>
            </thead>
            <tbody>
              {(["before", "after"] as const).map((side) => (
                <tr key={side}>
                  <th>{side === "before" ? "До" : "После"}</th>
                  <td>
                    {String(view.forest!.scores[`${side}_score_samples`])}
                  </td>
                  <td>
                    {String(view.forest!.scores[`${side}_decision_function`])}
                  </td>
                  <td>{view.forest!.scores[`${side}_prediction`]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : (
        <p>Не выбран. Отсутствующий результат не заменён нулём.</p>
      )}
      <h4>Нейросетевая модель</h4>
      {view.neural ? (
        <>
          <p className="mono">
            Model SHA-256: {view.neural.model_sha256}
            <br />
            Model card SHA-256: {view.neural.model_card_sha256}
          </p>
          <p>
            {view.neural.model_kind} · {view.neural.training_format} · runtime:{" "}
            {view.neural.runtime_torch_version}. Классы:{" "}
            {view.neural.classes.join(", ")}. Target semantics:{" "}
            {view.neural.target_semantics}. Предобучение:{" "}
            {view.neural.external_pretraining_exposure}.
          </p>
          <p>
            Головы:{" "}
            {Object.entries(view.neural.enabled_heads)
              .map(
                ([key, enabled]) =>
                  `${key}: ${enabled ? "включена" : "выключена"}`,
              )
              .join("; ")}
            . Числа экспериментальны; они не повышают формальную квалификацию.
          </p>
          <table aria-label="Нейросеть в совместном отчёте">
            <thead>
              <tr>
                <th>Снимок</th>
                <th>Anomaly score</th>
                <th>Строк оценено / всего</th>
                <th>Category scores</th>
                <th>Severity scores</th>
              </tr>
            </thead>
            <tbody>
              {(["before", "after"] as const).map((side) => {
                const output = view.neural![side];
                return (
                  <tr key={side}>
                    <th>{side === "before" ? "До" : "После"}</th>
                    <td>{missing(output.anomaly_score)}</td>
                    <td>
                      {output.scored_line_count} / {output.total_lines}
                    </td>
                    <td>
                      {output.category_scores
                        ? Object.entries(output.category_scores)
                            .map(([key, value]) => `${key}: ${value}`)
                            .join("; ")
                        : "недоступно"}
                    </td>
                    <td>
                      {output.severity_scores
                        ? Object.entries(output.severity_scores)
                            .map(([key, value]) => `${key}: ${value}`)
                            .join("; ")
                        : "недоступно"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      ) : (
        <p>Не выбрана. Отсутствующий результат не заменён нулём.</p>
      )}
      <h4>Сетевая проверка</h4>
      {view.network ? (
        <>
          <p>
            {sourceNetworkStatusNames[view.network.result.status]} (
            {view.network.result.status}). Причина: {view.network.result.reason}
            .
          </p>
          <p>
            Область IPv4: {view.network.result.scope.start_node} →{" "}
            {view.network.result.scope.destination}; устройств:{" "}
            {view.network.network_device_count}. Доступ управления, SSH/AAA,
            IPv6 и вся сеть этим не доказаны.
          </p>
          <p>
            Строк различий: {missing(view.network.result.difference_count)};
            строк ответа до:{" "}
            {missing(view.network.result.before_reachable_count)}; после:{" "}
            {missing(view.network.result.after_reachable_count)}. Очистка:{" "}
            {view.network.result.cleanup_complete === null
              ? "не подтверждена"
              : view.network.result.cleanup_complete
                ? "подтверждена"
                : "не выполнена"}
            .
          </p>
          <p>
            Engine: {view.network.result.engine_version ?? "недоступно"}. SDK:{" "}
            {"sdk_observation" in view.network
              ? `${view.network.sdk_version ?? "недоступно"} · ${sdkObservationNames[view.network.sdk_observation]} (${view.network.sdk_observation})`
              : "недоступно — исходная запись не сохраняла версию"}
            . Собственный ML-статус сетевой записи: {view.network.ml_status};
            отдельная нейросетевая запись его не меняет.
          </p>
          {"sdk_observation" in view.network && (
            <p className="hint">
              SDK — сохранённые метаданные дистрибутива рабочего процесса. Они
              не удостоверяют исполняемый файл, качество или формальное
              одобрение.
            </p>
          )}
          {"reachability_impact" in view.network ? (
            <ReachabilityImpactView impact={view.network.reachability_impact} />
          ) : (
            <p>Направление изменения в исходной записи не сохранялось.</p>
          )}
          {"ingress_scope" in view.network && (
            <IngressScopeView scope={view.network.ingress_scope} />
          )}
          <ul>
            {view.network.result.limitations.map((value, index) => (
              <li key={index}>{value}</li>
            ))}
          </ul>
        </>
      ) : (
        <p>Не выбрана. Сетевой результат отсутствует.</p>
      )}
      <h4>Ограничения</h4>
      <ul>
        {view.validation_blockers.map((value) => (
          <li key={value}>{blockerNames[value] ?? value}</li>
        ))}
      </ul>
      <ul aria-label="Привязки выбранных записей">
        {kinds.map((kind) => {
          const row = view[kind];
          return (
            row && (
              <li key={kind} className="mono">
                {names[kind]}: {row.record_id} · SHA-256: {row.review_sha256} ·
                завершено: {date(row.completed_at)}
              </li>
            )
          );
        })}
      </ul>
      <p className="mono">SHA-256 совместного отчёта: {view.review_sha256}</p>
      <p className="hint">
        Хеш связывает неизменяемую запись и выбранные результаты; он не
        удостоверяет личность инженера или истинность наблюдений. Сохранённая
        история не пересчитывается.
      </p>
      <details>
        <summary>Полная сохранённая запись совместного отчёта</summary>
        <pre className="json-view">{JSON.stringify(view, null, 2)}</pre>
      </details>
    </div>
  );
}
