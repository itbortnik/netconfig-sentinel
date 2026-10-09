import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type {
  AnalysisResult,
  ConfigurationSnapshot,
  ConfigurationSummary,
  Finding,
} from "./contracts";
import { stableJson } from "./contracts";
import {
  generateModelPatchSchema,
  generationMatches,
  proposalMatches,
} from "./modelPatches";
import type {
  GenerateModelPatch,
  ModelPatchCapabilities,
  ModelPatchProposal,
} from "./modelPatches";
import {
  decideModelPatchSchema,
  decisionMatches,
  reviewMatches,
  scopeSchema,
  verifyModelPatchSchema,
} from "./modelReviews";
import type {
  DecideModelPatch,
  SavedModelDecision,
  SavedModelReview,
  VerifyModelPatch,
} from "./modelReviews";
import { ModelReviewView, limitationLabel } from "./ModelReviewView";
import { date } from "./format";

type Intent =
  | { kind: "generation"; request: GenerateModelPatch }
  | {
      kind: "verification";
      patch: ModelPatchProposal;
      request: VerifyModelPatch;
    }
  | {
      kind: "decision";
      patch: ModelPatchProposal;
      run: SavedModelReview;
      request: DecideModelPatch;
    };
const unknown = (problem: unknown) =>
  !(problem instanceof ApiError) ||
  problem.status === 0 ||
  problem.status >= 500;
const bindingError = () =>
  new ApiError(
    0,
    "Запись не соответствует выбранной находке, кандидату или проверке.",
  );

export function ModelPatchPanel({
  analysis,
  finding,
  snapshot,
  client,
  busy,
  onError,
}: {
  analysis: AnalysisResult;
  finding: Finding;
  snapshot: ConfigurationSnapshot | null;
  client: ApiClient;
  busy: boolean;
  onError: (problem: unknown) => void;
}) {
  const [open, setOpen] = useState(false),
    [loading, setLoading] = useState(false);
  const [capabilities, setCapabilities] =
    useState<ModelPatchCapabilities | null>(null);
  const [history, setHistory] = useState<ModelPatchProposal[]>([]),
    [historyOffset, setHistoryOffset] = useState(0),
    [historyCount, setHistoryCount] = useState(0),
    [historyReady, setHistoryReady] = useState(false);
  const [proposal, setProposal] = useState<ModelPatchProposal | null>(null),
    [run, setRun] = useState<SavedModelReview | null>(null);
  const [reviews, setReviews] = useState<SavedModelReview[]>([]),
    [reviewOffset, setReviewOffset] = useState(0);
  const [decisions, setDecisions] = useState<SavedModelDecision[]>([]),
    [decisionOffset, setDecisionOffset] = useState(0);
  const [baselines, setBaselines] = useState<ConfigurationSummary[]>([]),
    [baselineOffset, setBaselineOffset] = useState(0),
    [baselineCount, setBaselineCount] = useState(0),
    [baseline, setBaseline] = useState<ConfigurationSummary | null>(null);
  const [networkPool, setNetworkPool] = useState<ConfigurationSummary[]>([]),
    [networkOffset, setNetworkOffset] = useState(0),
    [networkCount, setNetworkCount] = useState(0),
    [network, setNetwork] = useState<ConfigurationSummary[]>([]);
  const [allowGeneration, setAllowGeneration] = useState(false),
    [allowEngine, setAllowEngine] = useState(false),
    [allowML, setAllowML] = useState(false);
  const [startNode, setStartNode] = useState(
      snapshot?.canonical.device.hostname ?? "",
    ),
    [destination, setDestination] = useState("");
  const [verdict, setVerdict] = useState<DecideModelPatch["verdict"]>(
      "needs_more_information",
    ),
    [comment, setComment] = useState("");
  const [acknowledged, setAcknowledged] = useState<string[]>([]),
    [syntax, setSyntax] = useState(false),
    [access, setAccess] = useState(false),
    [rollback, setRollback] = useState(false);
  const [uncertain, setUncertain] = useState(false),
    [notice, setNotice] = useState("");
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<Intent | null>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const disabled = busy || loading,
    locked = disabled || uncertain;
  const supported =
    finding.detector === "policy_engine" &&
    ["management.telnet_enabled", "management.ssh_version_1"].includes(
      finding.category,
    );
  const canGenerate =
    client.permits("draft") && client.permits("model_explanation");
  const selected = analysis.explanations.find(
    (row) => row.finding_id === finding.finding_id,
  );
  function resetDecision() {
    setVerdict("needs_more_information");
    setComment("");
    setAcknowledged([]);
    setSyntax(false);
    setAccess(false);
    setRollback(false);
  }
  function boundRun(value: SavedModelReview, patch: ModelPatchProposal) {
    const original = analysis.statistical,
      repeated = value.statistical_recheck;
    return (
      reviewMatches(value, patch) &&
      (!value.report || value.report.selected_category === finding.category) &&
      (value.execution_status !== "completed" || !!repeated === !!original) &&
      (!repeated ||
        (!!original &&
          repeated.model_id === original.model.model_id &&
          repeated.artifact_sha256 === original.model.artifact_sha256 &&
          repeated.before_score_samples === original.score_samples &&
          repeated.before_decision_function === original.decision_function &&
          repeated.before_prediction === original.prediction))
    );
  }
  function showRun(value: SavedModelReview, patch: ModelPatchProposal) {
    if (!boundRun(value, patch)) throw bindingError();
    setRun(value);
    resetDecision();
  }
  function showProposal(value: ModelPatchProposal) {
    if (!proposalMatches(value, analysis, finding)) throw bindingError();
    setProposal(value);
    setRun(null);
    setReviews([]);
    setDecisions([]);
    setReviewOffset(0);
    setDecisionOffset(0);
    setNetwork([]);
    setNetworkPool([]);
    setAllowEngine(false);
    setAllowML(false);
    resetDecision();
  }
  async function action(task: () => Promise<void>) {
    if (busy || lock.current) return;
    lock.current = true;
    setLoading(true);
    setNotice("");
    try {
      await task();
    } catch (problem: unknown) {
      if (alive.current) onError(problem);
    } finally {
      lock.current = false;
      if (alive.current) setLoading(false);
    }
  }
  async function loadHistory(offset = historyOffset) {
    setHistoryReady(false);
    const [caps, rows] = await Promise.all([
      client.modelPatchCapabilities(),
      client.modelPatches(analysis.analysis_id, offset),
    ]);
    if (!alive.current) return;
    if (
      rows.some((row) => {
        const origin = analysis.findings.find(
          (item) => item.finding_id === row.finding_id,
        );
        return !origin || !proposalMatches(row, analysis, origin);
      })
    )
      throw bindingError();
    setCapabilities(caps);
    setHistory(rows.filter((row) => row.finding_id === finding.finding_id));
    setHistoryOffset(offset);
    setHistoryCount(rows.length);
    setHistoryReady(true);
  }
  async function loadBaselines(offset = baselineOffset) {
    const rows = await client.configurations(offset, analysis.device_id);
    if (!alive.current) return;
    if (
      rows.some((row) => row.device_id !== analysis.device_id) ||
      new Set(rows.map((row) => row.configuration_id)).size !== rows.length
    )
      throw bindingError();
    const cutoff = snapshot?.created_at;
    setBaselines(
      rows.filter(
        (row) =>
          row.configuration_id !== analysis.configuration_id &&
          cutoff &&
          Date.parse(row.created_at) <= Date.parse(cutoff),
      ),
    );
    setBaselineCount(rows.length);
    setBaselineOffset(offset);
  }
  async function loadNetwork(offset = networkOffset) {
    if (!proposal) return;
    const rows = await client.configurations(offset);
    if (!alive.current) return;
    if (new Set(rows.map((row) => row.configuration_id)).size !== rows.length)
      throw bindingError();
    setNetworkPool(
      rows.filter(
        (row) =>
          row.device_id !== proposal.source.device_id &&
          Date.parse(row.created_at) <= Date.parse(proposal.created_at),
      ),
    );
    setNetworkCount(rows.length);
    setNetworkOffset(offset);
  }
  async function loadReviews(offset = reviewOffset) {
    if (!proposal) return;
    const rows = await client.modelReviews(proposal.patch_id, offset);
    if (!alive.current) return;
    if (rows.some((row) => !boundRun(row, proposal))) throw bindingError();
    setReviews(rows);
    setReviewOffset(offset);
  }
  async function loadDecisions(offset = decisionOffset) {
    if (!proposal) return;
    const rows = await client.modelDecisions(proposal.patch_id, offset);
    const keys = [...new Set(rows.map((row) => row.request.verification_id))];
    const bound = await Promise.all(
      keys.map((key) => client.modelReview(proposal.patch_id, key)),
    );
    if (!alive.current) return;
    if (
      bound.some((row) => !boundRun(row, proposal)) ||
      rows.some((row) => {
        const check = bound.find(
          (item) => item.verification_id === row.request.verification_id,
        );
        return !check || !decisionMatches(row, check);
      })
    )
      throw bindingError();
    setDecisions(rows);
    setDecisionOffset(offset);
  }
  async function write(next: Intent) {
    if (intent.current || uncertain) return;
    intent.current = next;
    setUncertain(true);
    setAllowGeneration(false);
    setAllowEngine(false);
    setAllowML(false);
    try {
      if (next.kind === "generation") {
        const value = await client.generateModelPatch(next.request);
        if (!alive.current) return;
        showProposal(value);
        if (value.status === "generating") {
          setNotice(
            "Генерация ещё не завершена. Читайте сохранённую попытку без повторной отправки.",
          );
          return;
        }
      } else if (next.kind === "verification") {
        const value = await client.verifyModelPatch(
          next.patch.patch_id,
          next.request,
        );
        if (!alive.current) return;
        showRun(value, next.patch);
        if (value.execution_status === "running") {
          setNotice(
            "Исполнение ещё не завершено. Новый запуск заблокирован до чтения результата.",
          );
          return;
        }
      } else {
        const value = await client.decideModelPatch(
          next.patch.patch_id,
          next.request,
        );
        if (!alive.current) return;
        if (!decisionMatches(value, next.run)) throw bindingError();
        setDecisions([value]);
        setDecisionOffset(0);
        resetDecision();
        setNotice(
          "Решение сохранено неизменяемой записью. На оборудование ничего не отправлено.",
        );
      }
      intent.current = null;
      setUncertain(false);
    } catch (problem: unknown) {
      if (!alive.current) return;
      if (!unknown(problem)) {
        intent.current = null;
        setUncertain(false);
      } else
        setNotice(
          "Итог отправки неизвестен. Сначала прочитайте попытку по тому же идентификатору; автоматического повтора нет.",
        );
      throw problem;
    }
  }
  async function reconcile() {
    const current = intent.current;
    if (!current) return;
    try {
      if (current.kind === "generation") {
        const row = await client.modelPatch(current.request.patch_id);
        if (!alive.current) return;
        if (!generationMatches(row, current.request)) throw bindingError();
        showProposal(row);
        if (row.status === "generating") {
          setNotice(
            "Сохранено намерение генерации; завершённого ответа пока нет.",
          );
          return;
        }
      } else if (current.kind === "verification") {
        const row = await client.modelReview(
          current.patch.patch_id,
          current.request.verification_id,
        );
        if (!alive.current) return;
        if (stableJson(row.request) !== stableJson(current.request))
          throw bindingError();
        showRun(row, current.patch);
        if (row.execution_status === "running") {
          setNotice(
            "Сохранено намерение проверки; завершённого отчёта пока нет.",
          );
          return;
        }
      } else {
        const row = await client.modelDecision(
          current.patch.patch_id,
          current.request.decision_id,
        );
        if (!alive.current) return;
        if (
          stableJson(row.request) !== stableJson(current.request) ||
          !decisionMatches(row, current.run)
        )
          throw bindingError();
        setDecisions([row]);
        resetDecision();
      }
      intent.current = null;
      setUncertain(false);
      setNotice("Сохранённый итог прочитан без повторного запуска.");
    } catch (problem: unknown) {
      if (
        alive.current &&
        problem instanceof ApiError &&
        problem.status === 404
      )
        setNotice(
          "Запись пока не найдена. Это не подтверждение отсутствия исполнения; повторная отправка заблокирована.",
        );
      throw problem;
    }
  }
  function generate() {
    if (
      !historyReady ||
      !selected ||
      !supported ||
      !allowGeneration ||
      !canGenerate ||
      capabilities?.generation !== "configured" ||
      locked
    )
      return;
    const request = generateModelPatchSchema.parse({
      patch_id: crypto.randomUUID(),
      analysis_id: analysis.analysis_id,
      finding_id: finding.finding_id,
      finding_sha256: selected.finding_sha256,
      source_sha256: analysis.source_sha256,
      baseline_configuration_id: baseline?.configuration_id ?? null,
      baseline_source_sha256: baseline?.source_sha256 ?? null,
      allow_local_model_context: true,
    });
    return write({ kind: "generation", request });
  }
  function verify() {
    if (
      !proposal ||
      proposal.status !== "draft" ||
      !client.permits("verify") ||
      locked ||
      (allowEngine && capabilities?.network_engine !== "configured") ||
      (allowML && capabilities?.transformer !== "configured")
    )
      return;
    const request = verifyModelPatchSchema.parse({
      verification_id: crypto.randomUUID(),
      proposal_sha256: proposal.proposal_sha256,
      network: [proposal.source, ...network].map((row) => ({
        configuration_id: row.configuration_id,
        source_sha256: row.source_sha256,
      })),
      scope: { start_node: startNode, destination },
      mode: allowEngine ? "batfish" : "local_preflight",
      allow_local_engine_upload: allowEngine,
      transformer_sha256: allowML ? capabilities?.transformer_sha256 : null,
      allow_local_model_context: allowML,
    });
    return write({ kind: "verification", patch: proposal, request });
  }
  const decisionReady =
    !!run &&
    run.execution_status !== "running" &&
    !!comment.trim() &&
    (verdict !== "approved" ||
      (!run.approval_blockers.length &&
        syntax &&
        access &&
        rollback &&
        acknowledged.length === run.report?.missing_checks.length));
  function decide() {
    if (
      !proposal ||
      !run ||
      !decisionReady ||
      !client.permits("feedback") ||
      locked
    )
      return;
    const request = decideModelPatchSchema.parse({
      decision_id: crypto.randomUUID(),
      verification_id: run.verification_id,
      proposal_sha256: run.proposal_sha256,
      review_sha256: run.review_sha256,
      verdict,
      comment,
      acknowledged_limitations: acknowledged,
      device_syntax_checked: syntax,
      management_access_checked: access,
      rollback_ready: rollback,
    });
    return write({ kind: "decision", patch: proposal, run, request });
  }
  const pending = intent.current,
    pendingId =
      pending?.kind === "generation"
        ? pending.request.patch_id
        : pending?.kind === "verification"
          ? pending.request.verification_id
          : pending?.request.decision_id;
  const scopeReady = scopeSchema.safeParse({
    start_node: startNode,
    destination,
  }).success;
  return (
    <section className="knowledge-panel" aria-label="Модельное исправление">
      <h4>Модельное исправление и проверка</h4>
      <p className="hint">
        Отдельный черновик для Telnet / SSHv1. Генерация не меняет анализ, риск
        или оборудование. Нужен точный исходник, ранее сохранённый с
        разрешением; восстановление из нормализованных объектов не выполняется.
      </p>
      <button
        className="button secondary"
        disabled={disabled}
        onClick={() => {
          setOpen(true);
          void action(() => loadHistory(0));
        }}
      >
        Открыть модельные исправления
      </button>
      {open && (
        <>
          <p className="hint">
            {capabilities?.generation === "configured"
              ? "Генерация настроена; готовность проверяется отдельным запросом."
              : "Генерация выключена или настройки ещё не получены."}{" "}
            История доступна без запуска моделей.
          </p>
          {notice && (
            <p role="status" className="notice warning">
              {notice}
            </p>
          )}
          {loading && (
            <p role="status">Получение или сохранение выбранной записи…</p>
          )}
          {uncertain && (
            <div className="notice warning">
              <p>
                Неопределённый или незавершённый итог. Новый запуск
                заблокирован.
              </p>
              <p className="mono">Идентификатор: {pendingId}</p>
              <button
                className="button secondary"
                disabled={disabled}
                onClick={() => void action(reconcile)}
              >
                Прочитать сохранённую попытку
              </button>
              <p className="hint">
                После отключения сессии найдите эту запись в истории.
                Идентификатор и согласия не сохраняются в браузере.
              </p>
            </div>
          )}
          <h5>История черновиков выбранной находки</h5>
          <button
            className="button secondary"
            disabled={disabled}
            onClick={() => void action(() => loadHistory())}
          >
            Обновить историю черновиков
          </button>
          <ul>
            {history.map((row) => (
              <li key={row.patch_id}>
                <button
                  className="button secondary"
                  disabled={locked}
                  onClick={() =>
                    void action(async () => {
                      const value = await client.modelPatch(row.patch_id);
                      if (!alive.current) return;
                      if (
                        row.status !== "generating" &&
                        stableJson(value) !== stableJson(row)
                      )
                        throw bindingError();
                      if (alive.current) showProposal(value);
                    })
                  }
                >
                  {row.status} · {date(row.created_at)} · {row.patch_id}
                </button>
              </li>
            ))}
          </ul>
          {historyReady && !history.length && (
            <p className="hint">
              На этой странице нет черновиков выбранной находки.
            </p>
          )}
          <div className="split">
            <button
              className="button secondary"
              disabled={disabled || historyOffset === 0}
              onClick={() => void action(() => loadHistory(historyOffset - 20))}
            >
              Предыдущие черновики
            </button>
            <button
              className="button secondary"
              disabled={disabled || historyCount < 20}
              onClick={() => void action(() => loadHistory(historyOffset + 20))}
            >
              Следующие черновики
            </button>
          </div>
          {canGenerate && supported && (
            <fieldset disabled={locked}>
              <legend>Создать непроверенный черновик</legend>
              <button
                className="button secondary"
                onClick={() => void action(() => loadBaselines(0))}
              >
                Показать предыдущие снимки устройства
              </button>
              <p className="hint">
                Эталон необязателен, должен быть старше исходника и относится к
                тому же устройству. Его утверждение не предполагается.
              </p>
              <label htmlFor={`model-baseline-${finding.finding_id}`}>
                Эталон для генерации
              </label>
              <select
                id={`model-baseline-${finding.finding_id}`}
                value={baseline?.configuration_id ?? ""}
                onChange={(event) => {
                  setBaseline(
                    baselines.find(
                      (row) => row.configuration_id === event.target.value,
                    ) ?? null,
                  );
                  setAllowGeneration(false);
                }}
              >
                <option value="">Без эталона</option>
                {[
                  ...(baseline &&
                  !baselines.some(
                    (row) => row.configuration_id === baseline.configuration_id,
                  )
                    ? [baseline]
                    : []),
                  ...baselines,
                ].map((row) => (
                  <option
                    key={row.configuration_id}
                    value={row.configuration_id}
                  >
                    {date(row.created_at)} · {row.configuration_id}
                  </option>
                ))}
              </select>
              <div className="split">
                <button
                  className="button secondary"
                  disabled={baselineOffset === 0}
                  onClick={() =>
                    void action(() => loadBaselines(baselineOffset - 20))
                  }
                >
                  Предыдущие эталоны
                </button>
                <button
                  className="button secondary"
                  disabled={baselineCount < 20}
                  onClick={() =>
                    void action(() => loadBaselines(baselineOffset + 20))
                  }
                >
                  Следующие эталоны
                </button>
              </div>
              <label>
                <input
                  type="checkbox"
                  checked={allowGeneration}
                  disabled={
                    capabilities?.generation !== "configured" || !historyReady
                  }
                  onChange={(event) => setAllowGeneration(event.target.checked)}
                />{" "}
                Разрешаю контекст этого исправления локальной модели
              </label>
              <p className="hint">
                Передаются минимальные псевдонимизированные факты, строки
                разрешённого блока и документы. Номера строк, числа и hashes
                могут быть конфиденциальны. Полный файл не передаётся.
              </p>
              <button
                className="button"
                disabled={
                  !allowGeneration ||
                  !historyReady ||
                  capabilities?.generation !== "configured"
                }
                onClick={() =>
                  void action(async () => {
                    await generate();
                  })
                }
              >
                Создать модельное исправление
              </button>
            </fieldset>
          )}
          {!supported && (
            <p className="hint">
              Для этой категории создание модельного патча пока не
              поддерживается.
            </p>
          )}
          {!canGenerate && (
            <p className="hint">
              Роль сессии разрешает только чтение этой истории, без генерации
              исправлений.
            </p>
          )}
          {proposal && (
            <section aria-label="Сохранённый модельный черновик">
              <h5>Черновик: {proposal.status}</h5>
              <p className="mono">{proposal.patch_id}</p>
              <p className="hash">Исходник: {proposal.source_sha256}</p>
              <p className="hash">
                Кандидат: {proposal.candidate_sha256 ?? "Не создан"}
              </p>
              <p className="hash">
                Привязка предложения: {proposal.proposal_sha256}
              </p>
              <p className="notice warning">
                Текст модели недоверенный. Формальная проверка и ML не
                выполнялись при генерации. Утверждение и применение отсутствуют.
              </p>
              {proposal.answer && (
                <>
                  <p>{proposal.answer.summary}</p>
                  <pre>{proposal.answer.technical_explanation}</pre>
                  <h5>Предлагаемые изменения строк — не команды для запуска</h5>
                  {proposal.answer.patch_draft ? (
                    <ul>
                      {proposal.answer.patch_draft.edits.map((row) => (
                        <li key={row.source_line}>
                          Строка {row.source_line}:{" "}
                          <code>{row.replacement ?? "удалить строку"}</code>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>
                      Модель отказалась от создания патча; кандидат не
                      подставлен.
                    </p>
                  )}
                  <details>
                    <summary>Рекомендация, гипотезы и источники</summary>
                    <pre>{proposal.answer.recommendation}</pre>
                    <h5>Возможное влияние — гипотезы модели</h5>
                    <ul>
                      {proposal.answer.possible_impact.map((value, index) => (
                        <li key={index}>{value}</li>
                      ))}
                    </ul>
                    <h5>Допущения и недостающие сведения</h5>
                    <ul>
                      {[
                        ...proposal.answer.assumptions,
                        ...proposal.answer.missing_information,
                      ].map((value, index) => (
                        <li key={index}>{value}</li>
                      ))}
                    </ul>
                    <h5>Ссылки модели</h5>
                    <ul>
                      {proposal.answer.citations.map((value) => (
                        <li key={value}>{value}</li>
                      ))}
                    </ul>
                  </details>
                </>
              )}
              {proposal.status === "draft" && (
                <>
                  {client.permits("verify") && (
                    <fieldset disabled={locked}>
                      <legend>Проверить точный кандидат</legend>
                      <p className="hint">
                        Исходный снимок обязателен. Остальные устройства
                        выбираются явно, не более одного снимка на устройство и
                        не позднее генерации. У всех выбранных файлов должен
                        быть ранее сохранён точный исходник.
                      </p>
                      <p className="mono">
                        Обязательный снимок: {proposal.source.configuration_id}
                      </p>
                      <button
                        className="button secondary"
                        onClick={() => void action(() => loadNetwork(0))}
                      >
                        Показать снимки других устройств
                      </button>
                      <ul>
                        {networkPool.map((row) => {
                          const conflict = network.some(
                              (item) =>
                                item.device_id === row.device_id &&
                                item.configuration_id !== row.configuration_id,
                            ),
                            checked = network.some(
                              (item) =>
                                item.configuration_id === row.configuration_id,
                            );
                          return (
                            <li key={row.configuration_id}>
                              <label>
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  disabled={
                                    !checked &&
                                    (conflict || network.length >= 31)
                                  }
                                  onChange={(event) => {
                                    setNetwork((items) =>
                                      event.target.checked
                                        ? [...items, row]
                                        : items.filter(
                                            (item) =>
                                              item.configuration_id !==
                                              row.configuration_id,
                                          ),
                                    );
                                    setAllowEngine(false);
                                    setAllowML(false);
                                  }}
                                />
                                {row.hostname ?? "Без hostname"} ·{" "}
                                {row.configuration_id}
                              </label>
                            </li>
                          );
                        })}
                      </ul>
                      <div className="split">
                        <button
                          className="button secondary"
                          disabled={networkOffset === 0}
                          onClick={() =>
                            void action(() => loadNetwork(networkOffset - 20))
                          }
                        >
                          Предыдущие снимки сети
                        </button>
                        <button
                          className="button secondary"
                          disabled={networkCount < 20}
                          onClick={() =>
                            void action(() => loadNetwork(networkOffset + 20))
                          }
                        >
                          Следующие снимки сети
                        </button>
                      </div>
                      <p>Выбрано устройств: {network.length + 1}.</p>
                      {network.length > 0 && (
                        <ul aria-label="Выбранные снимки сети">
                          {network.map((row) => (
                            <li key={row.configuration_id}>
                              <span className="mono">
                                {row.configuration_id}
                              </span>
                              <button
                                className="button secondary"
                                onClick={() => {
                                  setNetwork((items) =>
                                    items.filter(
                                      (item) =>
                                        item.configuration_id !==
                                        row.configuration_id,
                                    ),
                                  );
                                  setAllowEngine(false);
                                  setAllowML(false);
                                }}
                              >
                                Убрать снимок
                              </button>
                            </li>
                          ))}
                        </ul>
                      )}
                      <label>
                        Начальный узел области
                        <input
                          maxLength={128}
                          value={startNode}
                          onChange={(event) => {
                            setStartNode(event.target.value);
                            setAllowEngine(false);
                            setAllowML(false);
                          }}
                        />
                      </label>
                      <label>
                        IPv4-сеть назначения
                        <input
                          placeholder="192.0.2.0/24"
                          maxLength={18}
                          value={destination}
                          onChange={(event) => {
                            setDestination(event.target.value);
                            setAllowEngine(false);
                            setAllowML(false);
                          }}
                        />
                      </label>
                      <label>
                        <input
                          type="checkbox"
                          disabled={
                            capabilities?.network_engine !== "configured"
                          }
                          checked={allowEngine}
                          onChange={(event) =>
                            setAllowEngine(event.target.checked)
                          }
                        />{" "}
                        Разрешаю исходники выбранной сети локальному Batfish
                      </label>
                      <p className="hint">
                        {capabilities?.network_engine === "configured"
                          ? "Движок настроен, результат ещё не получен."
                          : "Batfish выключен оператором."}{" "}
                        При выборе передаются полные конфиденциальные исходники
                        и кандидат.
                      </p>
                      <label>
                        <input
                          type="checkbox"
                          disabled={capabilities?.transformer !== "configured"}
                          checked={allowML}
                          onChange={(event) => setAllowML(event.target.checked)}
                        />{" "}
                        Разрешаю повторную оценку кандидата локальной ML-моделью
                      </label>
                      <p className="hint">
                        {capabilities?.transformer === "configured"
                          ? `Закреплённая модель: ${capabilities.transformer_sha256}.`
                          : "Transformer выключен оператором."}{" "}
                        До инференса тексты псевдонимизируются; оценка не
                        подтверждает качество.
                      </p>
                      <button
                        className="button"
                        disabled={!scopeReady}
                        onClick={() =>
                          void action(async () => {
                            await verify();
                          })
                        }
                      >
                        Сохранить проверку кандидата
                      </button>
                    </fieldset>
                  )}
                  <button
                    className="button secondary"
                    disabled={disabled}
                    onClick={() => void action(() => loadReviews(0))}
                  >
                    Обновить историю проверок кандидата
                  </button>
                  <ul>
                    {reviews.map((row) => (
                      <li key={row.verification_id}>
                        <button
                          className="button secondary"
                          disabled={locked}
                          onClick={() =>
                            void action(async () => {
                              const value = await client.modelReview(
                                proposal.patch_id,
                                row.verification_id,
                              );
                              if (!alive.current) return;
                              if (
                                row.execution_status !== "running" &&
                                stableJson(value) !== stableJson(row)
                              )
                                throw bindingError();
                              if (alive.current) showRun(value, proposal);
                            })
                          }
                        >
                          {row.execution_status} · {row.verification_id}
                        </button>
                      </li>
                    ))}
                  </ul>
                  <div className="split">
                    <button
                      className="button secondary"
                      disabled={disabled || reviewOffset === 0}
                      onClick={() =>
                        void action(() => loadReviews(reviewOffset - 20))
                      }
                    >
                      Предыдущие проверки
                    </button>
                    <button
                      className="button secondary"
                      disabled={disabled || reviews.length < 20}
                      onClick={() =>
                        void action(() => loadReviews(reviewOffset + 20))
                      }
                    >
                      Следующие проверки
                    </button>
                  </div>
                  {run && (
                    <>
                      <ModelReviewView run={run} />
                      {client.permits("feedback") &&
                        run.execution_status !== "running" && (
                          <fieldset disabled={locked}>
                            <legend>Сохранить решение инженера</legend>
                            <p className="hint">
                              Это запись роли сервисного ключа, не удостоверение
                              конкретного человека. Решение не меняет исходный
                              анализ и не применяет конфигурацию.
                            </p>
                            <label
                              htmlFor={`model-verdict-${finding.finding_id}`}
                            >
                              Решение о кандидате
                            </label>
                            <select
                              id={`model-verdict-${finding.finding_id}`}
                              value={verdict}
                              onChange={(event) => {
                                setVerdict(
                                  event.target
                                    .value as DecideModelPatch["verdict"],
                                );
                                setAcknowledged([]);
                                setSyntax(false);
                                setAccess(false);
                                setRollback(false);
                              }}
                            >
                              <option value="needs_more_information">
                                Нужны дополнительные сведения
                              </option>
                              <option value="rejected">Отклонить</option>
                              <option
                                value="approved"
                                disabled={run.approval_blockers.length > 0}
                              >
                                Утвердить после независимых проверок
                              </option>
                            </select>
                            <label>
                              Комментарий к решению
                              <textarea
                                maxLength={1200}
                                value={comment}
                                onChange={(event) =>
                                  setComment(event.target.value)
                                }
                              />
                            </label>
                            <p className="hint">
                              Не включайте пароли, исходные конфигурации или
                              персональные сведения.
                            </p>
                            {verdict === "approved" && (
                              <>
                                <label>
                                  <input
                                    type="checkbox"
                                    checked={syntax}
                                    onChange={(event) =>
                                      setSyntax(event.target.checked)
                                    }
                                  />{" "}
                                  Независимо проверен синтаксис на устройстве
                                </label>
                                <label>
                                  <input
                                    type="checkbox"
                                    checked={access}
                                    onChange={(event) =>
                                      setAccess(event.target.checked)
                                    }
                                  />{" "}
                                  Независимо проверен административный доступ
                                </label>
                                <label>
                                  <input
                                    type="checkbox"
                                    checked={rollback}
                                    onChange={(event) =>
                                      setRollback(event.target.checked)
                                    }
                                  />{" "}
                                  Подготовлен и проверен возврат к исходной
                                  конфигурации
                                </label>
                                <h5>
                                  Подтверждаю каждое оставшееся ограничение
                                </h5>
                                {run.report?.missing_checks.map((value) => (
                                  <label key={value}>
                                    <input
                                      type="checkbox"
                                      checked={acknowledged.includes(value)}
                                      onChange={(event) =>
                                        setAcknowledged((items) =>
                                          event.target.checked
                                            ? [...items, value]
                                            : items.filter(
                                                (item) => item !== value,
                                              ),
                                        )
                                      }
                                    />
                                    {limitationLabel(value)}
                                  </label>
                                ))}
                              </>
                            )}
                            <button
                              className="button"
                              disabled={!decisionReady}
                              onClick={() =>
                                void action(async () => {
                                  await decide();
                                })
                              }
                            >
                              Записать решение инженера
                            </button>
                          </fieldset>
                        )}
                    </>
                  )}
                  <h5>Неизменяемая история решений</h5>
                  <button
                    className="button secondary"
                    disabled={disabled}
                    onClick={() => void action(() => loadDecisions(0))}
                  >
                    Обновить историю решений
                  </button>
                  <ul aria-label="Сохранённые решения инженера">
                    {decisions.map((row) => (
                      <li key={row.request.decision_id}>
                        <strong>
                          {row.request.verdict === "approved"
                            ? "Утверждено решение роли сервиса; не применено"
                            : row.request.verdict === "rejected"
                              ? "Отклонено"
                              : "Нужны дополнительные сведения"}
                        </strong>
                        <p>{row.request.comment}</p>
                        <p className="hint">
                          {date(row.created_at)} · {row.service_role} · личность
                          человека не удостоверена.
                        </p>
                        <p className="mono">
                          Решение: {row.request.decision_id}
                        </p>
                        <p className="mono">
                          Проверка: {row.request.verification_id}
                        </p>
                      </li>
                    ))}
                  </ul>
                  <div className="split">
                    <button
                      className="button secondary"
                      disabled={disabled || decisionOffset === 0}
                      onClick={() =>
                        void action(() => loadDecisions(decisionOffset - 20))
                      }
                    >
                      Предыдущие решения
                    </button>
                    <button
                      className="button secondary"
                      disabled={disabled || decisions.length < 20}
                      onClick={() =>
                        void action(() => loadDecisions(decisionOffset + 20))
                      }
                    >
                      Следующие решения
                    </button>
                  </div>
                </>
              )}
            </section>
          )}
        </>
      )}
    </section>
  );
}
