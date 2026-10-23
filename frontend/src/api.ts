import { z } from "zod";
import {
  analysisSchema,
  analysisSummarySchema,
  configurationSummarySchema,
  snapshotSchema,
  modelSchema,
  feedbackSchema,
  snapshotDiffSchema,
  explanationBundleSchema,
  modelExplanationSchema,
  explanationCapabilitiesSchema,
  sessionAccessSchema,
} from "./contracts";
import type {
  AnalysisOptions,
  FeedbackSubmission,
  TrainModel,
  Upload,
  ExplainFinding,
  Permission,
} from "./contracts";
import {
  patchDraftSchema,
  patchSummarySchema,
  verificationSchema,
  verificationSummarySchema,
} from "./patches";
import type { CreatePatch, VerifyPatch } from "./patches";
import type { PatchDraft } from "./patches";
import {
  sourcePatchCapabilitiesSchema,
  sourcePatchVerificationSchema,
  sourcePatchVerificationSummarySchema,
  verifySourcePatchSchema,
  sourceSummaryBound,
  sourceVerificationBound,
} from "./sourcePatchVerification";
import type {
  VerifySourcePatch,
  SourcePatchVerificationSummary,
} from "./sourcePatchVerification";
import {
  generateModelPatchSchema,
  generationMatches,
  modelPatchCapabilitiesSchema,
  modelPatchProposalSchema,
  commonModelPatch,
  groundedBindingsMatch,
  groundedModelPatchProposalSchema,
  savedModelPatchCapabilitiesSchema,
  savedModelPatchProposalSchema,
} from "./modelPatches";
import type { GenerateModelPatch } from "./modelPatches";
import {
  decideModelPatchSchema,
  savedModelDecisionSchema,
  savedModelReviewSchema,
  verifyModelPatchSchema,
} from "./modelReviews";
import type { DecideModelPatch, VerifyModelPatch } from "./modelReviews";
import { stableJson } from "./contracts";
import {
  groundedExplanationCapabilitiesSchema,
  groundedExplanationSchema,
  groundedExplanationBindingsMatch,
} from "./groundedExplanation";
import {
  configurationModelCapabilitiesSchema,
  configurationModelRunSchema,
  runConfigurationModelSchema,
  configurationRunMatches,
} from "./configurationModels";
import type { RunConfigurationModel } from "./configurationModels";
import {
  runSourceMlRecheckSchema,
  sourceMlCapabilitiesSchema,
  sourceMlRecheckSchema,
  sourceMlSummarySchema,
  sourceMlSummaryBound,
  sourceMlRecheckBound,
} from "./sourceMlRecheck";
import type { RunSourceMlRecheck, SourceMlSummary } from "./sourceMlRecheck";
import {
  runSourceForestRecheckSchema,
  sourceForestSelectionSchema,
  sourceForestSelectionBound,
  sourceForestRecheckSchema,
  sourceForestRecheckBound,
  sourceForestSummarySchema,
  sourceForestSummaryBound,
} from "./sourceForestRecheck";
import type {
  RunSourceForestRecheck,
  SourceForestSelection,
  SourceForestSummary,
} from "./sourceForestRecheck";
import {
  runSourceDeterministicRecheckSchema,
  sourceDeterministicSelectionSchema,
  sourceDeterministicSelectionBound,
  sourceDeterministicRecheckSchema,
  sourceDeterministicRecheckBound,
  sourceDeterministicSummarySchema,
  sourceDeterministicSummaryBound,
} from "./sourceDeterministicRecheck";
import type {
  RunSourceDeterministicRecheck,
  SourceDeterministicSelection,
  SourceDeterministicSummary,
} from "./sourceDeterministicRecheck";
import {
  createSourceEvidenceReportSchema,
  sourceEvidenceReportSchema,
  sourceEvidenceReportBound,
  sourceEvidenceSummarySchema,
  sourceEvidenceSummaryBound,
} from "./sourceEvidenceReports";
import type {
  CreateSourceEvidenceReport,
  SourceEvidenceReport,
  SourceEvidenceSummary,
} from "./sourceEvidenceReports";
import {
  reviewSourceEvidenceReportSchema,
  sourceEvidenceDecisionSchema,
  sourceEvidenceDecisionBound,
  sourceEvidenceDecisionSummarySchema,
  sourceEvidenceDecisionSummaryBound,
} from "./sourceEvidenceDecisions";
import type {
  ReviewSourceEvidenceReport,
  SourceEvidenceDecision,
  SourceEvidenceDecisionSummary,
} from "./sourceEvidenceDecisions";
import {
  createSourceRiskAssessmentSchema,
  sourceRiskAssessmentSchema,
  sourceRiskAssessmentBound,
  sourceRiskSummarySchema,
  sourceRiskSummaryBound,
} from "./sourceRiskAssessments";
import type {
  CreateSourceRiskAssessment,
  SourceRiskAssessment,
  SourceRiskSummary,
} from "./sourceRiskAssessments";
import {
  operationPageSchema,
  operationRecordSchema,
  verifyReceiptBinding,
} from "./audit";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const messages: Record<number, string> = {
  400: "Запрос не принят. Проверьте формат, выбранные снимки, модель и ограничения операции.",
  401: "Токен не принят. Подключитесь заново.",
  403: "Недостаточно прав для этой операции или не разрешена передача контекста локальной модели.",
  404: "Запись не найдена. Обновите историю.",
  409: "Конфликт идентификатора или привязки записи. Проверьте UUID устройства, выбранные снимки и историю.",
  413: "Операция превышает допустимый размер или число изменений.",
  415: "Неподдерживаемый формат запроса.",
  422: "Параметры запроса не приняты.",
  429: "Операция уже выполняется. Дождитесь завершения и повторите запрос.",
  503: "Сервис недоступен или итог операции не подтверждён. Проверьте сохранённую историю перед повтором, настройки API, миграции и ключ шифрования.",
};

export class ApiClient {
  private readonly controller = new AbortController();
  private token: string;
  private permissions: Permission[] = [];
  constructor(
    token: string,
    private readonly transport: typeof fetch = globalThis.fetch.bind(
      globalThis,
    ),
  ) {
    if (
      token.length < 32 ||
      token.length > 512 ||
      !/^[\x21-\x7e]+$/.test(token)
    )
      throw new ApiError(401, messages[401]!);
    this.token = token;
  }
  async operationAudit(before?: string) {
    const query = new URLSearchParams({ limit: "20" });
    if (before) query.set("before", before);
    const page = await this.request(
      `/operation-audit?${query}`,
      operationPageSchema,
    );
    if (
      !(await Promise.all(page.records.map(verifyReceiptBinding))).every(
        Boolean,
      )
    )
      throw new ApiError(0, "Привязка записи журнала не подтверждена.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return page;
  }
  async operation(id: string) {
    const record = await this.request(
      `/operation-audit/${encodeURIComponent(id)}`,
      operationRecordSchema,
    );
    if (
      record.receipt.operation_id !== id ||
      !(await verifyReceiptBinding(record))
    )
      throw new ApiError(0, "Привязка записи журнала не подтверждена.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return record;
  }
  close() {
    this.token = "";
    this.permissions = [];
    this.controller.abort();
  }
  async access() {
    const result = await this.request("/session", sessionAccessSchema);
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    this.permissions = result.permissions;
    return result;
  }
  permits(permission: Permission) {
    return this.permissions.includes(permission);
  }
  private async request<T>(
    path: string,
    schema: z.ZodType<T>,
    body?:
      | Upload
      | AnalysisOptions
      | TrainModel
      | FeedbackSubmission
      | ExplainFinding
      | CreatePatch
      | VerifyPatch
      | VerifySourcePatch
      | GenerateModelPatch
      | VerifyModelPatch
      | DecideModelPatch
      | RunConfigurationModel
      | RunSourceMlRecheck
      | RunSourceForestRecheck
      | RunSourceDeterministicRecheck
      | CreateSourceEvidenceReport
      | CreateSourceRiskAssessment
      | ReviewSourceEvidenceReport,
    namespace: "v1" | "v2" = "v1",
    maximumResponseBytes?: number,
  ): Promise<T> {
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    const timeout = AbortSignal.timeout(30_000);
    try {
      const response = await this.transport(`/api/${namespace}${path}`, {
        method:
          body === undefined && !path.endsWith("/analyze") ? "GET" : "POST",
        headers: {
          Authorization: `Bearer ${this.token}`,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.any([this.controller.signal, timeout]),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
      if (!response.ok)
        throw new ApiError(
          response.status,
          messages[response.status] ?? "Запрос не выполнен. Повторите позже.",
        );
      let value: unknown;
      if (maximumResponseBytes === undefined) value = await response.json();
      else {
        const wire = await response.text();
        if (new TextEncoder().encode(wire).length > maximumResponseBytes)
          throw new ApiError(0, "Ответ API превышает допустимый размер.");
        value = JSON.parse(wire) as unknown;
      }
      const parsed = schema.safeParse(value);
      if (!parsed.success)
        throw new ApiError(
          0,
          "Ответ API не соответствует поддерживаемому контракту.",
        );
      if (this.controller.signal.aborted)
        throw new DOMException("Disconnected", "AbortError");
      return parsed.data;
    } catch (error) {
      if (error instanceof ApiError || this.controller.signal.aborted)
        throw error;
      throw new ApiError(
        0,
        timeout.aborted
          ? "Время ожидания истекло. Проверьте историю и реестр моделей перед повтором."
          : "Не удалось связаться с API. Проверьте локальный сервер.",
      );
    }
  }
  configurations(offset = 0, device?: string) {
    const query = new URLSearchParams({ limit: "20", offset: String(offset) });
    if (device) query.set("device_id", device);
    return this.request(
      `/configurations?${query}`,
      z.array(configurationSummarySchema),
    );
  }
  configurationModelCapabilities() {
    return this.request(
      "/configuration-model-runs/capabilities",
      configurationModelCapabilitiesSchema,
    );
  }
  async configurationModelRuns(analysis: string, offset = 0) {
    const query = new URLSearchParams({
      analysis_id: analysis,
      limit: "20",
      offset: String(offset),
    });
    const rows = await this.request(
      `/configuration-model-runs?${query}`,
      z.array(configurationModelRunSchema).max(20),
    );
    if (
      rows.some((row) => row.analysis_id !== analysis) ||
      new Set(rows.map((row) => row.inference_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "Привязка истории конфигурационной модели не подтверждена.",
      );
    return rows;
  }
  async configurationModelRun(id: string, expected?: RunConfigurationModel) {
    const row = await this.request(
      `/configuration-model-runs/${encodeURIComponent(id)}`,
      configurationModelRunSchema,
    );
    if (
      row.inference_id !== id ||
      (expected && !configurationRunMatches(row, expected))
    )
      throw new ApiError(
        0,
        "Привязка запуска конфигурационной модели не подтверждена.",
      );
    return row;
  }
  async runConfigurationModel(options: RunConfigurationModel) {
    const checked = runConfigurationModelSchema.parse(options);
    if (!checked.allow_local_model_context)
      throw new ApiError(403, messages[403]!);
    const row = await this.request(
      "/configuration-model-runs",
      configurationModelRunSchema,
      checked,
    );
    if (!configurationRunMatches(row, checked))
      throw new ApiError(
        0,
        "Привязка запуска конфигурационной модели не подтверждена.",
      );
    return row;
  }
  analyses(offset = 0, configuration?: string) {
    const query = new URLSearchParams({ limit: "20", offset: String(offset) });
    if (configuration) query.set("configuration_id", configuration);
    return this.request(`/analyses?${query}`, z.array(analysisSummarySchema));
  }
  configuration(id: string) {
    return this.request(
      `/configurations/${encodeURIComponent(id)}`,
      snapshotSchema,
    );
  }
  diff(current: string, reference: string) {
    const query = new URLSearchParams({
      reference_configuration_id: reference,
    });
    return this.request(
      `/configurations/${encodeURIComponent(current)}/diff?${query}`,
      snapshotDiffSchema,
    );
  }
  analysis(id: string) {
    return this.request(`/analyses/${encodeURIComponent(id)}`, analysisSchema);
  }
  upload(body: Upload) {
    return this.request("/configurations", snapshotSchema, body);
  }
  analyze(id: string, options?: AnalysisOptions) {
    return this.request(
      `/configurations/${encodeURIComponent(id)}/analyze`,
      analysisSchema,
      options,
    );
  }
  models(offset = 0) {
    return this.request(
      `/models?limit=20&offset=${offset}`,
      z.array(modelSchema),
    );
  }
  trainModel(options: TrainModel) {
    return this.request("/models/isolation-forest", modelSchema, options);
  }
  feedback(finding: string, analysis: string, offset = 0) {
    const query = new URLSearchParams({
      analysis_id: analysis,
      limit: "20",
      offset: String(offset),
    });
    return this.request(
      `/findings/${encodeURIComponent(finding)}/feedback?${query}`,
      z.array(feedbackSchema),
    );
  }
  submitFeedback(finding: string, submission: FeedbackSubmission) {
    return this.request(
      `/findings/${encodeURIComponent(finding)}/feedback`,
      feedbackSchema,
      submission,
    );
  }
  explain(finding: string, options: ExplainFinding) {
    return this.request(
      `/findings/${encodeURIComponent(finding)}/explain`,
      explanationBundleSchema,
      options,
    );
  }
  explanationCapabilities() {
    return this.request(
      "/explanation-capabilities",
      explanationCapabilitiesSchema,
    );
  }
  groundedExplanationCapabilities() {
    return this.request(
      "/explanation-capabilities",
      groundedExplanationCapabilitiesSchema,
      undefined,
      "v2",
    );
  }
  async explainGrounded(
    finding: string,
    options: ExplainFinding & {
      provider: "llm";
      allow_local_model_context: true;
    },
  ) {
    if (
      options.provider !== "llm" ||
      options.allow_local_model_context !== true
    )
      throw new ApiError(403, messages[403]!);
    const result = await this.request(
      `/findings/${encodeURIComponent(finding)}/explain`,
      groundedExplanationSchema,
      options,
      "v2",
    );
    if (
      result.finding_id !== finding ||
      result.analysis_id !== options.analysis_id ||
      result.finding_sha256 !== options.finding_sha256 ||
      result.retrieval !== (options.retrieval ?? "explicit_reference") ||
      !(await groundedExplanationBindingsMatch(result))
    )
      throw new ApiError(0, "Привязки закрытого объяснения не подтверждены.");
    return result;
  }
  explainModel(
    finding: string,
    options: ExplainFinding & {
      provider: "llm";
      allow_local_model_context: true;
    },
  ) {
    return this.request(
      `/findings/${encodeURIComponent(finding)}/explain`,
      modelExplanationSchema,
      options,
    );
  }
  patches(after: string, offset = 0) {
    const query = new URLSearchParams({
      after_configuration_id: after,
      limit: "20",
      offset: String(offset),
    });
    return this.request(
      `/patches?${query}`,
      z.array(patchSummarySchema).max(20),
    );
  }
  patch(id: string) {
    return this.request(`/patches/${encodeURIComponent(id)}`, patchDraftSchema);
  }
  createPatch(options: CreatePatch) {
    return this.request("/patches", patchDraftSchema, options);
  }
  verifications(patch: string, offset = 0) {
    return this.request(
      `/patches/${encodeURIComponent(patch)}/verifications?limit=20&offset=${offset}`,
      z.array(verificationSummarySchema).max(20),
    );
  }
  verification(patch: string, id: string) {
    return this.request(
      `/patches/${encodeURIComponent(patch)}/verifications/${encodeURIComponent(id)}`,
      verificationSchema,
    );
  }
  verifyPatch(patch: string, options: VerifyPatch) {
    return this.request(
      `/patches/${encodeURIComponent(patch)}/verify`,
      verificationSchema,
      options,
    );
  }
  modelPatchCapabilities() {
    return this.request(
      "/model-patches/capabilities",
      modelPatchCapabilitiesSchema,
    );
  }
  sourcePatchCapabilities() {
    return this.request(
      "/patches/capabilities",
      sourcePatchCapabilitiesSchema,
      undefined,
      "v2",
    );
  }
  sourceMlCapabilities() {
    return this.request(
      "/patches/ml-capabilities",
      sourceMlCapabilitiesSchema,
      undefined,
      "v2",
    );
  }
  async sourceForestSelection(draft: PatchDraft, analysisId: string) {
    const selected = z.guid().parse(analysisId);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/statistical-selection/${encodeURIComponent(selected)}`,
      sourceForestSelectionSchema,
      undefined,
      "v2",
    );
    if (!sourceForestSelectionBound(row, draft, selected))
      throw new ApiError(
        0,
        "Исходный анализ Forest не соответствует черновику.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourceForestRechecks(draft: PatchDraft, offset = 0) {
    const rows = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/statistical-rechecks?limit=20&offset=${offset}`,
      z.array(sourceForestSummarySchema).max(20),
      undefined,
      "v2",
    );
    if (
      rows.some((row) => !sourceForestSummaryBound(row, draft)) ||
      new Set(rows.map((row) => row.recheck_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "История исходного Forest не соответствует черновику.",
      );
    return rows;
  }
  async sourceForestRecheck(
    draft: PatchDraft,
    id: string,
    request?: RunSourceForestRecheck,
    summary?: SourceForestSummary,
    selection?: SourceForestSelection,
  ) {
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/statistical-rechecks/${encodeURIComponent(id)}`,
      sourceForestRecheckSchema,
      undefined,
      "v2",
    );
    if (
      row.recheck_id !== id ||
      !(await sourceForestRecheckBound(row, draft, request, summary, selection))
    )
      throw new ApiError(
        0,
        "Привязки пересчёта исходного Forest не подтверждены.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async runSourceForestRecheck(
    draft: PatchDraft,
    options: RunSourceForestRecheck,
    selection: SourceForestSelection,
  ) {
    const request = runSourceForestRecheckSchema.parse(options);
    const selected = sourceForestSelectionSchema.parse(selection);
    if (!request.allow_local_model_context)
      throw new ApiError(403, messages[403]!);
    if (
      !sourceForestSelectionBound(
        selected,
        draft,
        request.before_analysis_id,
      ) ||
      request.draft_sha256 !== draft.draft_sha256 ||
      request.before_analysis_sha256 !== selected.before_analysis_sha256 ||
      request.model_id !== selected.original.model.model_id ||
      request.artifact_sha256 !== selected.original.model.artifact_sha256
    )
      throw new ApiError(409, messages[409]!);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/statistical-rechecks`,
      sourceForestRecheckSchema,
      request,
      "v2",
    );
    if (
      !(await sourceForestRecheckBound(
        row,
        draft,
        request,
        undefined,
        selected,
      ))
    )
      throw new ApiError(
        0,
        "Привязки пересчёта исходного Forest не подтверждены.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourceDeterministicSelection(draft: PatchDraft, analysisId: string) {
    const selected = z.guid().parse(analysisId);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/deterministic-selection/${encodeURIComponent(selected)}`,
      sourceDeterministicSelectionSchema,
      undefined,
      "v2",
    );
    if (!sourceDeterministicSelectionBound(row, draft, selected))
      throw new ApiError(
        0,
        "Исходный анализ политик и сравнений не соответствует черновику.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourceDeterministicRechecks(draft: PatchDraft, offset = 0) {
    const rows = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/deterministic-rechecks?limit=20&offset=${offset}`,
      z.array(sourceDeterministicSummarySchema).max(20),
      undefined,
      "v2",
    );
    if (
      rows.some((row) => !sourceDeterministicSummaryBound(row, draft)) ||
      new Set(rows.map((row) => row.recheck_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "История исходного анализа не соответствует черновику.",
      );
    return rows;
  }
  async sourceDeterministicRecheck(
    draft: PatchDraft,
    id: string,
    request?: RunSourceDeterministicRecheck,
    summary?: SourceDeterministicSummary,
    selection?: SourceDeterministicSelection,
  ) {
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/deterministic-rechecks/${encodeURIComponent(id)}`,
      sourceDeterministicRecheckSchema,
      undefined,
      "v2",
    );
    if (
      row.recheck_id !== id ||
      !(await sourceDeterministicRecheckBound(
        row,
        draft,
        request,
        summary,
        selection,
      ))
    )
      throw new ApiError(
        0,
        "Привязки пересчёта исходного анализа не подтверждены.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async runSourceDeterministicRecheck(
    draft: PatchDraft,
    options: RunSourceDeterministicRecheck,
    selection: SourceDeterministicSelection,
  ) {
    const request = runSourceDeterministicRecheckSchema.parse(options);
    const selected = sourceDeterministicSelectionSchema.parse(selection);
    if (!request.allow_local_analysis_context)
      throw new ApiError(403, messages[403]!);
    if (
      !sourceDeterministicSelectionBound(
        selected,
        draft,
        request.before_analysis_id,
      ) ||
      request.draft_sha256 !== draft.draft_sha256 ||
      request.before_analysis_sha256 !== selected.before_analysis_sha256 ||
      request.reference_canonical_sha256 !==
        (selected.reference?.canonical_sha256 ?? null)
    )
      throw new ApiError(409, messages[409]!);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/deterministic-rechecks`,
      sourceDeterministicRecheckSchema,
      request,
      "v2",
    );
    if (
      !(await sourceDeterministicRecheckBound(
        row,
        draft,
        request,
        undefined,
        selected,
      ))
    )
      throw new ApiError(
        0,
        "Привязки пересчёта исходного анализа не подтверждены.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourceEvidenceReports(draft: PatchDraft, offset = 0) {
    const rows = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports?limit=20&offset=${offset}`,
      z.array(sourceEvidenceSummarySchema).max(20),
      undefined,
      "v2",
    );
    if (
      rows.some((row) => !sourceEvidenceSummaryBound(row, draft)) ||
      new Set(rows.map((row) => row.report_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "История совместных отчётов не соответствует черновику.",
      );
    return rows;
  }
  private async loadSourceEvidenceChildren(
    row: SourceEvidenceReport,
    draft: PatchDraft,
  ) {
    // Each existing child client verifies its own normative proof. A valid parent
    // hash alone cannot authenticate compact projections asserted by the parent.
    const selected = row.request;
    return Promise.all([
      this.sourceDeterministicRecheck(draft, selected.deterministic.record_id),
      selected.forest
        ? this.sourceForestRecheck(draft, selected.forest.record_id)
        : null,
      selected.neural
        ? this.sourceMlRecheck(draft, selected.neural.record_id)
        : null,
      selected.network
        ? this.sourcePatchVerification(draft, selected.network.record_id)
        : null,
    ]).catch((problem: unknown) => {
      if (this.controller.signal.aborted)
        throw new DOMException("Disconnected", "AbortError");
      // A refused child GET after a successful POST says nothing about whether
      // the immutable parent committed. Keep it uncertain, never resettable.
      if (problem instanceof DOMException && problem.name === "AbortError")
        throw problem;
      throw new ApiError(
        0,
        "Сохранённые результаты совместного отчёта не подтверждены.",
      );
    });
  }
  private async acceptSourceEvidenceReport(
    row: SourceEvidenceReport,
    draft: PatchDraft,
    request?: CreateSourceEvidenceReport,
    summary?: SourceEvidenceSummary,
  ) {
    const [deterministic, forest, neural, network] =
      await this.loadSourceEvidenceChildren(row, draft);
    if (
      !(await sourceEvidenceReportBound(
        row,
        draft,
        { deterministic, forest, neural, network },
        request,
        summary,
      ))
    )
      throw new ApiError(
        0,
        "Привязки совместного отчёта и сохранённых результатов не подтверждены.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourceEvidenceReport(
    draft: PatchDraft,
    id: string,
    request?: CreateSourceEvidenceReport,
    summary?: SourceEvidenceSummary,
  ) {
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports/${encodeURIComponent(id)}`,
      sourceEvidenceReportSchema,
      undefined,
      "v2",
    );
    if (row.report_id !== id)
      throw new ApiError(0, "Идентификатор совместного отчёта не подтверждён.");
    return this.acceptSourceEvidenceReport(row, draft, request, summary);
  }
  async createSourceEvidenceReport(
    draft: PatchDraft,
    options: CreateSourceEvidenceReport,
  ) {
    const request = createSourceEvidenceReportSchema.parse(options);
    if (request.draft_sha256 !== draft.draft_sha256)
      throw new ApiError(409, messages[409]!);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports`,
      sourceEvidenceReportSchema,
      request,
      "v2",
    );
    return this.acceptSourceEvidenceReport(row, draft, request);
  }
  async sourceRiskAssessments(report: SourceEvidenceReport, offset = 0) {
    const rows = await this.request(
      `/patches/${encodeURIComponent(report.patch_id)}/evidence-reports/${encodeURIComponent(report.report_id)}/risk-assessments?limit=20&offset=${offset}`,
      z.array(sourceRiskSummarySchema).max(20),
      undefined,
      "v2",
      128 * 1024,
    );
    if (
      rows.some((row) => !sourceRiskSummaryBound(row, report)) ||
      new Set(rows.map((row) => row.assessment_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "История приоритетов не соответствует совместному отчёту.",
      );
    return rows;
  }
  private async acceptSourceRiskAssessment(
    row: SourceRiskAssessment,
    draft: PatchDraft,
    report: SourceEvidenceReport,
    expected?: CreateSourceRiskAssessment,
    summary?: SourceRiskSummary,
  ) {
    let checked: SourceEvidenceReport, children;
    try {
      checked = await this.request(
        `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports/${encodeURIComponent(report.report_id)}`,
        sourceEvidenceReportSchema,
        undefined,
        "v2",
      );
      children = await this.loadSourceEvidenceChildren(checked, draft);
    } catch {
      if (this.controller.signal.aborted)
        throw new DOMException("Disconnected", "AbortError");
      throw new ApiError(
        0,
        "Отчёт или сохранённые результаты приоритета не подтверждены. Прочитайте оценку по её ID.",
      );
    }
    const [deterministic, forest, neural, network] = children;
    if (
      checked.review_sha256 !== report.review_sha256 ||
      !(await sourceRiskAssessmentBound(
        row,
        draft,
        checked,
        { deterministic, forest, neural, network },
        expected,
        summary,
      ))
    )
      throw new ApiError(
        0,
        "Привязки экспериментального приоритета не подтверждены.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourceRiskAssessment(
    draft: PatchDraft,
    report: SourceEvidenceReport,
    id: string,
    expected?: CreateSourceRiskAssessment,
    summary?: SourceRiskSummary,
  ) {
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports/${encodeURIComponent(report.report_id)}/risk-assessments/${encodeURIComponent(id)}`,
      sourceRiskAssessmentSchema,
      undefined,
      "v2",
      2 * 1024 * 1024,
    );
    if (row.assessment_id !== id)
      throw new ApiError(0, "Идентификатор приоритета не подтверждён.");
    return this.acceptSourceRiskAssessment(
      row,
      draft,
      report,
      expected,
      summary,
    );
  }
  async createSourceRiskAssessment(
    draft: PatchDraft,
    report: SourceEvidenceReport,
    options: CreateSourceRiskAssessment,
  ) {
    const request = createSourceRiskAssessmentSchema.parse(options);
    if (
      report.patch_id !== draft.patch_id ||
      report.draft_sha256 !== draft.draft_sha256 ||
      request.report_sha256 !== report.review_sha256
    )
      throw new ApiError(409, messages[409]!);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports/${encodeURIComponent(report.report_id)}/risk-assessments`,
      sourceRiskAssessmentSchema,
      request,
      "v2",
      2 * 1024 * 1024,
    );
    return this.acceptSourceRiskAssessment(row, draft, report, request);
  }
  async sourceEvidenceDecisions(report: SourceEvidenceReport, offset = 0) {
    const rows = await this.request(
      `/patches/${encodeURIComponent(report.patch_id)}/evidence-reports/${encodeURIComponent(report.report_id)}/decisions?limit=20&offset=${offset}`,
      z.array(sourceEvidenceDecisionSummarySchema).max(20),
      undefined,
      "v2",
      128 * 1024,
    );
    if (
      rows.some((row) => !sourceEvidenceDecisionSummaryBound(row, report)) ||
      new Set(rows.map((row) => row.decision_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "История решений не соответствует совместному отчёту.",
      );
    return rows;
  }
  private async acceptSourceEvidenceDecision(
    row: SourceEvidenceDecision,
    draft: PatchDraft,
    report: SourceEvidenceReport,
    expected?: ReviewSourceEvidenceReport,
    summary?: SourceEvidenceDecisionSummary,
  ) {
    let checked: SourceEvidenceReport;
    try {
      checked = await this.sourceEvidenceReport(draft, report.report_id);
    } catch {
      if (this.controller.signal.aborted)
        throw new DOMException("Disconnected", "AbortError");
      // A parent read after POST cannot establish that the decision was refused.
      throw new ApiError(
        0,
        "Совместный отчёт решения не подтверждён. Прочитайте решение по его ID.",
      );
    }
    if (
      checked.review_sha256 !== report.review_sha256 ||
      !(await sourceEvidenceDecisionBound(row, checked, expected, summary))
    )
      throw new ApiError(
        0,
        "Привязки решения к совместному отчёту не подтверждены.",
      );
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourceEvidenceDecision(
    draft: PatchDraft,
    report: SourceEvidenceReport,
    id: string,
    expected?: ReviewSourceEvidenceReport,
    summary?: SourceEvidenceDecisionSummary,
  ) {
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports/${encodeURIComponent(report.report_id)}/decisions/${encodeURIComponent(id)}`,
      sourceEvidenceDecisionSchema,
      undefined,
      "v2",
      128 * 1024,
    );
    if (row.decision_id !== id)
      throw new ApiError(0, "Идентификатор решения не подтверждён.");
    return this.acceptSourceEvidenceDecision(
      row,
      draft,
      report,
      expected,
      summary,
    );
  }
  async reviewSourceEvidenceReport(
    draft: PatchDraft,
    report: SourceEvidenceReport,
    options: ReviewSourceEvidenceReport,
  ) {
    const request = reviewSourceEvidenceReportSchema.parse(options);
    if (
      report.patch_id !== draft.patch_id ||
      report.draft_sha256 !== draft.draft_sha256 ||
      request.version.replace("source-evidence-decision-request-", "") !==
        report.version.replace("source-evidence-report-", "") ||
      request.report_sha256 !== report.review_sha256
    )
      throw new ApiError(409, messages[409]!);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/evidence-reports/${encodeURIComponent(report.report_id)}/decisions`,
      sourceEvidenceDecisionSchema,
      request,
      "v2",
      128 * 1024,
    );
    return this.acceptSourceEvidenceDecision(row, draft, report, request);
  }
  async sourceMlRechecks(draft: PatchDraft, offset = 0) {
    const rows = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/ml-rechecks?limit=20&offset=${offset}`,
      z.array(sourceMlSummarySchema).max(20),
      undefined,
      "v2",
    );
    if (
      rows.some((row) => !sourceMlSummaryBound(row, draft)) ||
      new Set(rows.map((row) => row.recheck_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "История парного ML-пересчёта не соответствует черновику.",
      );
    return rows;
  }
  async sourceMlRecheck(
    draft: PatchDraft,
    id: string,
    request?: RunSourceMlRecheck,
    summary?: SourceMlSummary,
  ) {
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/ml-rechecks/${encodeURIComponent(id)}`,
      sourceMlRecheckSchema,
      undefined,
      "v2",
    );
    if (
      row.recheck_id !== id ||
      !(await sourceMlRecheckBound(row, draft, request, summary))
    )
      throw new ApiError(0, "Привязки парного ML-пересчёта не подтверждены.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async runSourceMlRecheck(draft: PatchDraft, options: RunSourceMlRecheck) {
    const request = runSourceMlRecheckSchema.parse(options);
    if (!request.allow_local_model_context)
      throw new ApiError(
        403,
        "Требуется отдельное разрешение локального парного inference.",
      );
    if (request.draft_sha256 !== draft.draft_sha256)
      throw new ApiError(409, messages[409]!);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/ml-rechecks`,
      sourceMlRecheckSchema,
      request,
      "v2",
    );
    if (!(await sourceMlRecheckBound(row, draft, request)))
      throw new ApiError(0, "Привязки парного ML-пересчёта не подтверждены.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async sourcePatchVerifications(draft: PatchDraft, offset = 0) {
    const rows = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/verifications?limit=20&offset=${offset}`,
      z.array(sourcePatchVerificationSummarySchema).max(20),
      undefined,
      "v2",
    );
    if (
      rows.some((row) => !sourceSummaryBound(row, draft)) ||
      new Set(rows.map((row) => row.verification_id)).size !== rows.length
    )
      throw new ApiError(
        0,
        "История сетевых проверок не соответствует черновику.",
      );
    return rows;
  }
  async sourcePatchVerification(
    draft: PatchDraft,
    id: string,
    expected?: VerifySourcePatch,
    summary?: SourcePatchVerificationSummary,
  ) {
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/verifications/${encodeURIComponent(id)}`,
      sourcePatchVerificationSchema,
      undefined,
      "v2",
    );
    if (
      row.verification_id !== id ||
      !(await sourceVerificationBound(row, draft, expected, summary))
    )
      throw new ApiError(0, "Привязки сетевой проверки не подтверждены.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async verifySourcePatch(draft: PatchDraft, options: VerifySourcePatch) {
    const request = verifySourcePatchSchema.parse(options);
    if (!request.allow_local_engine_upload)
      throw new ApiError(
        403,
        "Требуется отдельное разрешение передачи исходников локальному сетевому движку.",
      );
    if (request.draft_sha256 !== draft.draft_sha256)
      throw new ApiError(409, messages[409]!);
    const row = await this.request(
      `/patches/${encodeURIComponent(draft.patch_id)}/verify`,
      sourcePatchVerificationSchema,
      request,
      "v2",
    );
    if (!(await sourceVerificationBound(row, draft, request)))
      throw new ApiError(0, "Привязки сетевой проверки не подтверждены.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async modelPatches(analysis: string, offset = 0) {
    const query = new URLSearchParams({
      analysis_id: analysis,
      limit: "20",
      offset: String(offset),
    });
    const rows = await this.request(
      `/model-patches?${query}`,
      z.array(modelPatchProposalSchema).max(20),
    );
    if (
      rows.some((row) => row.analysis_id !== analysis) ||
      new Set(rows.map((row) => row.patch_id)).size !== rows.length
    )
      throw new ApiError(0, "История черновиков не соответствует анализу.");
    return rows;
  }
  async modelPatch(id: string) {
    const row = await this.request(
      `/model-patches/${encodeURIComponent(id)}`,
      modelPatchProposalSchema,
    );
    if (row.patch_id !== id)
      throw new ApiError(0, "Привязка черновика не подтверждена.");
    return row;
  }
  async generateModelPatch(options: GenerateModelPatch) {
    const request = generateModelPatchSchema.parse(options);
    const row = await this.request(
      "/model-patches",
      modelPatchProposalSchema,
      request,
    );
    if (!generationMatches(row, request))
      throw new ApiError(0, "Черновик не соответствует запросу.");
    return row;
  }
  savedModelPatchCapabilities() {
    return this.request(
      "/model-patches/capabilities",
      savedModelPatchCapabilitiesSchema,
      undefined,
      "v2",
    );
  }
  async savedModelPatches(analysis: string, offset = 0) {
    const query = new URLSearchParams({
      analysis_id: analysis,
      limit: "20",
      offset: String(offset),
    });
    const rows = await this.request(
      `/model-patches?${query}`,
      z.array(savedModelPatchProposalSchema).max(20),
      undefined,
      "v2",
    );
    const views = rows.map(commonModelPatch);
    if (
      views.some((row) => row.analysis_id !== analysis) ||
      new Set(views.map((row) => row.patch_id)).size !== rows.length ||
      !(await Promise.all(rows.map(groundedBindingsMatch))).every(Boolean)
    )
      throw new ApiError(0, "История черновиков не соответствует анализу.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return rows;
  }
  async savedModelPatch(id: string) {
    const row = await this.request(
      `/model-patches/${encodeURIComponent(id)}`,
      savedModelPatchProposalSchema,
      undefined,
      "v2",
    );
    if (
      commonModelPatch(row).patch_id !== id ||
      !(await groundedBindingsMatch(row))
    )
      throw new ApiError(0, "Привязка черновика не подтверждена.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async generateGroundedModelPatch(options: GenerateModelPatch) {
    const request = generateModelPatchSchema.parse(options);
    const row = await this.request(
      "/model-patches",
      groundedModelPatchProposalSchema,
      request,
      "v2",
    );
    if (
      !generationMatches(row.projection, request) ||
      !(await groundedBindingsMatch(row))
    )
      throw new ApiError(0, "Черновик не соответствует запросу.");
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    return row;
  }
  async modelReviews(patch: string, offset = 0) {
    const rows = await this.request(
      `/model-patches/${encodeURIComponent(patch)}/verifications?limit=20&offset=${offset}`,
      z.array(savedModelReviewSchema).max(20),
    );
    if (
      rows.some((row) => row.patch_id !== patch) ||
      new Set(rows.map((row) => row.verification_id)).size !== rows.length
    )
      throw new ApiError(0, "История проверок не соответствует черновику.");
    return rows;
  }
  async modelReview(patch: string, id: string) {
    const row = await this.request(
      `/model-patches/${encodeURIComponent(patch)}/verifications/${encodeURIComponent(id)}`,
      savedModelReviewSchema,
    );
    if (row.patch_id !== patch || row.verification_id !== id)
      throw new ApiError(0, "Привязка проверки не подтверждена.");
    return row;
  }
  async verifyModelPatch(patch: string, options: VerifyModelPatch) {
    const request = verifyModelPatchSchema.parse(options);
    const row = await this.request(
      `/model-patches/${encodeURIComponent(patch)}/verify`,
      savedModelReviewSchema,
      request,
    );
    if (
      row.patch_id !== patch ||
      stableJson(row.request) !== stableJson(request)
    )
      throw new ApiError(0, "Проверка не соответствует запросу.");
    return row;
  }
  async modelDecisions(patch: string, offset = 0) {
    const rows = await this.request(
      `/model-patches/${encodeURIComponent(patch)}/decisions?limit=20&offset=${offset}`,
      z.array(savedModelDecisionSchema).max(20),
    );
    if (
      rows.some((row) => row.patch_id !== patch) ||
      new Set(rows.map((row) => row.request.decision_id)).size !== rows.length
    )
      throw new ApiError(0, "История решений не соответствует черновику.");
    return rows;
  }
  async modelDecision(patch: string, id: string) {
    const row = await this.request(
      `/model-patches/${encodeURIComponent(patch)}/decisions/${encodeURIComponent(id)}`,
      savedModelDecisionSchema,
    );
    if (row.patch_id !== patch || row.request.decision_id !== id)
      throw new ApiError(0, "Привязка решения не подтверждена.");
    return row;
  }
  async decideModelPatch(patch: string, options: DecideModelPatch) {
    const request = decideModelPatchSchema.parse(options);
    const row = await this.request(
      `/model-patches/${encodeURIComponent(patch)}/decisions`,
      savedModelDecisionSchema,
      request,
    );
    if (
      row.patch_id !== patch ||
      stableJson(row.request) !== stableJson(request)
    )
      throw new ApiError(0, "Решение не соответствует запросу.");
    return row;
  }
}
