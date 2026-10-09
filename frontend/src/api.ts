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
import {
  generateModelPatchSchema,
  generationMatches,
  modelPatchCapabilitiesSchema,
  modelPatchProposalSchema,
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
  configurationModelCapabilitiesSchema,
  configurationModelRunSchema,
  runConfigurationModelSchema,
  configurationRunMatches,
} from "./configurationModels";
import type { RunConfigurationModel } from "./configurationModels";
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
      | GenerateModelPatch
      | VerifyModelPatch
      | DecideModelPatch
      | RunConfigurationModel,
  ): Promise<T> {
    if (this.controller.signal.aborted)
      throw new DOMException("Disconnected", "AbortError");
    const timeout = AbortSignal.timeout(30_000);
    try {
      const response = await this.transport(`/api/v1${path}`, {
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
      const parsed = schema.safeParse(await response.json());
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
