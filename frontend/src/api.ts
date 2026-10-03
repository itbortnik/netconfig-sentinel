import { z } from "zod";
import {
  analysisSchema,
  analysisSummarySchema,
  configurationSummarySchema,
  snapshotSchema,
  modelSchema,
  feedbackSchema,
  snapshotDiffSchema,
} from "./contracts";
import type {
  AnalysisOptions,
  FeedbackSubmission,
  TrainModel,
  Upload,
} from "./contracts";

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
  404: "Запись не найдена. Обновите историю.",
  409: "Конфликт идентификатора или привязки записи. Проверьте UUID устройства, выбранные снимки и историю.",
  413: "Операция превышает допустимый размер или число изменений.",
  415: "Неподдерживаемый формат запроса.",
  422: "Параметры запроса не приняты.",
  429: "Обучение уже выполняется. Дождитесь завершения и обновите реестр.",
  503: "Хранилище недоступно. Проверьте настройки API, миграции и ключ шифрования.",
};

export class ApiClient {
  private readonly controller = new AbortController();
  private token: string;
  constructor(
    token: string,
    private readonly transport: typeof fetch = globalThis.fetch.bind(
      globalThis,
    ),
  ) {
    if (token.length < 32 || !/^[\x21-\x7e]+$/.test(token))
      throw new ApiError(401, messages[401]!);
    this.token = token;
  }
  close() {
    this.token = "";
    this.controller.abort();
  }
  private async request<T>(
    path: string,
    schema: z.ZodType<T>,
    body?: Upload | AnalysisOptions | TrainModel | FeedbackSubmission,
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
}
