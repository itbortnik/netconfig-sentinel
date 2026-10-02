import { z } from "zod";
import {
  analysisSchema,
  analysisSummarySchema,
  configurationSummarySchema,
  snapshotSchema,
} from "./contracts";
import type { AnalysisOptions, Upload } from "./contracts";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const messages: Record<number, string> = {
  400: "Конфигурация не принята. Проверьте формат, содержимое и ограничения загрузки.",
  401: "Токен не принят. Подключитесь заново.",
  404: "Запись не найдена. Обновите историю.",
  409: "Устройство уже существует с другим hostname, vendor или platform. Проверьте UUID.",
  413: "Загрузка превышает допустимый размер.",
  415: "Неподдерживаемый формат запроса.",
  422: "Параметры запроса не приняты.",
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
    body?: Upload | AnalysisOptions,
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
          ? "Время ожидания истекло. Проверьте историю перед повторной загрузкой или анализом."
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
}
