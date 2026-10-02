import { expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./api";

const token = "test-only-memory-bearer-token-32-characters";
it("uses only same-origin URLs and never puts credentials in query strings", async () => {
  const transport = vi.fn<typeof fetch>().mockResolvedValue(new Response("[]"));
  const api = new ApiClient(token, transport);
  expect(
    await api.configurations(20, "00000000-0000-0000-0000-000000000001"),
  ).toEqual([]);
  const [url, init] = transport.mock.calls[0]!;
  expect(url).toBe(
    "/api/v1/configurations?limit=20&offset=20&device_id=00000000-0000-0000-0000-000000000001",
  );
  expect(init?.headers).toEqual({ Authorization: `Bearer ${token}` });
  expect(init?.cache).toBe("no-store");
  expect(init?.credentials).toBe("omit");
  expect(init?.redirect).toBe("error");
  api.close();
});
it.each([401, 409, 413, 503, 500])(
  "does not reflect HTTP error bodies for %s",
  async (status) => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("private-config-secret", { status }));
    const api = new ApiClient(token, transport);
    await expect(api.configurations()).rejects.toMatchObject({ status });
    try {
      await api.configurations();
    } catch (error) {
      expect(String(error)).not.toContain("private-config-secret");
    }
    api.close();
  },
);
it("rejects incompatible successful responses without exposing their data", async () => {
  const api = new ApiClient(
    token,
    vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response('{"secret":"private-config-secret"}')),
  );
  await expect(api.configurations()).rejects.toBeInstanceOf(ApiError);
  api.close();
});
it("disconnect aborts in-flight requests and prohibits any further request", async () => {
  let signal: AbortSignal | undefined;
  const transport = vi.fn<typeof fetch>(
    (_, init) =>
      new Promise((_, reject) => {
        signal = init?.signal ?? undefined;
        signal?.addEventListener("abort", () =>
          reject(new DOMException("disconnected", "AbortError")),
        );
      }),
  );
  const api = new ApiClient(token, transport);
  const request = api.configurations();
  api.close();
  expect(signal?.aborted).toBe(true);
  await expect(request).rejects.toMatchObject({ name: "AbortError" });
  await expect(api.analyses()).rejects.toMatchObject({ name: "AbortError" });
  expect(transport).toHaveBeenCalledTimes(1);
});
it("sanitizes transport errors and validates tokens locally", async () => {
  const api = new ApiClient(
    token,
    vi.fn<typeof fetch>().mockRejectedValue(new Error("private-config-secret")),
  );
  await expect(api.configurations()).rejects.toThrow("Не удалось связаться");
  expect(() => new ApiClient("short")).toThrow(ApiError);
  expect(() => new ApiClient(token + "\n")).toThrow(ApiError);
  api.close();
});
it("sends explicit comparison IDs in the bounded JSON analysis body, not in the URL", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response("{}", { status: 400 }));
  const api = new ApiClient(token, transport);
  const options = {
    reference_configuration_id: "reference",
    peer_configuration_ids: ["one", "two", "three"],
    statistical_model_id: "selected-model",
  };
  await expect(api.analyze("current", options)).rejects.toBeInstanceOf(
    ApiError,
  );
  const [url, init] = transport.mock.calls[0]!;
  expect(url).toBe("/api/v1/configurations/current/analyze");
  expect(init?.method).toBe("POST");
  expect(init?.body).toBe(JSON.stringify(options));
  expect(init?.headers).toEqual({
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  });
  api.close();
});
it("training is a JSON POST with IDs, never an artifact upload or credential in the URL", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response("{}", { status: 400 }));
  const api = new ApiClient(token, transport);
  const options = {
    configuration_ids: Array.from({ length: 8 }, (_, n) => `snapshot-${n}`),
  };
  await expect(api.trainModel(options)).rejects.toBeInstanceOf(ApiError);
  const [url, init] = transport.mock.calls[0]!;
  expect(url).toBe("/api/v1/models/isolation-forest");
  expect(init?.method).toBe("POST");
  expect(init?.body).toBe(JSON.stringify(options));
  api.close();
});
