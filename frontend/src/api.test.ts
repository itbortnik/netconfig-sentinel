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
