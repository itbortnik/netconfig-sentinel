import { expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./api";
import { groundedFixture } from "./groundedModelPatches.fixtures";

const token = "test-only-memory-bearer-token-32-characters";
it("uses explicit v2 for grounded generation and mixed history without unwrapping provenance", async () => {
  const value = await groundedFixture();
  const view = value.projection;
  const options = {
    patch_id: view.patch_id,
    analysis_id: view.analysis_id,
    finding_id: view.finding_id,
    finding_sha256: view.finding_sha256,
    source_sha256: view.source_sha256,
    baseline_configuration_id: null,
    baseline_source_sha256: null,
    allow_local_model_context: true,
  };
  const legacy = {
    ...view,
    patch_id: "00000000-0000-0000-0000-000000000006",
  };
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(Response.json(value))
    .mockResolvedValueOnce(Response.json(value))
    .mockResolvedValueOnce(Response.json([legacy, value]));
  const api = new ApiClient(token, transport);
  expect(await api.generateGroundedModelPatch(options)).toEqual(value);
  expect(await api.savedModelPatch(view.patch_id)).toEqual(value);
  expect(await api.savedModelPatches(view.analysis_id, 20)).toEqual([
    legacy,
    value,
  ]);
  expect(transport.mock.calls.map(([url]) => url)).toEqual([
    "/api/v2/model-patches",
    `/api/v2/model-patches/${view.patch_id}`,
    `/api/v2/model-patches?analysis_id=${view.analysis_id}&limit=20&offset=20`,
  ]);
  const init = transport.mock.calls[0]![1]!;
  expect(init.method).toBe("POST");
  expect(JSON.parse(init.body as string)).toEqual(options);
  expect(init.credentials).toBe("omit");
  expect(init.redirect).toBe("error");
  expect(init.headers).toEqual({
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  });
  api.close();
});

it("keeps v1 generation/get strict legacy and performs no protocol fallback or retry", async () => {
  const value = await groundedFixture();
  const view = value.projection;
  const request = {
    patch_id: view.patch_id,
    analysis_id: view.analysis_id,
    finding_id: view.finding_id,
    finding_sha256: view.finding_sha256,
    source_sha256: view.source_sha256,
    baseline_configuration_id: null,
    baseline_source_sha256: null,
    allow_local_model_context: true,
  };
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(Response.json(view))
    .mockResolvedValueOnce(Response.json(view))
    .mockResolvedValueOnce(Response.json(value))
    .mockResolvedValueOnce(Response.json(view));
  const api = new ApiClient(token, transport);
  expect(await api.generateModelPatch(request)).toEqual(view);
  expect(await api.modelPatch(view.patch_id)).toEqual(view);
  await expect(api.modelPatch(view.patch_id)).rejects.toMatchObject({
    status: 0,
  });
  await expect(api.generateGroundedModelPatch(request)).rejects.toMatchObject({
    status: 0,
  });
  expect(transport.mock.calls.map(([url]) => url)).toEqual([
    "/api/v1/model-patches",
    `/api/v1/model-patches/${view.patch_id}`,
    `/api/v1/model-patches/${view.patch_id}`,
    "/api/v2/model-patches",
  ]);
  api.close();
});

it("rejects tampered grounded hashes and inconsistent history without reflecting data", async () => {
  const value = await groundedFixture();
  for (const changed of [
    { ...value, projection_sha256: "f".repeat(64) },
    {
      ...value,
      source_facts: { ...value.source_facts, observed_ssh_enabled: null },
    },
    {
      ...value,
      projection: {
        ...value.projection,
        patch_id: "00000000-0000-0000-0000-000000000999",
      },
    },
    {
      ...value,
      model_answer: { ...value.model_answer, summary: "private-config-secret" },
    },
  ]) {
    const transport = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => Response.json(changed));
    const api = new ApiClient(token, transport);
    await expect(
      api.savedModelPatch(value.projection.patch_id),
    ).rejects.toMatchObject({ status: 0 });
    try {
      await api.savedModelPatch(value.projection.patch_id);
    } catch (error) {
      expect(String(error)).not.toContain("private-config-secret");
    }
    api.close();
  }
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(Response.json([value, value]))
    .mockResolvedValueOnce(
      Response.json([
        {
          ...value,
          projection: {
            ...value.projection,
            analysis_id: "00000000-0000-0000-0000-000000000999",
          },
        },
      ]),
    )
    .mockResolvedValueOnce(
      Response.json([
        {
          ...value,
          facts_binding_sha256: "f".repeat(64),
          model_answer: {
            ...value.model_answer,
            facts_binding_sha256: "f".repeat(64),
          },
        },
      ]),
    );
  const api = new ApiClient(token, transport);
  for (let i = 0; i < 3; i++)
    await expect(
      api.savedModelPatches(value.projection.analysis_id),
    ).rejects.toMatchObject({ status: 0 });
  api.close();
});

it("reads saved capabilities in v2 and preserves separate operator controls", async () => {
  const value = {
    version: "saved-model-patch-capabilities-0.2.0",
    legacy: {
      version: "model-patch-capabilities-0.1.0",
      generation: "disabled",
      network_engine: "disabled",
      transformer: "disabled",
      transformer_sha256: null,
      individual_identity_verified: false,
      application_supported: false,
    },
    grounded_generation: "configured",
    grounded_protocol: "grounded-model-patch-0.1.0",
  };
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(Response.json(value));
  const api = new ApiClient(token, transport);
  expect(await api.savedModelPatchCapabilities()).toEqual(value);
  expect(transport.mock.calls[0]![0]).toBe(
    "/api/v2/model-patches/capabilities",
  );
  api.close();
});

it("a lost grounded response sends one POST only and permits an explicit GET", async () => {
  const value = await groundedFixture();
  const view = value.projection;
  const transport = vi
    .fn<typeof fetch>()
    .mockRejectedValueOnce(new Error("private-config-secret"))
    .mockResolvedValueOnce(Response.json(value));
  const api = new ApiClient(token, transport);
  await expect(
    api.generateGroundedModelPatch({
      patch_id: view.patch_id,
      analysis_id: view.analysis_id,
      finding_id: view.finding_id,
      finding_sha256: view.finding_sha256,
      source_sha256: view.source_sha256,
      baseline_configuration_id: null,
      baseline_source_sha256: null,
      allow_local_model_context: true,
    }),
  ).rejects.toMatchObject({ status: 0 });
  expect(transport).toHaveBeenCalledTimes(1);
  expect(await api.savedModelPatch(view.patch_id)).toEqual(value);
  expect(transport.mock.calls.map(([, init]) => init?.method)).toEqual([
    "POST",
    "GET",
  ]);
  api.close();
});
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
