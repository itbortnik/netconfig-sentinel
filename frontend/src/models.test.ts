import { expect, it } from "vitest";
import { trainingOptions, statisticalOptions } from "./models";
import { analysisSchema, modelSchema } from "./contracts";
import type { ModelSummary } from "./contracts";
import type { SelectedSnapshot } from "./comparison";

const guid = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const group = {
  vendor: "cisco" as const,
  platform: "ios",
  device_role: "edge",
  site_class: "branch",
  service_profile: "control",
};
const inputs: SelectedSnapshot[] = Array.from({ length: 8 }, (_, n) => ({
  id: guid(n + 10),
  device: guid(n + 20),
  hostname: `training-${n}`,
  hash: String(n).repeat(64),
  created: "2026-10-01T00:00:00Z",
  group: JSON.stringify(Object.values(group)),
  complete: true,
}));
const model: ModelSummary = {
  version: "model-registry-0.1.0",
  model_id: guid(100),
  created_at: "2026-10-01T01:00:00Z",
  status: "experimental",
  artifact_sha256: "a".repeat(64),
  decision_offset: -0.5,
  metadata: {
    model_version: "isolation-forest-0.1.0",
    library_version: "test",
    feature_schema_version: "structured-features-0.1.0",
    feature_names: Array.from({ length: 33 }, (_, i) => `feature-${i}`),
    group,
    sample_count: 8,
    contamination: 0.1,
    random_state: 42,
    estimator_count: 200,
    training_score_min: 0.3,
    training_score_max: 0.7,
    feature_medians: Array(33).fill(0),
    feature_scales: Array(33).fill(1),
  },
  training: inputs.map((item) => ({
    configuration_id: item.id,
    device_id: item.device,
    source_sha256: item.hash,
    created_at: item.created,
  })),
  training_hostnames: inputs.map((item) => item.hostname!),
};
const current: SelectedSnapshot = {
  ...inputs[0]!,
  id: guid(200),
  device: guid(201),
  hash: "b".repeat(64),
  hostname: "target",
  created: "2026-10-02T00:00:00Z",
};

it("uses only explicitly selected snapshots and a separately selected model", () => {
  expect(trainingOptions(inputs)).toEqual({
    configuration_ids: inputs.map((item) => item.id),
    contamination: 0.1,
  });
  expect(statisticalOptions(current, model)).toEqual({
    statistical_model_id: model.model_id,
  });
  expect(modelSchema.safeParse(model).success).toBe(true);
});
it.each(["id", "device", "hostname", "hash", "group", "complete"] as const)(
  "rejects unsuitable training %s",
  (key) => {
    const bad = inputs.map((item) => ({ ...item }));
    if (key === "group") bad[1]!.group = null;
    else if (key === "complete") bad[1]!.complete = false;
    else bad[1]![key] = bad[0]![key]!;
    expect(() => trainingOptions(bad)).toThrow();
  },
);
it("enforces training count limits", () => {
  expect(() => trainingOptions(inputs.slice(0, 7))).toThrow("8–100");
  expect(() => trainingOptions(Array(101).fill(inputs[0]))).toThrow("8–100");
});
it.each([
  { device: inputs[0]!.device },
  { hostname: inputs[0]!.hostname },
  { hash: inputs[0]!.hash },
  { created: "2026-09-01T00:00:00Z" },
  { group: null },
  { complete: false },
])("rejects leakage and incompatible target snapshots", (change) => {
  expect(() => statisticalOptions({ ...current, ...change }, model)).toThrow();
});
it.each([
  { status: "approved" },
  { artifact_sha256: "invalid" },
  { training: model.training.slice(0, 7) },
  { training_hostnames: Array(8).fill("duplicate") },
  { metadata: { ...model.metadata, feature_schema_version: "unsupported" } },
])("rejects altered registry manifests", (change) => {
  expect(modelSchema.safeParse({ ...model, ...change }).success).toBe(false);
});
it("records a completed zero statistical signal and rejects fake availability/weights", () => {
  const result = {
    version: "analysis-api-0.3.0",
    analysis_id: guid(300),
    configuration_id: current.id,
    device_id: current.device,
    source_sha256: current.hash,
    created_at: current.created,
    status: "completed",
    policy_catalog_version: "test",
    findings: [],
    explanations: [],
    limitations: [],
    comparison: null,
    statistical: {
      model,
      score_samples: -0.4,
      decision_function: 0.1,
      prediction: 1,
    },
    risk: {
      assessment_id: guid(301),
      device_id: current.device,
      score: 0,
      level: "low",
      model_version: "test",
      guardrails: [],
      limitations: [],
      components: [
        "policy",
        "peer_group",
        "statistical",
        "transformer",
        "verification",
      ].map((source) => ({
        source,
        status:
          source === "policy" || source === "statistical"
            ? "completed"
            : "unavailable",
        raw_score: source === "policy" || source === "statistical" ? 0 : null,
        configured_weight: {
          policy: 0.35,
          peer_group: 0.15,
          statistical: 0.1,
          transformer: 0.1,
          verification: 0.3,
        }[source as "policy"],
        effective_weight:
          source === "policy"
            ? 0.35 / 0.45
            : source === "statistical"
              ? 0.1 / 0.45
              : 0,
        finding_ids: [],
      })),
    },
  };
  expect(analysisSchema.safeParse(result).success).toBe(true);
  for (const change of [
    { version: "analysis-api-0.2.0" },
    { statistical: null },
    { statistical: { ...result.statistical, prediction: -1 } },
  ])
    expect(analysisSchema.safeParse({ ...result, ...change }).success).toBe(
      false,
    );
  result.risk.components[2]!.effective_weight = 0;
  expect(analysisSchema.safeParse(result).success).toBe(false);
});
