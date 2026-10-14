import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import {
  configurationModelRunSchema,
  configurationModelCapabilitiesSchema,
  runConfigurationModelSchema,
} from "./configurationModels";
import type {
  ConfigurationModelRun,
  RunConfigurationModel,
} from "./configurationModels";

const id = "9f7ca108-36f4-42a8-a671-b8c0c65c8297",
  hash = "a".repeat(64);
export const configurationRequest: RunConfigurationModel = {
  inference_id: id,
  analysis_id: id,
  source_sha256: hash,
  model_sha256: hash,
  allow_local_model_context: true,
};
export function configurationFixture(): ConfigurationModelRun {
  return {
    version: "configuration-model-run-0.1.0",
    inference_id: id,
    analysis_id: id,
    source: {
      configuration_id: id,
      device_id: id,
      source_sha256: hash,
      created_at: "2026-10-09T00:00:00Z",
    },
    analysis_sha256: hash,
    model_sha256: hash,
    total_lines: 2,
    created_at: "2026-10-09T00:01:00Z",
    completed_at: "2026-10-09T00:02:00Z",
    status: "completed",
    intent_sha256: hash,
    outcome_sha256: hash,
    attempt_limit: 1,
    risk_fused: false,
    requires_human_review: true,
    report: {
      version: "configuration-inference-0.1.0",
      runtime_torch_version: "synthetic-fixture",
      sanitization_version: "config-sanitizer-0.1.0",
      risk_fused: false,
      calibrated: false,
      quality_evaluated: false,
      production_quality_proven: false,
      model: {
        version: "config-model-card-0.1.0",
        kind: "native",
        model_sha256: hash,
        training_format: "multitask-training-0.1.0",
        report_sha256: hash,
        encoder_sha256: hash,
        tokenizer_sha256: hash,
        source_manifest_sha256: null,
        train_fingerprint: hash,
        selection_fingerprint: hash,
        classes: ["telnet_enabled"],
        enabled_heads: {
          anomaly: true,
          category: true,
          severity: false,
          localization: true,
          contrastive: false,
        },
        parameter_count: 200,
        trainable_parameters: 100,
        train_examples: 4,
        selection_examples: 2,
        target_semantics: "injected_mutation",
        external_pretraining_exposure: "not_applicable",
        status: "experimental",
        calibrated: false,
        production_quality_proven: false,
        activated: false,
      },
      prediction: {
        raw_source_sha256: hash,
        sanitized_source_sha256: hash,
        model_sha256: hash,
        total_lines: 2,
        anomaly_score: 0.3,
        category_scores: { telnet_enabled: 0.4 },
        severity_scores: null,
        line_scores: [0.2, null],
        block_attention: [1],
        embedding_sha256: null,
        embedding_dimensions: 0,
        replacement_counts: {},
        calibrated: false,
      },
    },
  };
}
export function fixtureConfigurationFixture(): ConfigurationModelRun {
  const row = configurationFixture();
  row.report!.model = {
    ...row.report!.model,
    version: "config-model-card-0.2.0",
    kind: "native",
    training_format: "multitask-training-0.3.0",
    source_manifest_sha256: hash,
    external_pretraining_exposure: "not_applicable",
    physical_pretraining_isolation_proven: false,
    pretraining: {
      version: "fixture-source-binding-0.1.0",
      pretraining_sha256: hash,
      report_sha256: hash,
      corpus_sha256: hash,
      source_manifest_sha256: hash,
      exposure: {
        version: "fixture-transfer-exposure-0.1.0",
        policy: { max_comparisons: 200000, near_duplicate_threshold: 0.82 },
        corpus_sha256: hash,
        downstream_manifest_sha256: hash,
        downstream_content_sha256: hash,
        source_intake_count: 3,
        downstream_unique_content_count: 24,
        comparisons: 72,
        train_overlap_counts: {
          source: 0,
          raw: 0,
          sanitized: 0,
          normalized: 0,
          template: 0,
          near: 0,
        },
        heldout_overlap_count: 0,
        physical_pretraining_isolation_proven: false,
      },
    },
  };
  return row;
}
export function balancedConfigurationFixture(): ConfigurationModelRun {
  const row = fixtureConfigurationFixture(),
    card = row.report!.model;
  if (card.version !== "config-model-card-0.2.0")
    throw new Error("fixture card required");
  row.report!.model = {
    ...card,
    version: "config-model-card-0.3.0",
    training_format: "multitask-training-0.4.0",
    localization_objective: {
      policy: {
        version: "train-balanced-localization-0.1.0",
        mode: "train_negative_over_positive",
        reduction: "mean_eligible_lines",
      },
      train_fingerprint: card.train_fingerprint,
      positive_lines: 1,
      negative_lines: 2,
      eligible_lines: 3,
      positive_weight: 2,
    },
    localization_task_weight: 1,
    line_score_semantics: "cost_sensitive_uncalibrated",
  };
  return row;
}
it("accepts explicit cost-sensitive fixture metadata without calibration", () => {
  const value = balancedConfigurationFixture();
  expect(configurationModelRunSchema.parse(value)).toEqual(value);
});
it.each([
  "ratio",
  "counts",
  "train",
  "policy",
  "reduction",
  "objective",
  "task_weight",
  "semantics",
  "head",
  "legacy",
  "physical",
  "activated",
  "calibrated",
])("rejects malformed balanced fixture %s", (damage) => {
  const value = balancedConfigurationFixture(),
    card = value.report!.model;
  if (card.version !== "config-model-card-0.3.0")
    throw new Error("balanced card required");
  if (damage === "ratio") card.localization_objective.positive_weight = 3;
  if (damage === "counts") card.localization_objective.eligible_lines++;
  if (damage === "train")
    card.localization_objective.train_fingerprint = "b".repeat(64);
  if (damage === "policy")
    Object.assign(card.localization_objective.policy, { mode: "selection" });
  if (damage === "reduction")
    Object.assign(card.localization_objective.policy, { reduction: "sum" });
  if (damage === "objective")
    Reflect.deleteProperty(card, "localization_objective");
  if (damage === "task_weight") card.localization_task_weight = 0;
  if (damage === "semantics")
    Object.assign(card, { line_score_semantics: "calibrated_probability" });
  if (damage === "head") card.enabled_heads.localization = false;
  if (damage === "legacy")
    Object.assign(card, {
      version: "config-model-card-0.2.0",
      training_format: "multitask-training-0.3.0",
    });
  if (damage === "physical")
    Object.assign(card, { physical_pretraining_isolation_proven: true });
  if (damage === "activated") Object.assign(card, { activated: true });
  if (damage === "calibrated") Object.assign(card, { calibrated: true });
  expect(configurationModelRunSchema.safeParse(value).success).toBe(false);
});
it("accepts explicit fixture provenance without manufacturing independent quality", () => {
  const value = fixtureConfigurationFixture();
  expect(configurationModelRunSchema.parse(value)).toEqual(value);
});
it.each([
  "physical",
  "heldout",
  "count",
  "budget",
  "corpus",
  "manifest",
  "format",
  "kind",
  "missing",
  "activated",
])("rejects malformed fixture %s", (damage) => {
  const value = fixtureConfigurationFixture(),
    card = value.report!.model;
  if (card.version !== "config-model-card-0.2.0")
    throw new Error("fixture card required");
  const exposure = card.pretraining.exposure;
  if (damage === "physical")
    Object.assign(card, { physical_pretraining_isolation_proven: true });
  if (damage === "heldout")
    Object.assign(exposure, { heldout_overlap_count: 1 });
  if (damage === "count") exposure.comparisons++;
  if (damage === "budget") exposure.policy.max_comparisons = 1;
  if (damage === "corpus") exposure.corpus_sha256 = "b".repeat(64);
  if (damage === "manifest") card.source_manifest_sha256 = "b".repeat(64);
  if (damage === "format")
    Object.assign(card, { training_format: "multitask-training-0.2.0" });
  if (damage === "kind") Object.assign(card, { kind: "foundation" });
  if (damage === "missing") Reflect.deleteProperty(card, "pretraining");
  if (damage === "activated") Object.assign(card, { activated: true });
  expect(configurationModelRunSchema.safeParse(value).success).toBe(false);
});
it("accepts a bounded synthetic result without pretending it is quality evidence", () => {
  expect(configurationModelRunSchema.parse(configurationFixture())).toEqual(
    configurationFixture(),
  );
});
it.each([
  "source",
  "model",
  "classes",
  "head",
  "severity",
  "lines",
  "embedding",
  "attention",
  "quality",
  "risk",
  "time",
  "pending",
  "unknown",
])("rejects inconsistent %s", (damage) => {
  const value = configurationFixture(),
    prediction = value.report!.prediction;
  if (damage === "source") prediction.raw_source_sha256 = "b".repeat(64);
  if (damage === "model") prediction.model_sha256 = "b".repeat(64);
  if (damage === "classes") prediction.category_scores = { invented: 0.4 };
  if (damage === "head") value.report!.model.enabled_heads.anomaly = false;
  if (damage === "severity")
    prediction.severity_scores = {
      info: 0.2,
      low: 0.2,
      medium: 0.2,
      high: 0.2,
      critical: 0.2,
    };
  if (damage === "lines") prediction.line_scores = [0.3];
  if (damage === "embedding") prediction.embedding_dimensions = 8;
  if (damage === "attention") prediction.block_attention = [0.5];
  if (damage === "quality")
    Object.assign(value.report!, { quality_evaluated: true });
  if (damage === "risk") Object.assign(value, { risk_fused: true });
  if (damage === "time") value.completed_at = "2026-10-08T00:00:00Z";
  if (damage === "pending") value.status = "pending";
  if (damage === "unknown") Object.assign(value, { approved: true });
  expect(configurationModelRunSchema.safeParse(value).success).toBe(false);
});
it.each(["pending", "failed"] as const)(
  "accepts %s only without scores",
  (status) => {
    const value = configurationFixture();
    value.status = status;
    value.report = null;
    if (status === "pending") {
      value.completed_at = null;
      value.outcome_sha256 = null;
    }
    expect(configurationModelRunSchema.safeParse(value).success).toBe(true);
  },
);
it.each([1, "true", null])("does not coerce consent %j", (consent) => {
  expect(
    runConfigurationModelSchema.safeParse({
      ...configurationRequest,
      allow_local_model_context: consent,
    }).success,
  ).toBe(false);
});
it("capabilities are fixed configuration, not a health check", () => {
  const value = {
    version: "configuration-model-capabilities-0.1.0",
    inference: "disabled",
    model_sha256: null,
    health_checked: false,
  };
  expect(configurationModelCapabilitiesSchema.safeParse(value).success).toBe(
    true,
  );
  expect(
    configurationModelCapabilitiesSchema.safeParse({
      ...value,
      inference: "configured",
    }).success,
  ).toBe(false);
  expect(
    configurationModelCapabilitiesSchema.safeParse({
      ...value,
      health_checked: true,
    }).success,
  ).toBe(false);
});
it("POST requires explicit consent and checks returned request bindings", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response(JSON.stringify(configurationFixture())));
  const client = new ApiClient(
    "owned-config-model-test-token-000001",
    transport,
  );
  await expect(
    client.runConfigurationModel({
      ...configurationRequest,
      allow_local_model_context: false,
    }),
  ).rejects.toMatchObject({ status: 403 });
  expect(transport).not.toHaveBeenCalled();
  await expect(
    client.runConfigurationModel(configurationRequest),
  ).resolves.toEqual(configurationFixture());
  expect(transport.mock.calls[0]![1]?.method).toBe("POST");
  transport.mockResolvedValue(
    new Response(JSON.stringify(configurationFixture())),
  );
  await expect(
    client.runConfigurationModel({
      ...configurationRequest,
      model_sha256: "b".repeat(64),
    }),
  ).rejects.toMatchObject({ status: 0 });
});
it("reconciliation and history are GET only and reject foreign/duplicate rows", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response(JSON.stringify(configurationFixture())));
  const client = new ApiClient(
    "owned-config-model-test-token-000001",
    transport,
  );
  await client.configurationModelRun(id, configurationRequest);
  expect(transport.mock.calls[0]![1]?.method).toBe("GET");
  transport.mockResolvedValue(
    new Response(
      JSON.stringify([configurationFixture(), configurationFixture()]),
    ),
  );
  await expect(client.configurationModelRuns(id)).rejects.toMatchObject({
    status: 0,
  });
});
it("failed POST is never retried automatically", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response("private-reason", { status: 503 }));
  const client = new ApiClient(
    "owned-config-model-test-token-000001",
    transport,
  );
  await expect(
    client.runConfigurationModel(configurationRequest),
  ).rejects.toMatchObject({ status: 503 });
  expect(transport).toHaveBeenCalledTimes(1);
});
