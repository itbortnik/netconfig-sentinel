import { z } from "zod";
import type { AnalysisResult } from "./contracts";
import { modelPatchBindingSchema } from "./modelPatches";
import { configurationPredictionSchema } from "./modelReviews";

const hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const label = z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/);
const count = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const modelCard = z
  .strictObject({
    version: z.literal("config-model-card-0.1.0"),
    kind: z.enum(["native", "foundation"]),
    model_sha256: hash,
    training_format: z.enum([
      "multitask-training-0.1.0",
      "multitask-training-0.2.0",
      "foundation-config-transfer-0.1.0",
    ]),
    report_sha256: hash,
    encoder_sha256: hash,
    tokenizer_sha256: hash,
    source_manifest_sha256: hash.nullable(),
    train_fingerprint: hash,
    selection_fingerprint: hash,
    classes: z.array(label).min(1).max(64),
    enabled_heads: z.strictObject({
      anomaly: z.boolean(),
      category: z.boolean(),
      localization: z.boolean(),
      severity: z.boolean(),
      contrastive: z.boolean(),
    }),
    parameter_count: count,
    trainable_parameters: count,
    train_examples: count,
    selection_examples: count,
    target_semantics: z.enum(["injected_mutation", "confirmed_anomaly"]),
    external_pretraining_exposure: z.enum(["unknown", "not_applicable"]),
    status: z.literal("experimental"),
    calibrated: z.literal(false),
    production_quality_proven: z.literal(false),
    activated: z.literal(false),
  })
  .refine(
    (card) =>
      (card.kind === "foundation") ===
        (card.training_format === "foundation-config-transfer-0.1.0") &&
      (card.kind === "foundation") ===
        (card.external_pretraining_exposure === "unknown") &&
      (card.training_format === "multitask-training-0.1.0") ===
        (card.source_manifest_sha256 === null) &&
      card.trainable_parameters < card.parameter_count &&
      new Set(card.classes).size === card.classes.length,
  );
const exposure = z
  .strictObject({
    version: z.literal("fixture-transfer-exposure-0.1.0"),
    policy: z.strictObject({
      max_comparisons: count.max(2_000_000),
      near_duplicate_threshold: z.number().min(0.5).max(1),
    }),
    corpus_sha256: hash,
    downstream_manifest_sha256: hash,
    downstream_content_sha256: hash,
    source_intake_count: count,
    downstream_unique_content_count: count,
    comparisons: count,
    train_overlap_counts: z.strictObject({
      source: z.number().int().nonnegative(),
      raw: z.number().int().nonnegative(),
      sanitized: z.number().int().nonnegative(),
      normalized: z.number().int().nonnegative(),
      template: z.number().int().nonnegative(),
      near: z.number().int().nonnegative(),
    }),
    heldout_overlap_count: z.literal(0),
    physical_pretraining_isolation_proven: z.literal(false),
  })
  .refine(
    (value) =>
      value.comparisons ===
        value.source_intake_count * value.downstream_unique_content_count &&
      value.comparisons <= value.policy.max_comparisons &&
      Object.values(value.train_overlap_counts).every(
        (n) => n <= value.downstream_unique_content_count,
      ),
  );
const fixtureSource = z
  .strictObject({
    version: z.literal("fixture-source-binding-0.1.0"),
    pretraining_sha256: hash,
    report_sha256: hash,
    corpus_sha256: hash,
    source_manifest_sha256: hash,
    exposure,
  })
  .refine(
    (value) =>
      value.corpus_sha256 === value.exposure.corpus_sha256 &&
      value.source_manifest_sha256 ===
        value.exposure.downstream_manifest_sha256,
  );
const fixtureCard = z
  .strictObject({
    ...modelCard.shape,
    version: z.literal("config-model-card-0.2.0"),
    kind: z.literal("native"),
    training_format: z.literal("multitask-training-0.3.0"),
    source_manifest_sha256: hash,
    external_pretraining_exposure: z.literal("not_applicable"),
    pretraining: fixtureSource,
    physical_pretraining_isolation_proven: z.literal(false),
  })
  .refine(
    (card) =>
      card.source_manifest_sha256 === card.pretraining.source_manifest_sha256 &&
      card.trainable_parameters < card.parameter_count &&
      new Set(card.classes).size === card.classes.length,
  );
const localizationObjective = z
  .strictObject({
    policy: z.strictObject({
      version: z.literal("train-balanced-localization-0.1.0"),
      mode: z.literal("train_negative_over_positive"),
      reduction: z.literal("mean_eligible_lines"),
    }),
    train_fingerprint: hash,
    positive_lines: count,
    negative_lines: count,
    eligible_lines: count.min(2),
    positive_weight: z.number().positive(),
  })
  .refine(
    (value) =>
      value.eligible_lines === value.positive_lines + value.negative_lines &&
      value.positive_weight === value.negative_lines / value.positive_lines,
  );
const balancedFixtureCard = z
  .strictObject({
    ...fixtureCard.shape,
    version: z.literal("config-model-card-0.3.0"),
    training_format: z.literal("multitask-training-0.4.0"),
    localization_objective: localizationObjective,
    localization_task_weight: z.number().positive().max(100),
    line_score_semantics: z.literal("cost_sensitive_uncalibrated"),
  })
  .refine(
    (card) =>
      card.source_manifest_sha256 === card.pretraining.source_manifest_sha256 &&
      card.trainable_parameters < card.parameter_count &&
      new Set(card.classes).size === card.classes.length &&
      card.enabled_heads.localization &&
      card.localization_objective.train_fingerprint === card.train_fingerprint,
  );
export const modelCardSchema = z.discriminatedUnion("version", [
  modelCard,
  fixtureCard,
  balancedFixtureCard,
]);
export const configurationInferenceSchema = z
  .strictObject({
    version: z.literal("configuration-inference-0.1.0"),
    model: modelCardSchema,
    prediction: configurationPredictionSchema,
    runtime_torch_version: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[a-zA-Z0-9.+_-]+$/),
    sanitization_version: z.literal("config-sanitizer-0.1.0"),
    risk_fused: z.literal(false),
    calibrated: z.literal(false),
    quality_evaluated: z.literal(false),
    production_quality_proven: z.literal(false),
  })
  .refine((value) => {
    const card = value.model,
      prediction = value.prediction,
      heads = card.enabled_heads;
    return (
      prediction.model_sha256 === card.model_sha256 &&
      heads.anomaly === (prediction.anomaly_score !== null) &&
      heads.category === (prediction.category_scores !== null) &&
      heads.severity === (prediction.severity_scores !== null) &&
      heads.contrastive === prediction.embedding_dimensions > 0 &&
      (!prediction.category_scores ||
        JSON.stringify(Object.keys(prediction.category_scores).sort()) ===
          JSON.stringify([...card.classes].sort())) &&
      (heads.localization || prediction.line_scores.every((x) => x === null))
    );
  });
export const runConfigurationModelSchema = z.strictObject({
  inference_id: z.guid(),
  analysis_id: z.guid(),
  source_sha256: hash,
  model_sha256: hash,
  allow_local_model_context: z.boolean().default(false),
});
export type RunConfigurationModel = z.infer<typeof runConfigurationModelSchema>;
export const configurationModelCapabilitiesSchema = z
  .strictObject({
    version: z.literal("configuration-model-capabilities-0.1.0"),
    inference: z.enum(["configured", "disabled"]),
    model_sha256: hash.nullable(),
    health_checked: z.literal(false),
  })
  .refine(
    (value) =>
      (value.inference === "configured") === (value.model_sha256 !== null),
  );
export type ConfigurationModelCapabilities = z.infer<
  typeof configurationModelCapabilitiesSchema
>;
export const configurationModelRunSchema = z
  .strictObject({
    version: z.literal("configuration-model-run-0.1.0"),
    inference_id: z.guid(),
    analysis_id: z.guid(),
    source: modelPatchBindingSchema,
    analysis_sha256: hash,
    model_sha256: hash,
    total_lines: count.max(10_000),
    created_at: timestamp,
    completed_at: timestamp.nullable(),
    status: z.enum(["pending", "completed", "failed"]),
    intent_sha256: hash,
    outcome_sha256: hash.nullable(),
    report: configurationInferenceSchema.nullable(),
    attempt_limit: z.literal(1),
    risk_fused: z.literal(false),
    requires_human_review: z.literal(true),
  })
  .refine((value) => {
    if (
      Date.parse(value.created_at) < Date.parse(value.source.created_at) ||
      (value.status === "pending") !== (value.completed_at === null) ||
      (value.status === "pending") !== (value.outcome_sha256 === null) ||
      (value.status === "completed") !== (value.report !== null) ||
      (value.completed_at !== null &&
        Date.parse(value.completed_at) < Date.parse(value.created_at))
    )
      return false;
    return (
      value.report === null ||
      (value.report.model.model_sha256 === value.model_sha256 &&
        value.report.prediction.raw_source_sha256 ===
          value.source.source_sha256 &&
        value.report.prediction.total_lines === value.total_lines)
    );
  });
export type ConfigurationModelRun = z.infer<typeof configurationModelRunSchema>;
export function configurationRunMatches(
  run: ConfigurationModelRun,
  request: RunConfigurationModel,
) {
  return (
    request.allow_local_model_context === true &&
    run.inference_id === request.inference_id &&
    run.analysis_id === request.analysis_id &&
    run.source.source_sha256 === request.source_sha256 &&
    run.model_sha256 === request.model_sha256
  );
}
export function configurationRunAnalysisMatches(
  run: ConfigurationModelRun,
  analysis: AnalysisResult,
) {
  return (
    run.analysis_id === analysis.analysis_id &&
    run.source.configuration_id === analysis.configuration_id &&
    run.source.device_id === analysis.device_id &&
    run.source.source_sha256 === analysis.source_sha256
  );
}
