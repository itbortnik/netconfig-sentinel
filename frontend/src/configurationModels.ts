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
export const configurationInferenceSchema = z
  .strictObject({
    version: z.literal("configuration-inference-0.1.0"),
    model: modelCard,
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
