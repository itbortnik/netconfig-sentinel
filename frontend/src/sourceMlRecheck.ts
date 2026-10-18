import { z } from "zod";
import { stableJson } from "./contracts";
import { configurationInferenceSchema } from "./configurationModels";
import { savedReviewProofMatches } from "./savedReviewProof";
import type { PatchDraft } from "./patches";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
export const sourceMlCapabilitiesSchema = z
  .strictObject({
    version: z.literal("source-ml-capabilities-0.1.0"),
    inference: z.enum(["disabled", "configured"]),
    model_sha256: hash.nullable(),
    health_checked: z.literal(false),
    exact_retained_sources_required: z.literal(true),
    request_consent_required: z.literal(true),
    formal_verification: z.literal("not_run"),
  })
  .refine(
    (row) => (row.inference === "configured") === (row.model_sha256 !== null),
  );
export type SourceMlCapabilities = z.infer<typeof sourceMlCapabilitiesSchema>;
export const runSourceMlRecheckSchema = z.strictObject({
  version: z
    .literal("source-ml-request-0.1.0")
    .default("source-ml-request-0.1.0"),
  recheck_id: id,
  draft_sha256: hash,
  model_sha256: hash,
  allow_local_model_context: z.boolean().default(false),
});
export type RunSourceMlRecheck = z.infer<typeof runSourceMlRecheckSchema>;
const memberSchema = z.strictObject({
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
  canonical_sha256: hash,
  total_lines: z.number().int().min(1).max(10000),
});
const intentSchema = z
  .strictObject({
    version: z.literal("source-ml-intent-0.1.0"),
    patch_id: id,
    request: runSourceMlRecheckSchema,
    before: memberSchema,
    after: memberSchema,
    created_at: timestamp,
  })
  .refine(
    ({ before, after, created_at, request }) =>
      request.allow_local_model_context === true &&
      before.device_id === after.device_id &&
      before.configuration_id !== after.configuration_id &&
      before.source_sha256 !== after.source_sha256 &&
      Date.parse(before.created_at) <= Date.parse(after.created_at) &&
      Date.parse(after.created_at) <= Date.parse(created_at),
  );
export const configurationPairSchema = z
  .strictObject({
    version: z.literal("configuration-pair-inference-0.1.0"),
    before: configurationInferenceSchema,
    after: configurationInferenceSchema,
    interpretation: z.literal("experimental_scores_not_change_validation"),
  })
  .refine(
    ({ before, after }) =>
      same(before.model, after.model) &&
      before.runtime_torch_version === after.runtime_torch_version &&
      before.sanitization_version === after.sanitization_version,
  );
const outcomeSchema = z
  .strictObject({
    version: z.literal("source-ml-outcome-0.1.0"),
    recheck_id: id,
    intent_sha256: hash,
    completed_at: timestamp,
    execution_status: z.enum(["completed", "failed"]),
    report: configurationPairSchema.nullable(),
    failure_reason: z.literal("worker_failed_or_unavailable").nullable(),
  })
  .refine(
    (row) =>
      (row.execution_status === "completed") === (row.report !== null) &&
      (row.execution_status === "failed") === (row.failure_reason !== null),
  );
export function sourceMlBlockers(
  outcome: z.infer<typeof outcomeSchema> | null,
) {
  const result = [
    "formal_verification_not_run",
    "change_specific_ml_quality_not_proven",
    "selected_model_independent_quality_not_proven",
    "baseline_approval_not_proven",
    "individual_engineer_review_required",
    "device_syntax_not_verified",
    "management_access_not_verified",
    "rollback_not_verified",
  ];
  if (!outcome) result.push("ml_execution_unknown");
  else if (outcome.execution_status === "failed")
    result.push("selected_ml_unavailable");
  return result;
}
export const sourceMlRecheckSchema = z
  .strictObject({
    version: z.literal("source-ml-recheck-0.1.0"),
    recheck_id: id,
    patch_id: id,
    draft_sha256: hash,
    model_sha256: hash,
    intent: intentSchema,
    outcome: outcomeSchema.nullable(),
    execution_status: z.enum(["pending_unknown", "completed", "failed"]),
    validation_blockers: z.array(z.string().min(1)).max(64),
    review_json: z
      .string()
      .min(1)
      .max(4 * 1024 * 1024),
    review_sha256: hash,
    status: z.literal("needs_review"),
    formal_verification: z.literal("not_run"),
    risk_fused: z.literal(false),
    calibrated: z.literal(false),
    quality_proven: z.literal(false),
    approved: z.literal(false),
    applied: z.literal(false),
  })
  .refine((row) => {
    const { intent, outcome } = row;
    return (
      row.recheck_id === intent.request.recheck_id &&
      row.patch_id === intent.patch_id &&
      row.draft_sha256 === intent.request.draft_sha256 &&
      row.model_sha256 === intent.request.model_sha256 &&
      row.execution_status ===
        (outcome?.execution_status ?? "pending_unknown") &&
      same(row.validation_blockers, sourceMlBlockers(outcome)) &&
      (!outcome ||
        (outcome.recheck_id === row.recheck_id &&
          Date.parse(outcome.completed_at) >= Date.parse(intent.created_at) &&
          (!outcome.report ||
            (
              [
                [outcome.report.before, intent.before],
                [outcome.report.after, intent.after],
              ] as const
            ).every(([report, source]) => {
              const prediction = report.prediction;
              return (
                prediction.model_sha256 === row.model_sha256 &&
                prediction.raw_source_sha256 === source.source_sha256 &&
                prediction.total_lines === source.total_lines
              );
            }))))
    );
  });
export type SourceMlRecheck = z.infer<typeof sourceMlRecheckSchema>;
export const sourceMlSummarySchema = z
  .strictObject({
    version: z.literal("source-ml-summary-0.1.0"),
    recheck_id: id,
    patch_id: id,
    draft_sha256: hash,
    model_sha256: hash,
    review_sha256: hash,
    created_at: timestamp,
    completed_at: timestamp.nullable(),
    execution_status: z.enum(["pending_unknown", "completed", "failed"]),
    status: z.literal("needs_review"),
  })
  .refine(
    (row) =>
      (row.execution_status === "pending_unknown") ===
        (row.completed_at === null) &&
      (row.completed_at === null ||
        Date.parse(row.completed_at) >= Date.parse(row.created_at)),
  );
export type SourceMlSummary = z.infer<typeof sourceMlSummarySchema>;
export function sourceMlSummaryBound(row: SourceMlSummary, draft: PatchDraft) {
  return (
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    Date.parse(row.created_at) >= Date.parse(draft.created_at)
  );
}
export async function sourceMlRecheckBound(
  row: SourceMlRecheck,
  draft: PatchDraft,
  request?: RunSourceMlRecheck,
  summary?: SourceMlSummary,
) {
  const { intent, outcome } = row;
  return (
    (await savedReviewProofMatches(row)) &&
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    Date.parse(intent.created_at) >= Date.parse(draft.created_at) &&
    (
      [
        [intent.before, draft.diff.before],
        [intent.after, draft.diff.after],
      ] as const
    ).every(
      ([member, target]) =>
        member.configuration_id === target.configuration_id &&
        member.device_id === target.device_id &&
        member.source_sha256 === target.source_sha256 &&
        Date.parse(member.created_at) === Date.parse(target.created_at),
    ) &&
    (!request || same(intent.request, request)) &&
    (!summary ||
      (sourceMlSummaryBound(summary, draft) &&
        summary.recheck_id === row.recheck_id &&
        summary.model_sha256 === row.model_sha256 &&
        summary.review_sha256 === row.review_sha256 &&
        Date.parse(summary.created_at) === Date.parse(intent.created_at) &&
        summary.completed_at === (outcome?.completed_at ?? null) &&
        summary.execution_status === row.execution_status))
  );
}
