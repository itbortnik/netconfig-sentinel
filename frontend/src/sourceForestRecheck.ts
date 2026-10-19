import { z } from "zod";
import {
  modelSchema,
  snapshotBindingSchema,
  stableJson,
  statisticalSchema,
} from "./contracts";
import { statisticalRecheckSchema } from "./modelReviews";
import { savedReviewProofMatches } from "./savedReviewProof";
import type { PatchDraft } from "./patches";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
// Preserve the server's sub-millisecond timestamp bindings.
function instant(value: string) {
  const fraction = (value.match(/\.(\d+)/)?.[1] ?? "").padEnd(9, "0");
  const milliseconds = Date.parse(value);
  // Invalid datetime strings are rejected by the field schema; refinements must
  // still return a validation result instead of throwing on BigInt(NaN).
  return Number.isFinite(milliseconds)
    ? BigInt(milliseconds) * 1_000_000n + BigInt(fraction.slice(3, 9))
    : 0n;
}
const bindingSchema = snapshotBindingSchema.strict();
const strictModelSchema = modelSchema
  .safeExtend({
    metadata: modelSchema.shape.metadata
      .safeExtend({
        group: modelSchema.shape.metadata.shape.group.strict(),
      })
      .strict(),
    training: z.array(bindingSchema).min(8).max(100),
  })
  .strict();
const originalSchema = statisticalSchema
  .safeExtend({ model: strictModelSchema })
  .strict();
export const runSourceForestRecheckSchema = z.strictObject({
  version: z
    .literal("source-forest-request-0.1.0")
    .default("source-forest-request-0.1.0"),
  recheck_id: id,
  draft_sha256: hash,
  before_analysis_id: id,
  before_analysis_sha256: hash,
  model_id: id,
  artifact_sha256: hash,
  allow_local_model_context: z.boolean().default(false),
});
export type RunSourceForestRecheck = z.infer<
  typeof runSourceForestRecheckSchema
>;
const memberSchema = bindingSchema.extend({ canonical_sha256: hash });
export const sourceForestSelectionSchema = z
  .strictObject({
    version: z.literal("source-forest-selection-0.1.0"),
    patch_id: id,
    draft_sha256: hash,
    before: bindingSchema,
    before_analysis_id: id,
    before_analysis_sha256: hash,
    before_analysis_created_at: timestamp,
    original: originalSchema,
  })
  .refine(
    (row) =>
      instant(row.before_analysis_created_at) >=
        instant(row.before.created_at) &&
      instant(row.original.model.created_at) <=
        instant(row.before_analysis_created_at),
  );
export type SourceForestSelection = z.infer<typeof sourceForestSelectionSchema>;
const intentSchema = z
  .strictObject({
    version: z.literal("source-forest-intent-0.1.0"),
    patch_id: id,
    request: runSourceForestRecheckSchema,
    before: memberSchema,
    after: memberSchema,
    selection: sourceForestSelectionSchema,
    created_at: timestamp,
  })
  .refine(({ request, before, after, selection, patch_id, created_at }) => {
    const { canonical_sha256: _canonical, ...binding } = before;
    return (
      request.allow_local_model_context === true &&
      instant(created_at) >= instant(after.created_at) &&
      instant(created_at) >= instant(selection.before_analysis_created_at) &&
      instant(before.created_at) <= instant(after.created_at) &&
      before.device_id === after.device_id &&
      before.configuration_id !== after.configuration_id &&
      before.source_sha256 !== after.source_sha256 &&
      patch_id === selection.patch_id &&
      request.draft_sha256 === selection.draft_sha256 &&
      request.before_analysis_id === selection.before_analysis_id &&
      request.before_analysis_sha256 === selection.before_analysis_sha256 &&
      request.model_id === selection.original.model.model_id &&
      request.artifact_sha256 === selection.original.model.artifact_sha256 &&
      same(binding, selection.before)
    );
  });
const reportSchema = z
  .strictObject({
    version: z.literal("source-forest-report-0.1.0"),
    model: strictModelSchema,
    scores: statisticalRecheckSchema,
    interpretation: z.literal("experimental_scores_not_change_validation"),
  })
  .refine(
    ({ model, scores }) =>
      scores.model_id === model.model_id &&
      scores.artifact_sha256 === model.artifact_sha256 &&
      (
        [
          [
            scores.before_score_samples,
            scores.before_decision_function,
            scores.before_prediction,
          ],
          [
            scores.after_score_samples,
            scores.after_decision_function,
            scores.after_prediction,
          ],
        ] as const
      ).every(
        ([score, decision, prediction]) =>
          score >= -1 &&
          score <= 0 &&
          decision >= -1 &&
          decision <= 1 &&
          decision === score - model.decision_offset &&
          prediction === (decision < 0 ? -1 : 1),
      ),
  );
const outcomeSchema = z
  .strictObject({
    version: z.literal("source-forest-outcome-0.1.0"),
    recheck_id: id,
    intent_sha256: hash,
    completed_at: timestamp,
    execution_status: z.enum(["completed", "failed"]),
    report: reportSchema.nullable(),
    failure_reason: z
      .literal("original_baseline_or_numeric_result_unavailable")
      .nullable(),
  })
  .refine(
    (row) =>
      (row.execution_status === "completed") === (row.report !== null) &&
      (row.execution_status === "failed") === (row.failure_reason !== null),
  );
export function sourceForestBlockers(
  outcome: z.infer<typeof outcomeSchema> | null,
) {
  const result = [
    "formal_verification_not_run",
    "original_statistical_quality_not_proven",
    "all_original_detectors_not_rerun",
    "baseline_approval_not_proven",
    "individual_engineer_review_required",
    "device_syntax_not_verified",
    "management_access_not_verified",
    "rollback_not_verified",
  ];
  if (!outcome) result.push("statistical_execution_unknown");
  else if (outcome.execution_status === "failed")
    result.push("original_statistical_unavailable");
  return result;
}
export const sourceForestRecheckSchema = z
  .strictObject({
    version: z.literal("source-forest-recheck-0.1.0"),
    recheck_id: id,
    patch_id: id,
    draft_sha256: hash,
    before_analysis_id: id,
    before_analysis_sha256: hash,
    model_id: id,
    artifact_sha256: hash,
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
    const { intent, outcome } = row,
      request = intent.request;
    return (
      row.recheck_id === request.recheck_id &&
      row.patch_id === intent.patch_id &&
      (
        [
          "draft_sha256",
          "before_analysis_id",
          "before_analysis_sha256",
          "model_id",
          "artifact_sha256",
        ] as const
      ).every((field) => row[field] === request[field]) &&
      row.execution_status ===
        (outcome?.execution_status ?? "pending_unknown") &&
      same(row.validation_blockers, sourceForestBlockers(outcome)) &&
      (!outcome ||
        (outcome.recheck_id === row.recheck_id &&
          instant(outcome.completed_at) >= instant(intent.created_at) &&
          (!outcome.report ||
            (same(outcome.report.model, intent.selection.original.model) &&
              outcome.report.scores.before_score_samples ===
                intent.selection.original.score_samples &&
              outcome.report.scores.before_decision_function ===
                intent.selection.original.decision_function &&
              outcome.report.scores.before_prediction ===
                intent.selection.original.prediction))))
    );
  });
export type SourceForestRecheck = z.infer<typeof sourceForestRecheckSchema>;
export const sourceForestSummarySchema = z
  .strictObject({
    version: z.literal("source-forest-summary-0.1.0"),
    recheck_id: id,
    patch_id: id,
    draft_sha256: hash,
    before_analysis_id: id,
    model_id: id,
    artifact_sha256: hash,
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
        instant(row.completed_at) >= instant(row.created_at)),
  );
export type SourceForestSummary = z.infer<typeof sourceForestSummarySchema>;
function snapshotBound(
  member: z.infer<typeof bindingSchema>,
  target: PatchDraft["diff"]["before"],
) {
  return (
    member.configuration_id === target.configuration_id &&
    member.device_id === target.device_id &&
    member.source_sha256 === target.source_sha256 &&
    instant(member.created_at) === instant(target.created_at)
  );
}
export function sourceForestSelectionBound(
  row: SourceForestSelection,
  draft: PatchDraft,
  analysisId?: string,
) {
  return (
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    snapshotBound(row.before, draft.diff.before) &&
    (!analysisId || row.before_analysis_id === analysisId)
  );
}
export function sourceForestSummaryBound(
  row: SourceForestSummary,
  draft: PatchDraft,
) {
  return (
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    instant(row.created_at) >= instant(draft.created_at)
  );
}
export async function sourceForestRecheckBound(
  row: SourceForestRecheck,
  draft: PatchDraft,
  request?: RunSourceForestRecheck,
  summary?: SourceForestSummary,
  selection?: SourceForestSelection,
) {
  const { intent, outcome } = row;
  return (
    (await savedReviewProofMatches(row)) &&
    sourceForestSelectionBound(intent.selection, draft) &&
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    instant(intent.created_at) >= instant(draft.created_at) &&
    snapshotBound(intent.before, draft.diff.before) &&
    snapshotBound(intent.after, draft.diff.after) &&
    (!request || same(intent.request, request)) &&
    (!selection || same(intent.selection, selection)) &&
    (!summary ||
      (sourceForestSummaryBound(summary, draft) &&
        (
          [
            "recheck_id",
            "before_analysis_id",
            "model_id",
            "artifact_sha256",
            "review_sha256",
            "execution_status",
          ] as const
        ).every((field) => summary[field] === row[field]) &&
        instant(summary.created_at) === instant(intent.created_at) &&
        (summary.completed_at === null
          ? outcome === null
          : outcome !== null &&
            instant(summary.completed_at) === instant(outcome.completed_at))))
  );
}
