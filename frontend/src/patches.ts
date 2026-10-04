import { z } from "zod";
import {
  analysisSchema,
  findingSchema,
  snapshotDiffSchema,
  stableJson,
} from "./contracts";
import type { ConfigurationSnapshot, SnapshotDiff } from "./contracts";
import { diffBound, diffSelection } from "./diff";

const id = z.guid();
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true });
const count = z.number().int().nonnegative();
const binding = z.strictObject({
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
});
const ordered = (a: z.infer<typeof binding>, b: z.infer<typeof binding>) =>
  a.configuration_id !== b.configuration_id &&
  a.device_id === b.device_id &&
  a.source_sha256 !== b.source_sha256 &&
  Date.parse(a.created_at) <= Date.parse(b.created_at);
export const createPatchSchema = z
  .strictObject({
    patch_id: id,
    before_configuration_id: id,
    after_configuration_id: id,
    before_source_sha256: hash,
    after_source_sha256: hash,
  })
  .refine(
    (item) =>
      item.before_configuration_id !== item.after_configuration_id &&
      item.before_source_sha256 !== item.after_source_sha256,
  );
export type CreatePatch = z.infer<typeof createPatchSchema>;
export const patchDraftSchema = z
  .strictObject({
    version: z.literal("snapshot-patch-draft-0.1.0"),
    patch_id: id,
    created_at: timestamp,
    draft_sha256: hash,
    status: z.literal("draft"),
    representation: z.literal("normalized_objects"),
    diff: snapshotDiffSchema,
    requires_human_review: z.literal(true),
  })
  .refine(
    (item) =>
      item.diff.source_changed &&
      item.diff.changes.length > 0 &&
      Date.parse(item.created_at) >= Date.parse(item.diff.after.created_at),
  );
export type PatchDraft = z.infer<typeof patchDraftSchema>;
export const patchSummarySchema = z
  .strictObject({
    version: z.literal("snapshot-patch-summary-0.1.0"),
    patch_id: id,
    created_at: timestamp,
    draft_sha256: hash,
    status: z.literal("draft"),
    before: binding,
    after: binding,
    coverage: z.enum(["supported_complete", "partial"]),
    change_count: count.min(1).max(500),
  })
  .refine(
    (item) =>
      ordered(item.before, item.after) &&
      Date.parse(item.created_at) >= Date.parse(item.after.created_at),
  );
export type PatchSummary = z.infer<typeof patchSummarySchema>;
const parseSummary = z
  .strictObject({
    source_sha256: hash,
    confidence: z.number().min(0).max(1),
    warning_count: count,
    unparsed_count: count,
    complete: z.boolean(),
  })
  .refine(
    (item) =>
      item.complete ===
      (item.confidence === 1 &&
        item.warning_count === 0 &&
        item.unparsed_count === 0),
  );
const finding = findingSchema.strict();
const policyChanges = z.strictObject({
  introduced: z.array(finding),
  resolved: z.array(finding),
  persistent: z.array(z.strictObject({ before: finding, after: finding })),
});
type Finding = z.infer<typeof finding>;
const facts = (item: Finding) =>
  stableJson([item.category, item.severity, item.observed, item.expected]);
const collection = (items: Finding[]) =>
  items.map(stableJson).sort().join("\n");
export const preflightSchema = z
  .strictObject({
    version: z.literal("preflight-0.1.0"),
    report_id: id,
    device_id: id,
    reference_id: z.string().min(1).max(256),
    policy_catalog_version: z.string().min(1),
    before: parseSummary,
    after: parseSummary,
    before_policy_findings: z.array(finding),
    after_policy_findings: z.array(finding),
    policy_changes: policyChanges.nullable(),
    reference_status: z.enum(["completed", "unavailable"]),
    reference_findings: z.array(finding),
    current_policy_risk: analysisSchema.shape.risk,
    review_status: z.literal("needs_review"),
    formal_verification: z.literal("not_run"),
    ml_status: z.literal("not_run"),
    requires_human_review: z.literal(true),
    limitations: z.array(z.string()),
  })
  .refine((report) => {
    const complete = report.before.complete && report.after.complete;
    if (
      (report.policy_changes !== null) !== complete ||
      (report.reference_status === "completed" && !complete) ||
      (report.reference_status === "unavailable" &&
        report.reference_findings.length > 0) ||
      (!report.after.complete && report.current_policy_risk !== null)
    )
      return false;
    if (
      [...report.before_policy_findings, ...report.after_policy_findings].some(
        (item) =>
          item.device_id !== report.device_id ||
          item.detector !== "policy_engine" ||
          item.model_version !== report.policy_catalog_version,
      )
    )
      return false;
    if (
      report.reference_findings.some(
        (item) =>
          item.device_id !== report.device_id ||
          item.detector !== "expected_configuration",
      )
    )
      return false;
    const changes = report.policy_changes;
    if (
      changes &&
      (changes.persistent.some(
        (item) => facts(item.before) !== facts(item.after),
      ) ||
        collection(report.before_policy_findings) !==
          collection([
            ...changes.resolved,
            ...changes.persistent.map((item) => item.before),
          ]) ||
        collection(report.after_policy_findings) !==
          collection([
            ...changes.introduced,
            ...changes.persistent.map((item) => item.after),
          ]))
    )
      return false;
    if (
      changes &&
      changes.introduced.some((item) =>
        changes.resolved.some((old) => facts(item) === facts(old)),
      )
    )
      return false;
    const risk = report.current_policy_risk;
    return (
      !risk ||
      (risk.device_id === report.device_id &&
        risk.components.length === 5 &&
        new Set(risk.components.map((item) => item.source)).size === 5 &&
        risk.components.every((item) =>
          item.source === "policy"
            ? item.status === "completed" &&
              item.effective_weight === 1 &&
              item.raw_score !== null &&
              [...item.finding_ids].sort().join() ===
                report.after_policy_findings
                  .map((item) => item.finding_id)
                  .sort()
                  .join()
            : item.status === "unavailable" &&
              item.effective_weight === 0 &&
              item.raw_score === null &&
              item.finding_ids.length === 0,
        ))
    );
  }, "inconsistent local preflight");
export function localBlockers(report: z.infer<typeof preflightSchema>) {
  const result = ["formal_verification_not_run", "human_review_required"];
  if (!report.before.complete || !report.after.complete)
    result.push("incomplete_parsing");
  if (report.reference_status !== "completed")
    result.push("reference_comparison_unavailable");
  if (report.after_policy_findings.length)
    result.push("current_policy_findings");
  if (report.policy_changes?.introduced.length)
    result.push("introduced_policy_findings");
  return result;
}
export const verifyPatchSchema = z.strictObject({
  verification_id: id,
  draft_sha256: hash,
  mode: z.literal("local_preflight"),
});
export type VerifyPatch = z.infer<typeof verifyPatchSchema>;
export const verificationSchema = z
  .strictObject({
    version: z.literal("snapshot-patch-review-0.1.0"),
    verification_id: id,
    patch_id: id,
    draft_sha256: hash,
    created_at: timestamp,
    kind: z.literal("local_preflight"),
    status: z.literal("needs_review"),
    before: binding,
    after: binding,
    preflight: preflightSchema,
    validation_blockers: z.array(z.string()),
  })
  .refine(
    (run) =>
      ordered(run.before, run.after) &&
      Date.parse(run.created_at) >= Date.parse(run.after.created_at) &&
      run.preflight.device_id === run.after.device_id &&
      run.preflight.reference_id === run.before.configuration_id &&
      run.preflight.before.source_sha256 === run.before.source_sha256 &&
      run.preflight.after.source_sha256 === run.after.source_sha256 &&
      stableJson(run.validation_blockers) ===
        stableJson(localBlockers(run.preflight)),
  );
export type VerificationRun = z.infer<typeof verificationSchema>;
export const verificationSummarySchema = z
  .strictObject({
    version: z.literal("snapshot-patch-review-summary-0.1.0"),
    verification_id: id,
    patch_id: id,
    draft_sha256: hash,
    created_at: timestamp,
    kind: z.literal("local_preflight"),
    status: z.literal("needs_review"),
    policy_catalog_version: z.string().min(1),
    before_complete: z.boolean(),
    after_complete: z.boolean(),
    current_policy_finding_count: count,
    introduced_count: count.nullable(),
    resolved_count: count.nullable(),
    formal_verification: z.literal("not_run"),
  })
  .refine(
    (item) =>
      (item.before_complete && item.after_complete) ===
        (item.introduced_count !== null && item.resolved_count !== null) &&
      (item.introduced_count === null) === (item.resolved_count === null),
  );
export type VerificationSummary = z.infer<typeof verificationSummarySchema>;
export function patchIntent(diff: SnapshotDiff, patch_id: string): CreatePatch {
  return createPatchSchema.parse({
    patch_id,
    before_configuration_id: diff.before.configuration_id,
    after_configuration_id: diff.after.configuration_id,
    before_source_sha256: diff.before.source_sha256,
    after_source_sha256: diff.after.source_sha256,
  });
}
export function patchBound(
  draft: PatchDraft,
  snapshot: ConfigurationSnapshot,
  diff?: SnapshotDiff | null,
) {
  return (
    diffBound(draft.diff, draft.diff.before, diffSelection(snapshot)) &&
    (!diff || stableJson(diff) === stableJson(draft.diff))
  );
}
function sameBinding(a: z.infer<typeof binding>, b: z.infer<typeof binding>) {
  return (
    a.configuration_id === b.configuration_id &&
    a.device_id === b.device_id &&
    a.source_sha256 === b.source_sha256 &&
    Date.parse(a.created_at) === Date.parse(b.created_at)
  );
}
export function summaryBound(
  item: PatchSummary,
  snapshot: ConfigurationSnapshot,
) {
  return sameBinding(item.after, {
    ...snapshot,
    source_sha256: snapshot.canonical.source.sha256,
  });
}
export function reviewBound(run: VerificationRun, draft: PatchDraft) {
  return (
    run.patch_id === draft.patch_id &&
    run.draft_sha256 === draft.draft_sha256 &&
    Date.parse(run.created_at) >= Date.parse(draft.created_at) &&
    sameBinding(run.before, draft.diff.before) &&
    sameBinding(run.after, draft.diff.after) &&
    run.preflight.before.confidence === draft.diff.before.parser_confidence &&
    run.preflight.before.warning_count === draft.diff.before.warning_count &&
    run.preflight.before.unparsed_count === draft.diff.before.unparsed_count &&
    run.preflight.after.confidence === draft.diff.after.parser_confidence &&
    run.preflight.after.warning_count === draft.diff.after.warning_count &&
    run.preflight.after.unparsed_count === draft.diff.after.unparsed_count
  );
}
export function summaryMatchesDraft(item: PatchSummary, draft: PatchDraft) {
  return (
    item.patch_id === draft.patch_id &&
    item.draft_sha256 === draft.draft_sha256 &&
    Date.parse(item.created_at) === Date.parse(draft.created_at) &&
    sameBinding(item.before, draft.diff.before) &&
    sameBinding(item.after, draft.diff.after) &&
    item.coverage === draft.diff.coverage &&
    item.change_count === draft.diff.changes.length
  );
}
