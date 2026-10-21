import { z } from "zod";
import {
  analysisSchema,
  findingSchema,
  snapshotBindingSchema,
  stableJson,
} from "./contracts";
import { makeExpandedComparisonSchema } from "./expandedComparisons";
import { makeMeasuredComparisonSchema } from "./measuredComparisons";
import { deterministicReferenceSchema as referenceSchema } from "./deterministicReference";
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
function withoutCanonical(member: z.infer<typeof memberSchema>) {
  const { canonical_sha256: _hash, ...binding } = member;
  return binding;
}
const finding = findingSchema.strict();
const comparison = analysisSchema.shape.comparison.unwrap().unwrap();
const expanded = makeExpandedComparisonSchema(bindingSchema, finding);
const measured = makeMeasuredComparisonSchema(bindingSchema, finding);
const peerEvaluation = z.union([
  expanded.shape.peer_evaluation.unwrap(),
  measured.shape.peer_evaluation.unwrap(),
]);
const originalSchema = z
  .strictObject({
    policy_catalog_version: z.string().min(1).max(128),
    comparison: comparison.nullable(),
    findings: z.array(finding).max(10000),
    statistical_present: z.boolean(),
  })
  .refine((row) => {
    const context = row.comparison;
    const versions: Record<string, string> = {
      policy_engine: row.policy_catalog_version,
    };
    if (context?.reference)
      versions.expected_configuration =
        "version" in context
          ? "expected-config-0.2.0"
          : "expected-config-0.1.0";
    if (context?.peer_baseline)
      versions.peer_baseline = context.peer_baseline.model_version;
    return (
      new Set(row.findings.map((f) => f.finding_id)).size ===
        row.findings.length &&
      row.findings.every((f) => versions[f.detector] === f.model_version) &&
      (!(context && "peer_evaluation" in context && context.peer_evaluation) ||
        same(
          context.peer_evaluation.findings,
          row.findings.filter((f) => f.detector === "peer_baseline"),
        ))
    );
  });
export const runSourceDeterministicRecheckSchema = z.strictObject({
  version: z
    .literal("source-deterministic-request-0.1.0")
    .default("source-deterministic-request-0.1.0"),
  recheck_id: id,
  draft_sha256: hash,
  before_analysis_id: id,
  before_analysis_sha256: hash,
  reference_canonical_sha256: hash.nullable(),
  allow_local_analysis_context: z.boolean().default(false),
});
export type RunSourceDeterministicRecheck = z.infer<
  typeof runSourceDeterministicRecheckSchema
>;
const memberSchema = bindingSchema.extend({ canonical_sha256: hash });
export const sourceDeterministicSelectionSchema = z
  .strictObject({
    version: z.literal("source-deterministic-selection-0.1.0"),
    patch_id: id,
    draft_sha256: hash,
    before: bindingSchema,
    before_analysis_id: id,
    before_analysis_sha256: hash,
    before_analysis_created_at: timestamp,
    original: originalSchema,
    reference: memberSchema.nullable(),
  })
  .refine((row) => {
    const context = row.original.comparison,
      selected = context?.reference ?? null;
    return (
      instant(row.before_analysis_created_at) >=
        instant(row.before.created_at) &&
      row.original.findings.every(
        (f) => f.device_id === row.before.device_id,
      ) &&
      (selected === null) === (row.reference === null) &&
      (!row.reference ||
        (same(withoutCanonical(row.reference), selected) &&
          row.reference.device_id === row.before.device_id &&
          row.reference.configuration_id !== row.before.configuration_id &&
          instant(row.reference.created_at) <=
            instant(row.before.created_at))) &&
      (!context ||
        context.peers.every(
          (p) =>
            p.device_id !== row.before.device_id &&
            p.configuration_id !== row.before.configuration_id &&
            p.source_sha256 !== row.before.source_sha256 &&
            instant(p.created_at) <= instant(row.before.created_at),
        )) &&
      (!(context && "peer_evaluation" in context && context.peer_evaluation) ||
        (context.peer_evaluation.device_id === row.before.device_id &&
          context.peer_evaluation.source_sha256 === row.before.source_sha256))
    );
  });
export type SourceDeterministicSelection = z.infer<
  typeof sourceDeterministicSelectionSchema
>;
const intentSchema = z
  .strictObject({
    version: z.literal("source-deterministic-intent-0.1.0"),
    patch_id: id,
    request: runSourceDeterministicRecheckSchema,
    before: memberSchema,
    after: memberSchema,
    selection: sourceDeterministicSelectionSchema,
    reference_projection: referenceSchema.nullable(),
    created_at: timestamp,
  })
  .refine(
    ({
      request,
      before,
      after,
      selection,
      patch_id,
      created_at,
      reference_projection,
    }) => {
      const { canonical_sha256: _canonical, ...binding } = before;
      return (
        request.allow_local_analysis_context === true &&
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
        request.reference_canonical_sha256 ===
          (selection.reference?.canonical_sha256 ?? null) &&
        (reference_projection === null) === (selection.reference === null) &&
        (!reference_projection ||
          (reference_projection.reference_id ===
            selection.reference?.configuration_id &&
            reference_projection.device_id === before.device_id &&
            reference_projection.source_sha256 ===
              selection.reference?.source_sha256 &&
            reference_projection.version ===
              (selection.original.comparison &&
              "version" in selection.original.comparison
                ? "expected-config-0.2.0"
                : "expected-config-0.1.0"))) &&
        (!selection.original.comparison ||
          selection.original.comparison.peers.every(
            (p) =>
              p.device_id !== after.device_id &&
              p.configuration_id !== after.configuration_id &&
              p.source_sha256 !== after.source_sha256 &&
              instant(p.created_at) <= instant(after.created_at),
          )) &&
        same(binding, selection.before)
      );
    },
  );
const sideSchema = z
  .strictObject({
    configuration_id: id,
    source_sha256: hash,
    policy_findings: z.array(finding).max(10000),
    reference_findings: z.array(finding).nullable(),
    peer_findings: z.array(finding).nullable(),
    peer_evaluation: peerEvaluation.nullable(),
  })
  .refine((row) => {
    const groups = [
      [row.policy_findings, "policy_engine"],
      [row.reference_findings ?? [], "expected_configuration"],
      [row.peer_findings ?? [], "peer_baseline"],
    ] as const;
    const all = groups.flatMap(([rows]) => rows);
    return (
      new Set(all.map((f) => f.finding_id)).size === all.length &&
      groups.every(([rows, detector]) =>
        rows.every((f) => f.detector === detector),
      ) &&
      (!row.peer_evaluation ||
        (row.peer_findings !== null &&
          same(row.peer_evaluation.findings, row.peer_findings) &&
          row.peer_evaluation.source_sha256 === row.source_sha256 &&
          row.peer_evaluation.status === "completed"))
    );
  });
const policyChanges = z.strictObject({
  introduced: z.array(finding),
  resolved: z.array(finding),
  persistent: z.array(z.strictObject({ before: finding, after: finding })),
});
const semantic = (f: z.infer<typeof finding>) =>
  stableJson([f.category, f.severity, f.observed, f.expected]);
const multiset = (rows: z.infer<typeof finding>[]) =>
  rows.map(stableJson).sort().join("\n");
const reportSchema = z
  .strictObject({
    version: z.literal("source-deterministic-report-0.1.0"),
    policy_catalog_version: z.string().min(1).max(128),
    comparison_version: z.enum(["not_selected", "0.1.0", "0.2.0", "0.3.0"]),
    before: sideSchema,
    after: sideSchema,
    reference_projection: referenceSchema.nullable(),
    peer_profile_sha256: hash.nullable(),
    policy_changes: policyChanges,
  })
  .refine((row) => {
    const changes = row.policy_changes,
      old = [...changes.resolved, ...changes.persistent.map((p) => p.before)],
      next = [...changes.introduced, ...changes.persistent.map((p) => p.after)];
    const resolved = new Set(changes.resolved.map(semantic));
    const all = [...row.before.policy_findings, ...row.after.policy_findings];
    return (
      all.every((f) => f.model_version === row.policy_catalog_version) &&
      new Set(all.map((f) => f.device_id)).size <= 1 &&
      multiset(old) === multiset(row.before.policy_findings) &&
      multiset(next) === multiset(row.after.policy_findings) &&
      changes.persistent.every(
        (p) => semantic(p.before) === semantic(p.after),
      ) &&
      changes.introduced.every((f) => !resolved.has(semantic(f)))
    );
  });
function reportBound(
  report: z.infer<typeof reportSchema>,
  intent: z.infer<typeof intentSchema>,
) {
  const original = intent.selection.original,
    context = original.comparison,
    profile = context?.peer_baseline ?? null;
  const version = context
    ? "version" in context
      ? context.version.endsWith("0.3.0")
        ? "0.3.0"
        : "0.2.0"
      : "0.1.0"
    : "not_selected";
  if (
    report.policy_catalog_version !== original.policy_catalog_version ||
    report.comparison_version !== version ||
    !same(report.reference_projection, intent.reference_projection) ||
    (report.peer_profile_sha256 === null) !== (profile === null)
  )
    return false;
  const before = [
    ...report.before.policy_findings,
    ...(report.before.reference_findings ?? []),
    ...(report.before.peer_findings ?? []),
  ];
  if (
    !same(before, original.findings) ||
    (context &&
      "peer_evaluation" in context &&
      !same(report.before.peer_evaluation, context.peer_evaluation))
  )
    return false;
  return (
    [
      [report.before, intent.before],
      [report.after, intent.after],
    ] as const
  ).every(([side, member]) => {
    if (
      side.configuration_id !== member.configuration_id ||
      side.source_sha256 !== member.source_sha256 ||
      (side.reference_findings !== null) !==
        (intent.reference_projection !== null) ||
      (side.peer_findings !== null) !== (profile !== null)
    )
      return false;
    if (
      [
        ...side.policy_findings,
        ...(side.reference_findings ?? []),
        ...(side.peer_findings ?? []),
      ].some((f) => f.device_id !== member.device_id)
    )
      return false;
    const reference = intent.reference_projection;
    if (
      reference &&
      side.reference_findings?.some(
        (f) =>
          f.model_version !== reference.version ||
          f.expected.reference_id !== reference.reference_id ||
          f.expected.source_sha256 !== reference.source_sha256 ||
          f.observed.source_sha256 !== side.source_sha256,
      )
    )
      return false;
    if (!profile) return side.peer_evaluation === null;
    if (
      side.peer_findings?.some((f) => f.model_version !== profile.model_version)
    )
      return false;
    if (context && "version" in context) {
      const evaluation = side.peer_evaluation;
      if (
        !evaluation ||
        evaluation.device_id !== member.device_id ||
        evaluation.baseline_sha256 !== context.peer_evaluation?.baseline_sha256
      )
        return false;
      return (
        context.version === "comparison-context-0.3.0" ? measured : expanded
      ).safeParse({ ...context, peer_evaluation: evaluation }).success;
    }
    return (
      side.peer_evaluation === null &&
      !!context &&
      side.peer_findings!.every((f) => {
        const feature =
          profile.model_version === "peer-baseline-0.1.0"
            ? profile.features.find(
                (v) => `baseline.${v.field}_deviation` === f.category,
              )
            : undefined;
        return (
          !!feature &&
          same(f.expected, {
            [feature.field]: feature.expected,
            peer_support_count: feature.support_count,
            peer_sample_count: feature.sample_count,
          }) &&
          f.confidence === feature.support_count / feature.sample_count &&
          f.anomaly_score === f.confidence
        );
      })
    );
  });
}
const outcomeSchema = z
  .strictObject({
    version: z.literal("source-deterministic-outcome-0.1.0"),
    recheck_id: id,
    intent_sha256: hash,
    completed_at: timestamp,
    execution_status: z.enum(["completed", "failed"]),
    report: reportSchema.nullable(),
    failure_reason: z
      .literal("original_context_or_deterministic_result_unavailable")
      .nullable(),
  })
  .refine(
    (row) =>
      (row.execution_status === "completed") === (row.report !== null) &&
      (row.execution_status === "failed") === (row.failure_reason !== null),
  );
export function sourceDeterministicBlockers(
  original: z.infer<typeof originalSchema>,
  outcome: z.infer<typeof outcomeSchema> | null,
) {
  const result = [
    "formal_verification_not_run",
    "deterministic_evidence_not_combined_with_qualified_verification",
    "deterministic_quality_not_proven",
    "baseline_approval_not_proven",
    "individual_engineer_review_required",
    "device_syntax_not_verified",
    "management_access_not_verified",
    "rollback_not_verified",
  ];
  if (original.statistical_present)
    result.push("original_statistical_not_rerun");
  if (!outcome) result.push("deterministic_execution_unknown");
  else if (outcome.execution_status === "failed")
    result.push("original_deterministic_unavailable");
  return result;
}
export const sourceDeterministicRecheckSchema = z
  .strictObject({
    version: z.literal("source-deterministic-recheck-0.1.0"),
    recheck_id: id,
    patch_id: id,
    draft_sha256: hash,
    before_analysis_id: id,
    before_analysis_sha256: hash,
    reference_canonical_sha256: hash.nullable(),
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
          "reference_canonical_sha256",
        ] as const
      ).every((field) => row[field] === request[field]) &&
      row.execution_status ===
        (outcome?.execution_status ?? "pending_unknown") &&
      same(
        row.validation_blockers,
        sourceDeterministicBlockers(intent.selection.original, outcome),
      ) &&
      (!outcome ||
        (outcome.recheck_id === row.recheck_id &&
          instant(outcome.completed_at) >= instant(intent.created_at) &&
          (!outcome.report || reportBound(outcome.report, intent))))
    );
  });
export type SourceDeterministicRecheck = z.infer<
  typeof sourceDeterministicRecheckSchema
>;
export const sourceDeterministicSummarySchema = z
  .strictObject({
    version: z.literal("source-deterministic-summary-0.1.0"),
    recheck_id: id,
    patch_id: id,
    draft_sha256: hash,
    before_analysis_id: id,
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
export type SourceDeterministicSummary = z.infer<
  typeof sourceDeterministicSummarySchema
>;
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
export function sourceDeterministicSelectionBound(
  row: SourceDeterministicSelection,
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
export function sourceDeterministicSummaryBound(
  row: SourceDeterministicSummary,
  draft: PatchDraft,
) {
  return (
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    instant(row.created_at) >= instant(draft.created_at)
  );
}
export async function sourceDeterministicRecheckBound(
  row: SourceDeterministicRecheck,
  draft: PatchDraft,
  request?: RunSourceDeterministicRecheck,
  summary?: SourceDeterministicSummary,
  selection?: SourceDeterministicSelection,
) {
  const { intent, outcome } = row;
  return (
    (await savedReviewProofMatches(row)) &&
    (await profileProofMatches(row)) &&
    sourceDeterministicSelectionBound(intent.selection, draft) &&
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    instant(intent.created_at) >= instant(draft.created_at) &&
    snapshotBound(intent.before, draft.diff.before) &&
    snapshotBound(intent.after, draft.diff.after) &&
    (!request || same(intent.request, request)) &&
    (!selection || same(intent.selection, selection)) &&
    (!summary ||
      (sourceDeterministicSummaryBound(summary, draft) &&
        (
          [
            "recheck_id",
            "before_analysis_id",

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

// Fingerprint the original Python wire bytes. JSON.stringify would change 1.0,
// small exponents and escaped Unicode in historical profile data.
async function profileProofMatches(row: SourceDeterministicRecheck) {
  const context = row.intent.selection.original.comparison;
  const report = row.outcome?.report;
  if (!report || !context?.peer_baseline) return true;
  try {
    const tokens = [
      ...row.review_json.matchAll(
        /"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,]+/gu,
      ),
    ];
    const wanted = [
      "intent",
      "selection",
      "original",
      "comparison",
      "peer_baseline",
    ];
    let cursor = 0,
      raw: string | undefined;
    function value(path: string[], depth: number): void {
      if (depth > 64) throw new Error("proof nesting exceeds budget");
      const start = tokens[cursor]!,
        token = start[0];
      if (token === "{") {
        cursor++;
        while (tokens[cursor]?.[0] !== "}") {
          const key = JSON.parse(tokens[cursor++]![0]) as string;
          if (tokens[cursor++]?.[0] !== ":")
            throw new Error("invalid proof object");
          value([...path, key], depth + 1);
          if (tokens[cursor]?.[0] !== ",") break;
          cursor++;
        }
        if (tokens[cursor++]?.[0] !== "}")
          throw new Error("invalid proof object");
      } else if (token === "[") {
        cursor++;
        while (tokens[cursor]?.[0] !== "]") {
          value([...path, "[]"], depth + 1);
          if (tokens[cursor]?.[0] !== ",") break;
          cursor++;
        }
        if (tokens[cursor++]?.[0] !== "]")
          throw new Error("invalid proof array");
      } else cursor++;
      if (same(path, wanted)) {
        const end = tokens[cursor - 1]!;
        raw = row.review_json.slice(start.index, end.index + end[0].length);
      }
    }
    value([], 0);
    if (!raw) return false;
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(raw),
    );
    return (
      [...new Uint8Array(digest)]
        .map((n) => n.toString(16).padStart(2, "0"))
        .join("") === report.peer_profile_sha256
    );
  } catch {
    return false;
  }
}
