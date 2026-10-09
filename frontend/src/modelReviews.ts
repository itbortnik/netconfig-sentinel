import { z } from "zod";
import { stableJson } from "./contracts";
import { localBlockers, preflightSchema } from "./patches";
import { modelPatchBindingSchema } from "./modelPatches";
import type { ModelPatchProposal } from "./modelPatches";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const score = z.number().min(0).max(1);
const label = z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/);
const strings = z.array(z.string().min(1).max(1000)).max(64);
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
export function ipv4Scope(value: string) {
  const [address, prefix, extra] = value.split("/");
  if (
    !address ||
    !prefix ||
    extra !== undefined ||
    !/^(0|[1-9]\d?)$/.test(prefix)
  )
    return false;
  const bits = Number(prefix),
    octets = address.split(".");
  if (
    bits > 32 ||
    octets.length !== 4 ||
    octets.some(
      (part) => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255,
    )
  )
    return false;
  const numeric = octets.reduce((total, part) => total * 256 + Number(part), 0);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (numeric & mask) >>> 0 === numeric;
}
export const scopeSchema = z.strictObject({
  start_node: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  destination: z.string().max(18).refine(ipv4Scope),
});
export const verifyModelPatchSchema = z
  .strictObject({
    verification_id: id,
    proposal_sha256: hash,
    mode: z.enum(["local_preflight", "batfish"]).default("local_preflight"),
    network: z
      .array(z.strictObject({ configuration_id: id, source_sha256: hash }))
      .min(1)
      .max(32),
    scope: scopeSchema,
    allow_local_engine_upload: z.boolean().default(false),
    transformer_sha256: hash.nullable().default(null),
    allow_local_model_context: z.boolean().default(false),
  })
  .refine(
    (value) =>
      new Set(value.network.map((row) => row.configuration_id)).size ===
        value.network.length &&
      (value.mode === "batfish" || !value.allow_local_engine_upload) &&
      (value.transformer_sha256 !== null || !value.allow_local_model_context),
  );
export type VerifyModelPatch = z.infer<typeof verifyModelPatchSchema>;

const span = z
  .strictObject({
    operation: z.enum(["insert", "delete", "replace"]),
    before_start: count,
    before_end: count,
    after_start: count,
    after_end: count,
  })
  .refine((value) => {
    const old = value.before_end - value.before_start,
      next = value.after_end - value.after_start;
    return (
      old >= 0 &&
      next >= 0 &&
      (old > 0 || next > 0) &&
      value.operation ===
        (old === 0 ? "insert" : next === 0 ? "delete" : "replace")
    );
  });
const sourceLineProposal = z
  .strictObject({
    version: z.literal("patch-proposal-0.1.0"),
    proposal_id: id,
    device_id: id,
    reference_id: z.string().min(1).max(256),
    vendor: z.enum(["cisco", "juniper"]),
    platform: z.string().min(1),
    before_sha256: hash,
    after_sha256: hash,
    before_line_count: count.min(1).max(10_000),
    after_line_count: count.min(1).max(10_000),
    changes: z.array(span).min(1).max(10_000),
    status: z.literal("draft"),
  })
  .refine((value) => {
    let old = 0,
      next = 0;
    if (value.before_sha256 === value.after_sha256) return false;
    for (const change of value.changes) {
      if (
        change.before_start < old ||
        change.after_start < next ||
        change.before_start - old !== change.after_start - next ||
        change.before_end > value.before_line_count ||
        change.after_end > value.after_line_count
      )
        return false;
      old = change.before_end;
      next = change.after_end;
    }
    return value.before_line_count - old === value.after_line_count - next;
  });
export const sourceLineReviewSchema = z
  .strictObject({
    version: z.literal("patch-review-0.1.0"),
    proposal: sourceLineProposal,
    preflight: preflightSchema,
    status: z.literal("needs_review"),
    validation_blockers: strings,
  })
  .refine(
    (value) =>
      value.proposal.device_id === value.preflight.device_id &&
      value.proposal.reference_id === value.preflight.reference_id &&
      value.proposal.before_sha256 === value.preflight.before.source_sha256 &&
      value.proposal.after_sha256 === value.preflight.after.source_sha256 &&
      same(value.validation_blockers, localBlockers(value.preflight)),
  );

export const batfishSchema = z
  .strictObject({
    version: z.literal("batfish-check-0.1.0"),
    before_sha256: hash,
    after_sha256: hash,
    scope: scopeSchema,
    status: z.enum([
      "unavailable",
      "error",
      "incomplete",
      "inconclusive",
      "differences_found",
      "no_differences_in_scope",
    ]),
    reason: z.enum([
      "upload_not_authorized",
      "sdk_missing",
      "worker_failed",
      "timeout",
      "engine_error",
      "initialization_issues",
      "empty_reachable_scope",
      "query_completed",
    ]),
    engine_version: z.string().min(1).max(2048).nullable(),
    network_name: z
      .string()
      .regex(/^sentinel-[0-9a-f]{32}$/)
      .nullable(),
    cleanup_complete: z.boolean().nullable(),
    difference_count: count.nullable(),
    before_reachable_count: count.nullable(),
    after_reachable_count: count.nullable(),
    requires_human_review: z.literal(true),
    limitations: strings,
  })
  .refine((value) => {
    const reasons = {
      unavailable: ["upload_not_authorized", "sdk_missing"],
      error: ["worker_failed", "timeout", "engine_error"],
      incomplete: ["initialization_issues"],
      inconclusive: ["empty_reachable_scope"],
      differences_found: ["query_completed"],
      no_differences_in_scope: ["query_completed"],
    };
    if (!reasons[value.status].includes(value.reason)) return false;
    const queried = [
      "inconclusive",
      "differences_found",
      "no_differences_in_scope",
    ].includes(value.status);
    const counts = [
      value.difference_count,
      value.before_reachable_count,
      value.after_reachable_count,
    ];
    if (
      queried
        ? counts.some((row) => row === null) || !value.engine_version?.trim()
        : counts.some((row) => row !== null)
    )
      return false;
    if (value.status === "no_differences_in_scope")
      return (
        value.difference_count === 0 &&
        !!value.before_reachable_count &&
        !!value.after_reachable_count
      );
    if (value.status === "differences_found") return !!value.difference_count;
    if (value.status === "inconclusive")
      return (
        value.difference_count === 0 &&
        (!value.before_reachable_count || !value.after_reachable_count)
      );
    return true;
  });
const networkReview = z.strictObject({
  version: z.literal("model-patch-batfish-0.1.0"),
  device_id: id,
  source_sha256: hash,
  candidate_sha256: hash,
  finding_sha256: hash,
  context_sha256: hash,
  batfish: batfishSchema,
  status: z.literal("needs_review"),
  requires_human_review: z.literal(true),
  approved: z.literal(false),
  application_supported: z.literal(false),
  device_syntax_verified: z.literal(false),
  management_access_verified: z.literal(false),
  model_execution_authenticated: z.literal(false),
  limitations: strings,
});
const side = z
  .strictObject({
    raw_source_sha256: hash,
    sanitized_source_sha256: hash,
    model_sha256: hash,
    total_lines: count.min(1).max(10_000),
    anomaly_score: score.nullable(),
    category_scores: z.record(label, score).nullable(),
    severity_scores: z
      .strictObject({
        info: score,
        low: score,
        medium: score,
        high: score,
        critical: score,
      })
      .nullable(),
    line_scores: z.array(score.nullable()).max(10_000),
    block_attention: z.array(score).min(1).max(10_000),
    embedding_sha256: hash.nullable(),
    embedding_dimensions: count.max(1024),
    replacement_counts: z.record(label, count.min(1).max(100_000)),
    calibrated: z.literal(false),
  })
  .refine(
    (value) =>
      value.line_scores.length === value.total_lines &&
      (value.embedding_sha256 === null) ===
        (value.embedding_dimensions === 0) &&
      (value.category_scores === null ||
        (Object.keys(value.category_scores).length > 0 &&
          Object.keys(value.category_scores).length <= 64)) &&
      (value.severity_scores === null ||
        Math.abs(
          Object.values(value.severity_scores).reduce((a, b) => a + b, 0) - 1,
        ) <= 1e-5) &&
      Math.abs(value.block_attention.reduce((a, b) => a + b, 0) - 1) <= 1e-5 &&
      Object.keys(value.replacement_counts).length <= 32,
  );
const transformer = z
  .strictObject({
    status: z.enum(["not_selected", "unavailable", "completed"]),
    reason: z.enum(["not_selected", "incomplete_parsing"]).nullable(),
    model_sha256: hash.nullable(),
    tokenizer_sha256: hash.nullable(),
    training_report_sha256: hash.nullable(),
    training_format: z
      .enum([
        "multitask-training-0.1.0",
        "multitask-training-0.2.0",
        "foundation-config-transfer-0.1.0",
      ])
      .nullable(),
    runtime_torch_version: z.string().min(1).max(64).nullable(),
    sanitization_version: z.literal("config-sanitizer-0.1.0").nullable(),
    before: side.nullable(),
    after: side.nullable(),
    risk_fused: z.literal(false),
    quality_evaluated: z.literal(false),
    calibrated: z.literal(false),
    production_quality_proven: z.literal(false),
  })
  .refine((value) => {
    const pins = [
      value.model_sha256,
      value.tokenizer_sha256,
      value.training_report_sha256,
      value.training_format,
      value.runtime_torch_version,
      value.sanitization_version,
    ];
    if (
      value.status === "not_selected" &&
      (value.reason !== "not_selected" || pins.some((pin) => pin !== null))
    )
      return false;
    if (value.status !== "not_selected" && pins.some((pin) => pin === null))
      return false;
    if (value.status !== "completed")
      return (
        value.before === null &&
        value.after === null &&
        (value.status !== "unavailable" ||
          value.reason === "incomplete_parsing")
      );
    const before = value.before,
      after = value.after;
    return (
      value.reason === null &&
      before !== null &&
      after !== null &&
      before.model_sha256 === value.model_sha256 &&
      after.model_sha256 === value.model_sha256 &&
      (before.anomaly_score === null) === (after.anomaly_score === null) &&
      (before.category_scores === null) === (after.category_scores === null) &&
      (before.severity_scores === null) === (after.severity_scores === null) &&
      before.embedding_dimensions === after.embedding_dimensions &&
      same(
        Object.keys(before.category_scores ?? {}).sort(),
        Object.keys(after.category_scores ?? {}).sort(),
      )
    );
  });
const mlReview = z
  .strictObject({
    version: z.literal("ml-change-review-0.1.0"),
    local_review: sourceLineReviewSchema,
    transformer,
    status: z.literal("needs_review"),
    formal_verification: z.literal("not_run"),
    device_syntax_verified: z.literal(false),
    management_access_verified: z.literal(false),
    applied: z.literal(false),
    independent_quality_evaluation: z.literal(false),
    pseudonymization_key_persisted: z.literal(false),
  })
  .refine((value) => {
    const model = value.transformer,
      local = value.local_review;
    if (model.status === "unavailable")
      return (
        !local.preflight.before.complete || !local.preflight.after.complete
      );
    if (model.status !== "completed") return true;
    return (
      local.preflight.before.complete &&
      local.preflight.after.complete &&
      model.before?.raw_source_sha256 === local.proposal.before_sha256 &&
      model.after?.raw_source_sha256 === local.proposal.after_sha256 &&
      model.before.total_lines === local.proposal.before_line_count &&
      model.after.total_lines === local.proposal.after_line_count
    );
  });
const candidateFieldsSchema = z.strictObject({
  version: z.literal("candidate-review-0.1.0"),
  device_id: id,
  source_sha256: hash,
  candidate_sha256: hash,
  finding_sha256: hash,
  context_sha256: hash,
  selected_category: z.enum([
    "management.telnet_enabled",
    "management.ssh_version_1",
  ]),
  before_snapshot_sha256: hash,
  after_snapshot_sha256: hash,
  scope: scopeSchema,
  local_review: sourceLineReviewSchema,
  network_result: networkReview.nullable(),
  ml_reviews: z.array(mlReview).max(4),
  expected_model_sha256s: z.array(hash.nullable()).max(4),
  missing_checks: strings,
  status: z.literal("needs_review"),
  requires_human_review: z.literal(true),
  approved: z.literal(false),
  applied: z.literal(false),
  execution_authenticated: z.literal(false),
  semantic_truth_proven: z.literal(false),
  confidential: z.literal(true),
});
type Candidate = z.infer<typeof candidateFieldsSchema>;
export const candidateReviewSchema = candidateFieldsSchema.refine((value) => {
  const local = value.local_review.proposal,
    network = value.network_result;
  if (
    local.device_id !== value.device_id ||
    local.before_sha256 !== value.source_sha256 ||
    local.after_sha256 !== value.candidate_sha256
  )
    return false;
  if (
    network &&
    (network.device_id !== value.device_id ||
      network.source_sha256 !== value.source_sha256 ||
      network.candidate_sha256 !== value.candidate_sha256 ||
      network.finding_sha256 !== value.finding_sha256 ||
      network.context_sha256 !== value.context_sha256 ||
      network.batfish.before_sha256 !== value.before_snapshot_sha256 ||
      network.batfish.after_sha256 !== value.after_snapshot_sha256 ||
      !same(network.batfish.scope, value.scope))
  )
    return false;
  const pins = value.expected_model_sha256s.filter((pin) => pin !== null);
  if (
    value.ml_reviews.length !== value.expected_model_sha256s.length ||
    new Set(pins).size !== pins.length
  )
    return false;
  if (
    value.ml_reviews.some(
      (row, index) =>
        !same(row.local_review, value.local_review) ||
        row.transformer.model_sha256 !== value.expected_model_sha256s[index] ||
        (row.transformer.status === "not_selected") !==
          (value.expected_model_sha256s[index] === null),
    )
  )
    return false;
  return same(value.missing_checks, missingChecks(value));
});
export function missingChecks(value: Candidate) {
  const missing = [
    "human_review_required",
    "device_syntax_not_verified",
    "management_access_not_verified",
    "rollback_not_verified",
    "operational_topology_not_verified",
    "execution_not_authenticated_by_report",
    "baseline_approval_not_established",
    "explicit_scope_not_full_network_qualification",
    "ml_quality_not_qualified",
  ];
  if (value.local_review.preflight.after_policy_findings.length)
    missing.push("current_policy_findings");
  const network = value.network_result?.batfish;
  if (!network) missing.push("formal_report_not_supplied");
  else {
    if (["unavailable", "error", "incomplete"].includes(network.status))
      missing.push("formal_query_not_completed");
    else if (network.status === "inconclusive")
      missing.push("empty_formal_scope");
    else if (network.status === "differences_found")
      missing.push("reachability_differences_unreviewed");
    if (network.cleanup_complete !== true)
      missing.push("network_cleanup_unconfirmed");
  }
  if (
    !value.ml_reviews.length ||
    value.ml_reviews.every((row) => row.transformer.status === "not_selected")
  )
    missing.push("ml_model_not_selected");
  if (value.ml_reviews.some((row) => row.transformer.status === "unavailable"))
    missing.push("ml_unavailable");
  if (
    value.ml_reviews.some(
      (row) =>
        row.transformer.status === "completed" &&
        row.transformer.before &&
        !(
          value.selected_category.slice("management.".length) in
          (row.transformer.before.category_scores ?? {})
        ),
    )
  )
    missing.push("ml_selected_category_not_supported");
  return missing;
}
export function approvalBlockers(report: Candidate | null, ml: string) {
  if (!report) return ["verification_not_completed"];
  const blocked: string[] = [],
    network = report.network_result?.batfish,
    local = report.local_review.preflight;
  if (network?.status !== "no_differences_in_scope")
    blocked.push("formal_scope_not_passed");
  if (network?.cleanup_complete !== true)
    blocked.push("engine_cleanup_not_confirmed");
  if (!local.before.complete || !local.after.complete)
    blocked.push("incomplete_parsing");
  if (!local.policy_changes || local.policy_changes.introduced.length)
    blocked.push("policy_regression_or_missing_comparison");
  if (
    ml !== "completed" ||
    !report.ml_reviews.length ||
    report.ml_reviews.some((row) => row.transformer.status !== "completed")
  )
    blocked.push("selected_ml_not_completed");
  if (report.missing_checks.includes("ml_selected_category_not_supported"))
    blocked.push("selected_ml_category_not_supported");
  return blocked;
}
const statistical = z.strictObject({
  model_id: id,
  artifact_sha256: hash,
  before_score_samples: z.number(),
  after_score_samples: z.number(),
  before_decision_function: z.number(),
  after_decision_function: z.number(),
  before_prediction: z.union([z.literal(-1), z.literal(1)]),
  after_prediction: z.union([z.literal(-1), z.literal(1)]),
  calibrated: z.literal(false),
  quality_proven: z.literal(false),
});
export const savedModelReviewSchema = z
  .strictObject({
    version: z.literal("saved-model-patch-review-0.1.0"),
    verification_id: id,
    patch_id: id,
    proposal_sha256: hash,
    review_sha256: hash,
    created_at: timestamp,
    completed_at: timestamp.nullable(),
    request: verifyModelPatchSchema,
    network: z.array(modelPatchBindingSchema).min(1).max(32),
    execution_status: z.enum(["running", "completed", "failed"]),
    report: candidateReviewSchema.nullable(),
    ml_execution: z.enum(["not_requested", "completed", "unavailable"]),
    statistical_recheck: statistical.nullable(),
    approval_blockers: strings,
    status: z.literal("needs_review"),
    applied: z.literal(false),
    topology_pinned_at_generation: z.literal(false),
  })
  .refine((value) => {
    if (
      value.verification_id !== value.request.verification_id ||
      (value.request.mode === "batfish" &&
        !value.request.allow_local_engine_upload) ||
      (value.request.transformer_sha256 !== null &&
        !value.request.allow_local_model_context) ||
      value.proposal_sha256 !== value.request.proposal_sha256 ||
      value.network.length !== value.request.network.length ||
      new Set(value.network.map((row) => row.device_id)).size !==
        value.network.length ||
      value.network.some(
        (row, index) =>
          row.configuration_id !==
            value.request.network[index]?.configuration_id ||
          row.source_sha256 !== value.request.network[index]?.source_sha256 ||
          Date.parse(row.created_at) > Date.parse(value.created_at),
      ) ||
      !same(
        value.approval_blockers,
        approvalBlockers(value.report, value.ml_execution),
      )
    )
      return false;
    if (value.execution_status === "running")
      return (
        value.completed_at === null &&
        value.report === null &&
        value.statistical_recheck === null &&
        value.ml_execution === "not_requested"
      );
    if (
      !value.completed_at ||
      Date.parse(value.completed_at) < Date.parse(value.created_at)
    )
      return false;
    if (value.execution_status === "failed")
      return (
        value.report === null &&
        value.statistical_recheck === null &&
        value.ml_execution !== "completed"
      );
    const report = value.report;
    return (
      report !== null &&
      same(report.scope, value.request.scope) &&
      (value.request.mode === "batfish") === (report.network_result !== null) &&
      (value.request.transformer_sha256 === null) ===
        (value.ml_execution === "not_requested") &&
      (value.ml_execution === "completed") ===
        (report.ml_reviews.length > 0 &&
          report.ml_reviews.every(
            (row) => row.transformer.status === "completed",
          )) &&
      same(
        report.expected_model_sha256s,
        report.ml_reviews.length ? [value.request.transformer_sha256] : [],
      )
    );
  });
export type SavedModelReview = z.infer<typeof savedModelReviewSchema>;
export const decideModelPatchSchema = z.strictObject({
  decision_id: id,
  verification_id: id,
  proposal_sha256: hash,
  review_sha256: hash,
  verdict: z.enum(["approved", "rejected", "needs_more_information"]),
  comment: z
    .string()
    .min(1)
    .max(1200)
    .refine(
      (value) =>
        !!value.trim() &&
        !/[\p{C}\p{Zl}\p{Zp}]/u.test(value.replace(/[\n\t]/g, "")),
    ),
  acknowledged_limitations: z
    .array(
      z
        .string()
        .min(1)
        .max(100)
        .regex(/^[\x20-\x7e]+$/),
    )
    .max(64)
    .default([])
    .refine((value) => new Set(value).size === value.length),
  device_syntax_checked: z.boolean().default(false),
  management_access_checked: z.boolean().default(false),
  rollback_ready: z.boolean().default(false),
});
export type DecideModelPatch = z.infer<typeof decideModelPatchSchema>;
export const savedModelDecisionSchema = z.strictObject({
  version: z.literal("saved-model-patch-decision-0.1.0"),
  patch_id: id,
  request: decideModelPatchSchema,
  created_at: timestamp,
  service_role: z.enum(["engineer", "admin"]),
  individual_identity_verified: z.literal(false),
  applied: z.literal(false),
});
export type SavedModelDecision = z.infer<typeof savedModelDecisionSchema>;
export function reviewMatches(
  run: SavedModelReview,
  proposal: ModelPatchProposal,
) {
  const report = run.report;
  return (
    proposal.status === "draft" &&
    run.patch_id === proposal.patch_id &&
    run.proposal_sha256 === proposal.proposal_sha256 &&
    run.network.some((row) => same(row, proposal.source)) &&
    run.network.every(
      (row) => Date.parse(row.created_at) <= Date.parse(proposal.created_at),
    ) &&
    Date.parse(run.created_at) >=
      Date.parse(proposal.completed_at ?? proposal.created_at) &&
    (!report ||
      (report.device_id === proposal.source.device_id &&
        report.local_review.proposal.reference_id ===
          proposal.source.configuration_id &&
        report.source_sha256 === proposal.source_sha256 &&
        report.candidate_sha256 === proposal.candidate_sha256 &&
        report.finding_sha256 === proposal.finding_sha256 &&
        report.context_sha256 === proposal.context_sha256))
  );
}
export function decisionMatches(
  decision: SavedModelDecision,
  run: SavedModelReview,
) {
  const request = decision.request;
  return (
    decision.patch_id === run.patch_id &&
    request.verification_id === run.verification_id &&
    request.proposal_sha256 === run.proposal_sha256 &&
    request.review_sha256 === run.review_sha256 &&
    run.execution_status !== "running" &&
    run.completed_at !== null &&
    Date.parse(decision.created_at) >= Date.parse(run.completed_at) &&
    request.acknowledged_limitations.every((item) =>
      run.report?.missing_checks.includes(item),
    ) &&
    (request.verdict !== "approved" ||
      (!run.approval_blockers.length &&
        request.device_syntax_checked &&
        request.management_access_checked &&
        request.rollback_ready &&
        same(
          [...request.acknowledged_limitations].sort(),
          [...(run.report?.missing_checks ?? [])].sort(),
        )))
  );
}
