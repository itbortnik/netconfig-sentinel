import { z } from "zod";
import { snapshotBindingSchema, stableJson } from "./contracts";
import { batfishSchema, statisticalRecheckSchema } from "./modelReviews";
import type { PatchDraft } from "./patches";
import type { SourceDeterministicRecheck } from "./sourceDeterministicRecheck";
import type { SourceForestRecheck } from "./sourceForestRecheck";
import type { SourceMlRecheck } from "./sourceMlRecheck";
import type { SourcePatchVerification } from "./sourcePatchVerification";
import {
  batfishExecutionSchema,
  sourceNetworkResult,
} from "./sourcePatchVerification";
import { batfishDirectionalExecutionSchema } from "./sourceReachabilityImpact";
import {
  batfishScopeExecutionSchema,
  ingressScopeProofMatches,
} from "./ingressScope";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const text = z.string().min(1).max(2048);
const blockers = z.array(text).max(64);
const label = z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/);
const score = z.number().min(0).max(1);
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
const kinds = ["deterministic", "forest", "neural", "network"] as const;
export type SourceEvidenceKind = (typeof kinds)[number];
export function evidenceInstant(value: string) {
  const milliseconds = Date.parse(value);
  const fraction = (value.match(/\.(\d+)/)?.[1] ?? "").padEnd(9, "0");
  return Number.isFinite(milliseconds)
    ? BigInt(milliseconds) * 1_000_000n + BigInt(fraction.slice(3, 9))
    : 0n;
}
const memberSchema = snapshotBindingSchema
  .strict()
  .extend({ canonical_sha256: hash });
const selectedSchema = z.strictObject({ record_id: id, review_sha256: hash });
const createSourceEvidenceReportV1Schema = z.strictObject({
  version: z.literal("source-evidence-request-0.1.0"),
  report_id: id,
  draft_sha256: hash,
  deterministic: selectedSchema,
  forest: selectedSchema.nullable(),
  neural: selectedSchema.nullable(),
  network: selectedSchema.nullable(),
});
const createSourceEvidenceReportV2Schema =
  createSourceEvidenceReportV1Schema.extend({
    version: z.literal("source-evidence-request-0.2.0"),
  });
const createSourceEvidenceReportV3Schema =
  createSourceEvidenceReportV1Schema.extend({
    version: z.literal("source-evidence-request-0.3.0"),
  });
const createSourceEvidenceReportV4Schema =
  createSourceEvidenceReportV1Schema.extend({
    version: z.literal("source-evidence-request-0.4.0"),
  });
export const createSourceEvidenceReportSchema = z.union([
  createSourceEvidenceReportV1Schema,
  createSourceEvidenceReportV2Schema,
  createSourceEvidenceReportV3Schema,
  createSourceEvidenceReportV4Schema,
]);
export type CreateSourceEvidenceReport = z.infer<
  typeof createSourceEvidenceReportSchema
>;
const completed = {
  record_id: id,
  review_sha256: hash,
  created_at: timestamp,
  completed_at: timestamp,
  validation_blockers: blockers,
};
const countsSchema = z.strictObject({
  policy: count,
  reference: count.nullable(),
  peer: count.nullable(),
});
const deterministicSchema = z
  .strictObject({
    ...completed,
    kind: z.literal("deterministic"),
    version: z.literal("source-deterministic-recheck-0.1.0"),
    policy_catalog_version: text,
    comparison_version: z.enum(["not_selected", "0.1.0", "0.2.0", "0.3.0"]),
    reference: memberSchema.nullable(),
    peer_profile_sha256: hash.nullable(),
    peer_count: count.max(20),
    before: countsSchema,
    after: countsSchema,
    policy_changes: z.strictObject({
      introduced: count,
      resolved: count,
      persistent: count,
    }),
  })
  .refine(
    (row) =>
      (row.peer_profile_sha256 !== null) === row.peer_count > 0 &&
      (row.peer_count === 0 || row.peer_count >= 3) &&
      row.before.policy ===
        row.policy_changes.resolved + row.policy_changes.persistent &&
      row.after.policy ===
        row.policy_changes.introduced + row.policy_changes.persistent &&
      (row.comparison_version === "not_selected") ===
        (row.reference === null && row.peer_profile_sha256 === null) &&
      [row.before, row.after].every(
        (side) =>
          (side.reference !== null) === (row.reference !== null) &&
          (side.peer !== null) === (row.peer_profile_sha256 !== null),
      ),
  );
const forestSchema = z
  .strictObject({
    ...completed,
    kind: z.literal("forest"),
    version: z.literal("source-forest-recheck-0.1.0"),
    model_id: id,
    artifact_sha256: hash,
    model_version: text,
    feature_schema_version: text,
    library: z.literal("scikit-learn"),
    library_version: text,
    decision_offset: z.number().min(-1).max(0),
    scores: statisticalRecheckSchema,
    interpretation: z.literal("experimental_scores_not_change_validation"),
  })
  .refine(
    (row) =>
      row.model_id === row.scores.model_id &&
      row.artifact_sha256 === row.scores.artifact_sha256 &&
      (["before", "after"] as const).every((side) => {
        const score = row.scores[`${side}_score_samples`],
          decision = row.scores[`${side}_decision_function`];
        return (
          score >= -1 &&
          score <= 0 &&
          decision >= -1 &&
          decision <= 1 &&
          decision === score - row.decision_offset &&
          row.scores[`${side}_prediction`] === (decision < 0 ? -1 : 1)
        );
      }),
  );
const headsSchema = z.strictObject({
  anomaly: z.boolean(),
  category: z.boolean(),
  localization: z.boolean(),
  severity: z.boolean(),
  contrastive: z.boolean(),
});
const neuralSideSchema = z
  .strictObject({
    raw_source_sha256: hash,
    sanitized_source_sha256: hash,
    total_lines: count.min(1).max(10000),
    anomaly_score: score.nullable(),
    category_scores: z
      .record(label, score)
      .refine((row) => Object.keys(row).length <= 64)
      .nullable(),
    severity_scores: z
      .strictObject({
        info: score,
        low: score,
        medium: score,
        high: score,
        critical: score,
      })
      .nullable(),
    scored_line_count: count.max(10000),
    embedding_dimensions: count.max(1024),
  })
  .refine(
    (row) =>
      row.scored_line_count <= row.total_lines &&
      (!row.severity_scores ||
        Math.abs(
          Object.values(row.severity_scores).reduce((a, b) => a + b, 0) - 1,
        ) <= 1e-5),
  );
const neuralSchema = z
  .strictObject({
    ...completed,
    kind: z.literal("neural"),
    version: z.literal("source-ml-recheck-0.1.0"),
    model_card_version: z.enum([
      "config-model-card-0.1.0",
      "config-model-card-0.2.0",
      "config-model-card-0.3.0",
    ]),
    model_card_sha256: hash,
    model_sha256: hash,
    model_kind: z.enum(["native", "foundation"]),
    training_format: text,
    training_report_sha256: hash,
    encoder_sha256: hash,
    tokenizer_sha256: hash,
    classes: z.array(label).min(1).max(64),
    enabled_heads: headsSchema,
    runtime_torch_version: text,
    sanitization_version: z.literal("config-sanitizer-0.1.0"),
    target_semantics: z.enum(["injected_mutation", "confirmed_anomaly"]),
    external_pretraining_exposure: z.enum(["unknown", "not_applicable"]),
    before: neuralSideSchema,
    after: neuralSideSchema,
    interpretation: z.literal("experimental_scores_not_change_validation"),
  })
  .refine(
    (row) =>
      new Set(row.classes).size === row.classes.length &&
      [row.before, row.after].every(
        (side) =>
          row.enabled_heads.anomaly === (side.anomaly_score !== null) &&
          row.enabled_heads.category === (side.category_scores !== null) &&
          row.enabled_heads.severity === (side.severity_scores !== null) &&
          row.enabled_heads.contrastive === side.embedding_dimensions > 0 &&
          (row.enabled_heads.localization || side.scored_line_count === 0) &&
          (!side.category_scores ||
            same(
              Object.keys(side.category_scores).sort(),
              [...row.classes].sort(),
            )),
      ),
  );
const networkSchema = z.strictObject({
  ...completed,
  kind: z.literal("network"),
  version: z.literal("source-patch-verification-0.1.0"),
  result: batfishSchema,
  sdk_version: z.null(),
  ml_status: z.literal("not_run"),
  network_device_count: count.min(1).max(32),
});
const networkV2Schema = networkSchema
  .extend({
    version: z.literal("source-patch-verification-0.2.0"),
    execution_version: z.literal("batfish-execution-0.2.0"),
    sdk_version: batfishExecutionSchema.shape.sdk_version,
    sdk_observation: batfishExecutionSchema.shape.sdk_observation,
  })
  .refine(
    (row) =>
      batfishExecutionSchema.safeParse({
        version: row.execution_version,
        result: row.result,
        sdk_version: row.sdk_version,
        sdk_observation: row.sdk_observation,
      }).success,
  );
const networkEvidenceSchema = z.union([networkSchema, networkV2Schema]);
const networkV3Schema = networkSchema
  .extend({
    version: z.literal("source-patch-verification-0.3.0"),
    execution_version: z.literal("batfish-execution-0.3.0"),
    sdk_version: batfishDirectionalExecutionSchema.shape.sdk_version,
    sdk_observation: batfishDirectionalExecutionSchema.shape.sdk_observation,
    reachability_impact:
      batfishDirectionalExecutionSchema.shape.reachability_impact,
  })
  .refine(
    (row) =>
      batfishDirectionalExecutionSchema.safeParse({
        version: row.execution_version,
        result: row.result,
        sdk_version: row.sdk_version,
        sdk_observation: row.sdk_observation,
        reachability_impact: row.reachability_impact,
      }).success,
  );
const networkV4Schema = networkSchema
  .extend({
    version: z.literal("source-patch-verification-0.4.0"),
    execution_version: z.literal("batfish-execution-0.4.0"),
    sdk_version: batfishScopeExecutionSchema.shape.sdk_version,
    sdk_observation: batfishScopeExecutionSchema.shape.sdk_observation,
    ingress_scope: batfishScopeExecutionSchema.shape.ingress_scope,
    reachability_impact: batfishScopeExecutionSchema.shape.reachability_impact,
  })
  .refine(
    (row) =>
      batfishScopeExecutionSchema.safeParse({
        version: row.execution_version,
        result: row.result,
        sdk_version: row.sdk_version,
        sdk_observation: row.sdk_observation,
        reachability_impact: row.reachability_impact,
        ingress_scope: row.ingress_scope,
      }).success,
  );
const directionalNetworkEvidenceSchema = z.union([
  networkSchema,
  networkV2Schema,
  networkV3Schema,
]);
const scopeNetworkEvidenceSchema = z.union([
  networkSchema,
  networkV2Schema,
  networkV3Schema,
  networkV4Schema,
]);
export function sourceEvidenceBlockers(row: {
  original_statistical_present: boolean;
  forest: unknown | null;
  neural: unknown | null;
  network: z.infer<typeof scopeNetworkEvidenceSchema> | null;
}) {
  const result = [
    "baseline_approval_not_proven",
    "device_syntax_not_verified",
    "management_access_not_verified",
    "rollback_not_verified",
    "individual_engineer_review_required",
    "independent_quality_not_proven",
    "calibration_not_proven",
    "formal_qualification_not_proven",
    "deterministic_quality_not_proven",
  ];
  if (!row.forest) {
    if (row.original_statistical_present)
      result.push("original_statistical_not_selected");
  } else result.push("original_statistical_quality_not_proven");
  if (!row.neural) result.push("neural_not_selected");
  else
    result.push(
      "change_specific_ml_quality_not_proven",
      "selected_model_independent_quality_not_proven",
    );
  if (!row.network) result.push("network_not_selected");
  else {
    result.push("network_scope_not_overall_formal_qualification");
    if (row.network.result.status !== "no_differences_in_scope")
      result.push("formal_scope_not_passed");
    if (row.network.result.cleanup_complete !== true)
      result.push("engine_cleanup_not_confirmed");
  }
  return result;
}
const reportBase = z.strictObject({
  version: z.literal("source-evidence-report-0.1.0"),
  request: createSourceEvidenceReportV1Schema,
  report_id: id,
  patch_id: id,
  draft_sha256: hash,
  before: memberSchema,
  after: memberSchema,
  before_analysis_id: id,
  before_analysis_sha256: hash,
  original_statistical_present: z.boolean(),
  created_at: timestamp,
  deterministic: deterministicSchema,
  forest: forestSchema.nullable(),
  neural: neuralSchema.nullable(),
  network: networkSchema.nullable(),
  validation_blockers: blockers,
  status: z.literal("needs_review"),
  formal_qualification: z.literal("not_proven"),
  risk_fused: z.literal(false),
  calibrated: z.literal(false),
  quality_proven: z.literal(false),
  approved: z.literal(false),
  applied: z.literal(false),
  review_json: z
    .string()
    .min(1)
    .max(4 * 1024 * 1024),
  review_sha256: hash,
});
const validReport = (
  row: Omit<z.infer<typeof reportBase>, "version" | "request" | "network"> & {
    request: CreateSourceEvidenceReport;
    network: z.infer<typeof scopeNetworkEvidenceSchema> | null;
  },
) => {
  if (
    row.report_id !== row.request.report_id ||
    row.draft_sha256 !== row.request.draft_sha256 ||
    row.before.device_id !== row.after.device_id ||
    row.before.configuration_id === row.after.configuration_id ||
    row.before.source_sha256 === row.after.source_sha256 ||
    evidenceInstant(row.before.created_at) >
      evidenceInstant(row.after.created_at) ||
    evidenceInstant(row.after.created_at) > evidenceInstant(row.created_at) ||
    (row.forest !== null && !row.original_statistical_present) ||
    !same(row.validation_blockers, sourceEvidenceBlockers(row))
  )
    return false;
  for (const kind of kinds) {
    const selected = row.request[kind],
      value = row[kind];
    if ((selected === null) !== (value === null)) return false;
    if (
      selected &&
      value &&
      (selected.record_id !== value.record_id ||
        selected.review_sha256 !== value.review_sha256 ||
        evidenceInstant(value.created_at) >
          evidenceInstant(value.completed_at) ||
        evidenceInstant(value.created_at) <
          evidenceInstant(row.after.created_at) ||
        evidenceInstant(value.completed_at) > evidenceInstant(row.created_at))
    )
      return false;
  }
  const reference = row.deterministic.reference;
  return (
    (!reference ||
      (reference.device_id === row.before.device_id &&
        ![row.before.configuration_id, row.after.configuration_id].includes(
          reference.configuration_id,
        ) &&
        evidenceInstant(reference.created_at) <=
          evidenceInstant(row.before.created_at))) &&
    (!row.neural ||
      (row.neural.before.raw_source_sha256 === row.before.source_sha256 &&
        row.neural.after.raw_source_sha256 === row.after.source_sha256))
  );
};
export const sourceEvidenceReportSchema = z.union([
  reportBase.refine(validReport),
  z
    .strictObject({
      ...reportBase.shape,
      version: z.literal("source-evidence-report-0.2.0"),
      request: createSourceEvidenceReportV2Schema,
      network: networkEvidenceSchema.nullable(),
    })
    .refine(validReport),
  z
    .strictObject({
      ...reportBase.shape,
      version: z.literal("source-evidence-report-0.3.0"),
      request: createSourceEvidenceReportV3Schema,
      network: directionalNetworkEvidenceSchema.nullable(),
    })
    .refine(validReport),
  z
    .strictObject({
      ...reportBase.shape,
      version: z.literal("source-evidence-report-0.4.0"),
      request: createSourceEvidenceReportV4Schema,
      network: scopeNetworkEvidenceSchema.nullable(),
    })
    .refine(validReport),
]);
export type SourceEvidenceReport = z.infer<typeof sourceEvidenceReportSchema>;
const summaryBase = z.strictObject({
  version: z.literal("source-evidence-summary-0.1.0"),
  report_id: id,
  patch_id: id,
  draft_sha256: hash,
  before_analysis_id: id,
  review_sha256: hash,
  created_at: timestamp,
  selected_kinds: z.array(z.enum(kinds)).min(1).max(4),
  status: z.literal("needs_review"),
});
const validSummary = (row: Omit<z.infer<typeof summaryBase>, "version">) =>
  row.selected_kinds[0] === "deterministic" &&
  same(
    row.selected_kinds,
    kinds.filter((kind) => row.selected_kinds.includes(kind)),
  );
export const sourceEvidenceSummarySchema = z.union([
  summaryBase.refine(validSummary),
  summaryBase
    .extend({ version: z.literal("source-evidence-summary-0.2.0") })
    .refine(validSummary),
  summaryBase
    .extend({ version: z.literal("source-evidence-summary-0.3.0") })
    .refine(validSummary),
  summaryBase
    .extend({ version: z.literal("source-evidence-summary-0.4.0") })
    .refine(validSummary),
]);
export type SourceEvidenceSummary = z.infer<typeof sourceEvidenceSummarySchema>;
export type SourceEvidenceChildren = {
  deterministic: SourceDeterministicRecheck;
  forest: SourceForestRecheck | null;
  neural: SourceMlRecheck | null;
  network: SourcePatchVerification | null;
};

// Read exact nested normative Python JSON bytes. Parsing also rejects duplicate keys,
// including in objects outside the requested path. Never re-encode model-card floats.
export function evidenceRawJsonAt(
  raw: string,
  path: string[],
): string | undefined {
  const tokens = [
    ...raw.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,]+/gu),
  ];
  let index = 0,
    found: string | undefined;
  function value(keys: string[]) {
    const start = tokens[index];
    if (!start) throw new Error("Missing JSON value");
    const token = start[0];
    if (token === "{") {
      index++;
      const seen = new Set<string>();
      if (tokens[index]?.[0] !== "}")
        while (true) {
          const name = JSON.parse(tokens[index++]![0]) as unknown;
          if (
            typeof name !== "string" ||
            seen.has(name) ||
            tokens[index++]?.[0] !== ":"
          )
            throw new Error("Invalid object");
          seen.add(name);
          value([...keys, name]);
          if (tokens[index]?.[0] !== ",") break;
          index++;
        }
      if (tokens[index++]?.[0] !== "}") throw new Error("Invalid object end");
    } else if (token === "[") {
      index++;
      let position = 0;
      if (tokens[index]?.[0] !== "]")
        while (true) {
          value([...keys, String(position++)]);
          if (tokens[index]?.[0] !== ",") break;
          index++;
        }
      if (tokens[index++]?.[0] !== "]") throw new Error("Invalid array end");
    } else {
      JSON.parse(token);
      index++;
    }
    if (same(keys, path)) {
      const end = tokens[index - 1]!;
      found = raw.slice(start.index, end.index + end[0].length);
    }
  }
  value([]);
  if (index !== tokens.length) throw new Error("Trailing JSON");
  return found;
}
async function digest(raw: string) {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw)),
    ),
  ]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
export async function sourceEvidenceProofMatches(row: SourceEvidenceReport) {
  try {
    const { review_json, review_sha256, ...body } = row;
    return (
      new TextEncoder().encode(review_json).length <= 4 * 1024 * 1024 &&
      evidenceRawJsonAt(review_json, []) !== undefined &&
      same(JSON.parse(review_json), body) &&
      (await digest(review_json)) === review_sha256
    );
  } catch {
    return false;
  }
}
export function sourceEvidenceSummaryBound(
  row: SourceEvidenceSummary,
  draft: PatchDraft,
) {
  return (
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    evidenceInstant(row.created_at) >= evidenceInstant(draft.created_at)
  );
}
function member(value: SourceDeterministicRecheck["intent"]["before"]) {
  const {
    configuration_id,
    device_id,
    source_sha256,
    created_at,
    canonical_sha256,
  } = value;
  return {
    configuration_id,
    device_id,
    source_sha256,
    created_at,
    canonical_sha256,
  };
}
function common(value: SourceEvidenceChildren[SourceEvidenceKind]) {
  if (!value?.outcome || value.execution_status !== "completed")
    throw new Error("No completed child");
  return {
    version: value.version,
    record_id: "recheck_id" in value ? value.recheck_id : value.verification_id,
    review_sha256: value.review_sha256,
    created_at: value.intent.created_at,
    completed_at: value.outcome.completed_at,
    validation_blockers: value.validation_blockers,
  };
}
export async function sourceEvidenceReportBound(
  row: SourceEvidenceReport,
  draft: PatchDraft,
  children: SourceEvidenceChildren,
  request?: CreateSourceEvidenceReport,
  summary?: SourceEvidenceSummary,
) {
  try {
    if (
      !sourceEvidenceReportSchema.safeParse(row).success ||
      !(await sourceEvidenceProofMatches(row)) ||
      row.patch_id !== draft.patch_id ||
      row.draft_sha256 !== draft.draft_sha256 ||
      evidenceInstant(row.created_at) < evidenceInstant(draft.created_at) ||
      (request && !same(row.request, request)) ||
      (summary &&
        (!sourceEvidenceSummaryBound(summary, draft) ||
          !same(summary, {
            version:
              row.version === "source-evidence-report-0.4.0"
                ? "source-evidence-summary-0.4.0"
                : row.version === "source-evidence-report-0.3.0"
                  ? "source-evidence-summary-0.3.0"
                  : row.version === "source-evidence-report-0.2.0"
                    ? "source-evidence-summary-0.2.0"
                    : "source-evidence-summary-0.1.0",
            report_id: row.report_id,
            patch_id: row.patch_id,
            draft_sha256: row.draft_sha256,
            before_analysis_id: row.before_analysis_id,
            review_sha256: row.review_sha256,
            created_at: row.created_at,
            selected_kinds: kinds.filter((kind) => row[kind] !== null),
            status: row.status,
          })))
    )
      return false;
    const deterministic = children.deterministic,
      report = deterministic.outcome?.report;
    if (
      !report ||
      row.before_analysis_id !== deterministic.before_analysis_id ||
      row.before_analysis_sha256 !== deterministic.before_analysis_sha256 ||
      row.original_statistical_present !==
        deterministic.intent.selection.original.statistical_present
    )
      return false;
    for (const side of ["before", "after"] as const) {
      if (!same(row[side], member(deterministic.intent[side]))) return false;
      const target = draft.diff[side],
        actual = row[side];
      if (
        actual.configuration_id !== target.configuration_id ||
        actual.device_id !== target.device_id ||
        actual.source_sha256 !== target.source_sha256 ||
        evidenceInstant(actual.created_at) !==
          evidenceInstant(target.created_at)
      )
        return false;
    }
    for (const kind of kinds) {
      const child = children[kind],
        reference = row.request[kind];
      if ((child === null) !== (reference === null)) return false;
      if (!child || !reference) continue;
      const bound = common(child);
      if (
        bound.record_id !== reference.record_id ||
        bound.review_sha256 !== reference.review_sha256 ||
        child.patch_id !== row.patch_id ||
        child.draft_sha256 !== row.draft_sha256
      )
        return false;
      for (const side of ["before", "after"] as const)
        if (!same(member(child.intent[side]), row[side])) return false;
    }
    const counts = (side: typeof report.before) => ({
      policy: side.policy_findings.length,
      reference: side.reference_findings?.length ?? null,
      peer: side.peer_findings?.length ?? null,
    });
    if (
      !same(row.deterministic, {
        ...common(deterministic),
        kind: "deterministic",
        policy_catalog_version: report.policy_catalog_version,
        comparison_version: report.comparison_version,
        reference: deterministic.intent.selection.reference
          ? member(deterministic.intent.selection.reference)
          : null,
        peer_profile_sha256: report.peer_profile_sha256,
        peer_count:
          deterministic.intent.selection.original.comparison?.peers.length ?? 0,
        before: counts(report.before),
        after: counts(report.after),
        policy_changes: {
          introduced: report.policy_changes.introduced.length,
          resolved: report.policy_changes.resolved.length,
          persistent: report.policy_changes.persistent.length,
        },
      })
    )
      return false;
    if (children.forest) {
      const child = children.forest,
        detail = child.outcome?.report;
      if (
        !detail ||
        child.before_analysis_id !== row.before_analysis_id ||
        child.before_analysis_sha256 !== row.before_analysis_sha256 ||
        !same(row.forest, {
          ...common(child),
          kind: "forest",
          model_id: child.model_id,
          artifact_sha256: child.artifact_sha256,
          model_version: detail.model.metadata.model_version,
          feature_schema_version: detail.model.metadata.feature_schema_version,
          library: "scikit-learn",
          library_version: detail.model.metadata.library_version,
          decision_offset: detail.model.decision_offset,
          scores: detail.scores,
          interpretation: detail.interpretation,
        })
      )
        return false;
    }
    if (children.neural) {
      const child = children.neural,
        detail = child.outcome?.report;
      if (!detail) return false;
      const model = detail.before.model,
        rawCard = evidenceRawJsonAt(child.review_json, [
          "outcome",
          "report",
          "before",
          "model",
        ]);
      if (!rawCard) return false;
      const projectSide = (side: typeof detail.before) => {
        const prediction = side.prediction;
        return {
          raw_source_sha256: prediction.raw_source_sha256,
          sanitized_source_sha256: prediction.sanitized_source_sha256,
          total_lines: prediction.total_lines,
          anomaly_score: prediction.anomaly_score,
          category_scores: prediction.category_scores,
          severity_scores: prediction.severity_scores,
          scored_line_count: prediction.line_scores.filter(
            (score) => score !== null,
          ).length,
          embedding_dimensions: prediction.embedding_dimensions,
        };
      };
      if (
        !same(row.neural, {
          ...common(child),
          kind: "neural",
          model_card_version: model.version,
          model_card_sha256: await digest(rawCard),
          model_sha256: model.model_sha256,
          model_kind: model.kind,
          training_format: model.training_format,
          training_report_sha256: model.report_sha256,
          encoder_sha256: model.encoder_sha256,
          tokenizer_sha256: model.tokenizer_sha256,
          classes: model.classes,
          enabled_heads: model.enabled_heads,
          runtime_torch_version: detail.before.runtime_torch_version,
          sanitization_version: detail.before.sanitization_version,
          target_semantics: model.target_semantics,
          external_pretraining_exposure: model.external_pretraining_exposure,
          before: projectSide(detail.before),
          after: projectSide(detail.after),
          interpretation: detail.interpretation,
        })
      )
        return false;
    }
    if (children.network) {
      const child = children.network;
      if (
        child.outcome &&
        "network_execution" in child.outcome &&
        "ingress_scope" in child.outcome.network_execution &&
        !(await ingressScopeProofMatches(
          child.outcome.network_execution.ingress_scope,
        ))
      )
        return false;
      if (
        !same(row.network, {
          ...common(child),
          kind: "network",
          result: sourceNetworkResult(child.outcome),
          ...(child.outcome && "network_execution" in child.outcome
            ? {
                execution_version: child.outcome.network_execution.version,
                sdk_version: child.outcome.network_execution.sdk_version,
                sdk_observation:
                  child.outcome.network_execution.sdk_observation,
                ...("ingress_scope" in child.outcome.network_execution
                  ? {
                      ingress_scope:
                        child.outcome.network_execution.ingress_scope,
                    }
                  : {}),
                ...("reachability_impact" in child.outcome.network_execution
                  ? {
                      reachability_impact:
                        child.outcome.network_execution.reachability_impact,
                    }
                  : {}),
              }
            : { sdk_version: null }),
          ml_status: child.ml_status,
          network_device_count: 1 + child.intent.companions.length,
        })
      )
        return false;
    }
    return true;
  } catch {
    return false;
  }
}
