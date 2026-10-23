import { z } from "zod";
import { snapshotBindingSchema, stableJson } from "./contracts";
import { batfishSchema } from "./modelReviews";
import { batfishDirectionalExecutionSchema } from "./sourceReachabilityImpact";
import { sourceNetworkResult } from "./sourcePatchVerification";
import {
  evidenceInstant,
  evidenceRawJsonAt,
  sourceEvidenceReportBound,
} from "./sourceEvidenceReports";
import type {
  SourceEvidenceChildren,
  SourceEvidenceReport,
} from "./sourceEvidenceReports";
import type { PatchDraft } from "./patches";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/),
  unit = z.number().min(0).max(1);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const text = z.string().min(1).max(128);
const flags = {
  individual_identity_verified: z.literal(false),
  approved: z.literal(false),
  applied: z.literal(false),
};
export const prioritySources = [
  "policy",
  "peer_group",
  "statistical",
  "transformer",
  "verification",
] as const;
const kinds = ["deterministic", "forest", "neural", "network"] as const;
const weights = [0.35, 0.15, 0.1, 0.1, 0.3];
const source = z.enum(prioritySources),
  band = z.enum(["low", "medium", "high", "critical"]);
const reportVersion = z.enum([
  "source-evidence-report-0.1.0",
  "source-evidence-report-0.2.0",
  "source-evidence-report-0.3.0",
]);
const childVersion = z.enum([
  "source-deterministic-recheck-0.1.0",
  "source-forest-recheck-0.1.0",
  "source-ml-recheck-0.1.0",
  "source-patch-verification-0.1.0",
  "source-patch-verification-0.2.0",
  "source-patch-verification-0.3.0",
]);
const networkVersion = z.enum([
  "source-patch-verification-0.1.0",
  "source-patch-verification-0.2.0",
  "source-patch-verification-0.3.0",
]);
const evidence = z
  .strictObject({
    kind: z.enum(kinds),
    version: childVersion,
    record_id: id,
    review_sha256: hash,
  })
  .refine((r) =>
    r.version.startsWith(
      {
        deterministic: "source-deterministic-recheck-",
        forest: "source-forest-recheck-",
        neural: "source-ml-recheck-",
        network: "source-patch-verification-",
      }[r.kind],
    ),
  );
const finding = z.strictObject({
  finding_id: id,
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  confidence: unit,
  anomaly_score: unit,
});
const findings = z
  .strictObject({
    kind: z.literal("findings"),
    detector: z.enum(["policy_engine", "peer_baseline"]),
    finding_count: z.number().int().min(0).max(10000),
    strongest: finding.nullable(),
    critical_policy_present: z.boolean(),
  })
  .refine(
    (r) =>
      (r.finding_count === 0) === (r.strongest === null) &&
      (!r.critical_policy_present ||
        (r.detector === "policy_engine" && r.finding_count > 0)) &&
      (r.detector !== "policy_engine" ||
        !r.strongest ||
        ((r.strongest.severity !== "critical" || r.critical_policy_present) &&
          (r.finding_count !== 1 ||
            r.critical_policy_present ===
              (r.strongest.severity === "critical")))),
  );
const normalize = (raw: number, min: number, max: number) =>
  max - min <= 0
    ? raw > max
      ? 1
      : 0.5
    : Math.min(1, Math.max(0, (raw - min) / (max - min)));
// Only arithmetic derived across Python/JavaScript may tolerate rounding. Retained
// observations, semantic fields, identities and normative proof bytes remain exact.
const close = (a: number | null, b: number | null) =>
  a === b ||
  (typeof a === "number" &&
    typeof b === "number" &&
    Number.isFinite(a) &&
    Number.isFinite(b) &&
    Math.abs(a - b) <= 1e-12);
const forest = z
  .strictObject({
    kind: z.literal("forest"),
    model_id: id,
    artifact_sha256: hash,
    model_version: text,
    after_score_samples: z.number().min(-1).max(0),
    after_decision_function: z.number().min(-1).max(1),
    after_prediction: z.union([z.literal(-1), z.literal(1)]),
    decision_offset: z.number().min(-1).max(0),
    training_sample_count: z.number().int().min(2).max(1000000),
    training_score_min: unit,
    training_score_max: unit,
    candidate_parser_confidence: unit,
    raw_anomaly_score: unit,
    normalized_anomaly: unit,
    proxy_confidence: unit,
    interpretation: z.literal("retained_forest_numeric_proxy_not_new_finding"),
  })
  .refine(
    (r) =>
      r.training_score_min <= r.training_score_max &&
      close(
        r.after_decision_function,
        r.after_score_samples - r.decision_offset,
      ) &&
      r.after_prediction === (r.after_decision_function < 0 ? -1 : 1) &&
      r.raw_anomaly_score === -r.after_score_samples &&
      close(
        r.normalized_anomaly,
        normalize(
          r.raw_anomaly_score,
          r.training_score_min,
          r.training_score_max,
        ),
      ) &&
      close(
        r.proxy_confidence,
        Math.min(
          r.candidate_parser_confidence,
          r.training_sample_count / 50,
          1,
        ),
      ),
  );
const neural = z
  .strictObject({
    kind: z.literal("neural"),
    model_sha256: hash,
    target_semantics: z.enum(["injected_mutation", "confirmed_anomaly"]),
    classes: z
      .array(z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/))
      .min(1)
      .max(64),
    anomaly_head_enabled: z.boolean(),
    anomaly_score: unit.nullable(),
    interpretation: z.literal("retained_uncalibrated_anomaly_head"),
  })
  .refine(
    (r) =>
      new Set(r.classes).size === r.classes.length &&
      r.anomaly_head_enabled === (r.anomaly_score !== null),
  );
const network = z
  .strictObject({
    kind: z.literal("verification"),
    protocol_version: networkVersion,
    result: batfishSchema,
    execution: batfishDirectionalExecutionSchema.nullable(),
  })
  .refine(
    (r) =>
      (r.protocol_version === "source-patch-verification-0.3.0") ===
        (r.execution !== null) &&
      (!r.execution || same(r.result, r.execution.result)),
  );
const observation = z.discriminatedUnion("kind", [
  findings,
  forest,
  neural,
  network,
]);
const component = z.strictObject({
  source,
  status: z.enum(["completed", "unavailable"]),
  reason: z.enum([
    "available",
    "not_selected",
    "peer_context_unavailable",
    "neural_anomaly_head_disabled",
    "legacy_network_protocol",
    "network_adverse_evidence_unavailable",
  ]),
  evidence: evidence.nullable(),
  observation: observation.nullable(),
  raw_score: unit.nullable(),
  configured_weight: unit,
  effective_weight: unit,
  contribution: unit.nullable(),
});
const guardrail = z
  .strictObject({
    kind: z.enum(["critical_policy", "observed_scoped_loss"]),
    floor: unit,
  })
  .refine((r) => r.floor === (r.kind === "critical_policy" ? 0.9 : 0.95));
export const priorityLimitations = [
  "This unitless engineering priority is not calibrated risk, probability, detector severity or detector confidence.",
  "Unavailable source weights are redistributed only within the recorded availability mask; partial coverage suppresses the aggregate. Completed zero does not establish overall safety.",
  "Forest normalization and confidence proxy are engineering operations; no new Finding is asserted.",
  "Neural values retain supported classes and injected-mutation or confirmed-anomaly target semantics; other classes are not qualified.",
  "Scoped differential examples use common active ingress locations and source IP inference from the after snapshot; they do not prove whole-network safety or formal qualification.",
  "The candidate after-side score and raw model outputs do not establish paired quality, a ranking delta or comparable scores across availability masks.",
  "The profile weights and priority bands at 0.25, 0.50 and 0.80 have not been calibrated or independently qualified.",
  "No model or verifier is rerun, and no quality, individual identity, approval or application is established.",
];
const compositionBase = z.strictObject({
  version: z.literal("source-priority-composition-0.1.0"),
  profile_version: z.literal("source-priority-profile-0.1.0"),
  side: z.literal("after"),
  report_id: id,
  report_sha256: hash,
  report_version: reportVersion,
  patch_id: id,
  draft_sha256: hash,
  before: snapshotBindingSchema.strict().extend({ canonical_sha256: hash }),
  after: snapshotBindingSchema.strict().extend({ canonical_sha256: hash }),
  before_analysis_id: id,
  before_analysis_sha256: hash,
  selected_evidence: z.array(evidence).min(1).max(4),
  coverage: z.enum(["supported_complete", "partial"]),
  candidate_parser_confidence: unit,
  components: z.array(component).length(5),
  availability_mask: z.array(source).max(5),
  status: z.enum(["completed", "unavailable"]),
  score: unit.nullable(),
  band: band.nullable(),
  applicable_guardrails: z.array(guardrail).max(2),
  applied_guardrails: z.array(guardrail).max(2),
  review_status: z.literal("needs_review"),
  formal_qualification: z.literal("not_proven"),
  calibrated: z.literal(false),
  quality_proven: z.literal(false),
  ...flags,
  limitations: z.array(z.string()).length(8),
});
type Composition = z.infer<typeof compositionBase>;
type Observation = z.infer<typeof observation>;
type Component = z.infer<typeof component>;
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
const severity = { info: 0.1, low: 0.25, medium: 0.5, high: 0.75, critical: 1 };
const findingScore = (r: z.infer<typeof finding>) =>
  Math.max(severity[r.severity], r.anomaly_score) * r.confidence;
const scopedLoss = (r: z.infer<typeof network>) =>
  r.execution !== null &&
  r.result.cleanup_complete === true &&
  r.execution.reachability_impact.state === "observed" &&
  ["loss_found", "loss_and_gain_found"].includes(
    r.execution.reachability_impact.direction ?? "",
  );
const sourceKind = [
  "deterministic",
  "deterministic",
  "forest",
  "neural",
  "network",
] as const;
function observedValue(
  row: Component,
  index: number,
): [number | null, Component["reason"]] | null {
  const o = row.observation;
  if (!row.evidence)
    return o === null && index > 1 ? [null, "not_selected"] : null;
  if (row.evidence.kind !== sourceKind[index]) return null;
  if (index <= 1) {
    if (index === 1 && o === null) return [null, "peer_context_unavailable"];
    return o?.kind === "findings" &&
      o.detector === (index === 0 ? "policy_engine" : "peer_baseline")
      ? [o.strongest ? findingScore(o.strongest) : 0, "available"]
      : null;
  }
  if (index === 2)
    return o?.kind === "forest"
      ? [
          o.after_prediction === 1
            ? 0
            : Math.max(0.5, o.normalized_anomaly) * o.proxy_confidence,
          "available",
        ]
      : null;
  if (index === 3)
    return o?.kind === "neural"
      ? [
          o.anomaly_score,
          o.anomaly_head_enabled ? "available" : "neural_anomaly_head_disabled",
        ]
      : null;
  if (o?.kind !== "verification" || o.protocol_version !== row.evidence.version)
    return null;
  return !o.execution
    ? [null, "legacy_network_protocol"]
    : scopedLoss(o)
      ? [1, "available"]
      : [null, "network_adverse_evidence_unavailable"];
}
const priorityBand = (n: number) =>
  n >= 0.8 ? "critical" : n >= 0.5 ? "high" : n >= 0.25 ? "medium" : "low";
function validComposition(c: Composition) {
  if (
    !same(
      c.components.map((r) => r.source),
      prioritySources,
    ) ||
    !same(
      c.selected_evidence.map((r) => r.kind),
      kinds.filter((k) => c.selected_evidence.some((r) => r.kind === k)),
    ) ||
    c.selected_evidence[0]?.kind !== "deterministic" ||
    !same(c.limitations, priorityLimitations)
  )
    return false;
  if (
    c.before.device_id !== c.after.device_id ||
    c.before.configuration_id === c.after.configuration_id ||
    c.before.source_sha256 === c.after.source_sha256 ||
    evidenceInstant(c.before.created_at) > evidenceInstant(c.after.created_at)
  )
    return false;
  const rails: z.infer<typeof guardrail>[] = [],
    mask: Component["source"][] = [];
  for (const [i, r] of c.components.entries()) {
    const value = observedValue(r, i),
      o = r.observation;
    if (
      !value ||
      !same(
        r.evidence,
        c.selected_evidence.find((e) => e.kind === sourceKind[i]) ?? null,
      ) ||
      r.configured_weight !== weights[i] ||
      !close(r.raw_score, value[0]) ||
      r.reason !== value[1] ||
      r.status !== (value[0] === null ? "unavailable" : "completed")
    )
      return false;
    if (
      o?.kind === "forest" &&
      o.candidate_parser_confidence !== c.candidate_parser_confidence
    )
      return false;
    if (value[0] !== null) mask.push(r.source);
    if (o?.kind === "findings" && o.critical_policy_present)
      rails.push({ kind: "critical_policy", floor: 0.9 });
    if (o?.kind === "verification" && scopedLoss(o))
      rails.push({ kind: "observed_scoped_loss", floor: 0.95 });
  }
  const complete = c.coverage === "supported_complete",
    total = c.components.reduce(
      (n, r) => n + (r.raw_score === null ? 0 : r.configured_weight),
      0,
    );
  if (
    !total ||
    !same(c.availability_mask, mask) ||
    !same(c.applicable_guardrails, rails) ||
    c.status !== (complete ? "completed" : "unavailable") ||
    (complete && c.candidate_parser_confidence !== 1)
  )
    return false;
  let sum = 0;
  for (const r of c.components) {
    const weight =
        complete && r.raw_score !== null ? r.configured_weight / total : 0,
      contribution =
        complete && r.raw_score !== null ? r.raw_score * weight : null;
    if (
      !close(r.effective_weight, weight) ||
      !close(r.contribution, contribution)
    )
      return false;
    sum += contribution ?? 0;
  }
  const score = complete
    ? Math.min(1, Math.max(sum, ...rails.map((r) => r.floor)))
    : null;
  return (
    close(c.score, score) &&
    c.band === (score === null ? null : priorityBand(score)) &&
    same(c.applied_guardrails, complete ? rails : [])
  );
}
export const sourcePriorityCompositionSchema =
  compositionBase.refine(validComposition);
export const createSourceRiskAssessmentSchema = z.strictObject({
  version: z.literal("source-risk-request-0.1.0"),
  assessment_id: id,
  report_sha256: hash,
  profile_version: z.literal("source-priority-profile-0.1.0"),
});
export type CreateSourceRiskAssessment = z.infer<
  typeof createSourceRiskAssessmentSchema
>;
export const sourceRiskAssessmentSchema = z
  .strictObject({
    version: z.literal("source-risk-assessment-0.1.0"),
    request: createSourceRiskAssessmentSchema,
    assessment_id: id,
    patch_id: id,
    report_id: id,
    report_sha256: hash,
    report_version: reportVersion,
    draft_sha256: hash,
    created_at: timestamp,
    service_role: z.enum(["engineer", "admin"]),
    composition: sourcePriorityCompositionSchema,
    ...flags,
    review_json: z
      .string()
      .min(1)
      .max(1024 * 1024),
    review_sha256: hash,
  })
  .refine(
    (r) =>
      r.assessment_id === r.request.assessment_id &&
      r.report_sha256 === r.request.report_sha256 &&
      r.request.profile_version === r.composition.profile_version &&
      [
        "patch_id",
        "report_id",
        "report_sha256",
        "report_version",
        "draft_sha256",
      ].every(
        (k) => r[k as keyof typeof r] === r.composition[k as keyof Composition],
      ) &&
      new TextEncoder().encode(r.review_json).length <= 1024 * 1024 &&
      new TextEncoder().encode(JSON.stringify(r)).length <= 2 * 1024 * 1024,
  );
export type SourceRiskAssessment = z.infer<typeof sourceRiskAssessmentSchema>;
export const sourceRiskSummarySchema = z
  .strictObject({
    version: z.literal("source-risk-summary-0.1.0"),
    assessment_id: id,
    patch_id: id,
    report_id: id,
    report_sha256: hash,
    report_version: reportVersion,
    draft_sha256: hash,
    review_sha256: hash,
    created_at: timestamp,
    service_role: z.enum(["engineer", "admin"]),
    profile_version: z.literal("source-priority-profile-0.1.0"),
    composition_status: z.enum(["completed", "unavailable"]),
    score: unit.nullable(),
    band: band.nullable(),
    coverage: z.enum(["supported_complete", "partial"]),
    availability_mask: z.array(source).min(1).max(5),
    applicable_guardrails: z
      .array(z.enum(["critical_policy", "observed_scoped_loss"]))
      .max(2),
    ...flags,
  })
  .refine(
    (r) =>
      r.availability_mask[0] === "policy" &&
      same(
        r.availability_mask,
        prioritySources.filter((s) => r.availability_mask.includes(s)),
      ) &&
      same(
        r.applicable_guardrails,
        (["critical_policy", "observed_scoped_loss"] as const).filter((s) =>
          r.applicable_guardrails.includes(s),
        ),
      ) &&
      (r.composition_status === "completed") ===
        (r.coverage === "supported_complete") &&
      (r.score !== null) === (r.coverage === "supported_complete") &&
      (r.band !== null) === (r.coverage === "supported_complete") &&
      (r.score === null || r.band === priorityBand(r.score)),
  );
export type SourceRiskSummary = z.infer<typeof sourceRiskSummarySchema>;
export function sourceRiskSummaryBound(
  r: SourceRiskSummary,
  p: SourceEvidenceReport,
) {
  return (
    r.patch_id === p.patch_id &&
    r.report_id === p.report_id &&
    r.report_sha256 === p.review_sha256 &&
    r.report_version === p.version &&
    r.draft_sha256 === p.draft_sha256 &&
    evidenceInstant(r.created_at) >= evidenceInstant(p.created_at)
  );
}
export function sourceRiskSummary(r: SourceRiskAssessment): SourceRiskSummary {
  const c = r.composition;
  return {
    version: "source-risk-summary-0.1.0",
    assessment_id: r.assessment_id,
    patch_id: r.patch_id,
    report_id: r.report_id,
    report_sha256: r.report_sha256,
    report_version: r.report_version,
    draft_sha256: r.draft_sha256,
    review_sha256: r.review_sha256,
    created_at: r.created_at,
    service_role: r.service_role,
    profile_version: c.profile_version,
    composition_status: c.status,
    score: c.score,
    band: c.band,
    coverage: c.coverage,
    availability_mask: c.availability_mask,
    applicable_guardrails: c.applicable_guardrails.map((g) => g.kind),
    individual_identity_verified: false,
    approved: false,
    applied: false,
  };
}
export async function sourceRiskProofMatches(r: SourceRiskAssessment) {
  try {
    const { review_json, review_sha256, ...body } = r;
    if (
      evidenceRawJsonAt(review_json, []) === undefined ||
      !same(JSON.parse(review_json), body)
    )
      return false;
    const bytes = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(review_json),
    );
    return (
      Array.from(new Uint8Array(bytes), (b) =>
        b.toString(16).padStart(2, "0"),
      ).join("") === review_sha256
    );
  } catch {
    return false;
  }
}
function findingObservation(
  rows: z.infer<typeof finding>[],
  detector: "policy_engine" | "peer_baseline",
): Observation {
  const selected = [...rows].sort(
    (a, b) =>
      findingScore(b) - findingScore(a) ||
      (a.finding_id < b.finding_id ? -1 : a.finding_id > b.finding_id ? 1 : 0),
  )[0];
  return {
    kind: "findings",
    detector,
    finding_count: rows.length,
    strongest: selected
      ? {
          finding_id: selected.finding_id,
          severity: selected.severity,
          confidence: selected.confidence,
          anomaly_score: selected.anomaly_score,
        }
      : null,
    critical_policy_present:
      detector === "policy_engine" &&
      rows.some((r) => r.severity === "critical"),
  };
}
// Validate the server's observation against full immutable children. A resealed,
// internally consistent summary cannot substitute a retained model output.
export async function sourceRiskAssessmentBound(
  r: SourceRiskAssessment,
  draft: PatchDraft,
  parent: SourceEvidenceReport,
  children: SourceEvidenceChildren,
  expected?: CreateSourceRiskAssessment,
  summary?: SourceRiskSummary,
) {
  if (
    !sourceRiskAssessmentSchema.safeParse(r).success ||
    !(await sourceRiskProofMatches(r)) ||
    !(await sourceEvidenceReportBound(parent, draft, children)) ||
    !sourceRiskSummaryBound(sourceRiskSummary(r), parent) ||
    (expected && !same(expected, r.request)) ||
    (summary && !same(summary, sourceRiskSummary(r)))
  )
    return false;
  const c = r.composition;
  if (
    c.coverage !== draft.diff.coverage ||
    c.candidate_parser_confidence !== draft.diff.after.parser_confidence ||
    !same(c.before, parent.before) ||
    !same(c.after, parent.after) ||
    c.before_analysis_id !== parent.before_analysis_id ||
    c.before_analysis_sha256 !== parent.before_analysis_sha256
  )
    return false;
  const refs = kinds.flatMap((kind) => {
    const p = parent[kind];
    return p
      ? [
          {
            kind,
            version: p.version,
            record_id: p.record_id,
            review_sha256: p.review_sha256,
          },
        ]
      : [];
  });
  if (!same(c.selected_evidence, refs)) return false;
  const after = children.deterministic.outcome?.report?.after;
  if (!after) return false;
  const observations: (Observation | null)[] = [
    findingObservation(after.policy_findings, "policy_engine"),
    after.peer_findings === null
      ? null
      : findingObservation(after.peer_findings, "peer_baseline"),
    null,
    null,
    null,
  ];
  if (children.forest) {
    const f = children.forest.outcome?.report;
    if (!f) return false;
    const m = f.model,
      s = f.scores,
      raw = -s.after_score_samples;
    observations[2] = {
      kind: "forest",
      model_id: m.model_id,
      artifact_sha256: m.artifact_sha256,
      model_version: m.metadata.model_version,
      after_score_samples: s.after_score_samples,
      after_decision_function: s.after_decision_function,
      after_prediction: s.after_prediction,
      decision_offset: m.decision_offset,
      training_sample_count: m.metadata.sample_count,
      training_score_min: m.metadata.training_score_min,
      training_score_max: m.metadata.training_score_max,
      candidate_parser_confidence: draft.diff.after.parser_confidence,
      raw_anomaly_score: raw,
      normalized_anomaly: normalize(
        raw,
        m.metadata.training_score_min,
        m.metadata.training_score_max,
      ),
      proxy_confidence: Math.min(
        draft.diff.after.parser_confidence,
        m.metadata.sample_count / 50,
        1,
      ),
      interpretation: "retained_forest_numeric_proxy_not_new_finding",
    };
  }
  if (children.neural) {
    const n = children.neural.outcome?.report?.after;
    if (!n) return false;
    observations[3] = {
      kind: "neural",
      model_sha256: n.model.model_sha256,
      target_semantics: n.model.target_semantics,
      classes: n.model.classes,
      anomaly_head_enabled: n.model.enabled_heads.anomaly,
      anomaly_score: n.prediction.anomaly_score,
      interpretation: "retained_uncalibrated_anomaly_head",
    };
  }
  if (children.network) {
    const n = children.network,
      outcome = n.outcome,
      result = sourceNetworkResult(outcome);
    if (!outcome || !result) return false;
    observations[4] = {
      kind: "verification",
      protocol_version: n.version,
      result,
      execution:
        "network_execution" in outcome &&
        outcome.network_execution.version === "batfish-execution-0.3.0"
          ? outcome.network_execution
          : null,
    };
  }
  return c.components.every((component, i) => {
    const expected = observations[i],
      actual = component.observation;
    if (expected?.kind === "forest" && actual?.kind === "forest") {
      const { normalized_anomaly: a, proxy_confidence: b, ...rest } = actual;
      const {
        normalized_anomaly: x,
        proxy_confidence: y,
        ...retained
      } = expected;
      return same(rest, retained) && close(a, x) && close(b, y);
    }
    return same(actual, expected);
  });
}
