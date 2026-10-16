import { z } from "zod";
import {
  explanationBundleSchema,
  explanationCapabilitiesSchema,
  stableJson,
} from "./contracts";
import type {
  AnalysisResult,
  ConfigurationSnapshot,
  Finding,
} from "./contracts";
import { explanationMatches } from "./explanation";

const hash = z.string().regex(/^[0-9a-f]{64}$/);
const count = z.number().int().min(0).max(1_000_000);
const fraction = z.number().min(0).max(1);
const finite = z.number().finite();
const unique = <T>(items: T[]) => new Set(items).size === items.length;
const same = (left: unknown, right: unknown) =>
  stableJson(left) === stableJson(right);
const lines = z
  .array(count.min(1))
  .refine(
    (items) => unique(items) && items.every((n, i) => !i || n > items[i - 1]!),
  );
const text = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .refine(
      (value) =>
        value.trim().length > 0 &&
        !/[\p{C}\p{Zl}\p{Zp}]/u.test(value.replace(/[\n\t]/g, "")),
    );
const peerVersion = z.enum([
  "peer-baseline-0.1.0",
  "peer-baseline-0.2.0",
  "peer-baseline-0.3.0",
]);
const peerReport = z
  .strictObject({
    version: z.enum([
      "peer-comparison-report-0.2.0",
      "peer-comparison-report-0.3.0",
    ]),
    status: z.enum(["completed", "partial"]),
    selected_peer_count: count.min(3).max(20),
    profile_feature_count: count.max(1024),
    compared_feature_count: count.max(1024),
    skipped_feature_count: count.max(1024),
  })
  .refine(
    (report) =>
      report.compared_feature_count + report.skipped_feature_count ===
        report.profile_feature_count &&
      (report.status === "completed"
        ? report.skipped_feature_count === 0
        : report.compared_feature_count === 0),
  );
const selectionFacts = z
  .strictObject({
    version: z.literal("grounded-explanation-selection-facts-0.1.0"),
    reference: z
      .strictObject({ source_sha256: hash, approval: z.literal("not_proven") })
      .nullable(),
    peer: z
      .strictObject({
        baseline_version: peerVersion,
        selected_peer_count: count.min(3).max(20),
        profile_feature_count: count.max(1024),
        baseline_sha256: hash.nullable(),
      })
      .nullable(),
    statistical: z
      .strictObject({
        training_sample_count: count.min(1),
        raw_anomaly_score: finite,
        decision_function: finite,
        artifact_sha256: hash.nullable(),
      })
      .nullable(),
  })
  .refine(
    (value) =>
      [value.reference, value.peer, value.statistical].filter(Boolean).length <=
      1,
  );
const peerFacts = z
  .strictObject({
    method: z.enum([
      "supported_property",
      "confidence_deficit_proxy",
      "measured_source_fraction",
    ]),
    support_count: count.min(1).max(20).nullable(),
    sample_count: count.min(1).max(20).nullable(),
    observed_fraction: fraction.nullable(),
    maximum_fraction: fraction.nullable(),
    unparsed_units: count.nullable(),
    command_units: count.min(1).nullable(),
    unit: z.literal("adapter_source_lines").nullable(),
    adapter_version: z
      .enum(["cisco-ios-source-lines-0.1.0", "junos-source-lines-0.1.0"])
      .nullable(),
    coverage_report_sha256: hash.nullable(),
  })
  .refine((value) => {
    if (
      (value.support_count === null) !== (value.sample_count === null) ||
      (value.support_count !== null &&
        value.support_count > value.sample_count!)
    )
      return false;
    const measured = [
      value.unparsed_units,
      value.command_units,
      value.unit,
      value.adapter_version,
      value.coverage_report_sha256,
    ];
    if (value.method === "measured_source_fraction") {
      if (
        measured.some((item) => item === null) ||
        value.maximum_fraction === null ||
        value.observed_fraction !== value.unparsed_units! / value.command_units!
      )
        return false;
    } else if (measured.some((item) => item !== null)) return false;
    return value.method === "supported_property"
      ? value.support_count !== null && value.observed_fraction === null
      : value.observed_fraction !== null && value.maximum_fraction !== null;
  });

export const groundedExplanationFactsSchema = z
  .strictObject({
    version: z.literal("grounded-explanation-source-facts-0.1.0"),
    phase: z.literal("saved_analysis_explanation"),
    source_sha256: hash,
    finding_sha256: hash,
    vendor: z.enum(["cisco", "juniper"]),
    platform: z.enum(["ios", "junos"]),
    detector: z.enum([
      "policy_engine",
      "expected_configuration",
      "peer_baseline",
      "isolation_forest",
    ]),
    detector_version: text(200),
    category: text(200),
    interpretation: z.enum([
      "project_policy",
      "selected_reference",
      "statistical_control",
      "peer_property",
      "peer_confidence_deficit_proxy",
      "peer_measured_source_fraction",
    ]),
    parser: z.strictObject({
      confidence: fraction,
      warning_count: count.max(10_000),
      unparsed_count: count.max(10_000),
    }),
    analysis_facts: z.strictObject({
      version: z.literal("explanation-analysis-facts-0.1.0"),
      analysis_status: z.enum(["completed", "partial", "not_supplied"]),
      peer_report: peerReport.nullable(),
    }),
    invocation_facts: z.strictObject({
      version: z.literal("explanation-invocation-facts-0.1.0"),
      entrypoint: z.literal("saved_analysis_http"),
      analysis_storage: z.literal("stored_analysis"),
      model_answer_storage: z.literal("not_stored_in_analysis"),
      selected_finding_peer_profile_storage: z.enum([
        "stored_in_analysis",
        "not_applicable",
        "not_supplied",
      ]),
    }),
    observed: z.record(z.string(), z.json()),
    expected: z.record(z.string(), z.json()),
    anchors: z.array(
      z.strictObject({
        source_sha256: hash,
        lines: lines.min(1),
        statement_sha256: hash,
      }),
    ),
    selection_facts: selectionFacts,
    reference: z
      .strictObject({
        source_sha256: hash,
        observed_present: z.boolean(),
        expected_present: z.boolean(),
        reference_lines: lines,
        approval: z.literal("not_proven"),
      })
      .nullable(),
    peer: peerFacts.nullable(),
    forest: z
      .strictObject({
        raw_anomaly_score: finite,
        decision_function: finite,
        training_sample_count: count.min(1),
        training_score_min: finite,
        training_score_max: finite,
      })
      .nullable(),
    knowledge_version: explanationBundleSchema.shape.knowledge_version,
    knowledge_sha256: hash,
    documents: z
      .array(
        z.strictObject({
          citation: text(330),
          document_sha256: hash,
          content_sha256: hash,
          role: z.enum(["required", "supplement"]),
          authority: z.literal("sealed_internal_project_document"),
        }),
      )
      .min(1)
      .max(4),
    formal_verification: z.literal("not_run"),
    verification_scope: z.strictObject({
      vendor_syntax: z.literal("not_checked_in_this_explanation"),
      network_impact: z.literal("not_checked_in_this_explanation"),
      management_access: z.literal("not_checked_in_this_explanation"),
      rollback: z.literal("not_checked_in_this_explanation"),
    }),
  })
  .refine(
    (facts) =>
      facts.platform === (facts.vendor === "cisco" ? "ios" : "junos") &&
      facts.anchors.every(
        (anchor) => anchor.source_sha256 === facts.source_sha256,
      ) &&
      (!facts.analysis_facts.peer_report ||
        facts.analysis_facts.peer_report.status ===
          facts.analysis_facts.analysis_status) &&
      (facts.reference !== null) ===
        (facts.detector === "expected_configuration") &&
      (facts.peer !== null) === (facts.detector === "peer_baseline") &&
      (facts.forest !== null) === (facts.detector === "isolation_forest"),
  );
export type GroundedExplanationFacts = z.infer<
  typeof groundedExplanationFactsSchema
>;

const factRefs = [
  "selected_finding",
  "observed_values",
  "expected_values",
  "source_anchors",
  "parser_scope",
  "analysis_scope",
  "invocation_scope",
  "method_limitations",
  "required_sources",
  "selected_reference",
  "peer_consensus",
  "selected_peer_profile",
  "peer_report",
  "measured_parser_coverage",
  "statistical_record",
] as const;
export const groundedExplanationAnswerSchema = z.strictObject({
  version: z.literal("grounded-explanation-answer-0.1.0"),
  facts_binding_sha256: hash,
  fact_refs: z.array(z.enum(factRefs)).min(1).max(16).refine(unique),
  recommendation_code: z.enum([
    "review_policy",
    "review_reference",
    "review_peers",
    "review_statistical",
    "review_parser",
  ]),
  missing_information_codes: z
    .array(
      z.enum([
        "operational_impact",
        "vendor_syntax",
        "management_access",
        "rollback",
        "credentials",
        "reference_approval",
        "peer_selection_bias",
        "training_representativeness",
        "organizational_policy",
      ]),
    )
    .max(9)
    .refine(unique),
  citations: z.array(text(330)).min(1).max(4).refine(unique),
  patch_draft: z.null(),
  requires_human_review: z.literal(true),
});
export const groundedExplanationPresentationSchema = z.strictObject({
  version: z.literal("grounded-explanation-presentation-0.1.0"),
  presentation_kind: z.literal("server_derived"),
  summary: text(1000),
  technical_explanation: text(100_000),
  possible_impact: z.array(text(8000)).max(10),
  recommendation: text(4000),
  assumptions: z.array(text(8000)).max(20),
  missing_information: z.array(text(8000)).max(20),
  citations: z.array(text(330)).min(1).max(4).refine(unique),
  patch_draft: z.null(),
  requires_human_review: z.literal(true),
});
export type GroundedExplanationPresentation = z.infer<
  typeof groundedExplanationPresentationSchema
>;

// JSON strings are the sole wire authority. Never hash a JS reserialization of facts:
// Python and JavaScript encode floating point exponents and integral floats differently.
function parseJson<T>(value: string, schema: z.ZodType<T>): T | null {
  try {
    const parsed: unknown = JSON.parse(value);
    // JSON.parse silently collapses duplicate keys. Track lexical object keys too.
    const objects: (Set<string> | null)[] = [];
    const tokens =
      value.match(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,]+/gu) ?? [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i]!;
      if (token === "{") objects.push(new Set());
      else if (token === "[") objects.push(null);
      else if (token === "}" || token === "]") objects.pop();
      else if (token.startsWith('"') && tokens[i + 1] === ":") {
        const keys = objects.at(-1);
        const key = JSON.parse(token) as string;
        if (!keys || keys.has(key)) return null;
        keys.add(key);
      }
    }
    return schema.parse(parsed);
  } catch {
    return null;
  }
}

export function groundedExplanationFacts(bundle: {
  source_facts_json: string;
}) {
  return parseJson(bundle.source_facts_json, groundedExplanationFactsSchema);
}
export function groundedExplanationPresentation(bundle: {
  projection_json: string;
}) {
  return parseJson(
    bundle.projection_json,
    groundedExplanationPresentationSchema,
  );
}

export const groundedExplanationCapabilitiesSchema = z.strictObject({
  version: z.literal("grounded-explanation-capabilities-0.1.0"),
  legacy: explanationCapabilitiesSchema,
  grounded_explanation: z.enum(["disabled", "configured"]),
  protocol: z.literal("grounded-model-explanation-0.1.0"),
  model_health_checked: z.literal(false),
  explicit_request_permission_required: z.literal(true),
});
export type GroundedExplanationCapabilities = z.infer<
  typeof groundedExplanationCapabilitiesSchema
>;
export const groundedExplanationSchema = z
  .strictObject({
    ...explanationBundleSchema.shape,
    version: z.literal("grounded-model-explanation-0.1.0"),
    provider: z.literal("loopback_grounded_language_model"),
    llm_status: z.literal("draft"),
    presentation_kind: z.literal("server_derived"),
    privacy_version: z.literal("finding-context-redaction-0.1.0"),
    model_alias: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/),
    context_sha256: hash,
    source_facts_json: z.string().max(65536),
    facts_binding_sha256: hash,
    model_answer: groundedExplanationAnswerSchema,
    model_answer_sha256: hash,
    instructions_sha256: hash,
    answer_schema_sha256: hash,
    renderer_version: z.literal("grounded-explanation-presentation-0.1.0"),
    renderer_policy_sha256: hash,
    projection_json: z.string().max(131072),
    projection_sha256: hash,
  })
  .refine((bundle) => {
    // Reuse the legacy context validator without reinterpreting legacy prose.
    const {
      version: _version,
      provider: _provider,
      llm_status: _status,
      presentation_kind: _kind,
      privacy_version: _privacy,
      model_alias: _alias,
      context_sha256: _context,
      source_facts_json: _facts,
      facts_binding_sha256: _factsHash,
      model_answer: _answer,
      model_answer_sha256: _answerHash,
      instructions_sha256: _instructions,
      answer_schema_sha256: _schema,
      renderer_version: _renderer,
      renderer_policy_sha256: _policy,
      projection_json: _projection,
      projection_sha256: _projectionHash,
      ...common
    } = bundle;
    const legacy = explanationBundleSchema.safeParse({
      ...common,
      version:
        bundle.retrieval === "semantic_supplement"
          ? "finding-context-0.2.0"
          : "finding-context-0.1.0",
      provider: "deterministic_local",
      llm_status: "unavailable",
    });
    const facts = groundedExplanationFacts(bundle);
    const presentation = groundedExplanationPresentation(bundle);
    if (!legacy.success || !facts || !presentation) return false;
    const required =
      bundle.semantic_retrieval?.required_citations ??
      bundle.documents.map((doc) => doc.citation);
    const available: string[] = [...factRefs.slice(0, 9)];
    if (facts.reference) available.push("selected_reference");
    if (facts.peer) available.push("peer_consensus");
    if (facts.selection_facts.peer) available.push("selected_peer_profile");
    if (facts.analysis_facts.peer_report) available.push("peer_report");
    if (facts.interpretation === "peer_measured_source_fraction")
      available.push("measured_parser_coverage");
    if (facts.forest) available.push("statistical_record");
    const missing = [
      "operational_impact",
      "vendor_syntax",
      "management_access",
      "rollback",
      "credentials",
    ];
    if (facts.reference) missing.push("reference_approval");
    if (facts.peer) missing.push("peer_selection_bias");
    if (facts.forest) missing.push("training_representativeness");
    if (facts.interpretation === "project_policy")
      missing.push("organizational_policy");
    const recommendation = {
      project_policy: "review_policy",
      selected_reference: "review_reference",
      statistical_control: "review_statistical",
      peer_property: "review_peers",
      peer_confidence_deficit_proxy: "review_parser",
      peer_measured_source_fraction: "review_parser",
    }[facts.interpretation];
    return (
      facts.source_sha256 === bundle.source_sha256 &&
      facts.finding_sha256 === bundle.finding_sha256 &&
      facts.detector_version === bundle.explanation.detector_version &&
      facts.knowledge_version === bundle.knowledge_version &&
      facts.knowledge_sha256 === bundle.knowledge_sha256 &&
      same(facts.anchors, bundle.explanation.anchors) &&
      facts.documents.length === bundle.documents.length &&
      facts.documents.every((pin, i) => {
        const doc = bundle.documents[i]!;
        return (
          pin.citation === doc.citation &&
          pin.document_sha256 === doc.document_sha256 &&
          pin.content_sha256 === doc.content_sha256 &&
          pin.role ===
            (required.includes(doc.citation) ? "required" : "supplement")
        );
      }) &&
      bundle.model_answer.facts_binding_sha256 ===
        bundle.facts_binding_sha256 &&
      same(bundle.model_answer.citations, required) &&
      same(presentation.citations, required) &&
      bundle.model_answer.fact_refs.every((ref) => available.includes(ref)) &&
      bundle.model_answer.missing_information_codes.every((code) =>
        missing.includes(code),
      ) &&
      bundle.model_answer.recommendation_code === recommendation
    );
  });
export type GroundedExplanation = z.infer<typeof groundedExplanationSchema>;

export async function explanationTextDigest(value: string) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
export async function groundedExplanationBindingsMatch(
  bundle: GroundedExplanation,
) {
  return (
    groundedExplanationSchema.safeParse(bundle).success &&
    (await explanationTextDigest(bundle.source_facts_json)) ===
      bundle.facts_binding_sha256 &&
    (await explanationTextDigest(bundle.projection_json)) ===
      bundle.projection_sha256 &&
    (await explanationTextDigest(stableJson(bundle.model_answer))) ===
      bundle.model_answer_sha256
  );
}

// Mirror the request-local pseudonym traversal, comparing values without exporting
// its private alias mapping. Only hashes of exact wire strings are normative.
function redactedFindingValues(finding: Finding) {
  const keys = new Map<string, string>(),
    values = new Map<string, string>();
  function redact(value: unknown): unknown {
    if (typeof value === "string") {
      if (!values.has(value))
        values.set(
          value,
          `[value_${String(values.size + 1).padStart(4, "0")}]`,
        );
      return values.get(value);
    }
    if (Array.isArray(value)) return value.map(redact);
    if (value !== null && typeof value === "object") {
      const result: Record<string, unknown> = {};
      const source = value as Record<string, unknown>;
      // Python sorts Unicode code points, not UTF-16 code units.
      const compare = (a: string, b: string) => {
        const left = Array.from(a, (c) => c.codePointAt(0)!),
          right = Array.from(b, (c) => c.codePointAt(0)!);
        for (let i = 0; i < Math.min(left.length, right.length); i++)
          if (left[i] !== right[i]) return left[i]! - right[i]!;
        return left.length - right.length;
      };
      for (const key of Object.keys(source).sort(compare)) {
        if (!keys.has(key))
          keys.set(key, `field_${String(keys.size + 1).padStart(4, "0")}`);
        result[keys.get(key)!] = redact(source[key]);
      }
      return result;
    }
    return value;
  }
  return {
    observed: redact(finding.observed),
    expected: redact(finding.expected),
  };
}

export async function groundedExplanationMatches(
  bundle: GroundedExplanation,
  analysis: AnalysisResult,
  finding: Finding,
  snapshot?: ConfigurationSnapshot | null,
) {
  const selected = analysis.findings.find(
    (item) => item.finding_id === finding.finding_id,
  );
  if (
    !selected ||
    !same(selected, finding) ||
    !snapshot ||
    !(await groundedExplanationBindingsMatch(bundle)) ||
    !(await explanationMatches(bundle, analysis, finding))
  )
    return false;
  const facts = groundedExplanationFacts(bundle)!;
  const config = snapshot.canonical,
    comparison = analysis.comparison;
  if (
    snapshot.configuration_id !== analysis.configuration_id ||
    snapshot.device_id !== analysis.device_id ||
    config.source.sha256 !== analysis.source_sha256 ||
    facts.vendor !== config.device.vendor ||
    facts.platform !== config.device.platform ||
    facts.parser.confidence !== config.parser_confidence ||
    facts.parser.warning_count !== config.parse_warnings.length ||
    facts.parser.unparsed_count !== config.unparsed_fragments.length ||
    facts.detector !== finding.detector ||
    facts.detector_version !== finding.model_version ||
    facts.analysis_facts.analysis_status !== analysis.status
  )
    return false;
  const redacted = redactedFindingValues(finding);
  const category = {
    policy_engine: finding.category,
    expected_configuration: "reference_difference",
    peer_baseline: "peer_difference",
    isolation_forest: "structured_outlier",
  }[finding.detector];
  if (
    facts.category !== category ||
    !same(facts.observed, redacted.observed) ||
    !same(facts.expected, redacted.expected)
  )
    return false;
  const report =
    finding.detector === "peer_baseline" &&
    comparison &&
    "peer_evaluation" in comparison
      ? comparison.peer_evaluation
      : null;
  const expectedReport = report
    ? {
        version: report.version,
        status: report.status,
        selected_peer_count: comparison!.peers.length,
        profile_feature_count: report.profile_features.length,
        compared_feature_count: report.compared_features.length,
        skipped_feature_count: report.skipped_features.length,
      }
    : null;
  if (
    !same(facts.analysis_facts.peer_report, expectedReport) ||
    facts.invocation_facts.selected_finding_peer_profile_storage !==
      (finding.detector !== "peer_baseline"
        ? "not_applicable"
        : comparison?.peer_baseline
          ? "stored_in_analysis"
          : "not_supplied")
  )
    return false;
  const selection = facts.selection_facts;
  if (finding.detector === "policy_engine")
    return (
      facts.interpretation === "project_policy" &&
      !selection.reference &&
      !selection.peer &&
      !selection.statistical
    );
  if (finding.detector === "expected_configuration") {
    return (
      facts.interpretation === "selected_reference" &&
      !!comparison?.reference &&
      same(selection.reference, {
        source_sha256: comparison.reference.source_sha256,
        approval: "not_proven",
      }) &&
      same(facts.reference, {
        source_sha256: finding.expected.source_sha256,
        observed_present: finding.observed.present,
        expected_present: finding.expected.present,
        reference_lines: finding.expected.reference_lines,
        approval: "not_proven",
      })
    );
  }
  if (finding.detector === "isolation_forest") {
    const statistical = analysis.statistical;
    return (
      facts.interpretation === "statistical_control" &&
      !!statistical &&
      same(selection.statistical, {
        training_sample_count: statistical.model.metadata.sample_count,
        raw_anomaly_score: -statistical.score_samples,
        decision_function: statistical.decision_function,
        artifact_sha256: statistical.model.artifact_sha256,
      }) &&
      same(facts.forest, {
        raw_anomaly_score: finding.observed.raw_anomaly_score,
        decision_function: finding.observed.decision_function,
        training_sample_count: finding.expected.training_sample_count,
        training_score_min: finding.expected.training_score_min,
        training_score_max: finding.expected.training_score_max,
      })
    );
  }
  const profile = comparison?.peer_baseline,
    selectedPeer = selection.peer,
    peer = facts.peer;
  if (!profile || !selectedPeer || !peer) return false;
  const properties = "properties" in profile ? profile.properties : profile;
  if (
    selectedPeer.baseline_version !== profile.model_version ||
    selectedPeer.selected_peer_count !== comparison!.peers.length ||
    selectedPeer.profile_feature_count !== properties.features.length ||
    selectedPeer.baseline_sha256 !== (finding.expected.baseline_sha256 ?? null)
  )
    return false;
  if (finding.category === "baseline.parser.unparsed_fraction_high")
    return (
      facts.interpretation === "peer_measured_source_fraction" &&
      peer.method === "measured_source_fraction" &&
      finding.model_version === "peer-baseline-0.3.0" &&
      peer.observed_fraction === finding.observed.value &&
      peer.maximum_fraction === finding.expected.maximum_unparsed_fraction &&
      peer.unparsed_units === finding.observed.unparsed_units &&
      peer.command_units === finding.observed.command_units &&
      peer.unit === finding.observed.unit &&
      peer.adapter_version === finding.observed.adapter_version &&
      peer.coverage_report_sha256 === finding.observed.coverage_report_sha256
    );
  if (finding.category === "baseline.parser.unsupported_ratio_high")
    return (
      facts.interpretation === "peer_confidence_deficit_proxy" &&
      peer.method === "confidence_deficit_proxy" &&
      finding.model_version !== "peer-baseline-0.3.0" &&
      peer.observed_fraction ===
        (finding.model_version === "peer-baseline-0.1.0"
          ? finding.observed.unsupported_ratio
          : finding.observed.value) &&
      peer.maximum_fraction === finding.expected.maximum_unsupported_ratio
    );
  return (
    facts.interpretation === "peer_property" &&
    peer.method === "supported_property" &&
    peer.support_count === finding.expected.peer_support_count &&
    peer.sample_count === finding.expected.peer_sample_count
  );
}

export type ExplanationRequestScope = {
  client: object;
  analysis: object;
  finding: object;
  snapshot: object | null;
  mode: "legacy" | "grounded";
  retrieval: "explicit_reference" | "semantic_supplement";
};
export function sameExplanationScope(
  left: ExplanationRequestScope,
  right: ExplanationRequestScope,
) {
  return (
    left.client === right.client &&
    left.analysis === right.analysis &&
    left.finding === right.finding &&
    left.snapshot === right.snapshot &&
    left.mode === right.mode &&
    left.retrieval === right.retrieval
  );
}
// Single-use consent and request identity are shared by the UI and the unit checks.
// Changing any input invalidates pending answers before the next effect can run.
export class ExplanationRequestGate {
  private scope: ExplanationRequestScope | null = null;
  private sequence = 0;
  permission = false;
  loading = false;
  bind(scope: ExplanationRequestScope) {
    if (!this.scope || !sameExplanationScope(this.scope, scope))
      this.invalidate();
    this.scope = scope;
  }
  allow(value: boolean) {
    this.permission = value;
  }
  begin(model: boolean) {
    if (this.loading || (model && !this.permission)) return null;
    this.permission = false;
    this.loading = true;
    return ++this.sequence;
  }
  current(request: number) {
    return request === this.sequence;
  }
  finish(request: number) {
    if (this.current(request)) this.loading = false;
  }
  invalidate() {
    this.sequence += 1;
    this.permission = false;
    this.loading = false;
  }
}
