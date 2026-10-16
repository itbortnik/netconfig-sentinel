import {
  analysisSchema,
  findingSchema,
  snapshotSchema,
  stableJson,
} from "./contracts";
import {
  explanationTextDigest,
  groundedExplanationSchema,
} from "./groundedExplanation";
import type {
  GroundedExplanation,
  GroundedExplanationFacts,
} from "./groundedExplanation";

// Authored software-contract data. No model, network or verifier runs here.
export const explanationFixtureId = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
export async function groundedExplanationFixture(
  version: GroundedExplanation["version"] = "grounded-model-explanation-0.2.0",
) {
  const id = explanationFixtureId;
  const source = "b".repeat(64),
    fingerprint = "a".repeat(64),
    statement = "c".repeat(64);
  const location = {
    source_lines: [3],
    raw_text_hash: statement,
    parser_confidence: 0.9,
  };
  const finding = findingSchema.parse({
    finding_id: id(1),
    device_id: id(2),
    detector: "policy_engine",
    category: "management.ssh_disabled",
    title: "Authored policy fixture",
    severity: "high",
    confidence: 0.9,
    anomaly_score: 1,
    affected_lines: [3],
    evidence: [
      {
        kind: "configuration",
        message: "Fixture evidence",
        source_location: location,
      },
    ],
    observed: { setting: false, tiny: 1e-7 },
    expected: { setting: true },
    remediation: "Review manually",
    references: ["docs/policies/management-plane.md#ssh-must-be-enabled"],
    limitations: ["Authored fixture"],
    model_version: "policy-rules-0.7.0",
  });
  const explanation = {
    version: "local-explanation-0.1.0" as const,
    provider: "deterministic_local" as const,
    finding_id: id(1),
    device_id: id(2),
    source_sha256: source,
    finding_sha256: fingerprint,
    detector_version: finding.model_version,
    severity: finding.severity,
    confidence: finding.confidence,
    anomaly_score: finding.anomaly_score,
    summary: "Authored deterministic fixture",
    technical_explanation: "Saved deterministic text",
    recommendation: "Review manually",
    anchors: [
      { source_sha256: source, lines: [3], statement_sha256: statement },
    ],
    citations: finding.references,
    limitations: ["Authored fixture"],
    formal_verification: "not_run" as const,
    patch_draft: null,
    requires_human_review: true as const,
  };
  const analysis = analysisSchema.parse({
    version: "analysis-api-0.1.0",
    analysis_id: id(3),
    configuration_id: id(4),
    device_id: id(2),
    source_sha256: source,
    created_at: "2026-10-15T10:00:00Z",
    status: "partial",
    policy_catalog_version: finding.model_version,
    findings: [finding],
    explanations: [explanation],
    risk: null,
    limitations: ["Partial parser fixture"],
  });
  const snapshot = snapshotSchema.parse({
    configuration_id: id(4),
    device_id: id(2),
    created_at: "2026-10-15T10:00:00Z",
    canonical: {
      schema_version: "1.0",
      source: {
        filename: "owned.cfg",
        sha256: source,
        collected_at: "2026-10-15T10:00:00Z",
      },
      device: { vendor: "cisco", platform: "ios", hostname: "fixture" },
      parser_confidence: 0.9,
      parse_warnings: ["Authored partial parser warning"],
      unparsed_fragments: [],
      interfaces: [],
      vlans: [],
      acls: [],
      static_routes: [],
    },
  });
  const content = "Authored internal source text.";
  const chunk = {
    document_id: "docs/policies/management-plane.md" as const,
    document_title: "Management",
    section: "ssh-must-be-enabled",
    section_title: "SSH must be enabled",
    citation: finding.references[0]!,
    document_sha256: "d".repeat(64),
    content_sha256: await explanationTextDigest(content),
    content,
    authority: "internal_project_document" as const,
  };
  const facts: GroundedExplanationFacts = {
    version: "grounded-explanation-source-facts-0.1.0",
    phase: "saved_analysis_explanation",
    source_sha256: source,
    finding_sha256: fingerprint,
    vendor: "cisco",
    platform: "ios",
    detector: finding.detector,
    detector_version: finding.model_version,
    category: finding.category,
    interpretation: "project_policy",
    parser: { confidence: 0.9, warning_count: 1, unparsed_count: 0 },
    analysis_facts: {
      version: "explanation-analysis-facts-0.1.0",
      analysis_status: "partial",
      peer_report: null,
    },
    invocation_facts: {
      version: "explanation-invocation-facts-0.1.0",
      entrypoint: "saved_analysis_http",
      analysis_storage: "stored_analysis",
      model_answer_storage: "not_stored_in_analysis",
      selected_finding_peer_profile_storage: "not_applicable",
    },
    observed: { field_0001: false, field_0002: 1e-7 },
    expected: { field_0001: true },
    anchors: explanation.anchors,
    selection_facts: {
      version: "grounded-explanation-selection-facts-0.1.0",
      reference: null,
      peer: null,
      statistical: null,
    },
    reference: null,
    peer: null,
    forest: null,
    knowledge_version: "project-knowledge-0.2.0",
    knowledge_sha256: "e".repeat(64),
    documents: [
      {
        citation: chunk.citation,
        document_sha256: chunk.document_sha256,
        content_sha256: chunk.content_sha256,
        role: "required",
        authority: "sealed_internal_project_document",
      },
    ],
    formal_verification: "not_run",
    verification_scope: {
      vendor_syntax: "not_checked_in_this_explanation",
      network_impact: "not_checked_in_this_explanation",
      management_access: "not_checked_in_this_explanation",
      rollback: "not_checked_in_this_explanation",
    },
  };
  // Python emits the exponent 1e-07, whereas JavaScript emits 1e-7.
  const source_facts_json = stableJson(facts).replace("1e-7", "1e-07");
  const facts_binding_sha256 = await explanationTextDigest(source_facts_json);
  const model_answer = {
    version: "grounded-explanation-answer-0.1.0" as const,
    facts_binding_sha256,
    fact_refs: ["selected_finding" as const, "observed_values" as const],
    recommendation_code: "review_policy" as const,
    missing_information_codes: ["vendor_syntax" as const],
    citations: [chunk.citation],
    patch_draft: null,
    requires_human_review: true as const,
  };
  const projection_json = stableJson({
    version: "grounded-explanation-presentation-0.1.0",
    presentation_kind: "server_derived",
    summary: "partial: authored saved finding",
    technical_explanation:
      "Server-derived software fixture. No verification performed.",
    possible_impact: ["Network impact remains unknown."],
    recommendation: "Review project facts manually.",
    assumptions: [],
    missing_information: [
      "Vendor syntax",
      "Network impact",
      "Management access",
      "Rollback",
      "Credentials",
      "Organization policy",
    ],
    citations: [chunk.citation],
    patch_draft: null,
    requires_human_review: true,
  });
  const bundle = groundedExplanationSchema.parse({
    version,
    provider: "loopback_grounded_language_model",
    llm_status: "draft",
    presentation_kind: "server_derived",
    privacy_version: "finding-context-redaction-0.1.0",
    model_alias: "authored-fixture",
    analysis_id: analysis.analysis_id,
    configuration_id: analysis.configuration_id,
    device_id: analysis.device_id,
    source_sha256: source,
    finding_id: finding.finding_id,
    finding_sha256: fingerprint,
    knowledge_version: facts.knowledge_version,
    knowledge_sha256: facts.knowledge_sha256,
    retrieval: "explicit_reference",
    semantic_retrieval: null,
    explanation,
    documents: [chunk],
    limitations: ["Authored software fixture"],
    context_sha256: "f".repeat(64),
    source_facts_json,
    facts_binding_sha256,
    model_answer,
    model_answer_sha256: await explanationTextDigest(stableJson(model_answer)),
    instructions_sha256: "1".repeat(64),
    answer_schema_sha256: "2".repeat(64),
    renderer_version: "grounded-explanation-presentation-0.1.0",
    renderer_policy_sha256: "3".repeat(64),
    projection_json,
    projection_sha256: await explanationTextDigest(projection_json),
  });
  return { bundle, facts, finding, analysis, snapshot };
}
