import { stableJson } from "./contracts";
import type { GroundedModelPatchProposal } from "./modelPatches";

// Authored contract data only; this fixture never executes a model or verifier.
export const fixtureId = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
export async function fixtureDigest(value: unknown) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(stableJson(value)),
  );
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
export async function groundedFixture(): Promise<GroundedModelPatchProposal> {
  const hash = "a".repeat(64);
  const facts: GroundedModelPatchProposal["source_facts"] = {
    version: "grounded-patch-source-facts-0.1.0",
    phase: "before_candidate_generation",
    source_sha256: hash,
    finding_sha256: hash,
    knowledge_sha256: hash,
    category: "management.ssh_version_1",
    observed_telnet_enabled: true,
    observed_ssh_enabled: true,
    observed_ssh_version: "1",
    baseline_status: "not_supplied",
    baseline_source_sha256: null,
    baseline_approval: "not_proven",
    formal_verification: "not_run",
    vendor_syntax: "not_checked",
    management_access: "not_checked",
    rollback: "not_checked",
    ml_recheck: "not_run",
  };
  const answer = {
    summary: "Authored synthetic BEFORE fixture.",
    technical_explanation:
      "BEFORE: approval not proven; formal and ML not run; vendor syntax, management access and rollback not checked.",
    possible_impact: [],
    recommendation: "Independent review and missing checks are required.",
    patch_draft: {
      edits: [{ source_line: 3, replacement: "ip ssh version 2" }],
    },
    assumptions: [],
    missing_information: ["Vendor syntax remains unchecked."],
    citations: ["owned#policy"],
    requires_human_review: true as const,
  };
  const factsHash = await fixtureDigest(facts);
  return {
    version: "grounded-source-bound-patch-proposal-0.1.0",
    presentation_kind: "server_derived",
    context_sha256: "c".repeat(64),
    edit_context_sha256: hash,
    projection: {
      version: "source-bound-patch-proposal-0.1.0",
      patch_id: fixtureId(3),
      analysis_id: fixtureId(4),
      finding_id: fixtureId(5),
      finding_sha256: hash,
      source_sha256: hash,
      source: {
        configuration_id: fixtureId(1),
        device_id: fixtureId(2),
        source_sha256: hash,
        created_at: "2026-10-09T10:00:00Z",
      },
      baseline: null,
      created_at: "2026-10-09T10:00:01Z",
      completed_at: "2026-10-09T10:00:02Z",
      status: "draft",
      context_sha256: hash,
      knowledge_version: "project-knowledge-0.2.0",
      knowledge_sha256: hash,
      model_alias_sha256: hash,
      proposal_sha256: hash,
      answer,
      candidate_sha256: "b".repeat(64),
      generation_attempt_limit: 1,
      formal_verification: "not_run",
      ml_verification: "not_run",
      requires_human_review: true,
      model_execution_authenticated: false,
      approved: false,
      applied: false,
    },
    source_facts: facts,
    facts_binding_sha256: factsHash,
    model_answer: {
      version: "grounded-model-patch-answer-0.1.0",
      facts_binding_sha256: factsHash,
      fact_refs: ["selected_finding_before"],
      possible_impact_codes: [],
      recommendation_code: "request_human_review_and_missing_checks",
      missing_information_codes: ["vendor_syntax"],
      patch_draft: answer.patch_draft,
      citations: answer.citations,
      requires_human_review: true,
    },
    instructions_sha256: hash,
    answer_schema_sha256: hash,
    renderer_version: "grounded-before-presentation-0.1.0",
    renderer_policy_sha256: hash,
    projection_sha256: await fixtureDigest(answer),
  };
}
