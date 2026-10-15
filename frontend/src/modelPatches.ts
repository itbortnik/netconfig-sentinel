import { z } from "zod";
import { modelDraftSchema, stableJson } from "./contracts";
import type { AnalysisResult, Finding } from "./contracts";
export const modelPatchCapabilitiesSchema = z
  .strictObject({
    version: z.literal("model-patch-capabilities-0.1.0"),
    generation: z.enum(["configured", "disabled"]),
    network_engine: z.enum(["configured", "disabled"]),
    transformer: z.enum(["configured", "disabled"]),
    transformer_sha256: z
      .string()
      .regex(/^[0-9a-f]{64}$/)
      .nullable(),
    individual_identity_verified: z.literal(false),
    application_supported: z.literal(false),
  })
  .refine(
    (value) =>
      (value.transformer === "configured") ===
      (value.transformer_sha256 !== null),
  );
export type ModelPatchCapabilities = z.infer<
  typeof modelPatchCapabilitiesSchema
>;

const id = z.guid();
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
export const modelPatchBindingSchema = z.strictObject({
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
});
export const generateModelPatchSchema = z
  .strictObject({
    patch_id: id,
    analysis_id: id,
    finding_id: id,
    finding_sha256: hash,
    source_sha256: hash,
    baseline_configuration_id: id.nullable().default(null),
    baseline_source_sha256: hash.nullable().default(null),
    allow_local_model_context: z.boolean().default(false),
  })
  .refine(
    (value) =>
      (value.baseline_configuration_id === null) ===
      (value.baseline_source_sha256 === null),
  );
export type GenerateModelPatch = z.infer<typeof generateModelPatchSchema>;

const edit = z.strictObject({
  source_line: z.number().int().min(1).max(10_000),
  replacement: z
    .string()
    .min(1)
    .max(256)
    .refine(
      (value) =>
        value === value.trim() &&
        /^[\x20-\x7e]+$/.test(value) &&
        !value.includes(";"),
    )
    .nullable(),
});
export const patchAnswerSchema = z
  .strictObject({
    ...modelDraftSchema.shape,
    patch_draft: z
      .strictObject({
        edits: z
          .array(edit)
          .min(1)
          .max(128)
          .refine((edits) =>
            edits.every(
              (value, index) =>
                index === 0 ||
                value.source_line > edits[index - 1]!.source_line,
            ),
          ),
      })
      .nullable(),
  })
  .refine(
    (answer) =>
      modelDraftSchema.safeParse({ ...answer, patch_draft: null }).success &&
      new TextEncoder().encode(JSON.stringify(answer)).byteLength <= 32768,
  );

export const modelPatchProposalSchema = z
  .strictObject({
    version: z.literal("source-bound-patch-proposal-0.1.0"),
    patch_id: id,
    analysis_id: id,
    finding_id: id,
    finding_sha256: hash,
    source_sha256: hash,
    source: modelPatchBindingSchema,
    baseline: modelPatchBindingSchema.nullable(),
    created_at: timestamp,
    completed_at: timestamp.nullable(),
    status: z.enum(["generating", "draft", "declined", "failed"]),
    context_sha256: hash,
    knowledge_version: z.literal("project-knowledge-0.2.0"),
    knowledge_sha256: hash,
    model_alias_sha256: hash,
    proposal_sha256: hash,
    answer: patchAnswerSchema.nullable(),
    candidate_sha256: hash.nullable(),
    generation_attempt_limit: z.literal(1),
    formal_verification: z.literal("not_run"),
    ml_verification: z.literal("not_run"),
    requires_human_review: z.literal(true),
    model_execution_authenticated: z.literal(false),
    approved: z.literal(false),
    applied: z.literal(false),
  })
  .refine((value) => {
    if (
      value.source_sha256 !== value.source.source_sha256 ||
      Date.parse(value.created_at) < Date.parse(value.source.created_at) ||
      (value.status === "generating") !== (value.completed_at === null) ||
      (value.completed_at !== null &&
        Date.parse(value.completed_at) < Date.parse(value.created_at))
    )
      return false;
    if (
      value.baseline !== null &&
      (value.baseline.device_id !== value.source.device_id ||
        value.baseline.configuration_id === value.source.configuration_id ||
        Date.parse(value.baseline.created_at) >
          Date.parse(value.source.created_at))
    )
      return false;
    if (value.status === "generating" || value.status === "failed")
      return value.answer === null && value.candidate_sha256 === null;
    return (
      value.answer !== null &&
      (value.status === "draft") === (value.answer.patch_draft !== null) &&
      (value.status === "draft") === (value.candidate_sha256 !== null) &&
      value.candidate_sha256 !== value.source_sha256
    );
  }, "inconsistent saved model proposal");
export type ModelPatchProposal = z.infer<typeof modelPatchProposalSchema>;

export const patchProtocols = [
  "legacy-model-patch-0.1.0",
  "grounded-model-patch-0.1.0",
] as const;
export type PatchProtocol = (typeof patchProtocols)[number];
export const savedModelPatchCapabilitiesSchema = z.strictObject({
  version: z.literal("saved-model-patch-capabilities-0.2.0"),
  legacy: modelPatchCapabilitiesSchema,
  grounded_generation: z.enum(["configured", "disabled"]),
  grounded_protocol: z.literal("grounded-model-patch-0.1.0"),
});
export type SavedModelPatchCapabilities = z.infer<
  typeof savedModelPatchCapabilitiesSchema
>;

export const groundedSourceFactsSchema = z
  .strictObject({
    version: z.literal("grounded-patch-source-facts-0.1.0"),
    phase: z.literal("before_candidate_generation"),
    source_sha256: hash,
    finding_sha256: hash,
    knowledge_sha256: hash,
    category: z.enum(["management.telnet_enabled", "management.ssh_version_1"]),
    observed_telnet_enabled: z.boolean().nullable(),
    observed_ssh_enabled: z.boolean().nullable(),
    observed_ssh_version: z.enum(["1", "2"]).nullable(),
    baseline_status: z.enum(["available", "not_supplied"]),
    baseline_source_sha256: hash.nullable(),
    baseline_approval: z.literal("not_proven"),
    formal_verification: z.literal("not_run"),
    vendor_syntax: z.literal("not_checked"),
    management_access: z.literal("not_checked"),
    rollback: z.literal("not_checked"),
    ml_recheck: z.literal("not_run"),
  })
  .refine(
    (facts) =>
      (facts.baseline_status === "available") ===
      (facts.baseline_source_sha256 !== null),
  );
const unique = (values: readonly string[]) =>
  new Set(values).size === values.length;
export const groundedPatchAnswerSchema = z.strictObject({
  version: z.literal("grounded-model-patch-answer-0.1.0"),
  facts_binding_sha256: hash,
  fact_refs: z
    .array(
      z.enum([
        "selected_finding_before",
        "source_management_observation",
        "baseline_availability",
        "baseline_approval_unknown",
        "formal_not_run",
        "vendor_syntax_not_checked",
        "management_access_not_checked",
        "rollback_not_checked",
        "ml_recheck_not_run",
      ]),
    )
    .min(1)
    .max(9)
    .refine(unique),
  possible_impact_codes: z
    .array(z.literal("management_access_may_change"))
    .max(1),
  recommendation_code: z.literal("request_human_review_and_missing_checks"),
  missing_information_codes: z
    .array(
      z.enum([
        "baseline_approval",
        "formal_verification",
        "management_access",
        "ml_recheck",
        "rollback",
        "vendor_syntax",
      ]),
    )
    .min(1)
    .max(6)
    .refine(unique),
  patch_draft: patchAnswerSchema.shape.patch_draft,
  citations: modelDraftSchema.shape.citations.refine(unique),
  requires_human_review: z.literal(true),
});
export const groundedModelPatchProposalSchema = z
  .strictObject({
    version: z.literal("grounded-source-bound-patch-proposal-0.1.0"),
    presentation_kind: z.literal("server_derived"),
    projection: modelPatchProposalSchema,
    context_sha256: hash,
    edit_context_sha256: hash,
    source_facts: groundedSourceFactsSchema,
    facts_binding_sha256: hash,
    model_answer: groundedPatchAnswerSchema.nullable(),
    instructions_sha256: hash,
    answer_schema_sha256: hash,
    renderer_version: z.literal("grounded-before-presentation-0.1.0"),
    renderer_policy_sha256: hash,
    projection_sha256: hash.nullable(),
  })
  .refine((value) => {
    const {
      projection: view,
      source_facts: facts,
      model_answer: answer,
    } = value;
    if (
      value.edit_context_sha256 !== view.context_sha256 ||
      facts.source_sha256 !== view.source_sha256 ||
      facts.finding_sha256 !== view.finding_sha256 ||
      facts.knowledge_sha256 !== view.knowledge_sha256 ||
      facts.baseline_source_sha256 !== (view.baseline?.source_sha256 ?? null)
    )
      return false;
    if (view.status === "failed" || view.status === "generating")
      return answer === null && value.projection_sha256 === null;
    return (
      answer !== null &&
      view.answer !== null &&
      value.projection_sha256 !== null &&
      answer.facts_binding_sha256 === value.facts_binding_sha256 &&
      stableJson(answer.patch_draft) === stableJson(view.answer.patch_draft) &&
      stableJson(answer.citations) === stableJson(view.answer.citations)
    );
  }, "inconsistent grounded model proposal");
export type GroundedModelPatchProposal = z.infer<
  typeof groundedModelPatchProposalSchema
>;
export const savedModelPatchProposalSchema = z.discriminatedUnion("version", [
  modelPatchProposalSchema,
  groundedModelPatchProposalSchema,
]);
export type SavedModelPatchProposal = z.infer<
  typeof savedModelPatchProposalSchema
>;
export function commonModelPatch(value: SavedModelPatchProposal) {
  return value.version === "grounded-source-bound-patch-proposal-0.1.0"
    ? value.projection
    : value;
}
export function proposalProtocol(
  value: SavedModelPatchProposal,
): PatchProtocol {
  return value.version === "grounded-source-bound-patch-proposal-0.1.0"
    ? "grounded-model-patch-0.1.0"
    : "legacy-model-patch-0.1.0";
}
export function savedProposalContinues(
  previous: SavedModelPatchProposal,
  current: SavedModelPatchProposal,
) {
  if (previous.version !== current.version) return false;
  const before = commonModelPatch(previous),
    after = commonModelPatch(current);
  if (before.status !== "generating")
    return stableJson(previous) === stableJson(current);
  const commonIdentity = (view: ModelPatchProposal) => ({
    ...view,
    completed_at: null,
    status: "generating",
    answer: null,
    candidate_sha256: null,
    proposal_sha256: null,
  });
  if (stableJson(commonIdentity(before)) !== stableJson(commonIdentity(after)))
    return false;
  if (
    previous.version === "grounded-source-bound-patch-proposal-0.1.0" &&
    current.version === "grounded-source-bound-patch-proposal-0.1.0"
  ) {
    const identity = (record: GroundedModelPatchProposal) => ({
      ...record,
      projection: null,
      model_answer: null,
      projection_sha256: null,
    });
    return stableJson(identity(previous)) === stableJson(identity(current));
  }
  return true;
}
async function digest(value: unknown) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(stableJson(value)),
  );
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
export async function groundedBindingsMatch(value: SavedModelPatchProposal) {
  if (value.version !== "grounded-source-bound-patch-proposal-0.1.0")
    return true;
  return (
    (await digest(value.source_facts)) === value.facts_binding_sha256 &&
    (value.projection.answer === null ||
      (await digest(value.projection.answer)) === value.projection_sha256)
  );
}
export function proposalMatches(
  value: ModelPatchProposal,
  analysis: AnalysisResult,
  finding: Finding,
) {
  const explanation = analysis.explanations.find(
    (row) => row.finding_id === finding.finding_id,
  );
  return (
    value.analysis_id === analysis.analysis_id &&
    value.finding_id === finding.finding_id &&
    value.finding_sha256 === explanation?.finding_sha256 &&
    value.source.configuration_id === analysis.configuration_id &&
    value.source.device_id === analysis.device_id &&
    finding.device_id === analysis.device_id &&
    value.source_sha256 === analysis.source_sha256 &&
    Date.parse(value.created_at) >= Date.parse(analysis.created_at)
  );
}
export function generationMatches(
  value: ModelPatchProposal,
  request: GenerateModelPatch,
) {
  return (
    value.patch_id === request.patch_id &&
    value.analysis_id === request.analysis_id &&
    value.finding_id === request.finding_id &&
    value.finding_sha256 === request.finding_sha256 &&
    value.source_sha256 === request.source_sha256 &&
    (value.baseline?.configuration_id ?? null) ===
      request.baseline_configuration_id &&
    (value.baseline?.source_sha256 ?? null) === request.baseline_source_sha256
  );
}
