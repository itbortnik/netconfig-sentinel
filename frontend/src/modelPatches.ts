import { z } from "zod";
import { modelDraftSchema } from "./contracts";
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
