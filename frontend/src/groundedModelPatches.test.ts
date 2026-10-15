import { expect, it } from "vitest";
import {
  commonModelPatch,
  groundedBindingsMatch,
  groundedModelPatchProposalSchema,
  modelPatchProposalSchema,
  proposalProtocol,
  savedModelPatchCapabilitiesSchema,
  savedModelPatchProposalSchema,
  savedProposalContinues,
} from "./modelPatches";
import type { GroundedModelPatchProposal } from "./modelPatches";
import {
  fixtureDigest,
  groundedFixture,
} from "./groundedModelPatches.fixtures";

it("keeps both historical protocols explicit and retains all grounded provenance", async () => {
  const grounded = await groundedFixture();
  const rows = [grounded.projection, grounded].map((row) =>
    savedModelPatchProposalSchema.parse(row),
  );
  expect(rows).toEqual([grounded.projection, grounded]);
  expect(modelPatchProposalSchema.safeParse(grounded).success).toBe(false);
  expect(commonModelPatch(grounded)).toBe(grounded.projection);
  expect(proposalProtocol(grounded)).toBe("grounded-model-patch-0.1.0");
  expect(proposalProtocol(grounded.projection)).toBe(
    "legacy-model-patch-0.1.0",
  );
  expect(grounded.context_sha256).not.toBe(
    commonModelPatch(grounded).context_sha256,
  );
  expect(await groundedBindingsMatch(grounded)).toBe(true);
});

it.each([
  { version: "grounded-source-bound-patch-proposal-0.2.0" },
  { version: "source-bound-patch-proposal-0.1.0" },
  { presentation_kind: "raw_model" },
  { edit_context_sha256: "b".repeat(64) },
  { renderer_version: "grounded-before-presentation-0.2.0" },
  { projection_sha256: null },
  { model_answer: null },
  { approved: false },
  { context_sha256: "private-not-a-hash" },
])("refuses expanded/unsupported grounded wrapper %#", async (change) => {
  const value = { ...(await groundedFixture()), ...change };
  expect(savedModelPatchProposalSchema.safeParse(value).success).toBe(false);
});

it.each([
  { version: "grounded-patch-source-facts-0.2.0" },
  { phase: "after_review" },
  { observed_telnet_enabled: 1 },
  { observed_ssh_version: 1 },
  { source_sha256: "b".repeat(64) },
  { finding_sha256: "b".repeat(64) },
  { knowledge_sha256: "b".repeat(64) },
  { baseline_status: "available" },
  { baseline_approval: "approved" },
  { formal_verification: "passed" },
  { vendor_syntax: "checked" },
  { management_access: "safe" },
  { rollback: "ready" },
  { ml_recheck: "completed" },
  { additional_claim: "safe" },
])(
  "rejects altered fact types, bindings or safety claims %#",
  async (change) => {
    const value = await groundedFixture();
    expect(
      groundedModelPatchProposalSchema.safeParse({
        ...value,
        source_facts: { ...value.source_facts, ...change },
      }).success,
    ).toBe(false);
  },
);

it.each([
  { version: "grounded-model-patch-answer-0.2.0" },
  { summary: "The model claims safety." },
  { fact_refs: ["formal_passed"] },
  { fact_refs: ["formal_not_run", "formal_not_run"] },
  { possible_impact_codes: ["safe_to_apply"] },
  { recommendation_code: "apply" },
  { missing_information_codes: ["rollback", "rollback"] },
  { missing_information_codes: ["nothing_missing"] },
  { citations: ["other#policy"] },
  { facts_binding_sha256: "b".repeat(64) },
  { patch_draft: null },
  { requires_human_review: 1 },
  { requires_human_review: false },
])(
  "rejects free prose, invented/duplicate choices or model-view mismatch %#",
  async (change) => {
    const value = await groundedFixture();
    expect(
      groundedModelPatchProposalSchema.safeParse({
        ...value,
        model_answer: { ...value.model_answer, ...change },
      }).success,
    ).toBe(false);
  },
);

it.each([
  { approved: true },
  { applied: true },
  { formal_verification: "passed" },
  { ml_verification: "completed" },
  { model_execution_authenticated: true },
  { context_sha256: "c".repeat(64) },
])(
  "retains legacy projection gates and edit-context binding %#",
  async (change) => {
    const value = await groundedFixture();
    expect(
      groundedModelPatchProposalSchema.safeParse({
        ...value,
        projection: { ...value.projection, ...change },
      }).success,
    ).toBe(false);
  },
);

it("detects stale fact/projection hashes even when types and cross-field pins match", async () => {
  const value = await groundedFixture();
  for (const changed of [
    {
      ...value,
      source_facts: { ...value.source_facts, observed_telnet_enabled: null },
    },
    { ...value, projection_sha256: "d".repeat(64) },
    {
      ...value,
      projection: {
        ...value.projection,
        answer: {
          ...value.projection.answer!,
          summary: "Altered server presentation.",
        },
      },
    },
  ]) {
    const parsed = groundedModelPatchProposalSchema.parse(changed);
    expect(await groundedBindingsMatch(parsed)).toBe(false);
  }
});

it("preserves null declines, rejected attempts and generation-phase facts", async () => {
  const value = await groundedFixture();
  const answer = { ...value.projection.answer!, patch_draft: null };
  const declined: GroundedModelPatchProposal = {
    ...value,
    projection: {
      ...value.projection,
      status: "declined",
      candidate_sha256: null,
      answer,
    },
    model_answer: { ...value.model_answer!, patch_draft: null },
    projection_sha256: await fixtureDigest(answer),
  };
  expect(groundedModelPatchProposalSchema.parse(declined)).toEqual(declined);
  expect(await groundedBindingsMatch(declined)).toBe(true);
  for (const status of ["generating", "failed"] as const) {
    const pending = {
      ...value,
      projection: {
        ...value.projection,
        status,
        answer: null,
        candidate_sha256: null,
        completed_at:
          status === "generating" ? null : value.projection.completed_at,
      },
      model_answer: null,
      projection_sha256: null,
    };
    expect(groundedModelPatchProposalSchema.parse(pending)).toEqual(pending);
    expect(await groundedBindingsMatch(pending)).toBe(true);
    expect(
      groundedModelPatchProposalSchema.safeParse({
        ...pending,
        model_answer: value.model_answer,
      }).success,
    ).toBe(false);
  }
  expect(declined.source_facts.formal_verification).toBe("not_run");
});

it("blocks reconciliation across protocols and changed immutable inputs", async () => {
  const value = await groundedFixture();
  const pending: GroundedModelPatchProposal = {
    ...value,
    projection: {
      ...value.projection,
      status: "generating",
      completed_at: null,
      answer: null,
      candidate_sha256: null,
    },
    model_answer: null,
    projection_sha256: null,
  };
  expect(savedProposalContinues(pending, value)).toBe(true);
  expect(savedProposalContinues(pending, value.projection)).toBe(false);
  expect(
    savedProposalContinues(pending, {
      ...value,
      context_sha256: "d".repeat(64),
    }),
  ).toBe(false);
  expect(
    savedProposalContinues(pending, {
      ...value,
      renderer_policy_sha256: "d".repeat(64),
    }),
  ).toBe(false);
  expect(
    savedProposalContinues(value, {
      ...value,
      projection: { ...value.projection, proposal_sha256: "d".repeat(64) },
    }),
  ).toBe(false);
});

it("keeps the grounded operator flag independent of legacy and rejects safety flags", () => {
  const value = {
    version: "saved-model-patch-capabilities-0.2.0",
    legacy: {
      version: "model-patch-capabilities-0.1.0",
      generation: "disabled",
      network_engine: "disabled",
      transformer: "disabled",
      transformer_sha256: null,
      individual_identity_verified: false,
      application_supported: false,
    },
    grounded_generation: "configured",
    grounded_protocol: "grounded-model-patch-0.1.0",
  };
  expect(savedModelPatchCapabilitiesSchema.parse(value)).toEqual(value);
  expect(
    savedModelPatchCapabilitiesSchema.safeParse({
      ...value,
      grounded_protocol: "grounded-model-patch-0.2.0",
    }).success,
  ).toBe(false);
  expect(
    savedModelPatchCapabilitiesSchema.safeParse({
      ...value,
      legacy: { ...value.legacy, application_supported: true },
    }).success,
  ).toBe(false);
});
