import { expect, it } from "vitest";
import {
  generateModelPatchSchema,
  modelPatchProposalSchema,
} from "./modelPatches";

const id = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const hash = "a".repeat(64);
const source = {
  configuration_id: id(1),
  device_id: id(2),
  source_sha256: hash,
  created_at: "2026-10-09T10:00:00Z",
};
const answer = {
  summary: "Synthetic browser contract fixture, not model quality.",
  technical_explanation: "The proposed command is an untrusted draft.",
  possible_impact: [],
  recommendation: "Review independently.",
  patch_draft: { edits: [{ source_line: 2, replacement: "ip ssh version 2" }] },
  assumptions: [],
  missing_information: ["Device syntax and formal checks."],
  citations: ["owned#policy"],
  requires_human_review: true,
};
const proposal = {
  version: "source-bound-patch-proposal-0.1.0",
  patch_id: id(3),
  analysis_id: id(4),
  finding_id: id(5),
  finding_sha256: hash,
  source_sha256: hash,
  source,
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
};

it("keeps an untrusted model patch separate from normalized drafts and approval", () => {
  expect(modelPatchProposalSchema.parse(proposal)).toEqual(proposal);
  expect(
    modelPatchProposalSchema.safeParse({
      ...proposal,
      version: "snapshot-patch-draft-0.1.0",
    }).success,
  ).toBe(false);
});

it.each([
  { approved: true },
  { applied: true },
  { requires_human_review: 1 },
  { model_execution_authenticated: true },
  { generation_attempt_limit: true },
  { formal_verification: "validated" },
  { ml_verification: "completed" },
  { source_sha256: "c".repeat(64) },
  { candidate_sha256: hash },
  { completed_at: null },
  { status: "failed" },
  { status: "declined" },
  {
    answer: {
      ...answer,
      patch_draft: { edits: [{ source_line: true, replacement: "reload" }] },
    },
  },
  {
    answer: {
      ...answer,
      patch_draft: {
        edits: [{ source_line: 2, replacement: "ip ssh version 2; reload" }],
      },
    },
  },
  { baseline: { ...source, configuration_id: id(6), device_id: id(7) } },
  { raw_candidate: "private" },
])(
  "refuses inconsistent or expanded model proposal projection %#",
  (changed) => {
    expect(
      modelPatchProposalSchema.safeParse({ ...proposal, ...changed }).success,
    ).toBe(false);
  },
);

it("preserves pending, failed and null-declined results without a fabricated candidate", () => {
  expect(
    modelPatchProposalSchema.safeParse({
      ...proposal,
      status: "generating",
      completed_at: null,
      answer: null,
      candidate_sha256: null,
    }).success,
  ).toBe(true);
  expect(
    modelPatchProposalSchema.safeParse({
      ...proposal,
      status: "failed",
      answer: null,
      candidate_sha256: null,
    }).success,
  ).toBe(true);
  expect(
    modelPatchProposalSchema.safeParse({
      ...proposal,
      status: "declined",
      answer: { ...answer, patch_draft: null },
      candidate_sha256: null,
    }).success,
  ).toBe(true);
});

it("pairs independent baseline pins and refuses truthy consent", () => {
  const request = {
    patch_id: id(3),
    analysis_id: id(4),
    finding_id: id(5),
    finding_sha256: hash,
    source_sha256: hash,
    allow_local_model_context: true,
  };
  expect(generateModelPatchSchema.safeParse(request).success).toBe(true);
  expect(
    generateModelPatchSchema.safeParse({
      ...request,
      allow_local_model_context: 1,
    }).success,
  ).toBe(false);
  expect(
    generateModelPatchSchema.safeParse({
      ...request,
      baseline_configuration_id: id(6),
    }).success,
  ).toBe(false);
});
