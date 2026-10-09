import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import {
  modelPatchCapabilitiesSchema,
  modelPatchProposalSchema,
} from "./modelPatches";
import {
  approvalBlockers,
  batfishSchema,
  candidateReviewSchema,
  decisionMatches,
  ipv4Scope,
  missingChecks,
  reviewMatches,
  savedModelDecisionSchema,
  savedModelReviewSchema,
  verifyModelPatchSchema,
} from "./modelReviews";

const id = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const a = "a".repeat(64),
  b = "b".repeat(64);
const scope = { start_node: "owned-edge", destination: "192.0.2.0/24" };
const source = {
  configuration_id: id(1),
  device_id: id(2),
  source_sha256: a,
  created_at: "2026-10-09T10:00:00Z",
};
const proposal = modelPatchProposalSchema.parse({
  version: "source-bound-patch-proposal-0.1.0",
  patch_id: id(3),
  analysis_id: id(4),
  finding_id: id(5),
  finding_sha256: a,
  source_sha256: a,
  source,
  baseline: null,
  created_at: "2026-10-09T10:00:01Z",
  completed_at: "2026-10-09T10:00:02Z",
  status: "draft",
  context_sha256: a,
  knowledge_version: "project-knowledge-0.2.0",
  knowledge_sha256: a,
  model_alias_sha256: a,
  proposal_sha256: a,
  answer: {
    summary: "Synthetic protocol fixture, not quality evidence.",
    technical_explanation: "Owned draft.",
    possible_impact: [],
    recommendation: "Review.",
    patch_draft: {
      edits: [{ source_line: 2, replacement: "ip ssh version 2" }],
    },
    assumptions: [],
    missing_information: [],
    citations: ["owned#fixture"],
    requires_human_review: true,
  },
  candidate_sha256: b,
  generation_attempt_limit: 1,
  formal_verification: "not_run",
  ml_verification: "not_run",
  requires_human_review: true,
  model_execution_authenticated: false,
  approved: false,
  applied: false,
});
const parse = (hash: string) => ({
  source_sha256: hash,
  confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
  complete: true,
});
const local = {
  version: "patch-review-0.1.0",
  status: "needs_review",
  validation_blockers: ["formal_verification_not_run", "human_review_required"],
  proposal: {
    version: "patch-proposal-0.1.0",
    proposal_id: id(6),
    device_id: id(2),
    reference_id: id(1),
    vendor: "cisco",
    platform: "ios",
    before_sha256: a,
    after_sha256: b,
    before_line_count: 3,
    after_line_count: 3,
    changes: [
      {
        operation: "replace",
        before_start: 1,
        before_end: 2,
        after_start: 1,
        after_end: 2,
      },
    ],
    status: "draft",
  },
  preflight: {
    version: "preflight-0.1.0",
    report_id: id(7),
    device_id: id(2),
    reference_id: id(1),
    policy_catalog_version: "test-0.1",
    before: parse(a),
    after: parse(b),
    before_policy_findings: [],
    after_policy_findings: [],
    policy_changes: { introduced: [], resolved: [], persistent: [] },
    reference_status: "completed",
    reference_findings: [],
    current_policy_risk: null,
    review_status: "needs_review",
    formal_verification: "not_run",
    ml_status: "not_run",
    requires_human_review: true,
    limitations: [],
  },
};
const facts = {
  version: "candidate-review-0.1.0",
  device_id: id(2),
  source_sha256: a,
  candidate_sha256: b,
  finding_sha256: a,
  context_sha256: a,
  selected_category: "management.ssh_version_1",
  before_snapshot_sha256: a,
  after_snapshot_sha256: b,
  scope,
  local_review: local,
  network_result: null,
  ml_reviews: [],
  expected_model_sha256s: [],
  missing_checks: [],
  status: "needs_review",
  requires_human_review: true,
  approved: false,
  applied: false,
  execution_authenticated: false,
  semantic_truth_proven: false,
  confidential: true,
};
// Explicit test-only facts; never a model run, formal-engine run or quality measurement.
const report = candidateReviewSchema.parse({
  ...facts,
  missing_checks: missingChecks(facts as Parameters<typeof missingChecks>[0]),
});
const request = verifyModelPatchSchema.parse({
  verification_id: id(8),
  proposal_sha256: a,
  network: [{ configuration_id: id(1), source_sha256: a }],
  scope,
});
const run = savedModelReviewSchema.parse({
  version: "saved-model-patch-review-0.1.0",
  verification_id: id(8),
  patch_id: id(3),
  proposal_sha256: a,
  review_sha256: b,
  created_at: "2026-10-09T10:00:03Z",
  completed_at: "2026-10-09T10:00:04Z",
  request,
  network: [source],
  execution_status: "completed",
  report,
  ml_execution: "not_requested",
  statistical_recheck: null,
  approval_blockers: approvalBlockers(report, "not_requested"),
  status: "needs_review",
  applied: false,
  topology_pinned_at_generation: false,
});
const decision = savedModelDecisionSchema.parse({
  version: "saved-model-patch-decision-0.1.0",
  patch_id: id(3),
  request: {
    decision_id: id(9),
    verification_id: id(8),
    proposal_sha256: a,
    review_sha256: b,
    verdict: "rejected",
    comment: "Independent checks are absent.",
  },
  created_at: "2026-10-09T10:00:05Z",
  service_role: "engineer",
  individual_identity_verified: false,
  applied: false,
});

it("binds exact saved proposal / verification / engineer decision without promoting local checks", () => {
  expect(reviewMatches(run, proposal)).toBe(true);
  expect(decisionMatches(decision, run)).toBe(true);
  expect(run.approval_blockers).toContain("formal_scope_not_passed");
  expect(
    decisionMatches(
      {
        ...decision,
        request: {
          ...decision.request,
          verdict: "approved",
          acknowledged_limitations: report.missing_checks,
          device_syntax_checked: true,
          management_access_checked: true,
          rollback_ready: true,
        },
      },
      run,
    ),
  ).toBe(false);
});
it.each([
  { review_sha256: a },
  { verification_id: id(10) },
  { proposal_sha256: b },
  { acknowledged_limitations: ["unknown_check"] },
])("refuses a decision rebound to different facts %#", (changed) => {
  expect(
    decisionMatches(
      { ...decision, request: { ...decision.request, ...changed } },
      run,
    ),
  ).toBe(false);
});
it.each([
  { patch_id: id(10) },
  { proposal_sha256: b },
  { network: [{ ...source, device_id: id(10) }] },
  { report: { ...report, source_sha256: b } },
])(
  "refuses verification from a different generation or source %#",
  (changed) => {
    expect(reviewMatches({ ...run, ...changed }, proposal)).toBe(false);
  },
);
it.each([
  { applied: true },
  { topology_pinned_at_generation: true },
  { execution_status: "running" },
  { completed_at: null },
  { ml_execution: "completed" },
  { approval_blockers: [] },
  { request: { ...request, proposal_sha256: b } },
  { network: [{ ...source, source_sha256: b }] },
  { report: { ...report, approved: true } },
  { report: { ...report, missing_checks: [] } },
  { raw_candidate: "not part of the public contract" },
  {
    statistical_recheck: {
      model_id: id(10),
      artifact_sha256: a,
      before_score_samples: Infinity,
      after_score_samples: 0,
      before_decision_function: 0,
      after_decision_function: 0,
      before_prediction: 1,
      after_prediction: 1,
      calibrated: false,
      quality_proven: false,
    },
  },
])("refuses inconsistent expanded verification projection %#", (changed) => {
  expect(savedModelReviewSchema.safeParse({ ...run, ...changed }).success).toBe(
    false,
  );
});
it.each(["192.0.2.0/24", "192.0.2.1/32", "0.0.0.0/0"])(
  "accepts explicit canonical IPv4 scope %s",
  (value) => expect(ipv4Scope(value)).toBe(true),
);
it.each([
  "192.0.2.1/24",
  "192.00.2.0/24",
  "192.0.2.0/024",
  "192.0.2.0/33",
  "localhost/32",
  "2001:db8::/64",
  "192.0.2.0/24/1",
])("refuses unsupported or noncanonical scope %s", (value) =>
  expect(ipv4Scope(value)).toBe(false),
);
const networkFacts = {
  version: "batfish-check-0.1.0",
  before_sha256: a,
  after_sha256: b,
  scope,
  status: "no_differences_in_scope",
  reason: "query_completed",
  engine_version: "synthetic-fixture",
  network_name: "sentinel-" + "0".repeat(32),
  cleanup_complete: true,
  difference_count: 0,
  before_reachable_count: 1,
  after_reachable_count: 1,
  requires_human_review: true,
  limitations: [],
};
it("does not confuse empty scope, differences, query failure or missing cleanup with a pass", () => {
  expect(batfishSchema.safeParse(networkFacts).success).toBe(true);
  for (const changed of [
    { before_reachable_count: 0 },
    { after_reachable_count: 0 },
    { difference_count: 1 },
    { engine_version: null },
    { reason: "empty_reachable_scope" },
    { status: "unavailable" },
  ])
    expect(
      batfishSchema.safeParse({ ...networkFacts, ...changed }).success,
    ).toBe(false);
  expect(
    batfishSchema.safeParse({
      ...networkFacts,
      status: "inconclusive",
      reason: "empty_reachable_scope",
      before_reachable_count: 0,
      after_reachable_count: 0,
    }).success,
  ).toBe(true);
});
it("capabilities reveal only configured permissions and a public model pin", () => {
  const value = {
    version: "model-patch-capabilities-0.1.0",
    generation: "configured",
    network_engine: "disabled",
    transformer: "disabled",
    transformer_sha256: null,
    individual_identity_verified: false,
    application_supported: false,
  };
  expect(modelPatchCapabilitiesSchema.safeParse(value).success).toBe(true);
  for (const changed of [
    { endpoint: "http://127.0.0.1:9999" },
    { transformer: "configured" },
    { application_supported: true },
    { generation: "validated" },
  ])
    expect(
      modelPatchCapabilitiesSchema.safeParse({ ...value, ...changed }).success,
    ).toBe(false);
});
it("saved API never retries POST and binds successful result IDs before display", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ ...run, patch_id: id(10) })),
    )
    .mockResolvedValueOnce(
      new Response("private failure body", { status: 503 }),
    );
  const api = new ApiClient(
    "owned-tests-memory-bearer-token-0000001",
    transport,
  );
  await expect(api.verifyModelPatch(id(3), request)).rejects.toThrow(
    "не соответствует запросу",
  );
  await expect(api.verifyModelPatch(id(3), request)).rejects.toMatchObject({
    status: 503,
  });
  expect(transport).toHaveBeenCalledTimes(2);
  expect(transport.mock.calls[0]![1]?.body).toBe(JSON.stringify(request));
  expect(transport.mock.calls[0]![1]?.redirect).toBe("error");
  api.close();
});
it("read-only attempt reconciliation does not resubmit a model or verification request", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(JSON.stringify(proposal)))
    .mockResolvedValueOnce(new Response(JSON.stringify(run)))
    .mockResolvedValueOnce(new Response(JSON.stringify(decision)));
  const api = new ApiClient(
    "owned-tests-memory-bearer-token-0000001",
    transport,
  );
  expect(await api.modelPatch(id(3))).toEqual(proposal);
  expect(await api.modelReview(id(3), id(8))).toEqual(run);
  expect(await api.modelDecision(id(3), id(9))).toEqual(decision);
  expect(transport.mock.calls.every(([, init]) => init?.method === "GET")).toBe(
    true,
  );
  api.close();
});

const pin = "c".repeat(64);
const prediction = (source: string) => ({
  raw_source_sha256: source,
  sanitized_source_sha256: "d".repeat(64),
  model_sha256: pin,
  total_lines: 3,
  anomaly_score: 0.5,
  category_scores: { ssh_version_1: 0.5 },
  severity_scores: null,
  line_scores: [null, 0.5, null],
  block_attention: [1],
  embedding_sha256: a,
  embedding_dimensions: 24,
  replacement_counts: {},
  calibrated: false,
});
const model = {
  status: "completed",
  reason: null,
  model_sha256: pin,
  tokenizer_sha256: a,
  training_report_sha256: a,
  training_format: "multitask-training-0.2.0",
  runtime_torch_version: "fixture",
  sanitization_version: "config-sanitizer-0.1.0",
  before: prediction(a),
  after: prediction(b),
  risk_fused: false,
  quality_evaluated: false,
  calibrated: false,
  production_quality_proven: false,
};
const ml = {
  version: "ml-change-review-0.1.0",
  local_review: report.local_review,
  transformer: model,
  status: "needs_review",
  formal_verification: "not_run",
  device_syntax_verified: false,
  management_access_verified: false,
  applied: false,
  independent_quality_evaluation: false,
  pseudonymization_key_persisted: false,
};
const combinedFacts = {
  ...report,
  network_result: {
    version: "model-patch-batfish-0.1.0",
    device_id: id(2),
    source_sha256: a,
    candidate_sha256: b,
    finding_sha256: a,
    context_sha256: a,
    batfish: networkFacts,
    status: "needs_review",
    requires_human_review: true,
    approved: false,
    application_supported: false,
    device_syntax_verified: false,
    management_access_verified: false,
    model_execution_authenticated: false,
    limitations: [],
  },
  ml_reviews: [ml],
  expected_model_sha256s: [pin],
};
const combined = candidateReviewSchema.parse({
  ...combinedFacts,
  missing_checks: missingChecks(
    combinedFacts as Parameters<typeof missingChecks>[0],
  ),
});
const checked = savedModelReviewSchema.parse({
  ...run,
  report: combined,
  request: {
    ...request,
    mode: "batfish",
    allow_local_engine_upload: true,
    transformer_sha256: pin,
    allow_local_model_context: true,
  },
  ml_execution: "completed",
  approval_blockers: [],
});
it("requires both supplied channels, exact limitations and three independent attestations for approval", () => {
  const approved = {
    ...decision,
    request: {
      ...decision.request,
      verdict: "approved" as const,
      acknowledged_limitations: combined.missing_checks,
      device_syntax_checked: true,
      management_access_checked: true,
      rollback_ready: true,
    },
  };
  expect(decisionMatches(approved, checked)).toBe(true);
  for (const changed of [
    { device_syntax_checked: false },
    { management_access_checked: false },
    { rollback_ready: false },
    { acknowledged_limitations: [] },
  ])
    expect(
      decisionMatches(
        { ...approved, request: { ...approved.request, ...changed } },
        checked,
      ),
    ).toBe(false);
  expect(combined.approved).toBe(false);
  expect(combined.semantic_truth_proven).toBe(false);
  expect(combined.missing_checks).toContain("ml_quality_not_qualified");
});
it.each([
  { model_sha256: b },
  { production_quality_proven: true },
  { before: { ...prediction(a), total_lines: 4 } },
  { after: { ...prediction(b), raw_source_sha256: a } },
  { after: { ...prediction(b), category_scores: { telnet_enabled: 0.5 } } },
  { after: { ...prediction(b), block_attention: [0.2] } },
  { after: { ...prediction(b), embedding_dimensions: 0 } },
])("rejects rebound, partial or falsely qualified ML facts %#", (changed) => {
  expect(
    candidateReviewSchema.safeParse({
      ...combined,
      ml_reviews: [{ ...ml, transformer: { ...model, ...changed } }],
    }).success,
  ).toBe(false);
});
it("preserves operator-selected ML failure without inventing scores", () => {
  expect(
    savedModelReviewSchema.safeParse({
      ...run,
      request: {
        ...request,
        transformer_sha256: pin,
        allow_local_model_context: true,
      },
      ml_execution: "unavailable",
    }).success,
  ).toBe(true);
  expect(
    savedModelReviewSchema.safeParse({
      ...checked,
      ml_execution: "unavailable",
    }).success,
  ).toBe(false);
});
it("cannot display completed selected workers without their exact request consent", () => {
  expect(
    savedModelReviewSchema.safeParse({
      ...checked,
      request: { ...checked.request, allow_local_engine_upload: false },
    }).success,
  ).toBe(false);
  expect(
    savedModelReviewSchema.safeParse({
      ...checked,
      request: { ...checked.request, allow_local_model_context: false },
    }).success,
  ).toBe(false);
  expect(
    reviewMatches(
      {
        ...run,
        report: {
          ...report,
          local_review: {
            ...report.local_review,
            proposal: { ...report.local_review.proposal, reference_id: id(11) },
          },
        },
      },
      proposal,
    ),
  ).toBe(false);
  expect(reviewMatches(run, { ...proposal, status: "declined" })).toBe(false);
});
