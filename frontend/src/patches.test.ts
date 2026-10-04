import { expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./api";
import { snapshotDiffSchema } from "./contracts";
import {
  createPatchSchema,
  patchDraftSchema,
  patchIntent,
  patchSummarySchema,
  preflightSchema,
  verificationSchema,
  verificationSummarySchema,
  reviewBound,
} from "./patches";
const id = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const binding = (n: number) => ({
  configuration_id: id(n),
  device_id: id(3),
  source_sha256: String(n).repeat(64),
  created_at: `2026-10-04T00:00:0${n}Z`,
});
const snapshot = (n: number) => ({
  ...binding(n),
  vendor: "cisco",
  platform: "ios",
  hostname: "edge",
  projection_sha256: String(n + 3).repeat(64),
  parser_confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
});
const diff = snapshotDiffSchema.parse({
  version: "snapshot-diff-0.1.0",
  representation: "normalized_objects",
  before: snapshot(1),
  after: snapshot(2),
  coverage: "supported_complete",
  source_changed: true,
  added_count: 1,
  removed_count: 0,
  modified_count: 0,
  changes: [
    {
      section: "interfaces",
      object_key: ["Gi0/1"],
      kind: "added",
      before_value: null,
      after_value: { enabled: true },
      before_locations: [],
      after_locations: [],
    },
  ],
  limitations: ["Supported objects only."],
});
const draft = {
  version: "snapshot-patch-draft-0.1.0",
  patch_id: id(4),
  created_at: "2026-10-04T00:00:03Z",
  draft_sha256: "a".repeat(64),
  status: "draft",
  representation: "normalized_objects",
  diff,
  requires_human_review: true,
};
const summary = {
  version: "snapshot-patch-summary-0.1.0",
  patch_id: draft.patch_id,
  created_at: draft.created_at,
  draft_sha256: draft.draft_sha256,
  status: "draft",
  before: binding(1),
  after: binding(2),
  coverage: "supported_complete",
  change_count: 1,
};
const parse = (n: number) => ({
  source_sha256: String(n).repeat(64),
  confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
  complete: true,
});
const preflight = {
  version: "preflight-0.1.0",
  report_id: id(5),
  device_id: id(3),
  reference_id: id(1),
  policy_catalog_version: "test-0.1",
  before: parse(1),
  after: parse(2),
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
  limitations: ["No network verification."],
};
const review = {
  version: "snapshot-patch-review-0.1.0",
  verification_id: id(6),
  patch_id: draft.patch_id,
  draft_sha256: draft.draft_sha256,
  created_at: "2026-10-04T00:00:04Z",
  kind: "local_preflight",
  status: "needs_review",
  before: binding(1),
  after: binding(2),
  preflight,
  validation_blockers: ["formal_verification_not_run", "human_review_required"],
};
const reviewSummary = {
  version: "snapshot-patch-review-summary-0.1.0",
  verification_id: id(6),
  patch_id: draft.patch_id,
  draft_sha256: draft.draft_sha256,
  created_at: review.created_at,
  kind: "local_preflight",
  status: "needs_review",
  policy_catalog_version: "test-0.1",
  before_complete: true,
  after_complete: true,
  current_policy_finding_count: 0,
  introduced_count: 0,
  resolved_count: 0,
  formal_verification: "not_run",
};
it("accepts only normalized draft / local review contracts and binds their inputs", () => {
  const parsed = patchDraftSchema.parse(draft);
  expect(patchSummarySchema.parse(summary).change_count).toBe(1);
  expect(reviewBound(verificationSchema.parse(review), parsed)).toBe(true);
  expect(
    verificationSummarySchema.parse(reviewSummary).formal_verification,
  ).toBe("not_run");
  expect(patchIntent(diff, id(4))).toEqual({
    patch_id: id(4),
    before_configuration_id: id(1),
    after_configuration_id: id(2),
    before_source_sha256: "1".repeat(64),
    after_source_sha256: "2".repeat(64),
  });
  expect(
    createPatchSchema.safeParse({
      ...patchIntent(diff, id(4)),
      status: "approved",
    }).success,
  ).toBe(false);
});
it.each([
  { status: "approved" },
  { representation: "commands" },
  { requires_human_review: false },
  { validated: true },
  { created_at: "2026-10-04T00:00:01Z" },
  { diff: { ...diff, changes: [], added_count: 0 } },
])("rejects authoritative or inconsistent draft %j", (update) =>
  expect(patchDraftSchema.safeParse({ ...draft, ...update }).success).toBe(
    false,
  ),
);
it.each([
  { status: "passed" },
  { kind: "batfish" },
  { validation_blockers: [] },
  { validated: true },
  { before: { ...binding(1), device_id: id(9) } },
  { preflight: { ...preflight, formal_verification: "passed" } },
  { preflight: { ...preflight, reference_id: id(9) } },
  { preflight: { ...preflight, requires_human_review: false } },
])("rejects false formal passes or inconsistent local evidence %j", (update) =>
  expect(verificationSchema.safeParse({ ...review, ...update }).success).toBe(
    false,
  ),
);
it("requires nullable change counts for partial history, never fabricated zero", () => {
  expect(
    verificationSummarySchema.safeParse({
      ...reviewSummary,
      after_complete: false,
    }).success,
  ).toBe(false);
  expect(
    verificationSummarySchema.safeParse({
      ...reviewSummary,
      after_complete: false,
      introduced_count: null,
      resolved_count: null,
    }).success,
  ).toBe(true);
  expect(
    preflightSchema.safeParse({
      ...preflight,
      after: { ...parse(2), complete: false },
    }).success,
  ).toBe(false);
  expect(
    preflightSchema.safeParse({
      ...preflight,
      after: {
        ...parse(2),
        confidence: 0.5,
        warning_count: 1,
        complete: false,
      },
      policy_changes: null,
      reference_status: "unavailable",
    }).success,
  ).toBe(true);
});
it("rejects draft hash and parser diagnostic substitutions across otherwise valid review records", () => {
  const parsed = patchDraftSchema.parse(draft),
    run = verificationSchema.parse(review);
  expect(reviewBound({ ...run, draft_sha256: "f".repeat(64) }, parsed)).toBe(
    false,
  );
  expect(
    reviewBound(
      {
        ...run,
        preflight: {
          ...run.preflight,
          after: { ...run.preflight.after, confidence: 0.5 },
        },
      },
      parsed,
    ),
  ).toBe(false);
});
it("uses scoped same-origin read paths and immutable JSON intents, never provider/device requests", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response("{}", { status: 400 }));
  const client = new ApiClient(
    "patch-tests-only-memory-token-0000001",
    transport,
  );
  const create = patchIntent(diff, id(4));
  const verify = {
    verification_id: id(6),
    draft_sha256: draft.draft_sha256,
    mode: "local_preflight" as const,
  };
  for (const action of [
    () => client.createPatch(create),
    () => client.verifyPatch(id(4), verify),
    () => client.patches(id(2), 20),
    () => client.patch(id(4)),
    () => client.verifications(id(4), 20),
    () => client.verification(id(4), id(6)),
  ])
    await expect(action()).rejects.toBeInstanceOf(ApiError);
  expect(transport.mock.calls.map((call) => call[0])).toEqual([
    "/api/v1/patches",
    `/api/v1/patches/${id(4)}/verify`,
    `/api/v1/patches?after_configuration_id=${id(2)}&limit=20&offset=20`,
    `/api/v1/patches/${id(4)}`,
    `/api/v1/patches/${id(4)}/verifications?limit=20&offset=20`,
    `/api/v1/patches/${id(4)}/verifications/${id(6)}`,
  ]);
  expect(transport.mock.calls[0]![1]?.body).toBe(JSON.stringify(create));
  expect(transport.mock.calls[1]![1]?.body).toBe(JSON.stringify(verify));
  for (const [, options] of transport.mock.calls) {
    expect(options?.credentials).toBe("omit");
    expect(options?.redirect).toBe("error");
    expect(options?.cache).toBe("no-store");
  }
  client.close();
});
