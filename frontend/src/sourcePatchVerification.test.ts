import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import type { ConfigurationSummary } from "./contracts";
import { patchDraftSchema } from "./patches";
import {
  sourceCompanionEligible,
  sourceNetworkDigest,
  sourcePatchCapabilitiesSchema,
  sourcePatchVerificationSchema,
  sourcePatchVerificationSummarySchema,
  sourceReviewProofMatches,
  sourceSummaryBound,
  sourceValidationBlockers,
  sourceVerificationBound,
  verifySourcePatchSchema,
} from "./sourcePatchVerification";
import type {
  SourcePatchVerification,
  SourcePatchVerificationSummary,
} from "./sourcePatchVerification";

const id = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const digest = (raw: string) => createHash("sha256").update(raw).digest("hex");
const hash = (n: number) => String(n).repeat(64);
const member = (n: number, device = 3, hostname = "edge") => ({
  configuration_id: id(n),
  device_id: id(device),
  source_sha256: hash(n),
  created_at: `2026-10-04T00:00:0${n}Z`,
  canonical_sha256: hash(n + 3),
  hostname,
  platform: "ios" as const,
});
const before = member(1),
  after = member(2),
  companion = member(3, 2, "core");
const snapshot = ({ canonical_sha256: _canonical, ...row }: typeof before) => ({
  ...row,
  vendor: "cisco",
  projection_sha256:
    row.configuration_id === before.configuration_id ? hash(6) : hash(7),
  parser_confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
});
const draft = patchDraftSchema.parse({
  version: "snapshot-patch-draft-0.1.0",
  patch_id: id(4),
  created_at: "2026-10-04T00:00:04Z",
  draft_sha256: hash(8),
  status: "draft",
  representation: "normalized_objects",
  requires_human_review: true,
  diff: {
    version: "snapshot-diff-0.1.0",
    representation: "normalized_objects",
    before: snapshot(before),
    after: snapshot(after),
    coverage: "supported_complete",
    source_changed: true,
    added_count: 1,
    removed_count: 0,
    modified_count: 0,
    changes: [
      {
        section: "management",
        object_key: ["ntp_servers"],
        kind: "added",
        before_value: null,
        after_value: { address: "192.0.2.1" },
        before_locations: [],
        after_locations: [],
      },
    ],
    limitations: ["Supported objects only"],
  },
});
const request = verifySourcePatchSchema.parse({
  verification_id: id(5),
  draft_sha256: draft.draft_sha256,
  companions: [
    {
      configuration_id: companion.configuration_id,
      source_sha256: companion.source_sha256,
    },
  ],
  scope: { start_node: "edge", destination: "198.51.100.1/32" },
  allow_local_engine_upload: true,
});
const parse = (source_sha256: string) => ({
  source_sha256,
  confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
  complete: true,
});
const preflight = {
  version: "preflight-0.1.0",
  report_id: id(6),
  device_id: before.device_id,
  reference_id: before.configuration_id,
  policy_catalog_version: "test-policy-1",
  before: parse(before.source_sha256),
  after: parse(after.source_sha256),
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
  limitations: ["Локальная проверка, без проверки устройства"],
};
const networkHash = (rows: (typeof before)[]) =>
  digest(
    JSON.stringify(
      [...rows]
        .sort((a, b) => a.device_id.localeCompare(b.device_id))
        .map((row) => [
          row.device_id,
          row.hostname,
          row.platform,
          row.source_sha256,
        ]),
    ),
  );
const intent = {
  version: "source-patch-intent-0.1.0",
  patch_id: draft.patch_id,
  request,
  created_at: "2026-10-04T00:00:05Z",
  before,
  after,
  companions: [companion],
  before_network_sha256: networkHash([before, companion]),
  after_network_sha256: networkHash([after, companion]),
  preflight,
};
// Python's normative wire retains 1.0 and escapes non-ASCII text. The browser
// must hash those bytes rather than serialize parsed JavaScript numbers again.
function normative(value: unknown) {
  return stableJson(value)
    .replace(/"confidence":1(?=[,}])/g, '"confidence":1.0')
    .replace(
      /[\u007f-\uffff]/g,
      (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
}
function seal(
  row: Omit<SourcePatchVerification, "review_json" | "review_sha256">,
) {
  if (row.outcome) row.outcome.intent_sha256 = digest(normative(row.intent));
  const raw = normative(row);
  return { ...row, review_json: raw, review_sha256: digest(raw) };
}
function verification(pending = false): SourcePatchVerification {
  const body = {
    version: "source-patch-verification-0.1.0",
    verification_id: request.verification_id,
    patch_id: draft.patch_id,
    draft_sha256: draft.draft_sha256,
    intent: structuredClone(intent),
    outcome: pending
      ? null
      : {
          version: "source-patch-outcome-0.1.0",
          verification_id: request.verification_id,
          intent_sha256: hash(0),
          completed_at: "2026-10-04T00:00:06Z",
          network_result: {
            version: "batfish-check-0.1.0",
            before_sha256: intent.before_network_sha256,
            after_sha256: intent.after_network_sha256,
            scope: request.scope,
            status: "no_differences_in_scope",
            reason: "query_completed",
            engine_version: "owned-test-fixture",
            network_name: `sentinel-${"a".repeat(32)}`,
            cleanup_complete: true,
            difference_count: 0,
            before_reachable_count: 1,
            after_reachable_count: 1,
            requires_human_review: true,
            limitations: ["Synthetic transport test"],
          },
        },
    execution_status: pending ? "pending_unknown" : "completed",
    validation_blockers: [],
    status: "needs_review",
    ml_status: "not_run",
    approved: false,
    applied: false,
  } as Omit<SourcePatchVerification, "review_json" | "review_sha256">;
  body.validation_blockers = sourceValidationBlockers(body);
  return sourcePatchVerificationSchema.parse(seal(body));
}
function summary(row = verification()): SourcePatchVerificationSummary {
  return sourcePatchVerificationSummarySchema.parse({
    version: "source-patch-verification-summary-0.1.0",
    verification_id: row.verification_id,
    patch_id: row.patch_id,
    draft_sha256: row.draft_sha256,
    review_sha256: row.review_sha256,
    created_at: row.intent.created_at,
    completed_at: row.outcome?.completed_at ?? null,
    execution_status: row.execution_status,
    network_status: row.outcome?.network_result.status ?? null,
    cleanup_complete: row.outcome?.network_result.cleanup_complete ?? null,
    status: "needs_review",
  });
}
const capabilities = {
  version: "source-patch-capabilities-0.1.0",
  network_engine: "configured",
  health_checked: false,
  exact_retained_sources_required: true,
  request_consent_required: true,
  maximum_devices: 32,
  maximum_network_bytes: 8388608,
  ml_status: "not_run",
};

it("verifies exact normative bytes, typed equality and the nested intent proof without float reserialization", async () => {
  const row = verification();
  expect(row.review_json).toContain('"confidence":1.0');
  expect(row.review_json).toContain("\\u041b");
  expect(digest(stableJson(row.intent))).not.toBe(row.outcome!.intent_sha256);
  expect(await sourceReviewProofMatches(row)).toBe(true);
  expect(await sourceVerificationBound(row, draft, request, summary(row))).toBe(
    true,
  );
  expect(row.intent.before.canonical_sha256).not.toBe(
    draft.diff.before.projection_sha256,
  );
});
it("hashes the sorted whole network, not a target source or canonical/projection hash", async () => {
  expect(await sourceNetworkDigest([before, companion])).toBe(
    networkHash([before, companion]),
  );
  expect(await sourceNetworkDigest([companion, before])).toBe(
    intent.before_network_sha256,
  );
  expect(intent.before_network_sha256).not.toBe(before.source_sha256);
  const row = verification();
  row.intent.before_network_sha256 = before.source_sha256;
  row.outcome!.network_result.before_sha256 = before.source_sha256;
  expect(await sourceVerificationBound(seal(row), draft)).toBe(false);
});
it("rejects altered wire, typed projections, duplicate JSON keys and an unrelated intent proof", async () => {
  const row = verification();
  for (const altered of [
    { ...row, review_sha256: hash(9) },
    { ...row, review_json: row.review_json + " " },
    {
      ...row,
      intent: {
        ...row.intent,
        before: { ...row.intent.before, canonical_sha256: hash(7) },
      },
    },
    { ...row, outcome: { ...row.outcome!, intent_sha256: hash(9) } },
  ])
    expect(await sourceReviewProofMatches(altered)).toBe(false);
  const duplicate = row.review_json.replace(
    '"approved":false',
    '"approved":false,"approved":false',
  );
  expect(
    await sourceReviewProofMatches({
      ...row,
      review_json: duplicate,
      review_sha256: digest(duplicate),
    }),
  ).toBe(false);
  const wrongProof = structuredClone(row);
  wrongProof.outcome!.intent_sha256 = hash(9);
  const { review_json: _raw, review_sha256: _hash, ...body } = wrongProof;
  const raw = normative(body);
  expect(
    await sourceReviewProofMatches({
      ...wrongProof,
      review_json: raw,
      review_sha256: digest(raw),
    }),
  ).toBe(false);
});
it.each([
  { approved: true },
  { applied: true },
  { approved: 0 },
  { status: "validated" },
  { ml_status: "completed" },
  { execution_status: "pending_unknown" },
  { validation_blockers: [] },
  { unexpected: true },
])("rejects false promotion or inconsistent source record %j", (update) => {
  expect(
    sourcePatchVerificationSchema.safeParse({ ...verification(), ...update })
      .success,
  ).toBe(false);
});
it("rejects request coercion, duplicate companions, unexpected fields and invalid IPv4 scopes", () => {
  for (const update of [
    { allow_local_engine_upload: "true" },
    { companions: [request.companions[0], request.companions[0]] },
    { scope: { start_node: "edge", destination: "198.51.100.1/24" } },
    { scope: { start_node: "edge", destination: "2001:db8::/32" } },
    { approved: true },
  ])
    expect(
      verifySourcePatchSchema.safeParse({ ...request, ...update }).success,
    ).toBe(false);
  expect(
    sourcePatchCapabilitiesSchema.safeParse({
      ...capabilities,
      health_checked: true,
    }).success,
  ).toBe(false);
});
it("rejects internally inconsistent source pairs, selection, preflight and scope", () => {
  const row = verification();
  for (const intentUpdate of [
    { before: { ...before, device_id: id(9) } },
    { after: { ...after, hostname: "other" } },
    { after: { ...after, source_sha256: before.source_sha256 } },
    { companions: [{ ...companion, hostname: "EDGE" }] },
    { request: { ...request, companions: [] } },
    { request: { ...request, allow_local_engine_upload: false } },
    {
      request: {
        ...request,
        scope: { ...request.scope, start_node: "unselected" },
      },
    },
    { preflight: { ...row.intent.preflight, formal_verification: "passed" } },
    {
      preflight: {
        ...row.intent.preflight,
        before: { ...row.intent.preflight.before, source_sha256: hash(9) },
      },
    },
  ])
    expect(
      sourcePatchVerificationSchema.safeParse({
        ...row,
        intent: { ...row.intent, ...intentUpdate },
      }).success,
    ).toBe(false);
  expect(
    sourcePatchVerificationSchema.safeParse({
      ...row,
      outcome: {
        ...row.outcome!,
        network_result: {
          ...row.outcome!.network_result,
          scope: { ...request.scope, start_node: "core" },
        },
      },
    }).success,
  ).toBe(false);
});
it.each([
  ["unavailable", "sdk_missing", null, null, null],
  ["error", "worker_failed", null, null, null],
  ["incomplete", "initialization_issues", null, null, null],
  ["inconclusive", "empty_reachable_scope", 0, 0, 0],
  ["differences_found", "query_completed", 1, 1, 1],
  ["no_differences_in_scope", "query_completed", 0, 1, 1],
])(
  "retains network status %s independently of needs_review and cleanup",
  (status, reason, differences, old, next) => {
    for (const cleanup_complete of [true, false, null]) {
      const row = verification();
      Object.assign(row.outcome!.network_result, {
        status,
        reason,
        cleanup_complete,
        difference_count: differences,
        before_reachable_count: old,
        after_reachable_count: next,
      });
      row.validation_blockers = sourceValidationBlockers(row);
      const parsed = sourcePatchVerificationSchema.parse(seal(row));
      expect(parsed.approved).toBe(false);
      expect(parsed.status).toBe("needs_review");
      expect(parsed.intent.preflight.formal_verification).toBe("not_run");
      expect(
        parsed.validation_blockers.includes("engine_cleanup_not_confirmed"),
      ).toBe(cleanup_complete !== true);
      expect(
        parsed.validation_blockers.includes("formal_scope_not_passed"),
      ).toBe(status !== "no_differences_in_scope");
    }
  },
);
it("keeps pending_unknown distinct from a completed worker and never fabricates counts", async () => {
  const row = verification(true);
  expect(await sourceVerificationBound(row, draft, request, summary(row))).toBe(
    true,
  );
  expect(row.outcome).toBeNull();
  expect(row.validation_blockers).toContain("network_execution_unknown");
  expect(row.validation_blockers).toContain("engine_cleanup_not_confirmed");
  expect(
    sourcePatchVerificationSummarySchema.safeParse({
      ...summary(row),
      network_status: "no_differences_in_scope",
    }).success,
  ).toBe(false);
});
it("binds a full result to the selected draft, exact request and summary", async () => {
  const row = verification(),
    index = summary(row);
  for (const wrongDraft of [
    { ...draft, patch_id: id(9) },
    { ...draft, draft_sha256: hash(9) },
    {
      ...draft,
      diff: {
        ...draft.diff,
        after: { ...draft.diff.after, configuration_id: id(9) },
      },
    },
    {
      ...draft,
      diff: {
        ...draft.diff,
        before: { ...draft.diff.before, created_at: "2026-10-04T00:00:00Z" },
      },
    },
  ])
    expect(await sourceVerificationBound(row, wrongDraft)).toBe(false);
  for (const wrongRequest of [
    { ...request, verification_id: id(9) },
    { ...request, companions: [] },
    { ...request, scope: { ...request.scope, destination: "203.0.113.1/32" } },
  ])
    expect(await sourceVerificationBound(row, draft, wrongRequest)).toBe(false);
  for (const wrongSummary of [
    { ...index, review_sha256: hash(9) },
    { ...index, cleanup_complete: false },
    { ...index, network_status: "differences_found" as const },
    { ...index, verification_id: id(9) },
  ])
    expect(
      await sourceVerificationBound(row, draft, undefined, wrongSummary),
    ).toBe(false);
  expect(sourceSummaryBound({ ...index, draft_sha256: hash(9) }, draft)).toBe(
    false,
  );
});
it("offers only clean distinct companion devices and displays the selected source binding", () => {
  const item: ConfigurationSummary = {
    ...companion,
    filename: "core.cfg",
    vendor: "cisco",
    parser_confidence: 1,
    warning_count: 0,
    unparsed_count: 0,
  };
  expect(sourceCompanionEligible(item, draft, [])).toBe(true);
  for (const update of [
    { device_id: before.device_id },
    { hostname: "EDGE" },
    { hostname: null },
    { warning_count: 1 },
    { platform: "unknown" },
  ])
    expect(sourceCompanionEligible({ ...item, ...update }, draft, [])).toBe(
      false,
    );
  expect(
    sourceCompanionEligible({ ...item, configuration_id: id(9) }, draft, [
      item,
    ]),
  ).toBe(false);
});

const transport = (value: unknown, status = 200) =>
  vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(value), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
  );
it("uses authenticated v2 source endpoints and leaves v1 local verification available", async () => {
  const row = verification(),
    send = transport(row),
    client = new ApiClient("x".repeat(32), send);
  expect(await client.verifySourcePatch(draft, request)).toEqual(row);
  expect(send.mock.calls[0]?.[0]).toBe(
    `/api/v2/patches/${draft.patch_id}/verify`,
  );
  const options = send.mock.calls[0]?.[1] as RequestInit;
  expect(options.method).toBe("POST");
  expect(options.headers).toMatchObject({
    Authorization: `Bearer ${"x".repeat(32)}`,
  });
  expect(JSON.parse(options.body as string)).toEqual(request);
  expect(options).toMatchObject({
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  send.mockResolvedValueOnce(new Response(JSON.stringify(row)));
  await client.sourcePatchVerification(draft, row.verification_id, request);
  expect(send.mock.calls[1]?.[0]).toBe(
    `/api/v2/patches/${draft.patch_id}/verifications/${row.verification_id}`,
  );
  expect((send.mock.calls[1]?.[1] as RequestInit).method).toBe("GET");
  send.mockResolvedValueOnce(new Response(JSON.stringify([summary(row)])));
  await client.sourcePatchVerifications(draft, 20);
  expect(send.mock.calls[2]?.[0]).toBe(
    `/api/v2/patches/${draft.patch_id}/verifications?limit=20&offset=20`,
  );
  send.mockResolvedValueOnce(new Response(JSON.stringify(capabilities)));
  await client.sourcePatchCapabilities();
  expect(send.mock.calls[3]?.[0]).toBe("/api/v2/patches/capabilities");
});
it("refuses consent/hash substitutions before sending and never retries lost POSTs", async () => {
  const send = transport(verification()),
    client = new ApiClient("x".repeat(32), send);
  await expect(
    client.verifySourcePatch(draft, {
      ...request,
      allow_local_engine_upload: false,
    }),
  ).rejects.toMatchObject({ status: 403 });
  await expect(
    client.verifySourcePatch(draft, { ...request, draft_sha256: hash(9) }),
  ).rejects.toMatchObject({ status: 409 });
  expect(send).not.toHaveBeenCalled();
  send.mockRejectedValueOnce(new TypeError("lost response"));
  await expect(client.verifySourcePatch(draft, request)).rejects.toMatchObject({
    status: 0,
  });
  expect(send).toHaveBeenCalledTimes(1);
});
it("rejects foreign full/list responses, altered proofs and summary substitutions at the API boundary", async () => {
  const row = verification(),
    send = transport(row),
    client = new ApiClient("x".repeat(32), send);
  await expect(
    client.sourcePatchVerification(draft, id(9)),
  ).rejects.toMatchObject({ status: 0 });
  await expect(
    client.sourcePatchVerification(draft, row.verification_id, {
      ...request,
      companions: [],
    }),
  ).rejects.toMatchObject({ status: 0 });
  await expect(
    client.sourcePatchVerification(draft, row.verification_id, undefined, {
      ...summary(row),
      review_sha256: hash(9),
    }),
  ).rejects.toMatchObject({ status: 0 });
  send.mockResolvedValueOnce(
    new Response(JSON.stringify({ ...row, review_sha256: hash(9) })),
  );
  await expect(client.verifySourcePatch(draft, request)).rejects.toMatchObject({
    status: 0,
  });
  send.mockResolvedValueOnce(
    new Response(JSON.stringify([summary(row), summary(row)])),
  );
  await expect(client.sourcePatchVerifications(draft)).rejects.toMatchObject({
    status: 0,
  });
  send.mockResolvedValueOnce(
    new Response(JSON.stringify([{ ...summary(row), draft_sha256: hash(9) }])),
  );
  await expect(client.sourcePatchVerifications(draft)).rejects.toMatchObject({
    status: 0,
  });
});
