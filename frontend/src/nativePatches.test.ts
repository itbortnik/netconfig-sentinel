import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { analysisSchema, stableJson } from "./contracts";
import { nativeControls } from "../tests/browser/native-patches-fixtures";
import {
  generateNativePatchSchema,
  nativePatchCandidateSchema,
  nativePatchSelectionSchema,
  nativePatchSummarySchema,
  nativeCandidateBound,
  nativeCommands,
  nativePatchRequest,
  nativeProofMatches,
  nativeSelectionBound,
  nativeSummaryMatches,
} from "./nativePatches";

const digest = (raw: string) => createHash("sha256").update(raw).digest("hex");
const control = (index = 0) => {
  const c = nativeControls[index]!;
  return {
    candidate: nativePatchCandidateSchema.parse(structuredClone(c.candidate)),
    selection: nativePatchSelectionSchema.parse(c.selection),
    analysis: analysisSchema.parse(c.analysis),
    summary: nativePatchSummarySchema.parse(c.summary),
  };
};
const token = "authored-native-patch-unit-control-token";
it.each([0, 1])(
  "validates actual pure Python %i native metadata and exact proof bytes",
  async (index) => {
    const { candidate, selection, analysis, summary } = control(index);
    expect(nativeSelectionBound(selection, analysis)).toBe(true);
    expect(
      nativeCandidateBound(
        candidate,
        analysis,
        candidate.selected_finding,
        selection,
      ),
    ).toBe(true);
    expect(nativeSummaryMatches(candidate, summary)).toBe(true);
    expect(await nativeProofMatches(candidate)).toBe(true);
    expect(nativeCommands(candidate.metadata)).toEqual(
      candidate.native_commands,
    );
    expect(
      nativePatchRequest(
        selection,
        candidate.selected_finding,
        candidate.candidate_id,
      ),
    ).toEqual(candidate.request);
    expect(candidate.approved).toBe(false);
    expect(candidate.formal_qualification).toBe("not_proven");
  },
);
it.each([
  { allow_private_candidate_retention: false },
  { allow_private_candidate_retention: 1 },
  { allow_local_native_generation: "true" },
  { allow_local_native_generation: undefined },
  { candidate_text: "arbitrary command" },
  { baseline_configuration_id: crypto.randomUUID() },
  { version: undefined },
  { policy_catalog_version: "policy-rules-0.6.0" },
])(
  "rejects missing or non-boolean consent and arbitrary client inputs %j",
  (update) => {
    expect(
      generateNativePatchSchema.safeParse({
        ...control().candidate.request,
        ...update,
      }).success,
    ).toBe(false);
  },
);
it.each([
  { approved: true },
  { applied: 0 },
  { quality_proven: "false" },
  { calibrated: true },
  { individual_identity_verified: false, extra: true },
  { formal_qualification: "passed" },
  { validation_blockers: [] },
  { native_commands: ["show running-config"] },
  { created_at: "2026-10-26T10:00:02" },
  { created_at: "2000-10-26T10:00:00.999999Z" },
])("rejects new assurance, command and timestamp drift %j", (update) => {
  expect(
    nativePatchCandidateSchema.safeParse({ ...control().candidate, ...update })
      .success,
  ).toBe(false);
});
it("rejects nested assurance, edit anchors, VTY ranges and local report drift", () => {
  const mutations = [
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.device_syntax_verified = 0 as never;
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.review.preflight.before.complete = 1 as never;
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.review.preflight.formal_verification = "passed" as never;
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.edits[0]!.vty!.last = -1;
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.edits[0]!.source_line += 1;
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.review.proposal.reference_id = crypto.randomUUID();
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.review.validation_blockers = [];
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.review.preflight.after.source_sha256 = "f".repeat(64);
    },
    (c: ReturnType<typeof control>["candidate"]) => {
      c.metadata.review.proposal.changes[0]!.before_end = 10000;
    },
  ];
  for (const mutate of mutations) {
    const c = control().candidate;
    mutate(c);
    expect(nativePatchCandidateSchema.safeParse(c).success).toBe(false);
  }
});
it("rejects changed public data, duplicate proof keys, wrong SHA and forged proposal identity", async () => {
  const original = control().candidate;
  const c = structuredClone(original);
  c.selected_finding.title += " changed";
  expect(await nativeProofMatches(c)).toBe(false);
  const duplicate = structuredClone(original);
  duplicate.review_json = duplicate.review_json.replace(
    '{"analysis_created_at":',
    '{"approved":false,"analysis_created_at":',
  );
  duplicate.review_sha256 = digest(duplicate.review_json);
  expect(await nativeProofMatches(duplicate)).toBe(false);
  expect(
    await nativeProofMatches({ ...original, review_sha256: "f".repeat(64) }),
  ).toBe(false);
  const forged = structuredClone(original);
  const before = forged.metadata.review.proposal.proposal_id;
  forged.metadata.review.proposal.proposal_id = crypto.randomUUID();
  forged.review_json = forged.review_json.replaceAll(
    before,
    forged.metadata.review.proposal.proposal_id,
  );
  forged.review_sha256 = digest(forged.review_json);
  expect(await nativeProofMatches(forged)).toBe(false);
  const changedFinding = structuredClone(original);
  changedFinding.selected_finding.title += " changed";
  const { review_json: _r, review_sha256: _h, ...body } = changedFinding;
  changedFinding.review_json = stableJson(body);
  changedFinding.review_sha256 = digest(changedFinding.review_json);
  expect(await nativeProofMatches(changedFinding)).toBe(false);
});
it("binds exact selection, analysis, finding, parent and summary", () => {
  const { candidate: c, analysis: a, selection: s, summary } = control();
  expect(
    nativeSelectionBound({ ...s, analysis_id: crypto.randomUUID() }, a),
  ).toBe(false);
  expect(nativeSelectionBound({ ...s, finding_pins: [] }, a)).toBe(false);
  expect(
    nativeSelectionBound(
      {
        ...s,
        finding_pins: [
          { ...s.finding_pins[0]!, finding_sha256: "f".repeat(64) },
        ],
      },
      a,
    ),
  ).toBe(false);
  expect(
    nativeCandidateBound(
      c,
      { ...a, configuration_id: crypto.randomUUID() },
      c.selected_finding,
      s,
    ),
  ).toBe(false);
  expect(
    nativeCandidateBound(
      c,
      a,
      { ...c.selected_finding, title: "other finding" },
      s,
    ),
  ).toBe(false);
  expect(
    nativeCandidateBound(c, a, c.selected_finding, {
      ...s,
      canonical_sha256: "f".repeat(64),
    }),
  ).toBe(false);
  expect(
    nativeCandidateBound(c, a, c.selected_finding, {
      ...s,
      analysis_sha256: "f".repeat(64),
    }),
  ).toBe(false);
  expect(nativeSummaryMatches(c, { ...summary, service_role: "admin" })).toBe(
    false,
  );
  expect(
    nativeSummaryMatches(c, { ...summary, review_sha256: "f".repeat(64) }),
  ).toBe(false);
});
it("uses exact native v2 URL, body and summary bindings", async () => {
  const { candidate: c, selection: s, summary } = control();
  const transport = vi
    .fn<typeof fetch>()
    .mockImplementation(async (url, init) => {
      if (String(url).includes("native-patch-selection"))
        return new Response(JSON.stringify(s));
      if (init?.method === "POST" || String(url).endsWith(c.candidate_id))
        return new Response(JSON.stringify(c));
      return new Response(JSON.stringify([summary]));
    });
  const client = new ApiClient(token, transport);
  expect(
    await client.nativePatchSelection(
      c.configuration_id,
      c.request.analysis_id,
    ),
  ).toEqual(s);
  expect(
    await client.generateNativePatch(c.configuration_id, c.request),
  ).toEqual(c);
  expect(
    await client.nativePatch(
      c.configuration_id,
      c.candidate_id,
      c.request,
      summary,
    ),
  ).toEqual(c);
  expect(await client.nativePatches(c.configuration_id)).toEqual([summary]);
  expect(transport.mock.calls[1]![0]).toBe(
    `/api/v2/configurations/${c.configuration_id}/native-patches`,
  );
  expect(JSON.parse(transport.mock.calls[1]![1]!.body as string)).toEqual(
    c.request,
  );
  expect(transport.mock.calls[3]![0]).toBe(
    `/api/v2/configurations/${c.configuration_id}/native-patches?limit=20&offset=0`,
  );
  await expect(
    client.nativePatch(crypto.randomUUID(), c.candidate_id),
  ).rejects.toThrow();
  await expect(
    client.nativePatch(c.configuration_id, crypto.randomUUID()),
  ).rejects.toThrow();
  await expect(
    client.nativePatch(c.configuration_id, c.candidate_id, {
      ...c.request,
      analysis_sha256: "f".repeat(64),
    }),
  ).rejects.toThrow();
});
it("rejects duplicate or foreign history and stale selection from API", async () => {
  const { candidate: c, selection: s, summary } = control();
  const transport = vi.fn<typeof fetch>();
  const client = new ApiClient(token, transport);
  for (const response of [
    [summary, summary],
    [{ ...summary, configuration_id: crypto.randomUUID() }],
  ]) {
    transport.mockResolvedValueOnce(new Response(JSON.stringify(response)));
    await expect(client.nativePatches(c.configuration_id)).rejects.toThrow();
  }
  transport.mockResolvedValueOnce(new Response(JSON.stringify(s)));
  await expect(
    client.nativePatchSelection(c.configuration_id, crypto.randomUUID()),
  ).rejects.toThrow();
  await expect(
    client.nativePatches(c.configuration_id, 10001),
  ).rejects.toThrow();
});
it("keeps the same request for explicit replay after committed-but-lost completion and aborts closed clients", async () => {
  const { candidate: c } = control();
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(new Response("{}", { status: 503 }))
    .mockResolvedValueOnce(new Response(JSON.stringify(c)))
    .mockResolvedValueOnce(new Response(JSON.stringify(c)));
  const client = new ApiClient(token, transport);
  await expect(
    client.generateNativePatch(c.configuration_id, c.request),
  ).rejects.toMatchObject({ status: 503 });
  expect(
    await client.nativePatch(c.configuration_id, c.candidate_id, c.request),
  ).toEqual(c);
  expect(
    await client.generateNativePatch(c.configuration_id, c.request),
  ).toEqual(c);
  expect(transport.mock.calls[0]![1]!.body).toBe(
    transport.mock.calls[2]![1]!.body,
  );
  client.close();
  await expect(
    client.nativePatch(c.configuration_id, c.candidate_id),
  ).rejects.toMatchObject({ name: "AbortError" });
  expect(transport).toHaveBeenCalledTimes(3);
});
