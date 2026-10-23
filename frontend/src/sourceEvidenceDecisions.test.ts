import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { patchDraftSchema } from "./patches";
import { sourceEvidenceReportSchema } from "./sourceEvidenceReports";
import {
  evidenceCommentLength,
  reviewSourceEvidenceReportSchema,
  sourceEvidenceCommentSchema,
  sourceEvidenceDecisionSchema,
  sourceEvidenceDecisionSummarySchema,
  sourceEvidenceDecisionProofMatches,
  sourceEvidenceDecisionBound,
} from "./sourceEvidenceDecisions";
import type { SourceEvidenceDecision } from "./sourceEvidenceDecisions";
import controls from "./testdata/sourceEvidenceDecisionControls.json";
import parents from "./testdata/sourceEvidenceControls.json";
import sdkControls from "./testdata/sourceSdkControls.json";

const token = "owned-source-evidence-decision-test-token-32-characters";
const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
function fixture(index = 0) {
  const item = structuredClone(controls.cases[index]!),
    parent = structuredClone(parents.cases[item.report_case_index]!);
  return {
    decision: sourceEvidenceDecisionSchema.parse(item.decision),
    summary: sourceEvidenceDecisionSummarySchema.parse(item.summary),
    report: sourceEvidenceReportSchema.parse(parent.report),
    draft: patchDraftSchema.parse(parent.draft),
    children: parent.children,
  };
}
function sdkFixture(index = 0) {
  const item = structuredClone(sdkControls.cases[index]!),
    decision = sourceEvidenceDecisionSchema.parse(item.decision);
  return {
    decision,
    summary: sourceEvidenceDecisionSummarySchema.parse({
      version: "source-evidence-decision-summary-0.2.0",
      decision_id: decision.decision_id,
      patch_id: decision.patch_id,
      report_id: decision.report_id,
      report_sha256: decision.report_sha256,
      decision_sha256: decision.decision_sha256,
      created_at: decision.created_at,
      verdict: decision.request.verdict,
      service_role: decision.service_role,
      individual_identity_verified: false,
      approved: false,
      applied: false,
    }),
    report: sourceEvidenceReportSchema.parse(item.report),
    draft: patchDraftSchema.parse(item.draft),
    children: {
      deterministic: item.deterministic,
      forest: item.forest,
      neural: item.neural,
      network: item.network,
    },
  };
}
function reseal(row: SourceEvidenceDecision) {
  const { decision_json: _json, decision_sha256: _sha, ...body } = row;
  row.decision_json = stableJson(body);
  row.decision_sha256 = digest(row.decision_json);
  return row;
}
function transportFor(
  value: Omit<ReturnType<typeof fixture>, "children"> & {
    children: Record<
      "deterministic" | "forest" | "neural" | "network",
      unknown
    >;
  } = fixture(),
) {
  return vi.fn<typeof fetch>().mockImplementation(async (url) => {
    const path = String(url);
    if (/\/decisions\?/.test(path)) return Response.json([value.summary]);
    if (/\/decisions(?:\/[^/]+)?$/.test(path))
      return Response.json(value.decision);
    if (/\/evidence-reports\/[^/]+$/.test(path))
      return Response.json(value.report);
    for (const [kind, segment] of [
      ["deterministic", "deterministic-rechecks"],
      ["forest", "statistical-rechecks"],
      ["neural", "ml-rechecks"],
      ["network", "verifications"],
    ] as const)
      if (path.includes(`/${segment}/`))
        return Response.json(value.children[kind]);
    throw new Error("Unexpected owned transport call");
  });
}
it.each([0, 1])(
  "accepts bounded Python authored decision %s with exact original role, comment and parent pins",
  async (index) => {
    const value = fixture(index);
    expect(await sourceEvidenceDecisionProofMatches(value.decision)).toBe(true);
    expect(
      await sourceEvidenceDecisionBound(
        value.decision,
        value.report,
        value.decision.request,
        value.summary,
      ),
    ).toBe(true);
    expect(value.decision.individual_identity_verified).toBe(false);
    expect(value.decision.approved).toBe(false);
    expect(value.decision.applied).toBe(false);
    const before = stableJson(value.report);
    const api = new ApiClient(token, transportFor(value));
    expect(
      await api.sourceEvidenceDecision(
        value.draft,
        value.report,
        value.decision.decision_id,
        undefined,
        value.summary,
      ),
    ).toEqual(value.decision);
    expect(stableJson(value.report)).toBe(before);
    api.close();
  },
);
it.each(sdkControls.cases.map((row, index) => [row.name, index] as const))(
  "accepts SDK-aware decision %s only with its exact complete saved report chain",
  async (_name, index) => {
    const value = sdkFixture(index);
    expect(await sourceEvidenceDecisionProofMatches(value.decision)).toBe(true);
    expect(
      await sourceEvidenceDecisionBound(
        value.decision,
        value.report,
        value.decision.request,
        value.summary,
      ),
    ).toBe(true);
    const api = new ApiClient(token, transportFor(value));
    expect(
      await api.reviewSourceEvidenceReport(
        value.draft,
        value.report,
        value.decision.request,
      ),
    ).toEqual(value.decision);
    expect(
      await api.sourceEvidenceDecision(
        value.draft,
        value.report,
        value.decision.decision_id,
        value.decision.request,
        value.summary,
      ),
    ).toEqual(value.decision);
    expect(await api.sourceEvidenceDecisions(value.report)).toEqual([
      value.summary,
    ]);
    api.close();
    expect(value.decision.individual_identity_verified).toBe(false);
    expect(value.decision.approved).toBe(false);
    expect(
      sourceEvidenceDecisionSchema.safeParse({
        ...value.decision,
        version: "source-evidence-decision-0.1.0",
      }).success,
    ).toBe(false);
    expect(
      sourceEvidenceDecisionSchema.safeParse({
        ...value.decision,
        report_version: "source-evidence-report-0.1.0",
      }).success,
    ).toBe(false);
    expect(
      await sourceEvidenceDecisionBound(
        value.decision,
        value.report,
        undefined,
        { ...value.summary, version: "source-evidence-decision-summary-0.1.0" },
      ),
    ).toBe(false);
  },
);
it("rejects mixed decision protocol before sending and keeps a resealed SDK projection uncertain", async () => {
  const value = sdkFixture(),
    send = transportFor(value),
    api = new ApiClient(token, send);
  await expect(
    api.reviewSourceEvidenceReport(value.draft, value.report, {
      ...value.decision.request,
      version: "source-evidence-decision-request-0.1.0",
    }),
  ).rejects.toMatchObject({ status: 409 });
  expect(send).not.toHaveBeenCalled();
  api.close();
  if (value.report.network?.version !== "source-patch-verification-0.2.0")
    throw new Error("Expected SDK-aware fixture");
  value.report.network.sdk_version = "resealed-false-sdk";
  const { review_json: _json, review_sha256: _sha, ...body } = value.report;
  value.report.review_json = stableJson(body);
  value.report.review_sha256 = digest(value.report.review_json);
  value.decision.report_sha256 = value.report.review_sha256;
  value.decision.request.report_sha256 = value.report.review_sha256;
  reseal(value.decision);
  expect(await sourceEvidenceDecisionBound(value.decision, value.report)).toBe(
    true,
  );
  const client = new ApiClient(token, transportFor(value));
  await expect(
    client.sourceEvidenceDecision(
      value.draft,
      value.report,
      value.decision.decision_id,
    ),
  ).rejects.toMatchObject({ status: 0 });
  client.close();
});
it.each([true, 0, 1, "false"])(
  "rejects numeric or promoted flags %j",
  (flag) => {
    for (const field of [
      "individual_identity_verified",
      "approved",
      "applied",
    ]) {
      expect(
        sourceEvidenceDecisionSchema.safeParse({
          ...fixture().decision,
          [field]: flag,
        }).success,
      ).toBe(false);
      expect(
        sourceEvidenceDecisionSummarySchema.safeParse({
          ...fixture().summary,
          [field]: flag,
        }).success,
      ).toBe(false);
    }
  },
);
it.each([
  "",
  " \n\t",
  "x".repeat(1201),
  "😀".repeat(1201),
  "text\r",
  "text\u0000",
  "text\u200b",
  "text\u00a0",
  "text\u2028",
  "text\ue000",
  "text\ud800",
])("rejects invalid or oversized Python-compatible comment %#", (comment) => {
  expect(sourceEvidenceCommentSchema.safeParse(comment).success).toBe(false);
});
it("counts Unicode codepoints and preserves allowed newline/tab and exact untrimmed comment", () => {
  const comment = "😀".repeat(1200);
  expect(comment.length).toBe(2400);
  expect(evidenceCommentLength(comment)).toBe(1200);
  expect(sourceEvidenceCommentSchema.parse(comment)).toBe(comment);
  expect(sourceEvidenceCommentSchema.parse(" \nКомментари́й\t😀 ")).toBe(
    " \nКомментари́й\t😀 ",
  );
  const request = fixture().decision.request,
    { version: _version, ...withoutVersion } = request;
  expect(reviewSourceEvidenceReportSchema.parse(withoutVersion)).toEqual(
    request,
  );
});
it.each([
  { verdict: "approved" },
  { verdict: "" },
  { comment: 3 },
  { service_role: "admin" },
  { individual_identity_verified: true },
  { version: "source-evidence-decision-request-9.0.0" },
])(
  "request rejects unsupported verdict, actor fields and invalid data %j",
  (change) => {
    expect(
      reviewSourceEvidenceReportSchema.safeParse({
        ...fixture().decision.request,
        ...change,
      }).success,
    ).toBe(false);
  },
);
it("rejects self-consistent resealed false projection against the unchanged accepted parent", async () => {
  const changes: ((row: SourceEvidenceDecision) => void)[] = [
    (row) => {
      row.patch_id = crypto.randomUUID();
    },
    (row) => {
      row.draft_sha256 = "9".repeat(64);
    },
    (row) => {
      row.report_id = crypto.randomUUID();
    },
    (row) => {
      row.report_sha256 = "9".repeat(64);
      row.request.report_sha256 = row.report_sha256;
    },
    (row) => {
      row.before.configuration_id = crypto.randomUUID();
    },
    (row) => {
      row.before.canonical_sha256 = "9".repeat(64);
    },
    (row) => {
      row.after.source_sha256 = "9".repeat(64);
    },
    (row) => {
      row.before.created_at = "2000-01-01T00:00:00Z";
    },
    (row) => {
      row.before_analysis_id = crypto.randomUUID();
    },
    (row) => {
      row.before_analysis_sha256 = "9".repeat(64);
    },
    (row) => {
      row.created_at = "2000-01-01T00:00:00Z";
    },
  ];
  for (const change of changes) {
    const value = fixture();
    change(value.decision);
    reseal(value.decision);
    const parsed = sourceEvidenceDecisionSchema.parse(value.decision);
    expect(await sourceEvidenceDecisionProofMatches(parsed)).toBe(true);
    expect(await sourceEvidenceDecisionBound(parsed, value.report)).toBe(false);
    const api = new ApiClient(token, transportFor(value));
    await expect(
      api.sourceEvidenceDecision(value.draft, value.report, parsed.decision_id),
    ).rejects.toMatchObject({ status: 0 });
    api.close();
  }
});
it("exact request prevents resealed changed comment or verdict on POST and recovery", async () => {
  for (const field of ["comment", "verdict"] as const) {
    const value = fixture(),
      expected = structuredClone(value.decision.request);
    if (field === "comment") value.decision.request.comment += " changed";
    else value.decision.request.verdict = "needs_more_information";
    reseal(value.decision);
    expect(
      await sourceEvidenceDecisionBound(value.decision, value.report, expected),
    ).toBe(false);
    const api = new ApiClient(token, transportFor(value));
    await expect(
      api.reviewSourceEvidenceReport(value.draft, value.report, expected),
    ).rejects.toMatchObject({ status: 0 });
    api.close();
  }
});
it("refuses invalid normative proof, duplicate keys and incompatible summary role or digest", async () => {
  for (const change of [
    (row: SourceEvidenceDecision) => {
      row.decision_sha256 = "9".repeat(64);
    },
    (row: SourceEvidenceDecision) => {
      row.decision_json = row.decision_json.replace(
        '"applied":false',
        '"applied":false,"applied":false',
      );
      row.decision_sha256 = digest(row.decision_json);
    },
    (row: SourceEvidenceDecision) => {
      row.request.comment += " altered";
    },
  ]) {
    const value = fixture();
    change(value.decision);
    expect(
      await sourceEvidenceDecisionBound(value.decision, value.report),
    ).toBe(false);
  }
  for (const change of [
    { service_role: "admin" as const },
    { decision_sha256: "9".repeat(64) },
    { verdict: "needs_more_information" as const },
  ]) {
    const value = fixture();
    expect(
      await sourceEvidenceDecisionBound(
        value.decision,
        value.report,
        undefined,
        { ...value.summary, ...change },
      ),
    ).toBe(false);
  }
  expect(
    sourceEvidenceDecisionSummarySchema.safeParse({
      ...fixture().summary,
      comment: "must remain detail only",
    }).success,
  ).toBe(false);
});
it("POST acceptance re-fetches integrity-checked parent and children, and preserves recorded role on replay", async () => {
  const value = fixture(),
    transport = transportFor(value),
    api = new ApiClient(token, transport);
  const result = await api.reviewSourceEvidenceReport(
    value.draft,
    value.report,
    value.decision.request,
  );
  expect(result.service_role).toBe("engineer");
  expect(transport.mock.calls).toHaveLength(5); // POST + parent + deterministic/neural/network.
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "POST"),
  ).toHaveLength(1);
  expect(JSON.parse(String(transport.mock.calls[0]![1]!.body))).toEqual(
    value.decision.request,
  );
  expect(transport.mock.calls[0]![1]!.credentials).toBe("omit");
  expect(transport.mock.calls[0]![1]!.redirect).toBe("error");
  api.close();
});
it("rejects resealed false parent projection even when the decision's own proof is valid", async () => {
  const value = fixture();
  value.report.deterministic.policy_catalog_version = "fabricated-catalog";
  const { review_json: _json, review_sha256: _sha, ...body } = value.report;
  value.report.review_json = stableJson(body);
  value.report.review_sha256 = digest(value.report.review_json);
  value.decision.report_sha256 = value.report.review_sha256;
  value.decision.request.report_sha256 = value.report.review_sha256;
  reseal(value.decision);
  const api = new ApiClient(token, transportFor(value));
  await expect(
    api.sourceEvidenceDecision(
      value.draft,
      value.report,
      value.decision.decision_id,
    ),
  ).rejects.toMatchObject({ status: 0 });
  api.close();
});
it("a refused parent GET after successful POST remains uncertain and explicit decision GET recovers", async () => {
  const value = fixture(),
    normal = transportFor(value);
  let failing = true;
  const transport = vi
    .fn<typeof fetch>()
    .mockImplementation(async (url, init) =>
      failing && /\/evidence-reports\/[^/]+$/.test(String(url))
        ? new Response(null, { status: 404 })
        : normal(url, init),
    );
  const api = new ApiClient(token, transport);
  await expect(
    api.reviewSourceEvidenceReport(
      value.draft,
      value.report,
      value.decision.request,
    ),
  ).rejects.toMatchObject({ status: 0 });
  failing = false;
  expect(
    await api.sourceEvidenceDecision(
      value.draft,
      value.report,
      value.decision.decision_id,
      value.decision.request,
    ),
  ).toEqual(value.decision);
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "POST"),
  ).toHaveLength(1);
  api.close();
});
it("lost POST has no implicit retry and supports only explicit same-ID GET recovery", async () => {
  const value = fixture(),
    transport = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new Error("private-comment-secret"))
      .mockImplementation(transportFor(value)),
    api = new ApiClient(token, transport);
  await expect(
    api.reviewSourceEvidenceReport(
      value.draft,
      value.report,
      value.decision.request,
    ),
  ).rejects.toMatchObject({ status: 0 });
  expect(transport).toHaveBeenCalledTimes(1);
  expect(
    await api.sourceEvidenceDecision(
      value.draft,
      value.report,
      value.decision.decision_id,
      value.decision.request,
    ),
  ).toEqual(value.decision);
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "POST"),
  ).toHaveLength(1);
  api.close();
});
it("bounds plaintext proof and actual outer response bytes", async () => {
  const value = fixture();
  expect(
    sourceEvidenceDecisionSchema.safeParse({
      ...value.decision,
      decision_json: "x".repeat(32 * 1024 + 1),
    }).success,
  ).toBe(false);
  const api = new ApiClient(
    token,
    vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        new Response(" ".repeat(128 * 1024) + JSON.stringify(value.decision)),
      ),
  );
  await expect(
    api.sourceEvidenceDecision(
      value.draft,
      value.report,
      value.decision.decision_id,
    ),
  ).rejects.toMatchObject({ status: 0 });
  api.close();
});
it("history is bounded metadata only with explicit pagination and no detector or detail fetch", async () => {
  const value = fixture(),
    transport = transportFor(value),
    api = new ApiClient(token, transport);
  expect(await api.sourceEvidenceDecisions(value.report, 20)).toEqual([
    value.summary,
  ]);
  expect(transport.mock.calls[0]![0]).toBe(
    `/api/v2/patches/${value.draft.patch_id}/evidence-reports/${value.report.report_id}/decisions?limit=20&offset=20`,
  );
  expect(transport).toHaveBeenCalledTimes(1);
  api.close();
  for (const rows of [
    [value.summary, value.summary],
    [{ ...value.summary, report_id: crypto.randomUUID() }],
    Array.from({ length: 21 }, () => value.summary),
  ]) {
    const client = new ApiClient(
      token,
      vi.fn<typeof fetch>().mockResolvedValue(Response.json(rows)),
    );
    await expect(
      client.sourceEvidenceDecisions(value.report),
    ).rejects.toMatchObject({ status: 0 });
    client.close();
  }
});
it("close aborts a decision's in-flight parent GET and prohibits stale acceptance", async () => {
  const value = fixture(),
    normal = transportFor(value);
  let reached: (() => void) | undefined;
  const started = new Promise<void>((resolve) => {
    reached = resolve;
  });
  const transport = vi
    .fn<typeof fetch>()
    .mockImplementation(async (url, init) => {
      if (/\/evidence-reports\/[^/]+$/.test(String(url))) {
        reached!();
        return new Promise((_, reject) =>
          init?.signal?.addEventListener("abort", () =>
            reject(new DOMException("closed", "AbortError")),
          ),
        );
      }
      return normal(url, init);
    });
  const api = new ApiClient(token, transport),
    pending = api.sourceEvidenceDecision(
      value.draft,
      value.report,
      value.decision.decision_id,
    );
  await started;
  api.close();
  await expect(pending).rejects.toMatchObject({ name: "AbortError" });
});
