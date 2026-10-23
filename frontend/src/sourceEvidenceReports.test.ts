import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { patchDraftSchema } from "./patches";
import { sourceDeterministicRecheckSchema } from "./sourceDeterministicRecheck";
import { sourceForestRecheckSchema } from "./sourceForestRecheck";
import { sourceMlRecheckSchema } from "./sourceMlRecheck";
import { sourcePatchVerificationSchema } from "./sourcePatchVerification";
import {
  createSourceEvidenceReportSchema,
  evidenceRawJsonAt,
  sourceEvidenceReportSchema,
  sourceEvidenceReportBound,
  sourceEvidenceProofMatches,
  sourceEvidenceSummarySchema,
} from "./sourceEvidenceReports";
import type { SourceEvidenceReport } from "./sourceEvidenceReports";
import controls from "./testdata/sourceEvidenceControls.json";
import sdkControls from "./testdata/sourceSdkControls.json";

const token = "test-only-evidence-memory-bearer-token-32-characters";
const digest = (raw: string) => createHash("sha256").update(raw).digest("hex");
function fixture(index = 1) {
  const item = structuredClone(controls.cases[index]!);
  return {
    draft: patchDraftSchema.parse(item.draft),
    request: createSourceEvidenceReportSchema.parse(item.request),
    report: sourceEvidenceReportSchema.parse(item.report),
    summary: sourceEvidenceSummarySchema.parse(item.summary),
    children: {
      deterministic: sourceDeterministicRecheckSchema.parse(
        item.children.deterministic,
      ),
      forest: item.children.forest
        ? sourceForestRecheckSchema.parse(item.children.forest)
        : null,
      neural: item.children.neural
        ? sourceMlRecheckSchema.parse(item.children.neural)
        : null,
      network: item.children.network
        ? sourcePatchVerificationSchema.parse(item.children.network)
        : null,
    },
  };
}
function sdkFixture(index = 0) {
  const item = structuredClone(sdkControls.cases[index]!),
    report = sourceEvidenceReportSchema.parse(item.report);
  return {
    draft: patchDraftSchema.parse(item.draft),
    request: createSourceEvidenceReportSchema.parse(report.request),
    report,
    summary: sourceEvidenceSummarySchema.parse({
      version: "source-evidence-summary-0.2.0",
      report_id: report.report_id,
      patch_id: report.patch_id,
      draft_sha256: report.draft_sha256,
      before_analysis_id: report.before_analysis_id,
      review_sha256: report.review_sha256,
      created_at: report.created_at,
      selected_kinds: (
        ["deterministic", "forest", "neural", "network"] as const
      ).filter((kind) => report[kind] !== null),
      status: report.status,
    }),
    children: {
      deterministic: sourceDeterministicRecheckSchema.parse(item.deterministic),
      forest: sourceForestRecheckSchema.parse(item.forest),
      neural: sourceMlRecheckSchema.parse(item.neural),
      network: item.network
        ? sourcePatchVerificationSchema.parse(item.network)
        : null,
    },
  };
}
function reseal(row: SourceEvidenceReport) {
  const { review_json: _json, review_sha256: _sha, ...body } = row;
  row.review_json = stableJson(body);
  row.review_sha256 = digest(row.review_json);
  return row;
}
function transportFor(value = fixture()) {
  return vi.fn<typeof fetch>().mockImplementation(async (url) => {
    const path = String(url);
    if (/evidence-reports\?/.test(path)) return Response.json([value.summary]);
    if (/evidence-reports(?:\/[^/]+)?$/.test(path))
      return Response.json(value.report);
    for (const [kind, segment] of [
      ["deterministic", "deterministic-rechecks"],
      ["forest", "statistical-rechecks"],
      ["neural", "ml-rechecks"],
      ["network", "verifications"],
    ] as const) {
      if (path.includes(`/${segment}/`))
        return Response.json(value.children[kind]);
    }
    throw new Error("Unexpected request");
  });
}
it.each(controls.cases.map((row, index) => [row.name, index] as const))(
  "accepts authored saved Python %s controls without asserting model or engine quality",
  async (_name, index) => {
    const value = fixture(index);
    expect(
      await sourceEvidenceReportBound(
        value.report,
        value.draft,
        value.children,
        value.request,
        value.summary,
      ),
    ).toBe(true);
    expect(await sourceEvidenceProofMatches(value.report)).toBe(true);
    expect(value.report.formal_qualification).toBe("not_proven");
    expect(value.report.approved).toBe(false);
    expect(value.report.network?.ml_status ?? "not_selected").toBe(
      value.children.network?.ml_status ?? "not_selected",
    );
    expect(
      new TextEncoder().encode(value.report.review_json).length,
    ).toBeLessThan(20000);
  },
);
it.each(sdkControls.cases.map((row, index) => [row.name, index] as const))(
  "verifies full authored SDK-aware report chain %s including legacy or absent network",
  async (_name, index) => {
    const value = sdkFixture(index);
    expect(await sourceEvidenceProofMatches(value.report)).toBe(true);
    expect(
      await sourceEvidenceReportBound(
        value.report,
        value.draft,
        value.children,
        value.request,
        value.summary,
      ),
    ).toBe(true);
    const api = new ApiClient(token, transportFor(value));
    expect(
      await api.createSourceEvidenceReport(value.draft, value.request),
    ).toEqual(value.report);
    expect(
      await api.sourceEvidenceReport(
        value.draft,
        value.report.report_id,
        value.request,
        value.summary,
      ),
    ).toEqual(value.report);
    expect(await api.sourceEvidenceReports(value.draft)).toEqual([
      value.summary,
    ]);
    api.close();
    expect(value.report.formal_qualification).toBe("not_proven");
    expect(value.report.quality_proven).toBe(false);
    expect(value.report.approved).toBe(false);
    expect(
      sourceEvidenceReportSchema.safeParse({
        ...value.report,
        version: "source-evidence-report-0.1.0",
      }).success,
    ).toBe(false);
    if (value.report.network?.version === "source-patch-verification-0.2.0")
      expect(
        sourceEvidenceReportSchema.safeParse({
          ...value.report,
          version: "source-evidence-report-0.1.0",
          request: {
            ...value.report.request,
            version: "source-evidence-request-0.1.0",
          },
        }).success,
      ).toBe(false);
    expect(
      await sourceEvidenceReportBound(
        value.report,
        value.draft,
        value.children,
        value.request,
        { ...value.summary, version: "source-evidence-summary-0.1.0" },
      ),
    ).toBe(false);
  },
);
it("rejects coherently resealed SDK metadata and observation projections against the exact saved child", async () => {
  for (const update of [
    { sdk_version: "fabricated-sdk-9" },
    { sdk_version: null, sdk_observation: "metadata_unavailable" as const },
  ]) {
    const value = sdkFixture();
    if (value.report.network?.version !== "source-patch-verification-0.2.0")
      throw new Error("Expected SDK-aware fixture");
    Object.assign(value.report.network, update);
    reseal(value.report);
    sourceEvidenceReportSchema.parse(value.report);
    expect(await sourceEvidenceProofMatches(value.report)).toBe(true);
    expect(
      await sourceEvidenceReportBound(
        value.report,
        value.draft,
        value.children,
      ),
    ).toBe(false);
    const api = new ApiClient(token, transportFor(value));
    await expect(
      api.createSourceEvidenceReport(value.draft, value.request),
    ).rejects.toMatchObject({ status: 0 });
    api.close();
  }
});
it.each([
  { status: "validated" },
  { formal_qualification: "passed" },
  { risk_fused: true },
  { calibrated: true },
  { quality_proven: true },
  { approved: true },
  { applied: true },
  { validation_blockers: [] },
  { unexpected: true },
  { forest: undefined },
  { neural: undefined },
  { network: undefined },
])(
  "rejects qualification, flags and incomplete nullable projections %j",
  (change) => {
    expect(
      sourceEvidenceReportSchema.safeParse({ ...fixture().report, ...change })
        .success,
    ).toBe(false);
  },
);
it("requires explicit required optional pins and keeps absent results distinct from zero", () => {
  const value = fixture(0);
  expect(value.report.deterministic.before.reference).toBeNull();
  expect(value.report.deterministic.before.peer).toBeNull();
  for (const kind of ["forest", "neural", "network"] as const) {
    expect(
      createSourceEvidenceReportSchema.safeParse({
        ...value.request,
        [kind]: undefined,
      }).success,
    ).toBe(false);
    expect(value.report[kind]).toBeNull();
  }
  expect(
    sourceEvidenceReportSchema.safeParse({
      ...value.report,
      deterministic: {
        ...value.report.deterministic,
        before: { ...value.report.deterministic.before, reference: 0 },
      },
    }).success,
  ).toBe(false);
});
it("rejects resealed false compact projections while all selected valid child hashes stay unchanged", async () => {
  const changes: ((row: SourceEvidenceReport) => void)[] = [
    (row) => {
      row.deterministic.policy_catalog_version = "false-catalog";
    },
    (row) => {
      row.deterministic.policy_changes.introduced++;
      row.deterministic.after.policy++;
    },
    (row) => {
      row.deterministic.peer_profile_sha256 = "9".repeat(64);
    },
    (row) => {
      row.forest!.library_version = "false-library";
    },
    (row) => {
      row.neural!.before.anomaly_score = 0.123;
    },
    (row) => {
      row.neural!.runtime_torch_version = "false-runtime";
    },
    (row) => {
      row.neural!.model_card_sha256 = "9".repeat(64);
    },
    (row) => {
      row.network!.result.difference_count = 0;
      row.network!.result.before_reachable_count = 999;
      row.network!.result.after_reachable_count = 999;
    },
    (row) => {
      row.before.canonical_sha256 = "9".repeat(64);
    },
    (row) => {
      row.before_analysis_sha256 = "9".repeat(64);
    },
    (row) => {
      row.before_analysis_id = crypto.randomUUID();
    },
  ];
  for (const change of changes) {
    const value = fixture();
    const refs = structuredClone(value.report.request);
    change(value.report);
    reseal(value.report);
    const parsed = sourceEvidenceReportSchema.parse(value.report);
    expect(await sourceEvidenceProofMatches(parsed)).toBe(true);
    expect(parsed.request).toEqual(refs);
    expect(
      await sourceEvidenceReportBound(parsed, value.draft, value.children),
    ).toBe(false);
    const api = new ApiClient(
      token,
      transportFor({ ...value, report: parsed }),
    );
    await expect(
      api.sourceEvidenceReport(value.draft, parsed.report_id),
    ).rejects.toMatchObject({ status: 0 });
    api.close();
  }
});
it("does not accept child identity, SHA, exact pair or original-analysis mismatches", async () => {
  for (const change of [
    (value: ReturnType<typeof fixture>) => {
      value.children.forest!.before_analysis_id = crypto.randomUUID();
    },
    (value: ReturnType<typeof fixture>) => {
      value.children.forest!.before_analysis_sha256 = "9".repeat(64);
    },
    (value: ReturnType<typeof fixture>) => {
      value.children.neural!.intent.after.canonical_sha256 = "9".repeat(64);
    },
    (value: ReturnType<typeof fixture>) => {
      value.children.network!.review_sha256 = "9".repeat(64);
    },
    (value: ReturnType<typeof fixture>) => {
      value.children.deterministic.intent.before.created_at =
        "2000-01-01T00:00:00Z";
    },
    (value: ReturnType<typeof fixture>) => {
      value.report.draft_sha256 = "9".repeat(64);
    },
    (value: ReturnType<typeof fixture>) => {
      value.report.before.source_sha256 = "9".repeat(64);
    },
  ]) {
    const value = fixture();
    change(value);
    expect(
      await sourceEvidenceReportBound(
        value.report,
        value.draft,
        value.children,
      ),
    ).toBe(false);
  }
});
it("verifies normative raw bytes and rejects duplicate JSON keys, bad digest and changed numbers", async () => {
  const value = fixture();
  const rawCard = evidenceRawJsonAt(value.children.neural!.review_json, [
    "outcome",
    "report",
    "before",
    "model",
  ]);
  expect(digest(rawCard!)).toBe(value.report.neural!.model_card_sha256);
  for (const change of [
    (row: SourceEvidenceReport) => {
      row.review_sha256 = "0".repeat(64);
    },
    (row: SourceEvidenceReport) => {
      row.review_json = row.review_json.replace(
        '"applied":false',
        '"applied":false,"applied":false',
      );
      row.review_sha256 = digest(row.review_json);
    },
    (row: SourceEvidenceReport) => {
      row.review_json = row.review_json.replace(
        '"anomaly_score":0.8',
        '"anomaly_score":0.81',
      );
      row.review_sha256 = digest(row.review_json);
    },
  ]) {
    const changed = fixture().report;
    change(changed);
    expect(await sourceEvidenceProofMatches(changed)).toBe(false);
  }
  expect(() => evidenceRawJsonAt('{"a":{"x":1,"x":1}}', ["a"])).toThrow();
});
it("preserves actual network errors and inconclusive results separately from unselected evidence", () => {
  const error = fixture(2).report,
    inconclusive = fixture(3).report,
    absent = fixture(0).report;
  expect(error.network!.result.status).toBe("error");
  expect(error.network!.result.difference_count).toBeNull();
  expect(error.validation_blockers).toContain("formal_scope_not_passed");
  expect(error.network!.ml_status).toBe("not_run");
  expect(error.neural).not.toBeNull();
  expect(error.network!.sdk_version).toBeNull();
  expect(inconclusive.network!.result.status).toBe("inconclusive");
  expect(absent.network).toBeNull();
  expect(absent.validation_blockers).toContain("network_not_selected");
});
it("keeps native card3 classes and heads with exact Python float bytes and no qualification", async () => {
  const value = fixture(4),
    child = value.children.neural!;
  const rawCard = evidenceRawJsonAt(child.review_json, [
    "outcome",
    "report",
    "before",
    "model",
  ]);
  expect(rawCard).toContain('"localization_task_weight":1.0');
  expect(digest(rawCard!)).toBe(value.report.neural!.model_card_sha256);
  expect(digest(stableJson(JSON.parse(rawCard!)))).not.toBe(
    value.report.neural!.model_card_sha256,
  );
  expect(value.report.neural!.classes).toEqual([
    "authored_category",
    "second_category",
  ]);
  expect(value.report.neural!.enabled_heads.localization).toBe(true);
  expect(
    await sourceEvidenceReportBound(value.report, value.draft, value.children),
  ).toBe(true);
  const api = new ApiClient(token, transportFor(value));
  expect(
    await api.sourceEvidenceReport(value.draft, value.report.report_id),
  ).toEqual(value.report);
  expect(value.report.formal_qualification).toBe("not_proven");
  api.close();
});
it("POST and GET both load the exact selected children and never run detectors or models", async () => {
  const value = fixture(),
    transport = transportFor(value),
    api = new ApiClient(token, transport);
  expect(
    await api.createSourceEvidenceReport(value.draft, value.request),
  ).toEqual(value.report);
  expect(
    await api.sourceEvidenceReport(
      value.draft,
      value.report.report_id,
      value.request,
      value.summary,
    ),
  ).toEqual(value.report);
  expect(transport.mock.calls).toHaveLength(10);
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "POST"),
  ).toHaveLength(1);
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "GET"),
  ).toHaveLength(9);
  const init = transport.mock.calls[0]![1]!;
  expect(JSON.parse(String(init.body))).toEqual(value.request);
  expect(init.credentials).toBe("omit");
  expect(init.redirect).toBe("error");
  api.close();
});
it("a child GET failure after saved POST remains uncertain; explicit report GET can recover", async () => {
  const value = fixture();
  let failing = true;
  const normal = transportFor(value),
    transport = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
      if (failing && String(url).includes("/ml-rechecks/"))
        return new Response(null, { status: 404 });
      return normal(url, init);
    });
  const api = new ApiClient(token, transport);
  await expect(
    api.createSourceEvidenceReport(value.draft, value.request),
  ).rejects.toMatchObject({ status: 0 });
  failing = false;
  expect(
    await api.sourceEvidenceReport(
      value.draft,
      value.report.report_id,
      value.request,
    ),
  ).toEqual(value.report);
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "POST"),
  ).toHaveLength(1);
  api.close();
});
it("lost responses have no retry or fallback and only explicit GET recovery", async () => {
  const value = fixture(),
    normal = transportFor(value);
  const transport = vi
    .fn<typeof fetch>()
    .mockRejectedValueOnce(new Error("private-config-secret"))
    .mockImplementation(normal);
  const api = new ApiClient(token, transport);
  await expect(
    api.createSourceEvidenceReport(value.draft, value.request),
  ).rejects.toMatchObject({ status: 0 });
  expect(transport).toHaveBeenCalledTimes(1);
  expect(
    await api.sourceEvidenceReport(
      value.draft,
      value.report.report_id,
      value.request,
    ),
  ).toEqual(value.report);
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "POST"),
  ).toHaveLength(1);
  api.close();
});
it("history is bounded, explicitly paginated and rejects duplicates or wrong draft", async () => {
  const value = fixture(),
    transport = transportFor(value),
    api = new ApiClient(token, transport);
  expect(await api.sourceEvidenceReports(value.draft, 20)).toEqual([
    value.summary,
  ]);
  expect(transport.mock.calls[0]![0]).toBe(
    `/api/v2/patches/${value.draft.patch_id}/evidence-reports?limit=20&offset=20`,
  );
  api.close();
  for (const rows of [
    [value.summary, value.summary],
    [{ ...value.summary, draft_sha256: "9".repeat(64) }],
    Array.from({ length: 21 }, () => value.summary),
  ]) {
    const client = new ApiClient(
      token,
      vi.fn<typeof fetch>().mockResolvedValue(Response.json(rows)),
    );
    await expect(
      client.sourceEvidenceReports(value.draft),
    ).rejects.toMatchObject({ status: 0 });
    client.close();
  }
  for (const selected_kinds of [
    ["forest"],
    ["deterministic", "network", "neural"],
    ["deterministic", "forest", "forest"],
  ])
    expect(
      sourceEvidenceSummarySchema.safeParse({
        ...value.summary,
        selected_kinds,
      }).success,
    ).toBe(false);
});
it("disconnect invalidates parent and child requests without accepting stale results", async () => {
  const value = fixture(),
    transport = transportFor(value),
    api = new ApiClient(token, transport);
  api.close();
  await expect(
    api.sourceEvidenceReport(value.draft, value.report.report_id),
  ).rejects.toMatchObject({ name: "AbortError" });
  expect(transport).not.toHaveBeenCalled();
});
