import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { patchDraftSchema } from "./patches";
import { deterministicReferenceSchema } from "./deterministicReference";
import controls from "./testdata/sourceDeterministicControls.json";
import {
  runSourceDeterministicRecheckSchema,
  sourceDeterministicBlockers,
  sourceDeterministicSelectionSchema,
  sourceDeterministicSelectionBound,
  sourceDeterministicRecheckSchema,
  sourceDeterministicRecheckBound,
  sourceDeterministicSummarySchema,
} from "./sourceDeterministicRecheck";
import type { SourceDeterministicRecheck } from "./sourceDeterministicRecheck";

const digest = (text: string) =>
  createHash("sha256").update(text).digest("hex");
const fixture = (index = 0) => {
  const item = controls.cases[index]!;
  return {
    draft: patchDraftSchema.parse(item.draft),
    view: sourceDeterministicRecheckSchema.parse(structuredClone(item.view)),
    summary: sourceDeterministicSummarySchema.parse(item.summary),
  };
};
it.each(
  controls.cases.map(
    (row, index) => [row.vendor, row.version, row.cohort, index] as const,
  ),
)(
  "accepts authored saved Python %s/%s/%s controls with exact normative proof",
  async (_vendor, _version, _cohort, index) => {
    const { draft, view, summary } = fixture(index);
    expect(
      await sourceDeterministicRecheckBound(
        view,
        draft,
        view.intent.request,
        summary,
        view.intent.selection,
      ),
    ).toBe(true);
    expect(view.status).toBe("needs_review");
    expect(view.formal_verification).toBe("not_run");
    expect(view.validation_blockers).not.toContain(
      "original_statistical_not_rerun",
    );
  },
);
it.each([
  { approved: true },
  { applied: true },
  { quality_proven: true },
  { calibrated: true },
  { risk_fused: true },
  { formal_verification: "passed" },
  { status: "validated" },
  { validation_blockers: [] },
  { unexpected: true },
])("rejects promotion and projection drift %j", (update) => {
  expect(
    sourceDeterministicRecheckSchema.safeParse({ ...fixture().view, ...update })
      .success,
  ).toBe(false);
});
it("requires explicit nullable reference pin and strict consent", () => {
  const request = fixture().view.intent.request;
  for (const update of [
    { allow_local_analysis_context: "true" },
    { allow_local_analysis_context: 1 },
    { reference_canonical_sha256: undefined },
    { model_id: crypto.randomUUID() },
  ]) {
    expect(
      runSourceDeterministicRecheckSchema.safeParse({ ...request, ...update })
        .success,
    ).toBe(false);
  }
});
it("rejects exact before finding, original report, reference, profile and source binding drift", () => {
  const changes: ((row: SourceDeterministicRecheck) => void)[] = [
    (row) => {
      row.outcome!.report!.before.policy_findings[0]!.title += " changed";
    },
    (row) => {
      row.outcome!.report!.before.reference_findings![0]!.observed = {
        changed: true,
      };
    },
    (row) => {
      row.outcome!.report!.after.reference_findings = null;
    },
    (row) => {
      row.outcome!.report!.reference_projection!.source_sha256 = "b".repeat(64);
    },
    (row) => {
      row.outcome!.report!.after.source_sha256 = "b".repeat(64);
    },
    (row) => {
      row.outcome!.report!.after.peer_findings = null;
    },
    (row) => {
      row.outcome!.report!.policy_catalog_version = "another-catalog";
    },
    (row) => {
      row.intent.after.device_id = crypto.randomUUID();
    },
    (row) => {
      row.intent.selection.before_analysis_sha256 = "b".repeat(64);
    },
    (row) => {
      row.intent.request.reference_canonical_sha256 = null;
    },
    (row) => {
      row.outcome!.report!.comparison_version = "not_selected";
    },
    (row) => {
      row.outcome!.report!.peer_profile_sha256 = null;
    },
    (row) => {
      row.intent.reference_projection!.reference_id = crypto.randomUUID();
    },
    (row) => {
      row.outcome!.report!.policy_changes.resolved = [];
    },
  ];
  for (const change of changes) {
    const { view } = fixture();
    change(view);
    expect(sourceDeterministicRecheckSchema.safeParse(view).success).toBe(
      false,
    );
  }
  const { view } = fixture(2);
  view.outcome!.report!.before.peer_evaluation!.limitations.push(
    "changed history",
  );
  expect(sourceDeterministicRecheckSchema.safeParse(view).success).toBe(false);
});
it.each([0, 5])(
  "rejects resealed invalid reference facts in contract control %s",
  async (index) => {
    const { draft, view } = fixture(index);
    const projection = view.intent.reference_projection!;
    Object.assign(projection.facts[0]!, {
      field: "invented.unknown_field",
      value: { arbitrary: "invalid" },
    });
    view.outcome!.report!.reference_projection = structuredClone(projection);
    view.outcome!.intent_sha256 = digest(stableJson(view.intent));
    const { review_json: _raw, review_sha256: _hash, ...body } = view;
    view.review_json = stableJson(body);
    view.review_sha256 = digest(view.review_json);
    expect(sourceDeterministicRecheckSchema.safeParse(view).success).toBe(
      false,
    );
    const send = transport(view),
      client = new ApiClient("x".repeat(32), send);
    await expect(
      client.sourceDeterministicRecheck(draft, view.recheck_id),
    ).rejects.toThrow();
  },
);
it("enforces version-specific reference values, identities, inventories and canonical order", () => {
  const candidate = fixture(5).view.intent.reference_projection!;
  if (candidate.version !== "expected-config-0.2.0")
    throw new Error("expanded control required");
  const original = candidate;
  const changes: ((row: typeof original) => void)[] = [
    (row) => {
      row.facts = row.facts.filter((f) => f.field !== "management.aaa_enabled");
    },
    (row) => {
      row.facts = row.facts.filter((f) => f.field !== "interface.enabled");
    },
    (row) => {
      row.facts.reverse();
    },
    (row) => {
      row.facts.push(structuredClone(row.facts[0]!));
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "management.ssh_enabled")!,
        { value: null },
      );
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "management.ssh_version")!,
        { value: "3" },
      );
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "interface.present")!,
        { value: false },
      );
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "interface.mode")!,
        { value: "unknown-mode" },
      );
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "interface.addresses")!,
        { value: { invalid: true } },
      );
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "management.snmp_versions")!,
        { value: ["v3", "v1"] },
      );
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "management.snmp_versions")!,
        { value: ["v9"] },
      );
    },
    (row) => {
      row.facts.find((f) => f.field === "interface.present")!.object_key = [
        "Gi0/1",
      ];
    },
    (row) => {
      row.facts.find((f) => f.field === "management.ssh_enabled")!.object_key =
        ["other-device"];
    },
    (row) => {
      row.facts.find((f) => f.field === "interface.present")!.object_key = [
        "Gi\n0/1",
        "",
      ];
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "ospf.present")!,
        { value: true },
      );
    },
    (row) => {
      Object.assign(
        row.facts.find((f) => f.field === "bgp.present")!,
        { value: true },
      );
    },
    (row) => {
      row.facts[0]!.locations.push({
        source_lines: [2, 1],
        raw_text_hash: "b".repeat(64),
        parser_confidence: 1,
      });
    },
  ];
  for (const change of changes) {
    const projection = structuredClone(original);
    change(projection);
    expect(deterministicReferenceSchema.safeParse(projection).success).toBe(
      false,
    );
  }
  const legacy = fixture(0).view.intent.reference_projection!;
  Object.assign(legacy.facts[0]!, { value: { invalid: true } });
  expect(deterministicReferenceSchema.safeParse(legacy).success).toBe(false);
});
it("keeps completed zero findings distinct from an unselected comparator", () => {
  const { view } = fixture(4);
  expect(view.outcome!.report!.before.reference_findings).toBeNull();
  expect(view.outcome!.report!.before.peer_findings).toBeNull();
  view.outcome!.report!.after.reference_findings = [];
  expect(sourceDeterministicRecheckSchema.safeParse(view).success).toBe(false);
});
function terminal(state: "failed" | "pending_unknown", statistical = false) {
  const { view } = fixture(4);
  view.intent.selection.original.statistical_present = statistical;
  view.outcome =
    state === "pending_unknown"
      ? null
      : {
          version: "source-deterministic-outcome-0.1.0",
          recheck_id: view.recheck_id,
          intent_sha256: digest(stableJson(view.intent)),
          completed_at: view.outcome!.completed_at,
          execution_status: "failed",
          report: null,
          failure_reason:
            "original_context_or_deterministic_result_unavailable",
        };
  view.execution_status = state;
  view.validation_blockers = sourceDeterministicBlockers(
    view.intent.selection.original,
    view.outcome,
  );
  const { review_json: _raw, review_sha256: _hash, ...body } = view;
  view.review_json = stableJson(body);
  view.review_sha256 = digest(view.review_json);
  return view;
}
it.each(["failed", "pending_unknown"] as const)(
  "keeps %s explicit without invented report or false ML claim",
  async (state) => {
    const { draft } = fixture(4),
      view = terminal(state, true);
    expect(sourceDeterministicRecheckSchema.safeParse(view).success).toBe(true);
    expect(await sourceDeterministicRecheckBound(view, draft)).toBe(true);
    expect(view.validation_blockers).toContain(
      "original_statistical_not_rerun",
    );
    expect(view.outcome?.report ?? null).toBeNull();
  },
);
it("binds historical profile digest to original Python bytes and rejects forged proof", async () => {
  const { draft, view } = fixture(2);
  expect(
    await sourceDeterministicRecheckBound(
      { ...view, review_sha256: "b".repeat(64) },
      draft,
    ),
  ).toBe(false);
  view.outcome!.report!.peer_profile_sha256 = "b".repeat(64);
  // Preserve every original Python numeric/Unicode token while independently resealing
  // the outer proof. A metadata-looking profile digest must still match its profile.
  const old = controls.cases[2]!.view.outcome!.report!.peer_profile_sha256!;
  view.review_json = view.review_json.replace(
    `"peer_profile_sha256":"${old}"`,
    `"peer_profile_sha256":"${"b".repeat(64)}"`,
  );
  view.review_sha256 = digest(view.review_json);
  expect(sourceDeterministicRecheckSchema.safeParse(view).success).toBe(true);
  expect(await sourceDeterministicRecheckBound(view, draft)).toBe(false);
});
it("binds draft, request, summary and explicit selection without current detector access", async () => {
  const { draft, view, summary } = fixture();
  expect(
    sourceDeterministicSelectionBound(
      view.intent.selection,
      draft,
      crypto.randomUUID(),
    ),
  ).toBe(false);
  expect(
    await sourceDeterministicRecheckBound(view, {
      ...draft,
      draft_sha256: "b".repeat(64),
    }),
  ).toBe(false);
  expect(
    await sourceDeterministicRecheckBound(view, draft, {
      ...view.intent.request,
      reference_canonical_sha256: null,
    }),
  ).toBe(false);
  expect(
    await sourceDeterministicRecheckBound(view, draft, undefined, {
      ...summary,
      before_analysis_id: crypto.randomUUID(),
    }),
  ).toBe(false);
  expect(
    await sourceDeterministicRecheckBound(view, draft, undefined, undefined, {
      ...view.intent.selection,
      before_analysis_sha256: "b".repeat(64),
    }),
  ).toBe(false);
  expect(
    sourceDeterministicSummarySchema.safeParse({
      ...summary,
      completed_at: null,
    }).success,
  ).toBe(false);
});
it("does not round source timestamps or accept stale analysis chronology", () => {
  const { draft, view } = fixture();
  const selection = structuredClone(view.intent.selection);
  selection.before.created_at = selection.before.created_at.replace(
    /(\.\d{5})\d/,
    "$19",
  );
  expect(sourceDeterministicSelectionBound(selection, draft)).toBe(false);
  selection.before_analysis_created_at = "2020-01-01T00:00:00Z";
  expect(sourceDeterministicSelectionSchema.safeParse(selection).success).toBe(
    false,
  );
});
const transport = (value: unknown) =>
  vi.fn(
    async (_url: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(value)),
  );
it("uses authenticated v2 selection/run/detail/list endpoints with explicit original pins", async () => {
  const { draft, view, summary } = fixture(),
    selection = view.intent.selection,
    send = transport(selection),
    client = new ApiClient("x".repeat(32), send);
  expect(
    await client.sourceDeterministicSelection(
      draft,
      selection.before_analysis_id,
    ),
  ).toEqual(selection);
  send.mockResolvedValueOnce(new Response(JSON.stringify(view)));
  expect(
    await client.runSourceDeterministicRecheck(
      draft,
      view.intent.request,
      selection,
    ),
  ).toEqual(view);
  send.mockResolvedValueOnce(new Response(JSON.stringify(view)));
  await client.sourceDeterministicRecheck(
    draft,
    view.recheck_id,
    view.intent.request,
  );
  send.mockResolvedValueOnce(new Response(JSON.stringify([summary])));
  await client.sourceDeterministicRechecks(draft, 20);
  expect(send.mock.calls.map(([url]) => url)).toEqual([
    `/api/v2/patches/${draft.patch_id}/deterministic-selection/${selection.before_analysis_id}`,
    `/api/v2/patches/${draft.patch_id}/deterministic-rechecks`,
    `/api/v2/patches/${draft.patch_id}/deterministic-rechecks/${view.recheck_id}`,
    `/api/v2/patches/${draft.patch_id}/deterministic-rechecks?limit=20&offset=20`,
  ]);
  expect(send.mock.calls[1]![1]).toMatchObject({
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    headers: { Authorization: `Bearer ${"x".repeat(32)}` },
  });
  expect(JSON.parse(send.mock.calls[1]![1]!.body as string)).toEqual(
    view.intent.request,
  );
});
it("refuses absent consent and stale reference before transport and never retries lost POST", async () => {
  const { draft, view } = fixture(),
    selection = view.intent.selection,
    send = transport(view),
    client = new ApiClient("x".repeat(32), send);
  await expect(
    client.runSourceDeterministicRecheck(
      draft,
      { ...view.intent.request, allow_local_analysis_context: false },
      selection,
    ),
  ).rejects.toThrow();
  await expect(
    client.runSourceDeterministicRecheck(
      draft,
      { ...view.intent.request, reference_canonical_sha256: null },
      selection,
    ),
  ).rejects.toThrow();
  expect(send).not.toHaveBeenCalled();
  send.mockRejectedValueOnce(new TypeError("owned lost response"));
  await expect(
    client.runSourceDeterministicRecheck(draft, view.intent.request, selection),
  ).rejects.toThrow();
  expect(send).toHaveBeenCalledTimes(1);
});
