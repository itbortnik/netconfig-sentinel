import { createHash } from "node:crypto";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { stableJson } from "./contracts";
import { IngressScopeView } from "./IngressScopeView";
import {
  batfishScopeExecutionSchema,
  ingressScopeLimitations,
  ingressScopeProofMatches,
  ingressScopeSchema,
} from "./ingressScope";
import type { IngressScope } from "./ingressScope";
import directionControls from "./testdata/sourceDirectionControls.json";
import {
  sourcePatchVerificationSchema,
  sourceVerificationBound,
} from "./sourcePatchVerification";
import { patchDraftSchema } from "./patches";
import normativeControls from "./testdata/sourceIngressControls.json";
import { sourceDeterministicRecheckSchema } from "./sourceDeterministicRecheck";
import { sourceForestRecheckSchema } from "./sourceForestRecheck";
import { sourceMlRecheckSchema } from "./sourceMlRecheck";
import {
  sourceEvidenceReportBound,
  sourceEvidenceReportSchema,
} from "./sourceEvidenceReports";
import {
  sourceEvidenceDecisionBound,
  sourceEvidenceDecisionSchema,
} from "./sourceEvidenceDecisions";
import {
  sourceRiskAssessmentBound,
  sourceRiskAssessmentSchema,
} from "./sourceRiskAssessments";

// Authored software controls exercise the browser trust boundary; no SDK or engine runs here.
const digest = (s: string) => createHash("sha256").update(s).digest("hex");
function observation(
  name = "GigabitEthernet0/1",
  change: Record<string, unknown> = {},
) {
  const node =
    directionControls.cases[0]!.network!.intent.request.scope.start_node;
  const source_ip_rendering = "<script>owned opaque IP text & empty</script>";
  return {
    node,
    interface: name,
    canonical_id_sha256: digest(
      stableJson({
        version: "ingress-location-0.1.0",
        kind: "interface",
        node,
        interface: name,
      }),
    ),
    location_rendering: `InterfaceLocation{nodeName=${node}, interfaceName=${name}}`,
    active: true,
    switchport: false,
    interface_type: "PHYSICAL",
    concrete_ipv4_prefixes: ["192.0.2.10/24"],
    eligible: true,
    eligibility_reason: "active_concrete_ipv4",
    source_ip_rendering,
    source_ip_sha256: digest(source_ip_rendering),
    ...change,
  };
}
function scope() {
  const result =
    directionControls.cases[0]!.network!.outcome!.network_execution!.result;
  const row = observation();
  return ingressScopeSchema.parse({
    version: "ingress-scope-0.1.0",
    before_sha256: result.before_sha256,
    after_sha256: result.after_sha256,
    scope: result.scope,
    network_name: "sentinel-" + "1".repeat(32),
    acquisition_state: "observed",
    reason: "query_completed",
    before: { interfaces: [row] },
    after: { interfaces: [row] },
    eligibility_complete: true,
    selected_before_only: [],
    selected_after_only: [],
    common_eligible: [row.canonical_id_sha256],
    before_eligible_only: [],
    after_eligible_only: [],
    after_common_assignments: [
      {
        canonical_id_sha256: row.canonical_id_sha256,
        source_ip_rendering: row.source_ip_rendering,
        source_ip_sha256: row.source_ip_sha256,
      },
    ],
    semantic_ip_sets_verified: false,
    complete_flow_coverage: false,
    source_assignment_context: "after",
    method: "selected-interface-concrete-ipv4-origination-0.1.0",
    limitations: ingressScopeLimitations,
  });
}
function unknown(
  base: IngressScope,
  reason: "query_failed" | "cleanup_unconfirmed" = "query_failed",
) {
  return ingressScopeSchema.parse({
    ...base,
    acquisition_state: "unknown",
    reason,
    before: null,
    after: null,
    eligibility_complete: null,
    selected_before_only: null,
    selected_after_only: null,
    common_eligible: null,
    before_eligible_only: null,
    after_eligible_only: null,
    after_common_assignments: null,
  });
}
function execution(ingress_scope = scope()) {
  return batfishScopeExecutionSchema.parse({
    ...directionControls.cases[0]!.network!.outcome!.network_execution,
    version: "batfish-execution-0.4.0",
    ingress_scope,
    result: {
      ...directionControls.cases[0]!.network!.outcome!.network_execution!
        .result,
      network_name: ingress_scope.network_name,
    },
  });
}
it("validates independent identity and opaque rendering hashes", async () => {
  const s = scope();
  expect(await ingressScopeProofMatches(s)).toBe(true);
  for (const field of ["canonical_id_sha256", "source_ip_sha256"] as const) {
    const forged = structuredClone(s);
    forged.before!.interfaces[0]![field] = "f".repeat(64);
    expect(await ingressScopeProofMatches(forged)).toBe(false);
  }
});
it("preserves unknown physical JunOS eligibility while keeping selected additions/removals known", () => {
  const s = scope(),
    parent = observation("ge-0/0/0", {
      concrete_ipv4_prefixes: [],
      eligible: null,
      eligibility_reason: "no_concrete_ipv4",
    });
  const before = { interfaces: [parent] },
    after = { interfaces: [] };
  const result = ingressScopeSchema.parse({
    ...s,
    before,
    after,
    eligibility_complete: false,
    selected_before_only: [parent.canonical_id_sha256],
    common_eligible: null,
    before_eligible_only: null,
    after_eligible_only: null,
    after_common_assignments: null,
  });
  expect(result.selected_before_only).toHaveLength(1);
  expect(result.common_eligible).toBeNull();
  expect(
    ingressScopeSchema.safeParse({ ...result, common_eligible: [] }).success,
  ).toBe(false);
  expect(
    ingressScopeSchema.safeParse({ ...result, eligibility_complete: true })
      .success,
  ).toBe(false);
});
it("recomputes eligibility for shutdown and switchport without interpreting opaque source IP text", () => {
  const s = scope(),
    row = s.after!.interfaces[0]!;
  const stopped = {
    ...row,
    active: false,
    eligible: false,
    eligibility_reason: "inactive",
  };
  const next = {
    ...s,
    after: { interfaces: [stopped] },
    common_eligible: [],
    before_eligible_only: [row.canonical_id_sha256],
    after_common_assignments: [],
  };
  expect(ingressScopeSchema.safeParse(next).success).toBe(true);
  expect(
    ingressScopeSchema.safeParse({
      ...next,
      common_eligible: [row.canonical_id_sha256],
    }).success,
  ).toBe(false);
  expect(
    ingressScopeSchema.safeParse({
      ...s,
      after: {
        interfaces: [
          {
            ...row,
            concrete_ipv4_prefixes: [],
            eligible: false,
            eligibility_reason: "no_concrete_ipv4",
            source_ip_rendering: "empty",
            source_ip_sha256: digest("empty"),
          },
        ],
      },
    }).success,
  ).toBe(false);
});
it("rejects derived forgeries, duplicate rows, unsupported names, coercion, false promotion and byte overruns", () => {
  const s = scope();
  for (const change of [
    { common_eligible: [] },
    { selected_after_only: ["f".repeat(64)] },
    { after_common_assignments: [] },
    { semantic_ip_sets_verified: 0 },
    { complete_flow_coverage: true },
    { unexpected: true },
    {
      before: {
        interfaces: [s.before!.interfaces[0], s.before!.interfaces[0]],
      },
    },
    {
      after: {
        interfaces: [{ ...s.after!.interfaces[0], interface: "x] | .*" }],
      },
    },
    { after: { interfaces: [{ ...s.after!.interfaces[0], active: "true" }] } },
    {
      after: {
        interfaces: [
          { ...s.after!.interfaces[0], source_ip_rendering: "я".repeat(2049) },
        ],
      },
    },
    {
      after: {
        interfaces: [
          { ...s.after!.interfaces[0], source_ip_rendering: "one\ntwo" },
        ],
      },
    },
    {
      after: {
        interfaces: [
          {
            ...s.after!.interfaces[0],
            concrete_ipv4_prefixes: ["192.0.2.010/24"],
          },
        ],
      },
    },
  ])
    expect(ingressScopeSchema.safeParse({ ...s, ...change }).success).toBe(
      false,
    );
  expect(
    ingressScopeSchema.safeParse({
      ...s,
      before: {
        interfaces: Array.from({ length: 257 }, () => s.before!.interfaces[0]),
      },
    }).success,
  ).toBe(false);
});
it("binds the whole execution scope and preserves valid loss when acquisition failed", () => {
  const e = execution(unknown(scope()));
  expect(e.reachability_impact.direction).toBe("loss_found");
  for (const change of [
    { network_name: null },
    { before_sha256: "f".repeat(64) },
    { scope: { ...e.result.scope, start_node: "other" } },
    { acquisition_state: "not_observed", reason: "not_run" },
  ]) {
    expect(
      batfishScopeExecutionSchema.safeParse({
        ...e,
        ingress_scope: { ...e.ingress_scope, ...change },
      }).success,
    ).toBe(false);
  }
});
it("validates source v4 proof without reinterpreting the legacy record", async () => {
  const control = structuredClone(directionControls.cases[0]!);
  const old = sourcePatchVerificationSchema.parse(control.network);
  const intent = {
    ...old.intent,
    version: "source-patch-intent-0.4.0",
    request: { ...old.intent.request, version: "source-patch-request-0.4.0" },
  };
  const outcome = {
    ...old.outcome,
    version: "source-patch-outcome-0.4.0",
    network_execution: execution(),
    intent_sha256: digest(stableJson(intent)),
  };
  const { review_json: _json, review_sha256: _sha, ...body } = old;
  const value = {
    ...body,
    version: "source-patch-verification-0.4.0",
    intent,
    outcome,
  };
  const review_json = stableJson(value),
    parsed = sourcePatchVerificationSchema.parse({
      ...value,
      review_json,
      review_sha256: digest(review_json),
    });
  expect(
    await sourceVerificationBound(
      parsed,
      patchDraftSchema.parse(control.draft),
    ),
  ).toBe(true);
  expect(
    sourcePatchVerificationSchema.safeParse({
      ...parsed,
      version: "source-patch-verification-0.3.0",
    }).success,
  ).toBe(false);
  expect(old.version).toBe("source-patch-verification-0.3.0");
});
it("renders observations as escaped text and never renders unknown as zero", () => {
  const html = renderToStaticMarkup(
    createElement(IngressScopeView, { scope: scope() }),
  );
  expect(html).toContain("&lt;script&gt;");
  expect(html).not.toContain("<script>");
  const missing = renderToStaticMarkup(
    createElement(IngressScopeView, { scope: unknown(scope()) }),
  );
  expect(missing).toContain("неизвестно");
  expect(missing).not.toContain("Выбрано интерфейсов до: 0");
});

function normative(index = 0) {
  const record = normativeControls.cases[index]!,
    parent = directionControls.cases.find(
      (c) => c.name === record.case_ref.name,
    )!;
  return {
    source: sourcePatchVerificationSchema.parse(record.source4),
    report: sourceEvidenceReportSchema.parse(record.report4),
    decision: sourceEvidenceDecisionSchema.parse(record.decision4),
    risk: sourceRiskAssessmentSchema.parse(record.risk2),
    draft: patchDraftSchema.parse(parent.draft),
    children: {
      deterministic: sourceDeterministicRecheckSchema.parse(
        parent.children.deterministic,
      ),
      forest: parent.children.forest
        ? sourceForestRecheckSchema.parse(parent.children.forest)
        : null,
      neural: parent.children.neural
        ? sourceMlRecheckSchema.parse(parent.children.neural)
        : null,
      network: sourcePatchVerificationSchema.parse(record.source4),
    },
  };
}
for (const [index, control] of normativeControls.cases.entries())
  it(`binds server-produced ${control.name} bytes across the complete versioned chain`, async () => {
    const n = normative(index);
    expect(await sourceVerificationBound(n.source, n.draft)).toBe(true);
    expect(await sourceEvidenceReportBound(n.report, n.draft, n.children)).toBe(
      true,
    );
    expect(await sourceEvidenceDecisionBound(n.decision, n.report)).toBe(true);
    expect(
      await sourceRiskAssessmentBound(n.risk, n.draft, n.report, n.children),
    ).toBe(true);
    if (control.name === "loss_unknown") {
      expect(n.risk.composition.components[4]!.raw_score).toBe(1);
      expect(n.risk.composition.score).toBe(0.95);
    }
  });
it("rejects a resealed internally consistent scope substituted for the full immutable child", async () => {
  const n = normative(),
    forged = structuredClone(n.report);
  if (
    !forged.network ||
    !("ingress_scope" in forged.network) ||
    !forged.network.ingress_scope.after
  )
    throw new Error("Expected observed control");
  forged.network.ingress_scope.after.interfaces[0]!.source_ip_rendering =
    "opaque substituted value";
  forged.network.ingress_scope.after.interfaces[0]!.source_ip_sha256 = digest(
    "opaque substituted value",
  );
  const id =
    forged.network.ingress_scope.after.interfaces[0]!.canonical_id_sha256;
  for (const a of forged.network.ingress_scope.after_common_assignments ?? [])
    if (a.canonical_id_sha256 === id) {
      a.source_ip_rendering = "opaque substituted value";
      a.source_ip_sha256 = digest(a.source_ip_rendering);
    }
  const { review_json: _json, review_sha256: _sha, ...body } = forged;
  forged.review_json = stableJson(body);
  forged.review_sha256 = digest(forged.review_json);
  expect(sourceEvidenceReportSchema.safeParse(forged).success).toBe(true);
  expect(await sourceEvidenceReportBound(forged, n.draft, n.children)).toBe(
    false,
  );
});
it("keeps risk .2 and composition .2 strictly coupled to report .4", () => {
  const n = normative();
  expect(
    sourceRiskAssessmentSchema.safeParse({
      ...n.risk,
      version: "source-risk-assessment-0.1.0",
    }).success,
  ).toBe(false);
  expect(
    sourceRiskAssessmentSchema.safeParse({
      ...n.risk,
      report_version: "source-evidence-report-0.3.0",
    }).success,
  ).toBe(false);
  expect(
    sourceRiskAssessmentSchema.safeParse({
      ...n.risk,
      composition: {
        ...n.risk.composition,
        version: "source-priority-composition-0.1.0",
      },
    }).success,
  ).toBe(false);
});
