import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { patchDraftSchema } from "./patches";
import {
  sourceDeterministicRecheckSchema,
  sourceDeterministicRecheckBound,
  runSourceDeterministicRecheckSchema,
  policyDiagnosticParseSchema,
  sourcePartialBlockers,
} from "./sourceDeterministicRecheck";
import {
  createSourceEvidenceReportSchema,
  sourceEvidenceReportSchema,
  sourceEvidenceReportBound,
  sourceEvidenceSummarySchema,
} from "./sourceEvidenceReports";
import {
  sourceRiskAssessmentSchema,
  sourceRiskAssessmentBound,
  sourceRiskSummary,
  sourceRiskSummarySchema,
} from "./sourceRiskAssessments";
import {
  sourceEvidenceDecisionSchema,
  sourceEvidenceDecisionBound,
  sourceEvidenceDecisionSummarySchema,
} from "./sourceEvidenceDecisions";
import controls from "./testdata/sourcePartialDiagnosticControls.json";

const digest = (s: string) => createHash("sha256").update(s).digest("hex");
function fixture(index = 0) {
  const raw = structuredClone(controls.cases[index]!);
  const draft = patchDraftSchema.parse(raw.draft),
    diagnostic = sourceDeterministicRecheckSchema.parse(raw.diagnostic),
    report = sourceEvidenceReportSchema.parse(raw.report),
    assessment = sourceRiskAssessmentSchema.parse(raw.assessment);
  if (
    diagnostic.version !== "source-deterministic-recheck-0.2.0" ||
    report.version !== "source-evidence-report-0.5.0" ||
    assessment.version !== "source-risk-assessment-0.3.0"
  )
    throw new Error("Partial fixture protocol differs");
  return {
    raw,
    draft,
    diagnostic,
    report,
    assessment,
    children: {
      deterministic: diagnostic,
      forest: null,
      neural: null,
      network: null,
    },
    decisions: raw.decisions.map((d) => sourceEvidenceDecisionSchema.parse(d)),
  };
}
function seal<T extends { review_json: string; review_sha256: string }>(r: T) {
  const { review_json: _j, review_sha256: _h, ...body } = r;
  r.review_json = stableJson(body);
  r.review_sha256 = digest(r.review_json);
  return r;
}
it.each(
  controls.cases.map(
    (c, i) => [c.vendor, c.partial_side, c.critical_control, i] as const,
  ),
)(
  "validates normative authored %s/%s/critical=%s full immutable chain",
  async (_v, _s, _c, i) => {
    const f = fixture(i);
    expect(await sourceDeterministicRecheckBound(f.diagnostic, f.draft)).toBe(
      true,
    );
    expect(await sourceEvidenceReportBound(f.report, f.draft, f.children)).toBe(
      true,
    );
    expect(
      await sourceRiskAssessmentBound(
        f.assessment,
        f.draft,
        f.report,
        f.children,
      ),
    ).toBe(true);
    for (const d of f.decisions)
      expect(await sourceEvidenceDecisionBound(d, f.report)).toBe(true);
    expect(f.assessment.composition.score).toBeNull();
    expect(f.assessment.composition.band).toBeNull();
    expect(
      f.assessment.composition.components.every(
        (c) => c.effective_weight === 0 && c.contribution === null,
      ),
    ).toBe(true);
    expect(f.assessment.composition.applied_guardrails).toEqual([]);
  },
);
it("requires exact explicit protocol, mode, consent and unavailable contexts", async () => {
  const f = fixture();
  for (const update of [
    { version: undefined },
    { mode: undefined },
    { mode: "complete" },
    { version: "source-deterministic-request-0.1.0" },
    { allow_local_analysis_context: 1 },
    { reference_canonical_sha256: "a".repeat(64) },
  ])
    expect(
      runSourceDeterministicRecheckSchema.safeParse({
        ...f.diagnostic.intent.request,
        ...update,
      }).success,
    ).toBe(false);
  for (const update of [
    { version: "source-evidence-request-0.4.0" },
    { mode: undefined },
    { forest: f.report.request.deterministic },
    { neural: f.report.request.deterministic },
    { network: f.report.request.deterministic },
  ])
    expect(
      createSourceEvidenceReportSchema.safeParse({
        ...f.report.request,
        ...update,
      }).success,
    ).toBe(false);
  const bad = structuredClone(f.diagnostic);
  bad.intent.selection.original.statistical_present = true;
  seal(bad);
  expect(sourceDeterministicRecheckSchema.safeParse(bad).success).toBe(false);
});
it.each(["before", "after"] as const)(
  "binds %s parser diagnostics to the draft and exact source",
  async (side) => {
    const f = fixture(),
      d = structuredClone(f.diagnostic),
      parsed = side === "before" ? "before_parse" : "after_parse";
    d.intent[parsed].summary.confidence = 0.5;
    if (d.outcome?.report)
      d.outcome.report[side].parse.summary.confidence = 0.5;
    d.outcome!.intent_sha256 = digest(stableJson(d.intent));
    seal(d);
    expect(await sourceDeterministicRecheckBound(d, f.draft)).toBe(false);
  },
);
it.each([
  (d: ReturnType<typeof fixture>["diagnostic"]) => {
    d.intent.before_analysis_status = "completed";
  },
  (d: ReturnType<typeof fixture>["diagnostic"]) => {
    d.outcome!.report!.before.policy_findings[0]!.title =
      "Changed original finding";
  },
  (d: ReturnType<typeof fixture>["diagnostic"]) => {
    d.outcome!.report!.after.parse.unknown_locations.push({
      ...d.intent.before_parse.unknown_locations[0]!,
    });
  },
  (d: ReturnType<typeof fixture>["diagnostic"]) => {
    d.validation_blockers.pop();
  },
])(
  "rejects typed nested data drift even after an outer reseal (%#)",
  async (change) => {
    const f = fixture(),
      d = structuredClone(f.diagnostic);
    change(d);
    seal(d);
    expect(await sourceDeterministicRecheckBound(d, f.draft)).toBe(false);
  },
);
it("rejects resealed full joint projection drift against saved diagnostic bytes", async () => {
  const f = fixture(),
    r = structuredClone(f.report);
  r.deterministic.report.after.policy_findings[0]!.title =
    "Fabricated after finding";
  seal(r);
  expect(await sourceEvidenceReportBound(r, f.draft, f.children)).toBe(false);
  const a = structuredClone(f.assessment);
  a.composition.components[0]!.observation!.strongest!.confidence = 0.5;
  a.composition.components[0]!.raw_score = 0.375;
  seal(a);
  expect(
    await sourceRiskAssessmentBound(a, f.draft, f.report, f.children),
  ).toBe(false);
});
it("rejects missing/extra unknown locations, raw fragments, warnings and promotion", () => {
  const f = fixture(),
    p = f.diagnostic.intent.before_parse;
  for (const update of [
    { unknown_locations: [] },
    { unknown_locations: [...p.unknown_locations, ...p.unknown_locations] },
    { locations_truncated: true },
    { raw_text: "untrusted" },
    { parse_warnings: ["untrusted"] },
    {
      unknown_locations: [{ ...p.unknown_locations[0], source_lines: [6, 6] }],
    },
  ])
    expect(
      policyDiagnosticParseSchema.safeParse({ ...p, ...update }).success,
    ).toBe(false);
  for (const update of [
    { approved: true },
    { applied: true },
    { quality_proven: true },
    { status: "validated" },
    { coverage: "supported_complete" },
    { mode: undefined },
  ])
    expect(
      sourceDeterministicRecheckSchema.safeParse({ ...f.diagnostic, ...update })
        .success,
    ).toBe(false);
  for (const update of [
    { score: 0 },
    { band: "low" },
    { status: "completed" },
    { applied_guardrails: [{ kind: "critical_policy", floor: 0.9 }] },
  ])
    expect(
      sourceRiskAssessmentSchema.safeParse({
        ...f.assessment,
        composition: { ...f.assessment.composition, ...update },
      }).success,
    ).toBe(false);
});
it("accepts bounded truncation and preserves failed/pending without synthetic results", async () => {
  const f = fixture(),
    p = f.diagnostic.intent.before_parse;
  expect(
    policyDiagnosticParseSchema.safeParse({
      ...p,
      summary: { ...p.summary, unparsed_count: 257 },
      unknown_locations: Array.from(
        { length: 256 },
        () => p.unknown_locations[0],
      ),
      locations_truncated: true,
    }).success,
  ).toBe(true);
  for (const failed of [false, true]) {
    const d = structuredClone(f.diagnostic);
    d.execution_status = failed ? "failed" : "pending_unknown";
    d.outcome = failed
      ? {
          ...d.outcome!,
          execution_status: "failed",
          report: null,
          failure_reason:
            "original_context_or_deterministic_result_unavailable",
        }
      : null;
    if (d.outcome) d.outcome.intent_sha256 = digest(stableJson(d.intent));
    d.validation_blockers = sourcePartialBlockers(
      d.intent.selection.original,
      d.outcome,
    );
    seal(d);
    expect(await sourceDeterministicRecheckBound(d, f.draft)).toBe(true);
  }
});
it("rejects parent/version/summary crossovers and retains first service role/time", async () => {
  const f = fixture(),
    d = f.decisions[0]!;
  expect(
    await sourceEvidenceDecisionBound(d, {
      ...f.report,
      review_sha256: "f".repeat(64),
    }),
  ).toBe(false);
  expect(
    sourceEvidenceSummarySchema.safeParse({
      version: "source-evidence-summary-0.5.0",
      report_id: f.report.report_id,
      patch_id: f.report.patch_id,
      draft_sha256: f.report.draft_sha256,
      before_analysis_id: f.report.before_analysis_id,
      review_sha256: f.report.review_sha256,
      created_at: f.report.created_at,
      selected_kinds: ["deterministic"],
      status: "needs_review",
    }).success,
  ).toBe(false);
  expect(
    sourceRiskSummarySchema.safeParse({
      ...sourceRiskSummary(f.assessment),
      score: 0,
    }).success,
  ).toBe(false);
  expect(
    sourceEvidenceDecisionSummarySchema.safeParse({
      version: "source-evidence-decision-summary-0.5.0",
      decision_id: d.decision_id,
      patch_id: d.patch_id,
      report_id: d.report_id,
      report_sha256: d.report_sha256,
      decision_sha256: d.decision_sha256,
      created_at: d.created_at,
      verdict: "approved",
      service_role: "engineer",
      individual_identity_verified: false,
      approved: false,
      applied: false,
    }).success,
  ).toBe(false);
});
it("uses saved GET dependencies and recovers a lost POST response with the same ID", async () => {
  const f = fixture(),
    calls: string[] = [];
  const transport = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input);
    calls.push(`${init?.method} ${path}`);
    if (init?.method === "POST") throw new TypeError("fixture lost response");
    if (path.includes("risk-assessments/")) return Response.json(f.assessment);
    if (path.includes("/decisions/")) return Response.json(f.decisions[0]);
    if (path.includes("evidence-reports/")) return Response.json(f.report);
    if (path.includes("deterministic-rechecks/"))
      return Response.json(f.diagnostic);
    return Response.json([]);
  });
  const api = new ApiClient(
    "owned-partial-diagnostic-memory-token-32-chars",
    transport,
  );
  await expect(
    api.runSourceDeterministicRecheck(
      f.draft,
      f.diagnostic.intent.request,
      f.diagnostic.intent.selection,
    ),
  ).rejects.toThrow();
  expect(
    (
      await api.sourceDeterministicRecheck(
        f.draft,
        f.diagnostic.recheck_id,
        f.diagnostic.intent.request,
      )
    ).review_sha256,
  ).toBe(f.diagnostic.review_sha256);
  expect(
    (await api.sourceEvidenceReport(f.draft, f.report.report_id)).review_sha256,
  ).toBe(f.report.review_sha256);
  expect(
    (
      await api.sourceRiskAssessment(
        f.draft,
        f.report,
        f.assessment.assessment_id,
      )
    ).service_role,
  ).toBe(f.assessment.service_role);
  expect(
    (
      await api.sourceEvidenceDecision(
        f.draft,
        f.report,
        f.decisions[0]!.decision_id,
      )
    ).created_at,
  ).toBe(f.decisions[0]!.created_at);
  expect(calls.filter((c) => c.startsWith("POST"))).toHaveLength(1);
  api.close();
});
