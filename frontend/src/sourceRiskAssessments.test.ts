import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { patchDraftSchema } from "./patches";
import { sourceEvidenceReportSchema } from "./sourceEvidenceReports";
import { sourceDeterministicRecheckSchema } from "./sourceDeterministicRecheck";
import { sourceForestRecheckSchema } from "./sourceForestRecheck";
import { sourceMlRecheckSchema } from "./sourceMlRecheck";
import { sourcePatchVerificationSchema } from "./sourcePatchVerification";
import {
  createSourceRiskAssessmentSchema,
  sourceRiskAssessmentSchema,
  sourceRiskAssessmentBound,
  sourceRiskProofMatches,
  sourceRiskSummarySchema,
  sourceRiskSummaryBound,
} from "./sourceRiskAssessments";
import type { SourceRiskAssessment } from "./sourceRiskAssessments";
import controls from "./testdata/sourceRiskControls.json";
import parents from "./testdata/sourceDirectionControls.json";
const token = "test-only-risk-memory-bearer-token-32-characters";
const digest = (s: string) => createHash("sha256").update(s).digest("hex");
function fixture(index = 0) {
  const risk = structuredClone(controls.cases[index]!),
    p = parents.cases.find((p) => p.name === risk.source_direction_case)!;
  return {
    assessment: sourceRiskAssessmentSchema.parse(risk.assessment),
    request: createSourceRiskAssessmentSchema.parse(risk.request),
    summary: sourceRiskSummarySchema.parse(risk.summary),
    draft: patchDraftSchema.parse(p.draft),
    parent: sourceEvidenceReportSchema.parse(p.report),
    children: {
      deterministic: sourceDeterministicRecheckSchema.parse(
        p.children.deterministic,
      ),
      forest: p.children.forest
        ? sourceForestRecheckSchema.parse(p.children.forest)
        : null,
      neural: p.children.neural
        ? sourceMlRecheckSchema.parse(p.children.neural)
        : null,
      network: p.children.network
        ? sourcePatchVerificationSchema.parse(p.children.network)
        : null,
    },
  };
}
function seal(row: SourceRiskAssessment) {
  const { review_json: _json, review_sha256: _hash, ...body } = row;
  row.review_json = stableJson(body);
  row.review_sha256 = digest(row.review_json);
  return row;
}
function transportFor(
  f: ReturnType<typeof fixture>,
  options: {
    parentStatus?: number;
    childStatus?: number;
    row?: SourceRiskAssessment;
    list?: unknown[];
  } = {},
) {
  return vi.fn<typeof fetch>().mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes("/risk-assessments"))
      return new Response(
        JSON.stringify(
          url.includes("?")
            ? (options.list ?? [f.summary])
            : (options.row ?? f.assessment),
        ),
      );
    if (url.endsWith(`/evidence-reports/${f.parent.report_id}`))
      return new Response(JSON.stringify(f.parent), {
        status: options.parentStatus ?? 200,
      });
    for (const [kind, child] of Object.entries(f.children)) {
      if (
        child &&
        url.includes(
          {
            deterministic: "/deterministic-rechecks/",
            forest: "/statistical-rechecks/",
            neural: "/ml-rechecks/",
            network: "/verifications/",
          }[kind]!,
        )
      )
        return new Response(JSON.stringify(child), {
          status: options.childStatus ?? 200,
        });
    }
    throw new Error(`Unexpected URL ${url}`);
  });
}
for (const [index, c] of controls.cases.entries())
  it(`binds normative ${c.source_direction_case} to exact complete retained children`, async () => {
    const f = fixture(index);
    expect(await sourceRiskProofMatches(f.assessment)).toBe(true);
    expect(sourceRiskSummaryBound(f.summary, f.parent)).toBe(true);
    expect(
      await sourceRiskAssessmentBound(
        f.assessment,
        f.draft,
        f.parent,
        f.children,
        f.request,
        f.summary,
      ),
    ).toBe(true);
    expect(f.parent.risk_fused).toBe(false);
  });
it("keeps loss and mixed adverse while gain/unknown/legacy remain unavailable", () => {
  for (const [i, c] of controls.cases.entries()) {
    const f = fixture(i),
      n = f.assessment.composition.components[4]!;
    expect(n.raw_score).toBe(
      ["loss", "mixed_equal_counts", "metadata_unavailable"].includes(
        c.source_direction_case,
      )
        ? 1
        : null,
    );
    if (n.raw_score !== null) expect(f.assessment.composition.score).toBe(0.95);
  }
});
it("rejects unknown fields, duplicate/missing components, non-finite and coercible numbers, flags and profile", () => {
  const f = fixture();
  for (const mutate of [
    (r: SourceRiskAssessment) => {
      Object.assign(r, { extra: true });
    },
    (r: SourceRiskAssessment) => {
      r.approved = true as false;
    },
    (r: SourceRiskAssessment) => {
      r.composition.components.pop();
    },
    (r: SourceRiskAssessment) => {
      r.composition.components[1] = r.composition.components[0]!;
    },
    (r: SourceRiskAssessment) => {
      r.composition.components[0]!.raw_score = NaN;
    },
    (r: SourceRiskAssessment) => {
      r.composition.components[0]!.configured_weight =
        "0.35" as unknown as number;
    },
    (r: SourceRiskAssessment) => {
      r.composition.profile_version = "other" as never;
    },
  ]) {
    const row = structuredClone(f.assessment);
    mutate(row);
    expect(sourceRiskAssessmentSchema.safeParse(row).success).toBe(false);
  }
});
it("rejects resealed self-consistent observations that contradict actual child findings", async () => {
  const f = fixture(),
    r = structuredClone(f.assessment),
    o = r.composition.components[0]!.observation;
  expect(o?.kind).toBe("findings");
  if (o?.kind !== "findings" || !o.strongest) throw Error();
  o.strongest.finding_id = "00000000-0000-4000-8000-000000000001";
  seal(r);
  expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(true);
  expect(await sourceRiskProofMatches(r)).toBe(true);
  expect(
    await sourceRiskAssessmentBound(r, f.draft, f.parent, f.children),
  ).toBe(false);
});
it("rejects resealed neural semantic/model substitutions even when arithmetic stays valid", async () => {
  const f = fixture();
  for (const key of ["classes", "target_semantics", "model_sha256"] as const) {
    const r = structuredClone(f.assessment),
      o = r.composition.components[3]!.observation;
    if (o?.kind !== "neural") throw Error();
    if (key === "classes") o.classes = ["unobserved_class"];
    else if (key === "target_semantics")
      o.target_semantics = "confirmed_anomaly";
    else o.model_sha256 = "f".repeat(64);
    seal(r);
    expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(true);
    expect(
      await sourceRiskAssessmentBound(r, f.draft, f.parent, f.children),
    ).toBe(false);
  }
});
it("rejects resealed Forest numeric metadata, even if all derived zero inlier values remain consistent", async () => {
  const f = fixture(),
    r = structuredClone(f.assessment),
    o = r.composition.components[2]!.observation;
  if (o?.kind !== "forest") throw Error();
  o.model_id = "00000000-0000-4000-8000-000000000001";
  seal(r);
  expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(true);
  expect(
    await sourceRiskAssessmentBound(r, f.draft, f.parent, f.children),
  ).toBe(false);
});
it("rejects wrong parent, role, timestamp, summary and request bindings", async () => {
  const f = fixture();
  for (const mutate of [
    (r: SourceRiskAssessment) => {
      r.service_role = "reader" as never;
    },
    (r: SourceRiskAssessment) => {
      r.created_at = "2000-01-01T00:00:00Z";
    },
    (r: SourceRiskAssessment) => {
      r.request.assessment_id = "00000000-0000-4000-8000-000000000001";
    },
    (r: SourceRiskAssessment) => {
      r.report_sha256 = "f".repeat(64);
    },
  ]) {
    const r = seal(mutateRow(f.assessment, mutate));
    expect(
      await sourceRiskAssessmentBound(
        r,
        f.draft,
        f.parent,
        f.children,
        f.request,
        f.summary,
      ),
    ).toBe(false);
  }
  const summary = { ...f.summary, service_role: "admin" as const };
  expect(
    await sourceRiskAssessmentBound(
      f.assessment,
      f.draft,
      f.parent,
      f.children,
      f.request,
      summary,
    ),
  ).toBe(false);
});
function mutateRow(
  row: SourceRiskAssessment,
  mutate: (r: SourceRiskAssessment) => void,
) {
  const r = structuredClone(row);
  mutate(r);
  return r;
}
it("rejects proof byte changes, duplicate JSON keys and exact retained field rounding", async () => {
  const f = fixture();
  let r = structuredClone(f.assessment);
  r.review_json += " ";
  expect(await sourceRiskProofMatches(r)).toBe(false);
  r = structuredClone(f.assessment);
  r.review_json = r.review_json.replace("{", '{"approved":false,');
  r.review_sha256 = digest(r.review_json);
  expect(await sourceRiskProofMatches(r)).toBe(false);
  r = structuredClone(f.assessment);
  const o = r.composition.components[3]!.observation;
  if (o?.kind !== "neural") throw Error();
  o.anomaly_score! += 1e-13;
  seal(r);
  expect(
    await sourceRiskAssessmentBound(r, f.draft, f.parent, f.children),
  ).toBe(false);
});
it("validates API POST/read/list with refetched parent and children", async () => {
  const f = fixture(),
    transport = transportFor(f),
    api = new ApiClient(token, transport);
  expect(
    await api.createSourceRiskAssessment(f.draft, f.parent, f.request),
  ).toEqual(f.assessment);
  expect(
    await api.sourceRiskAssessment(
      f.draft,
      f.parent,
      f.assessment.assessment_id,
      f.request,
      f.summary,
    ),
  ).toEqual(f.assessment);
  expect(await api.sourceRiskAssessments(f.parent, 20)).toEqual([f.summary]);
  expect(
    transport.mock.calls.some(([url]) =>
      String(url).endsWith("risk-assessments?limit=20&offset=20"),
    ),
  ).toBe(true);
  expect(
    transport.mock.calls.filter(([, init]) => init?.method === "POST"),
  ).toHaveLength(1);
  api.close();
});
for (const kind of ["parentStatus", "childStatus"] as const)
  it(`keeps post uncertainty when ${kind} GET is refused`, async () => {
    const f = fixture(),
      transport = transportFor(f, { [kind]: 403 }),
      api = new ApiClient(token, transport);
    await expect(
      api.createSourceRiskAssessment(f.draft, f.parent, f.request),
    ).rejects.toMatchObject({ status: 0 });
    api.close();
  });
it("rejects wrong read identity and duplicate/unbound history", async () => {
  const f = fixture();
  let api = new ApiClient(token, transportFor(f));
  await expect(
    api.sourceRiskAssessment(
      f.draft,
      f.parent,
      "00000000-0000-4000-8000-000000000001",
    ),
  ).rejects.toMatchObject({ status: 0 });
  api.close();
  api = new ApiClient(token, transportFor(f, { list: [f.summary, f.summary] }));
  await expect(api.sourceRiskAssessments(f.parent)).rejects.toMatchObject({
    status: 0,
  });
  api.close();
});
it("rejects oversized Unicode proof by byte budget and expired/disconnected clients", async () => {
  const f = fixture(),
    r = structuredClone(f.assessment);
  r.review_json = "Я".repeat(600000);
  expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(false);
  let release!: (r: Response) => void;
  const transport = vi.fn<typeof fetch>().mockReturnValue(
      new Promise((resolve) => {
        release = resolve;
      }),
    ),
    api = new ApiClient(token, transport),
    request = api.sourceRiskAssessment(
      f.draft,
      f.parent,
      f.assessment.assessment_id,
    );
  api.close();
  release(new Response(JSON.stringify(f.assessment)));
  await expect(request).rejects.toMatchObject({ name: "AbortError" });
});

it("partial coverage preserves adverse observations and guards but suppresses every aggregate field", () => {
  const r = fixture().assessment,
    c = r.composition;
  c.coverage = "partial";
  c.candidate_parser_confidence = 0.8;
  c.status = "unavailable";
  c.score = null;
  c.band = null;
  c.applied_guardrails = [];
  for (const component of c.components) {
    component.effective_weight = 0;
    component.contribution = null;
    if (component.observation?.kind === "forest")
      component.observation.candidate_parser_confidence = 0.8;
  }
  expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(true);
  expect(c.applicable_guardrails).toEqual([
    { kind: "observed_scoped_loss", floor: 0.95 },
  ]);
  c.components[0]!.contribution = 0;
  expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(false);
});
it("critical policy guard is independent of the strongest noncritical finding", () => {
  const r = fixture().assessment,
    c = r.composition,
    o = c.components[0]!.observation;
  if (o?.kind !== "findings") throw Error();
  o.critical_policy_present = true;
  c.applicable_guardrails = [
    { kind: "critical_policy", floor: 0.9 },
    ...c.applicable_guardrails,
  ];
  c.applied_guardrails = [...c.applicable_guardrails];
  expect(o.strongest?.severity).toBe("high");
  expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(true);
  c.applicable_guardrails.shift();
  expect(sourceRiskAssessmentSchema.safeParse(r).success).toBe(false);
});
