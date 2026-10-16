import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { ExplanationPanel } from "./ExplanationPanel";
import {
  ExplanationRequestGate,
  explanationTextDigest,
  groundedExplanationBindingsMatch,
  groundedExplanationCapabilitiesSchema,
  groundedExplanationFacts,
  groundedExplanationFactsSchema,
  groundedExplanationMatches,
  groundedExplanationPresentation,
  groundedExplanationSchema,
} from "./groundedExplanation";
import type { ExplanationRequestScope } from "./groundedExplanation";
import { groundedExplanationFixture } from "./groundedExplanation.fixtures";

it("keeps exact Python JSON bytes authoritative and parses only one facts/presentation authority", async () => {
  const { bundle, facts, analysis, finding, snapshot } =
    await groundedExplanationFixture();
  expect(bundle.source_facts_json).toContain("1e-07");
  expect(stableJson(facts)).toContain("1e-7");
  expect(await explanationTextDigest(stableJson(facts))).not.toBe(
    bundle.facts_binding_sha256,
  );
  expect(groundedExplanationFacts(bundle)).toEqual(facts);
  expect(groundedExplanationPresentation(bundle)?.presentation_kind).toBe(
    "server_derived",
  );
  expect(
    await groundedExplanationMatches(bundle, analysis, finding, snapshot),
  ).toBe(true);
  expect(await groundedExplanationMatches(bundle, analysis, finding)).toBe(
    false,
  );
  expect(
    groundedExplanationSchema.safeParse({ ...bundle, source_facts: facts })
      .success,
  ).toBe(false);
  expect(
    groundedExplanationSchema.safeParse({
      ...bundle,
      presentation: groundedExplanationPresentation(bundle),
    }).success,
  ).toBe(false);
});

it.each([
  { title: "Foreign unsaved title" },
  { device_id: "00000000-0000-0000-0000-000000000099" },
  { severity: "critical" as const },
  { references: ["other#reference"] },
  { evidence: [] },
  { affected_lines: [99] },
])(
  "requires the exact selected saved Finding, not only its reused ID %#",
  async (change) => {
    const { bundle, analysis, finding, snapshot } =
      await groundedExplanationFixture();
    expect(
      await groundedExplanationMatches(
        bundle,
        analysis,
        { ...finding, ...change },
        snapshot,
      ),
    ).toBe(false);
  },
);

it("rejects a selected Finding absent from saved analysis.findings", async () => {
  const { bundle, analysis, finding, snapshot } =
    await groundedExplanationFixture();
  expect(
    await groundedExplanationMatches(
      bundle,
      { ...analysis, findings: [] },
      finding,
      snapshot,
    ),
  ).toBe(false);
});

it.each([
  { version: "model-explanation-0.1.0" },
  { provider: "loopback_language_model" },
  { presentation_kind: "model_prose" },
  { renderer_version: "future" },
  { model_answer: null },
  { approved: true },
  { formal_verification: "passed" },
  { model_alias: "private/path" },
  { source_facts_json: "null" },
  { projection_json: "[]" },
])("rejects unsupported or ambiguous envelope %#", async (change) => {
  const { bundle } = await groundedExplanationFixture();
  expect(
    groundedExplanationSchema.safeParse({ ...bundle, ...change }).success,
  ).toBe(false);
});

it.each([
  { summary: "Free model prose" },
  { fact_refs: ["formal_passed"] },
  { fact_refs: ["selected_finding", "selected_finding"] },
  { fact_refs: ["peer_report"] },
  { recommendation_code: "review_peers" },
  { missing_information_codes: ["peer_selection_bias"] },
  { citations: ["other#source"] },
  { requires_human_review: 1 },
  { requires_human_review: false },
  { patch_draft: "configure terminal" },
  { facts_binding_sha256: "0".repeat(64) },
])("rejects invented choices and model authority %#", async (change) => {
  const { bundle } = await groundedExplanationFixture();
  expect(
    groundedExplanationSchema.safeParse({
      ...bundle,
      model_answer: { ...bundle.model_answer, ...change },
    }).success,
  ).toBe(false);
});

it("rejects duplicate JSON keys, unsupported fact fields and altered semantic document roles", async () => {
  const { bundle, facts } = await groundedExplanationFixture();
  expect(
    groundedExplanationSchema.safeParse({
      ...bundle,
      source_facts_json: bundle.source_facts_json.replace(
        '"phase":',
        '"phase":"hidden","phase":',
      ),
    }).success,
  ).toBe(false);
  expect(
    groundedExplanationSchema.safeParse({
      ...bundle,
      projection_json: bundle.projection_json.replace(
        '"summary":',
        '"summary":"hidden","summary":',
      ),
    }).success,
  ).toBe(false);
  expect(
    groundedExplanationFactsSchema.safeParse({ ...facts, network_safe: true })
      .success,
  ).toBe(false);
  expect(
    groundedExplanationFactsSchema.safeParse({
      ...facts,
      parser: { ...facts.parser, confidence: true },
    }).success,
  ).toBe(false);
  expect(
    groundedExplanationSchema.safeParse({
      ...bundle,
      source_facts_json: stableJson({
        ...facts,
        documents: [{ ...facts.documents[0], role: "supplement" }],
      }),
    }).success,
  ).toBe(false);
  const supplement = {
    ...bundle.documents[0]!,
    section: "telnet-must-be-disabled",
    citation: "docs/policies/management-plane.md#telnet-must-be-disabled",
  };
  const supplementalFacts = {
    ...facts,
    documents: [
      ...facts.documents,
      {
        ...facts.documents[0]!,
        citation: supplement.citation,
        role: "supplement",
      },
    ],
  };
  const expanded = {
    ...bundle,
    retrieval: "semantic_supplement",
    documents: [...bundle.documents, supplement],
    source_facts_json: stableJson(supplementalFacts),
    semantic_retrieval: {
      index_sha256: "0".repeat(64),
      encoder: {
        model_id: "fixture",
        revision: "1".repeat(40),
        files_sha256: "2".repeat(64),
        pipeline_version: "fixture",
        dimensions: 2,
        runtime_versions: ["fixture=1"],
      },
      query_source: "public_detector_metadata",
      query_sha256: "3".repeat(64),
      required_citations: [bundle.documents[0]!.citation],
      matches: [
        {
          citation: supplement.citation,
          content_sha256: supplement.content_sha256,
          cosine_similarity: 0.5,
        },
      ],
    },
  };
  expect(groundedExplanationSchema.safeParse(expanded).success).toBe(true);
  expect(
    groundedExplanationSchema.safeParse({
      ...expanded,
      source_facts_json: stableJson({
        ...supplementalFacts,
        documents: supplementalFacts.documents.map((pin) => ({
          ...pin,
          role: "required",
        })),
      }),
    }).success,
  ).toBe(false);
});

it("detects stale hashes and mismatched selected source, parser, finding, or analysis facts", async () => {
  const { bundle, facts, analysis, finding, snapshot } =
    await groundedExplanationFixture();
  for (const changed of [
    {
      ...bundle,
      facts_binding_sha256: "0".repeat(64),
      model_answer: {
        ...bundle.model_answer,
        facts_binding_sha256: "0".repeat(64),
      },
    },
    { ...bundle, projection_sha256: "0".repeat(64) },
    { ...bundle, model_answer_sha256: "0".repeat(64) },
  ])
    expect(await groundedExplanationBindingsMatch(changed)).toBe(false);
  expect(
    await groundedExplanationMatches(
      bundle,
      { ...analysis, analysis_id: "other" },
      finding,
      snapshot,
    ),
  ).toBe(false);
  expect(
    await groundedExplanationMatches(
      bundle,
      analysis,
      { ...finding, observed: { setting: true } },
      snapshot,
    ),
  ).toBe(false);
  expect(
    await groundedExplanationMatches(
      bundle,
      analysis,
      { ...finding, model_version: "future" },
      snapshot,
    ),
  ).toBe(false);
  expect(
    await groundedExplanationMatches(bundle, analysis, finding, {
      ...snapshot,
      canonical: { ...snapshot.canonical, parser_confidence: 1 },
    }),
  ).toBe(false);
  expect(
    await groundedExplanationMatches(bundle, analysis, finding, {
      ...snapshot,
      canonical: {
        ...snapshot.canonical,
        device: {
          ...snapshot.canonical.device,
          vendor: "juniper",
          platform: "junos",
        },
      },
    }),
  ).toBe(false);
  for (const change of [
    {
      analysis_facts: { ...facts.analysis_facts, analysis_status: "completed" },
    },
    { observed: { ...facts.observed, field_0002: 0 } },
    {
      selection_facts: {
        ...facts.selection_facts,
        reference: { source_sha256: "4".repeat(64), approval: "not_proven" },
      },
    },
  ]) {
    const source_facts_json = stableJson({ ...facts, ...change });
    const facts_binding_sha256 = await explanationTextDigest(source_facts_json);
    const model_answer = { ...bundle.model_answer, facts_binding_sha256 };
    const changed = {
      ...bundle,
      source_facts_json,
      facts_binding_sha256,
      model_answer,
      model_answer_sha256: await explanationTextDigest(
        stableJson(model_answer),
      ),
    };
    expect(
      await groundedExplanationMatches(changed, analysis, finding, snapshot),
    ).toBe(false);
  }
});

it("keeps capability configuration distinct from checked health", () => {
  const value = {
    version: "grounded-explanation-capabilities-0.1.0",
    legacy: {
      version: "explanation-capabilities-0.2.0",
      local_model: "configured",
      model_health_checked: false,
      transport: "literal_loopback_only",
      explicit_request_permission_required: true,
    },
    grounded_explanation: "configured",
    protocol: "grounded-model-explanation-0.1.0",
    model_health_checked: false,
    explicit_request_permission_required: true,
  };
  expect(groundedExplanationCapabilitiesSchema.safeParse(value).success).toBe(
    true,
  );
  expect(
    groundedExplanationCapabilitiesSchema.safeParse({
      ...value,
      model_health_checked: true,
    }).success,
  ).toBe(false);
});

function scope(): ExplanationRequestScope {
  return {
    client: {},
    analysis: {},
    finding: {},
    snapshot: {},
    mode: "legacy",
    retrieval: "explicit_reference",
  };
}
it.each([
  "client",
  "analysis",
  "finding",
  "snapshot",
  "mode",
  "retrieval",
] as const)(
  "resets single-use consent and suppresses stale responses after %s changes",
  (field) => {
    const gate = new ExplanationRequestGate(),
      original = scope();
    gate.bind(original);
    gate.allow(true);
    const request = gate.begin(true)!;
    expect(gate.permission).toBe(false);
    expect(gate.begin(true)).toBeNull();
    const next = {
      ...original,
      [field]:
        field === "mode"
          ? "grounded"
          : field === "retrieval"
            ? "semantic_supplement"
            : {},
    } as ExplanationRequestScope;
    gate.allow(true);
    gate.bind(next);
    expect(gate.permission).toBe(false);
    expect(gate.loading).toBe(false);
    expect(gate.current(request)).toBe(false);
    expect(gate.begin(true)).toBeNull();
    gate.allow(true);
    const current = gate.begin(true)!;
    gate.finish(request);
    expect(gate.loading).toBe(true);
    gate.finish(current);
    expect(gate.loading).toBe(false);
    expect(gate.permission).toBe(false);
  },
);
it("consumes consent on every send and requires a new grant after a failed or completed attempt", () => {
  const gate = new ExplanationRequestGate(),
    selected = scope();
  gate.bind(selected);
  expect(gate.begin(true)).toBeNull();
  gate.allow(true);
  gate.bind({ ...selected });
  expect(gate.permission).toBe(true);
  const sources = gate.begin(false)!;
  expect(gate.permission).toBe(false);
  gate.finish(sources);
  expect(gate.begin(true)).toBeNull();
  gate.allow(true);
  const model = gate.begin(true)!;
  gate.finish(model);
  expect(gate.begin(true)).toBeNull();
  expect(gate.permission).toBe(false);
  gate.invalidate();
  expect(gate.current(model)).toBe(false);
});
it("does not enable model requests or execute markup during initial static rendering", async () => {
  const { analysis, finding, snapshot } = await groundedExplanationFixture();
  const client = new ApiClient("authored-memory-token-with-32-characters");
  const markup = renderToStaticMarkup(
    createElement(ExplanationPanel, {
      analysis,
      finding,
      snapshot,
      client,
      busy: false,
      onError: () => undefined,
    }),
  );
  expect(markup).toContain("Объяснение с источниками");
  expect(markup).not.toContain("Разрешаю передачу");
  expect(markup).not.toContain("<script");
  client.close();
});
