import { expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./api";
import {
  explanationBundleSchema,
  modelExplanationSchema,
  modelDraftSchema,
  explanationCapabilitiesSchema,
} from "./contracts";
import type { ExplanationBundle } from "./contracts";
import { explanationMatches } from "./explanation";

const id = "00000000-0000-0000-0000-000000000001";
const other = "00000000-0000-0000-0000-000000000002";
const token = "test-only-memory-bearer-token-32-characters";
const content = "Review the supported facts.";
const digest = Array.from(
  new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content)),
  ),
  (byte) => byte.toString(16).padStart(2, "0"),
).join("");
const explanation = {
  version: "local-explanation-0.1.0" as const,
  provider: "deterministic_local" as const,
  finding_id: id,
  device_id: id,
  finding_sha256: "a".repeat(64),
  source_sha256: "b".repeat(64),
  detector_version: "policy-rules-0.6.0",
  severity: "high" as const,
  confidence: 1,
  anomaly_score: 1,
  summary: "Review",
  technical_explanation: "Observed fact",
  recommendation: "Check intent",
  anchors: [],
  citations: ["docs/policies/management-plane.md#ssh-must-be-enabled"],
  limitations: ["Scope is limited"],
  formal_verification: "not_run" as const,
  patch_draft: null,
  requires_human_review: true as const,
};
const bundle: ExplanationBundle = {
  version: "finding-context-0.1.0",
  analysis_id: id,
  configuration_id: id,
  device_id: id,
  source_sha256: "b".repeat(64),
  finding_id: id,
  finding_sha256: "a".repeat(64),
  knowledge_version: "project-knowledge-0.1.0",
  knowledge_sha256: "c".repeat(64),
  retrieval: "explicit_reference",
  provider: "deterministic_local",
  llm_status: "unavailable",
  explanation,
  documents: [
    {
      document_id: "docs/policies/management-plane.md",
      document_title: "Management",
      section: "ssh-must-be-enabled",
      section_title: "SSH must be enabled",
      citation: "docs/policies/management-plane.md#ssh-must-be-enabled",
      document_sha256: "d".repeat(64),
      content_sha256: digest,
      content,
      authority: "internal_project_document",
    },
  ],
  limitations: ["No LLM was called"],
};
const analysis = {
  analysis_id: id,
  configuration_id: id,
  device_id: id,
  source_sha256: "b".repeat(64),
  explanations: [explanation],
};
const finding = { finding_id: id };
const answer = {
  summary: "Model draft",
  technical_explanation: "Unverified text",
  recommendation: "Review operational intent",
  possible_impact: ["Hypothesis"],
  assumptions: [],
  missing_information: [],
  citations: [bundle.documents[0]!.citation],
  patch_draft: null,
  requires_human_review: true,
};
const modelBundle = {
  ...bundle,
  version: "model-explanation-0.1.0",
  provider: "loopback_language_model",
  llm_status: "draft",
  privacy_version: "finding-context-redaction-0.1.0",
  context_sha256: "e".repeat(64),
  model_alias: "synthetic-model",
  answer,
};

it("accepts only bound model drafts without changing the original deterministic explanation", async () => {
  const parsed = modelExplanationSchema.parse(modelBundle);
  expect(await explanationMatches(parsed, analysis, finding)).toBe(true);
  expect(
    modelExplanationSchema.safeParse({
      ...modelBundle,
      finding_sha256: "f".repeat(64),
    }).success,
  ).toBe(false);
  expect(
    explanationCapabilitiesSchema.safeParse({
      version: "explanation-capabilities-0.1.0",
      local_model: "configured",
      model_health_checked: false,
      transport: "literal_loopback_only",
      explicit_request_permission_required: true,
    }).success,
  ).toBe(true);
});
it.each([
  { approved: true },
  { risk: 0 },
  { patch_draft: "command" },
  { requires_human_review: false },
  { requires_human_review: 1 },
  { summary: "" },
  { technical_explanation: "hidden\u202etext" },
  { citations: [] },
  { citations: [answer.citations[0], answer.citations[0]] },
  { possible_impact: Array(11).fill("unverified") },
])("rejects unsafe model answer %j", (update) =>
  expect(modelDraftSchema.safeParse({ ...answer, ...update }).success).toBe(
    false,
  ),
);
it.each([
  { llm_status: "verified" },
  { approved: true },
  { provider: "remote" },
  { privacy_version: "unknown" },
  { model_alias: "private/path" },
  { answer: { ...answer, citations: ["outside#source"] } },
])("rejects misleading or unrelated model response %j", (update) =>
  expect(
    modelExplanationSchema.safeParse({ ...modelBundle, ...update }).success,
  ).toBe(false),
);
it("does not accept a model answer exceeding the wire budget or claiming checked health", () => {
  expect(
    modelDraftSchema.safeParse({
      ...answer,
      assumptions: Array(20).fill("x".repeat(2000)),
    }).success,
  ).toBe(false);
  expect(
    explanationCapabilitiesSchema.safeParse({
      version: "explanation-capabilities-0.1.0",
      local_model: "configured",
      model_health_checked: true,
      transport: "literal_loopback_only",
      explicit_request_permission_required: true,
    }).success,
  ).toBe(false);
});
it("model calls use the same-origin binding and explicit permission, never a browser-selected provider URL", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response("{}", { status: 403 }));
  const api = new ApiClient(token, transport);
  const options = {
    analysis_id: id,
    finding_sha256: bundle.finding_sha256,
    provider: "llm" as const,
    allow_local_model_context: true as const,
  };
  await expect(api.explainModel(id, options)).rejects.toBeInstanceOf(ApiError);
  expect(transport.mock.calls[0]![0]).toBe(`/api/v1/findings/${id}/explain`);
  expect(transport.mock.calls[0]![1]?.body).toBe(JSON.stringify(options));
  expect(transport.mock.calls[0]![1]?.credentials).toBe("omit");
  expect(transport.mock.calls[0]![1]?.redirect).toBe("error");
  api.close();
});

it("accepts only the selected analysis, original explanation and exact chunk contents", async () => {
  const parsed = explanationBundleSchema.parse(bundle);
  expect(await explanationMatches(parsed, analysis, finding)).toBe(true);
  for (const field of [
    "analysis_id",
    "configuration_id",
    "device_id",
    "finding_id",
  ] as const)
    expect(
      await explanationMatches(
        { ...parsed, [field]: other },
        analysis,
        finding,
      ),
    ).toBe(false);
  expect(
    await explanationMatches(
      { ...parsed, explanation: { ...parsed.explanation, severity: "low" } },
      analysis,
      finding,
    ),
  ).toBe(false);
  expect(
    await explanationMatches(
      {
        ...parsed,
        documents: [{ ...parsed.documents[0]!, content: "modified" }],
      },
      analysis,
      finding,
    ),
  ).toBe(false);
});

it.each([
  { provider: "llm" },
  { knowledge_version: "project-knowledge-0.2.0" },
  { knowledge_version: "unreviewed-version" },
  { llm_status: "completed" },
  { approved: true },
  { documents: [] },
  { documents: [bundle.documents[0], bundle.documents[0]] },
  {
    documents: [
      { ...bundle.documents[0], citation: "https://outside.invalid" },
    ],
  },
  { documents: [{ ...bundle.documents[0], document_id: "../private.txt" }] },
  { documents: [{ ...bundle.documents[0], content: "я".repeat(4097) }] },
  { explanation: { ...explanation, patch_draft: "configure terminal" } },
  { explanation: { ...explanation, formal_verification: "passed" } },
  { explanation: { ...explanation, finding_sha256: "f".repeat(64) } },
])("rejects unsupported or inconsistent source bundles: %j", (updates) => {
  expect(
    explanationBundleSchema.safeParse({ ...bundle, ...updates }).success,
  ).toBe(false);
});

it("binds current and historical knowledge releases to the recorded detector for both providers", () => {
  const latest = {
    ...bundle,
    knowledge_version: "project-knowledge-0.2.0",
    explanation: { ...explanation, detector_version: "policy-rules-0.7.0" },
  };
  expect(explanationBundleSchema.safeParse(latest).success).toBe(true);
  expect(
    explanationBundleSchema.safeParse({
      ...latest,
      knowledge_version: "project-knowledge-0.1.0",
    }).success,
  ).toBe(false);
  expect(
    modelExplanationSchema.safeParse({
      ...modelBundle,
      knowledge_version: latest.knowledge_version,
      explanation: latest.explanation,
    }).success,
  ).toBe(true);
  expect(
    modelExplanationSchema.safeParse({
      ...modelBundle,
      knowledge_version: "project-knowledge-0.2.0",
    }).success,
  ).toBe(false);
});

it("requests local sources explicitly, without credentials in the body or private error reflection", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(JSON.stringify(bundle)))
    .mockResolvedValueOnce(
      new Response("private-provider-key", { status: 503 }),
    );
  const api = new ApiClient(token, transport);
  const body = {
    analysis_id: id,
    finding_sha256: "a".repeat(64),
    provider: "local" as const,
  };
  expect(await api.explain(id, body)).toEqual(bundle);
  const [url, init] = transport.mock.calls[0]!;
  expect(url).toBe(`/api/v1/findings/${id}/explain`);
  expect(init?.method).toBe("POST");
  expect(init?.body).toBe(JSON.stringify(body));
  expect(init?.body).not.toContain(token);
  expect(init?.credentials).toBe("omit");
  expect(init?.cache).toBe("no-store");
  await expect(api.explain(id, body)).rejects.toBeInstanceOf(ApiError);
  api.close();
});
