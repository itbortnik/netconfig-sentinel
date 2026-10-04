import { expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./api";
import { explanationBundleSchema } from "./contracts";
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
