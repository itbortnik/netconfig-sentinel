import { expect, it } from "vitest";
import { analysisSchema, findingSchema } from "./contracts";

const device = "00000000-0000-0000-0000-000000000001";
const finding = {
  finding_id: device,
  device_id: device,
  detector: "policy_engine",
  category: "test.rule",
  title: "Test rule",
  severity: "high",
  confidence: 1,
  anomaly_score: 0,
  affected_lines: [1],
  evidence: [],
  observed: {},
  expected: {},
  remediation: null,
  references: [],
  limitations: [],
  model_version: "test-catalog",
};
const explanation = {
  version: "local-explanation-0.1.0",
  provider: "deterministic_local",
  finding_id: device,
  device_id: device,
  finding_sha256: "a".repeat(64),
  source_sha256: "b".repeat(64),
  detector_version: "test-catalog",
  severity: "high",
  confidence: 1,
  anomaly_score: 0,
  summary: "Test",
  technical_explanation: "Test",
  recommendation: "Test",
  anchors: [],
  citations: [],
  limitations: [],
  formal_verification: "not_run",
  patch_draft: null,
  requires_human_review: true,
};
const analysis = {
  version: "analysis-api-0.1.0",
  analysis_id: device,
  configuration_id: device,
  device_id: device,
  source_sha256: "b".repeat(64),
  created_at: "2026-10-02T00:00:00Z",
  status: "partial",
  policy_catalog_version: "test-catalog",
  findings: [finding],
  explanations: [explanation],
  risk: null,
  limitations: [],
};
it("validates a bound partial result without inventing a risk", () => {
  expect(analysisSchema.safeParse(analysis).success).toBe(true);
});
it.each([
  { version: "unsupported" },
  { status: "completed" },
  { device_id: "00000000-0000-0000-0000-000000000002" },
  { source_sha256: "c".repeat(64) },
  { policy_catalog_version: "changed" },
  { explanations: [] },
  { findings: [finding, finding], explanations: [explanation, explanation] },
  { explanations: [{ ...explanation, confidence: 0.2 }] },
  { explanations: [{ ...explanation, formal_verification: "verified" }] },
])("rejects altered or incompatible analysis contracts", (change) => {
  expect(analysisSchema.safeParse({ ...analysis, ...change }).success).toBe(
    false,
  );
});
it("will not present a future ML detector as a current policy finding", () => {
  expect(
    findingSchema.safeParse({ ...finding, detector: "transformer" }).success,
  ).toBe(false);
  expect(findingSchema.safeParse({ ...finding, confidence: 1.1 }).success).toBe(
    false,
  );
});
