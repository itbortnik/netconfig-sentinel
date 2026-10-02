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

const guid = (number: number) =>
  `00000000-0000-0000-0000-${String(number).padStart(12, "0")}`;
const context = {
  reference: null,
  peers: [2, 3, 4].map((number) => ({
    configuration_id: guid(number + 3),
    device_id: guid(number),
    source_sha256: String(number).repeat(64),
    created_at: "2026-10-01T00:00:00Z",
  })),
  peer_baseline: {
    model_version: "peer-baseline-0.1.0",
    group: {
      vendor: "cisco",
      platform: "ios",
      device_role: "edge",
      site_class: "branch",
      service_profile: "internal",
    },
    sample_count: 3,
    consensus_threshold: 0.75,
    features: [],
    unsupported_ratio_median: 0,
    unsupported_ratio_limit: 0.05,
  },
};
const peerFinding = {
  ...finding,
  finding_id: guid(8),
  detector: "peer_baseline",
  model_version: "peer-baseline-0.1.0",
};
const peerExplanation = {
  ...explanation,
  finding_id: guid(8),
  detector_version: "peer-baseline-0.1.0",
};
const hybrid = {
  ...analysis,
  version: "analysis-api-0.2.0",
  status: "completed",
  comparison: context,
  findings: [finding, peerFinding],
  explanations: [explanation, peerExplanation],
  risk: {
    assessment_id: guid(10),
    device_id: device,
    score: 0.8,
    level: "critical",
    model_version: "risk-fusion-0.1.0",
    guardrails: [],
    limitations: [],
    components: [
      "policy",
      "peer_group",
      "statistical",
      "transformer",
      "verification",
    ].map((source, index) => ({
      source,
      status: index < 2 ? "completed" : "unavailable",
      raw_score: index < 2 ? 0.8 : null,
      configured_weight: [0.35, 0.15, 0.1, 0.1, 0.3][index],
      effective_weight: [0.7, 0.3, 0, 0, 0][index],
      finding_ids: index < 2 ? [index === 0 ? device : guid(8)] : [],
    })),
  },
};
it("accepts actual peer completion with normalized weights and immutable inputs", () => {
  expect(analysisSchema.safeParse(hybrid).success).toBe(true);
  expect(
    analysisSchema.safeParse({ ...hybrid, status: "partial", risk: null })
      .success,
  ).toBe(true);
});
it.each([
  { comparison: null },
  { version: "analysis-api-0.1.0" },
  { comparison: { ...context, peers: context.peers.slice(0, 2) } },
  {
    comparison: {
      ...context,
      peers: [context.peers[0], context.peers[0], context.peers[2]],
    },
  },
  {
    comparison: {
      ...context,
      peers: context.peers.map((peer) => ({ ...peer, device_id: device })),
    },
  },
  {
    risk: {
      ...hybrid.risk,
      components: hybrid.risk.components.map((part) => ({
        ...part,
        effective_weight: 0,
      })),
    },
  },
  {
    risk: {
      ...hybrid.risk,
      components: hybrid.risk.components.map((part) => ({
        ...part,
        finding_ids: [],
      })),
    },
  },
  {
    findings: [
      finding,
      {
        ...peerFinding,
        detector: "expected_configuration",
        model_version: "expected-config-0.1.0",
      },
    ],
  },
])("rejects incompatible extended comparison results", (change) => {
  expect(analysisSchema.safeParse({ ...hybrid, ...change }).success).toBe(
    false,
  );
});
