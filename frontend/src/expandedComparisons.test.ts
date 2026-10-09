import { expect, it } from "vitest";
import { analysisSchema } from "./contracts";
import {
  expandedPeerFields,
  expandedPeerBaselineSchema,
} from "./expandedComparisons";
import { comparisonOptions } from "./comparison";

const id = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const peers = [2, 3, 4].map((n) => ({
  configuration_id: id(n + 10),
  device_id: id(n),
  source_sha256: String(n).repeat(64),
  created_at: "2026-10-01T01:00:00Z",
}));
const booleans = new Set([
  "management.ssh_enabled",
  "management.telnet_enabled",
  "management.aaa_enabled",
  "bgp.present",
  "bgp.router_id_configured",
  "ospf.present",
]);
const profile = {
  model_version: "peer-baseline-0.2.0",
  group: {
    vendor: "cisco",
    platform: "ios",
    device_role: "edge",
    site_class: "branch",
    service_profile: "owned",
  },
  sample_count: 3,
  samples: peers.map((peer, index) => ({
    hostname: `peer-${index}`,
    source_sha256: peer.source_sha256,
    collected_at: "2026-10-01T00:00:00Z",
  })),
  consensus_threshold: 0.75,
  features: [...expandedPeerFields].sort().map((field) => ({
    field,
    expected: booleans.has(field)
      ? false
      : field === "management.ssh_version" || field === "bgp.local_as"
        ? null
        : [],
    support_count: 3,
    sample_count: 3,
  })),
  omitted_features: [],
  unsupported_ratio_median: 0,
  unsupported_ratio_limit: 0.05,
};
const report = {
  version: "peer-comparison-report-0.2.0",
  device_id: id(1),
  source_sha256: "b".repeat(64),
  baseline_sha256: "a".repeat(64),
  status: "partial",
  unsupported_ratio: 0.01,
  profile_features: profile.features.map((item) => item.field),
  compared_features: [],
  skipped_features: profile.features.map((item) => item.field),
  findings: [],
  limitations: ["Properties were skipped."],
};
const result = {
  version: "analysis-api-0.4.0",
  analysis_id: id(20),
  configuration_id: id(21),
  device_id: id(1),
  source_sha256: "b".repeat(64),
  created_at: "2026-10-02T00:00:00Z",
  status: "partial",
  policy_catalog_version: "policy-rules-0.7.0",
  findings: [],
  explanations: [],
  risk: null,
  limitations: ["Owned software fixture, not detector quality."],
  statistical: null,
  comparison: {
    version: "comparison-context-0.2.0",
    reference: null,
    peers,
    peer_baseline: profile,
    peer_evaluation: report,
  },
};

it("retains an empty partial report rather than claiming all properties matched", () => {
  const parsed = analysisSchema.parse(result);
  expect(parsed.version).toBe("analysis-api-0.4.0");
  expect(
    parsed.comparison &&
      "peer_evaluation" in parsed.comparison &&
      parsed.comparison.peer_evaluation?.skipped_features,
  ).toHaveLength(19);
});
it.each([
  "version",
  "profile_version",
  "unknown_field",
  "missing_report",
  "sample",
  "future_sample",
  "duplicate",
  "feature_type",
  "feature_inventory",
  "support",
  "status",
  "report_source",
  "report_device",
  "properties_checked",
  "extra_context",
])("rejects corrupted expanded bindings: %s", (change) => {
  const changed = structuredClone(result);
  const context = changed.comparison,
    baseline = context.peer_baseline,
    evaluation = context.peer_evaluation;
  if (change === "version") changed.version = "analysis-api-0.2.0";
  if (change === "profile_version")
    baseline.model_version = "peer-baseline-0.1.0";
  if (change === "unknown_field")
    Object.assign(baseline.features[0]!, { field: "unsupported" });
  if (change === "missing_report")
    Object.assign(context, { peer_evaluation: null });
  if (change === "sample") context.peers[0]!.source_sha256 = "f".repeat(64);
  if (change === "future_sample")
    baseline.samples[0]!.collected_at = "2026-10-03T00:00:00Z";
  if (change === "duplicate") context.peers[1] = context.peers[0]!;
  if (change === "feature_type") baseline.features[0]!.expected = true;
  if (change === "feature_inventory") baseline.features.pop();
  if (change === "support") baseline.features[0]!.support_count = 2;
  if (change === "status") evaluation.status = "completed";
  if (change === "report_source") evaluation.source_sha256 = "f".repeat(64);
  if (change === "report_device") evaluation.device_id = id(40);
  if (change === "properties_checked")
    Object.assign(evaluation, {
      compared_features: evaluation.profile_features,
    });
  if (change === "extra_context")
    Object.assign(context, { private_input: "unsupported" });
  expect(analysisSchema.safeParse(changed).success).toBe(false);
});
it("distinguishes absent consensus from parsing skips", () => {
  const changed = structuredClone(result);
  const omitted = changed.comparison.peer_baseline.features.pop()!.field;
  Object.assign(changed.comparison.peer_baseline, {
    omitted_features: [omitted],
  });
  changed.comparison.peer_evaluation.profile_features.pop();
  changed.comparison.peer_evaluation.skipped_features.pop();
  expect(analysisSchema.safeParse(changed).success).toBe(true);
});
it("accepts a reference-only expanded contract without pretending a peer report exists", () => {
  const reference = { ...peers[0]!, device_id: id(1) };
  expect(
    analysisSchema.safeParse({
      ...result,
      comparison: {
        version: "comparison-context-0.2.0",
        reference,
        peers: [],
        peer_baseline: null,
        peer_evaluation: null,
      },
    }).success,
  ).toBe(true);
});
it("bounds primitives and consensus values independently from detector quality", () => {
  expect(
    expandedPeerBaselineSchema.safeParse({
      ...profile,
      consensus_threshold: NaN,
    }).success,
  ).toBe(false);
  expect(
    expandedPeerBaselineSchema.safeParse({ ...profile, samples: [] }).success,
  ).toBe(false);
});
it("rejects a partial report that omits a required parser-deficit finding", () => {
  const changed = structuredClone(result);
  changed.comparison.peer_evaluation.unsupported_ratio = 0.4;
  expect(analysisSchema.safeParse(changed).success).toBe(false);
});
it("sends the selected version explicitly only when comparison inputs are present", () => {
  const current = {
    id: id(21),
    device: id(1),
    hostname: "target",
    hash: "b".repeat(64),
    created: "2026-10-02T00:00:00Z",
    group: "owned",
    complete: true,
  };
  const reference = { ...current, id: id(22), created: "2026-10-01T00:00:00Z" };
  expect(comparisonOptions(current, reference, [], "0.2.0")).toEqual({
    comparison_version: "0.2.0",
    reference_configuration_id: id(22),
  });
  expect(comparisonOptions(current, null, [], "0.2.0")).toBeUndefined();
});
