import { expect, it } from "vitest";
import {
  batfishDirectionalExecutionSchema,
  reachabilityImpactLimitations,
  reachabilityImpactSchema,
  reachabilityWitnessSchema,
} from "./sourceReachabilityImpact";
import type { ReachabilityImpact } from "./sourceReachabilityImpact";
import {
  sourceNetworkResult,
  sourcePatchVerificationSchema,
} from "./sourcePatchVerification";
import sdkControls from "./testdata/sourceSdkControls.json";

function witness(direction: "loss" | "gain", digit = "1") {
  return {
    flow_sha256: digit.repeat(64),
    before_dispositions: [direction === "loss" ? "ACCEPTED" : "NULL_ROUTED"],
    after_dispositions: [direction === "loss" ? "NULL_ROUTED" : "ACCEPTED"],
    before_trace_count: 1,
    after_trace_count: 1,
    direction,
  };
}
function observed(witnesses = [witness("loss")]) {
  const lost = witnesses.filter((row) => row.direction === "loss").length,
    gained = witnesses.length - lost;
  return {
    version: "reachability-impact-0.1.0",
    state: "observed",
    reason: "query_completed",
    direction:
      lost && gained
        ? "loss_and_gain_found"
        : lost
          ? "loss_found"
          : gained
            ? "gain_found"
            : "no_witnesses_returned",
    lost_witness_count: lost,
    gained_witness_count: gained,
    witnesses,
    max_witnesses: 64,
    max_traces: 16,
    method: "differential-success-example-flows-0.1.0",
    limitations: [...reachabilityImpactLimitations],
  };
}
const empty = (
  state: "unknown" | "inconclusive" | "not_observed",
  reason: string,
) => ({
  ...observed([]),
  state,
  reason,
  direction: null,
  lost_witness_count: null,
  gained_witness_count: null,
});
const result = sourceNetworkResult(
  sourcePatchVerificationSchema.parse(sdkControls.cases[0]!.network).outcome,
)!;
function execution(impact: unknown = observed()) {
  return {
    version: "batfish-execution-0.3.0",
    sdk_version: "owned-sdk-0.1",
    sdk_observation: "observed",
    result: {
      ...result,
      status: "differences_found",
      reason: "query_completed",
      cleanup_complete: true,
      difference_count: 1,
      before_reachable_count: 1,
      after_reachable_count: 1,
    },
    reachability_impact: impact,
  };
}
it.each([
  [[], "no_witnesses_returned", 0, 0],
  [[witness("loss")], "loss_found", 1, 0],
  [[witness("gain")], "gain_found", 0, 1],
  [[witness("loss"), witness("gain", "2")], "loss_and_gain_found", 1, 1],
] as const)(
  "derives direction from complete example witnesses, including equal totals: %s",
  (rows, direction, lost, gained) => {
    const impact = reachabilityImpactSchema.parse(observed([...rows]));
    expect(impact.direction).toBe(direction);
    expect(impact.lost_witness_count).toBe(lost);
    expect(impact.gained_witness_count).toBe(gained);
    if (rows.length === 2) {
      const value = execution(impact);
      value.result.difference_count = 2;
      expect(batfishDirectionalExecutionSchema.safeParse(value).success).toBe(
        true,
      );
      expect(value.result.before_reachable_count).toBe(
        value.result.after_reachable_count,
      );
    }
  },
);
it("accepts complete multi-path outcomes and never classifies from only the first trace", () => {
  const row = {
    ...witness("loss"),
    before_dispositions: ["DENIED_IN", "EXITS_NETWORK"],
    before_trace_count: 2,
  };
  expect(reachabilityWitnessSchema.safeParse(row).success).toBe(true);
  expect(
    reachabilityWitnessSchema.safeParse({ ...row, direction: "gain" }).success,
  ).toBe(false);
  expect(
    reachabilityWitnessSchema.safeParse({ ...row, before_trace_count: 3 })
      .success,
  ).toBe(false);
});
it.each([
  { direction: "gain" },
  { before_dispositions: ["NULL_ROUTED"] },
  { after_dispositions: ["ACCEPTED"] },
  { before_dispositions: ["INSUFFICIENT_INFO"] },
  { after_dispositions: ["NEW_DISPOSITION"] },
  { before_dispositions: [] },
  { after_dispositions: [] },
  { before_dispositions: ["NO_ROUTE", "ACCEPTED"], before_trace_count: 2 },
  { before_dispositions: Array(17).fill("ACCEPTED"), before_trace_count: 17 },
  { before_trace_count: 0 },
  { before_trace_count: 2 },
  { before_trace_count: true },
  { before_trace_count: "1" },
  { before_trace_count: 1.5 },
  { after_trace_count: null },
  { flow_sha256: "x".repeat(64) },
  { flow_sha256: "1".repeat(64) + "\n" },
  { flow_sha256: "1".repeat(64) + "\r" },
  { flow_sha256: "1".repeat(64) + "\u2028" },
  { raw_flow: { secret: "not-allowed" } },
])("rejects unsupported or incomplete directional witness %j", (change) => {
  expect(
    reachabilityWitnessSchema.safeParse({ ...witness("loss"), ...change })
      .success,
  ).toBe(false);
});
it.each([
  { state: "unknown" },
  { reason: "not_run" },
  { direction: "gain_found" },
  { direction: null },
  { lost_witness_count: 0 },
  { gained_witness_count: 1 },
  { lost_witness_count: true },
  { gained_witness_count: "0" },
  { lost_witness_count: 1.5 },
  { witnesses: [witness("loss"), witness("loss")] },
  {
    witnesses: [witness("gain", "2"), witness("loss")],
    direction: "loss_and_gain_found",
    lost_witness_count: 1,
    gained_witness_count: 1,
  },
  { witnesses: Array(65).fill(witness("loss")), lost_witness_count: 65 },
  { max_witnesses: 65 },
  { max_traces: 32 },
  { method: "total_difference" },
  { limitations: [] },
  { limitations: [...reachabilityImpactLimitations].reverse() },
  { limitations: [...reachabilityImpactLimitations, "extra"] },
  { limitations: ["all flows", ...reachabilityImpactLimitations.slice(1)] },
  { severity: "critical" },
  { approved: true },
])("rejects false direction, counts, ordering or promotion %j", (change) => {
  expect(
    reachabilityImpactSchema.safeParse({ ...observed(), ...change }).success,
  ).toBe(false);
});
it.each([
  ["inconclusive", "empty_reachable_scope"],
  ["not_observed", "not_run"],
  ...[
    "unsupported_frame",
    "witness_limit_exceeded",
    "incomplete_traces",
    "ambiguous_witness",
    "unknown_disposition",
    "insufficient_information",
    "cleanup_unconfirmed",
  ].map((reason) => ["unknown", reason]),
])(
  "retains unmeasured direction %s/%s without zero substitution",
  (state, reason) => {
    const value = empty(state as "unknown", reason!);
    expect(reachabilityImpactSchema.parse(value).lost_witness_count).toBeNull();
    for (const change of [
      { direction: "no_witnesses_returned" },
      { lost_witness_count: 0 },
      { gained_witness_count: 0 },
      { witnesses: [witness("loss")] },
    ])
      expect(
        reachabilityImpactSchema.safeParse({ ...value, ...change }).success,
      ).toBe(false);
  },
);
it("binds interpretation to actual query status, cleanup and differential witness count", () => {
  expect(batfishDirectionalExecutionSchema.safeParse(execution()).success).toBe(
    true,
  );
  const value = execution();
  expect(
    batfishDirectionalExecutionSchema.safeParse({
      ...value,
      result: { ...value.result, difference_count: 2 },
    }).success,
  ).toBe(false);
  for (const cleanup_complete of [null, false]) {
    const altered = { ...value, result: { ...value.result, cleanup_complete } };
    expect(batfishDirectionalExecutionSchema.safeParse(altered).success).toBe(
      false,
    );
    expect(
      batfishDirectionalExecutionSchema.safeParse({
        ...altered,
        reachability_impact: empty("unknown", "cleanup_unconfirmed"),
      }).success,
    ).toBe(true);
  }
  const noDifference = {
    ...value,
    result: {
      ...value.result,
      status: "no_differences_in_scope",
      difference_count: 0,
    },
  };
  expect(
    batfishDirectionalExecutionSchema.safeParse({
      ...noDifference,
      reachability_impact: observed([]),
    }).success,
  ).toBe(true);
  expect(
    batfishDirectionalExecutionSchema.safeParse({
      ...noDifference,
      reachability_impact: empty("unknown", "incomplete_traces"),
    }).success,
  ).toBe(true);
  const inconclusive = {
    ...value,
    result: {
      ...value.result,
      status: "inconclusive",
      reason: "empty_reachable_scope",
      difference_count: 0,
      before_reachable_count: 0,
      after_reachable_count: 0,
    },
  };
  expect(
    batfishDirectionalExecutionSchema.safeParse(inconclusive).success,
  ).toBe(false);
  expect(
    batfishDirectionalExecutionSchema.safeParse({
      ...inconclusive,
      reachability_impact: empty("inconclusive", "empty_reachable_scope"),
    }).success,
  ).toBe(true);
});
it("preserves SDK observation separately from unavailable query and interpretation failure", () => {
  const value = execution(empty("not_observed", "not_run")),
    failed = {
      ...value,
      result: {
        ...value.result,
        status: "error",
        reason: "engine_error",
        difference_count: null,
        before_reachable_count: null,
        after_reachable_count: null,
      },
    };
  expect(batfishDirectionalExecutionSchema.safeParse(failed).success).toBe(
    true,
  );
  expect(
    batfishDirectionalExecutionSchema.safeParse({
      ...failed,
      reachability_impact: observed(),
    }).success,
  ).toBe(false);
  for (const reason of ["worker_failed", "timeout"])
    for (const sdk_observation of [
      "observed",
      "metadata_unavailable",
      "not_observed",
    ])
      expect(
        batfishDirectionalExecutionSchema.safeParse({
          ...failed,
          result: { ...failed.result, reason },
          sdk_observation,
          sdk_version: sdk_observation === "observed" ? "owned-sdk" : null,
        }).success,
      ).toBe(sdk_observation === "not_observed");
  for (const sdk_version of [
    "a\n",
    "a\r",
    "a\u2028",
    " a",
    "версия",
    "a".repeat(129),
  ])
    expect(
      batfishDirectionalExecutionSchema.safeParse({ ...failed, sdk_version })
        .success,
    ).toBe(false);
  const unknown = reachabilityImpactSchema.parse(
    empty("unknown", "incomplete_traces"),
  ) as ReachabilityImpact;
  expect(
    batfishDirectionalExecutionSchema.safeParse(execution(unknown)).success,
  ).toBe(true);
});
