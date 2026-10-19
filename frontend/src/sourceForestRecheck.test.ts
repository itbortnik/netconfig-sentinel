import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { patchDraftSchema } from "./patches";
import { savedReviewProofMatches } from "./savedReviewProof";
import {
  runSourceForestRecheckSchema,
  sourceForestBlockers,
  sourceForestSelectionSchema,
  sourceForestSelectionBound,
  sourceForestRecheckSchema,
  sourceForestRecheckBound,
  sourceForestSummarySchema,
  sourceForestSummaryBound,
} from "./sourceForestRecheck";
import type { SourceForestRecheck } from "./sourceForestRecheck";

const id = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const hash = (n: number) => String(n).repeat(64);
const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const time = (n: number) => `2026-10-18T00:00:0${n}.000001Z`;
const binding = (n: number) => ({
  configuration_id: id(n),
  device_id: id(3),
  source_sha256: hash(n),
  created_at: time(n),
});
const before = { ...binding(1), canonical_sha256: hash(4) },
  after = { ...binding(2), canonical_sha256: hash(5) };
const snapshot = (n: number) => ({
  ...binding(n),
  hostname: "owned-forest",
  vendor: "cisco",
  platform: "ios",
  projection_sha256: hash(n),
  parser_confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
});
const draft = patchDraftSchema.parse({
  version: "snapshot-patch-draft-0.1.0",
  patch_id: id(4),
  created_at: time(3),
  draft_sha256: hash(8),
  status: "draft",
  representation: "normalized_objects",
  requires_human_review: true,
  diff: {
    version: "snapshot-diff-0.1.0",
    representation: "normalized_objects",
    before: snapshot(1),
    after: snapshot(2),
    coverage: "supported_complete",
    source_changed: true,
    added_count: 1,
    removed_count: 0,
    modified_count: 0,
    changes: [
      {
        section: "management",
        object_key: ["ntp_servers"],
        kind: "added",
        before_value: null,
        after_value: { address: "192.0.2.1" },
        before_locations: [],
        after_locations: [],
      },
    ],
    limitations: ["Supported objects only"],
  },
});
const model = {
  version: "model-registry-0.1.0",
  model_id: id(6),
  created_at: time(0),
  status: "experimental",
  artifact_sha256: hash(9),
  decision_offset: -0.5,
  metadata: {
    model_version: "isolation-forest-0.1.0",
    library_version: "unit-contract-only",
    feature_schema_version: "structured-features-0.1.0",
    feature_names: Array.from({ length: 33 }, (_, n) => `feature_${n}`),
    group: {
      vendor: "cisco",
      platform: "ios",
      device_role: "edge",
      site_class: "branch",
      service_profile: "owned-control",
    },
    sample_count: 8,
    contamination: 0.1,
    random_state: 42,
    estimator_count: 10,
    training_score_min: 0,
    training_score_max: 1,
    feature_medians: Array(33).fill(0),
    feature_scales: Array(33).fill(1),
  },
  training: Array.from({ length: 8 }, (_, n) => ({
    configuration_id: id(20 + n),
    device_id: id(40 + n),
    source_sha256: digest(String(n)),
    created_at: time(0),
  })),
  training_hostnames: Array.from({ length: 8 }, (_, n) => `owned-${n}`),
};
const selection = sourceForestSelectionSchema.parse({
  version: "source-forest-selection-0.1.0",
  patch_id: draft.patch_id,
  draft_sha256: draft.draft_sha256,
  before: binding(1),
  before_analysis_id: id(7),
  before_analysis_sha256: hash(7),
  before_analysis_created_at: time(3),
  original: {
    model,
    score_samples: -0.75,
    decision_function: -0.25,
    prediction: -1,
  },
});
const request = runSourceForestRecheckSchema.parse({
  recheck_id: id(5),
  draft_sha256: draft.draft_sha256,
  before_analysis_id: selection.before_analysis_id,
  before_analysis_sha256: selection.before_analysis_sha256,
  model_id: model.model_id,
  artifact_sha256: model.artifact_sha256,
  allow_local_model_context: true,
});
function normative(row: unknown) {
  return stableJson(row)
    .replace(/"training_score_min":0/g, '"training_score_min":0.0')
    .replace(/"training_score_max":1/g, '"training_score_max":1.0');
}
function seal(row: Omit<SourceForestRecheck, "review_json" | "review_sha256">) {
  if (row.outcome) row.outcome.intent_sha256 = digest(normative(row.intent));
  const raw = normative(row);
  return { ...row, review_json: raw, review_sha256: digest(raw) };
}
function recheck(
  state: "completed" | "failed" | "pending_unknown" = "completed",
): SourceForestRecheck {
  const row: Omit<SourceForestRecheck, "review_json" | "review_sha256"> = {
    version: "source-forest-recheck-0.1.0",
    recheck_id: request.recheck_id,
    patch_id: draft.patch_id,
    draft_sha256: draft.draft_sha256,
    before_analysis_id: request.before_analysis_id,
    before_analysis_sha256: request.before_analysis_sha256,
    model_id: request.model_id,
    artifact_sha256: request.artifact_sha256,
    intent: {
      version: "source-forest-intent-0.1.0",
      patch_id: draft.patch_id,
      request: { ...request },
      before: { ...before },
      after: { ...after },
      selection: structuredClone(selection),
      created_at: time(4),
    },
    outcome:
      state === "pending_unknown"
        ? null
        : {
            version: "source-forest-outcome-0.1.0",
            recheck_id: request.recheck_id,
            intent_sha256: hash(0),
            completed_at: time(5),
            execution_status: state,
            failure_reason:
              state === "failed"
                ? "original_baseline_or_numeric_result_unavailable"
                : null,
            report:
              state === "failed"
                ? null
                : {
                    version: "source-forest-report-0.1.0",
                    model: structuredClone(selection.original.model),
                    scores: {
                      model_id: request.model_id,
                      artifact_sha256: request.artifact_sha256,
                      before_score_samples: -0.75,
                      before_decision_function: -0.25,
                      before_prediction: -1,
                      after_score_samples: -0.25,
                      after_decision_function: 0.25,
                      after_prediction: 1,
                      calibrated: false,
                      quality_proven: false,
                    },
                    interpretation: "experimental_scores_not_change_validation",
                  },
          },
    execution_status: state,
    validation_blockers: [],
    status: "needs_review",
    formal_verification: "not_run",
    risk_fused: false,
    calibrated: false,
    quality_proven: false,
    approved: false,
    applied: false,
  };
  row.validation_blockers = sourceForestBlockers(row.outcome);
  return sourceForestRecheckSchema.parse(seal(row));
}
function summary(row = recheck()) {
  return sourceForestSummarySchema.parse({
    version: "source-forest-summary-0.1.0",
    recheck_id: row.recheck_id,
    patch_id: row.patch_id,
    draft_sha256: row.draft_sha256,
    before_analysis_id: row.before_analysis_id,
    model_id: row.model_id,
    artifact_sha256: row.artifact_sha256,
    review_sha256: row.review_sha256,
    created_at: row.intent.created_at,
    completed_at: row.outcome?.completed_at ?? null,
    execution_status: row.execution_status,
    status: "needs_review",
  });
}

it.each(["completed", "failed", "pending_unknown"] as const)(
  "verifies %s normative JSON and nested intent without promoting status",
  async (state) => {
    const row = recheck(state);
    expect(row.review_json).toContain('"training_score_min":0.0');
    expect(
      await sourceForestRecheckBound(
        row,
        draft,
        request,
        summary(row),
        selection,
      ),
    ).toBe(true);
    expect(row.intent.before.canonical_sha256).not.toBe(
      draft.diff.before.projection_sha256,
    );
    expect(
      row.validation_blockers.includes("statistical_execution_unknown"),
    ).toBe(state === "pending_unknown");
    expect(
      row.validation_blockers.includes("original_statistical_unavailable"),
    ).toBe(state === "failed");
  },
);
it.each([
  { quality_proven: true },
  { approved: 0 },
  { applied: true },
  { risk_fused: true },
  { calibrated: true },
  { formal_verification: "passed" },
  { status: "validated" },
  { validation_blockers: [] },
  { unexpected: 1 },
])("refuses promotion or projection drift %j", (update) => {
  expect(
    sourceForestRecheckSchema.safeParse({ ...recheck(), ...update }).success,
  ).toBe(false);
});
it("rejects non-strict request, selection and nested model metadata", () => {
  for (const update of [
    { allow_local_model_context: "true" },
    { model_id: hash(7) },
    { before: before },
  ])
    expect(
      runSourceForestRecheckSchema.safeParse({ ...request, ...update }).success,
    ).toBe(false);
  for (const change of [
    (row: typeof selection) => {
      Object.assign(row.original.model.metadata.group, { unexpected: true });
    },
    (row: typeof selection) => {
      Object.assign(row.original.model.training[0]!, { unexpected: true });
    },
    (row: typeof selection) => {
      row.before_analysis_created_at = time(0);
    },
    (row: typeof selection) => {
      row.original.model.created_at = time(4);
    },
  ]) {
    const row = structuredClone(selection);
    change(row);
    expect(sourceForestSelectionSchema.safeParse(row).success).toBe(false);
  }
});
it("binds scores exactly to original model, before tuple, offset, range and prediction", () => {
  for (const change of [
    (row: SourceForestRecheck) => {
      row.outcome!.report!.scores.after_score_samples = 0.1;
    },
    (row: SourceForestRecheck) => {
      row.outcome!.report!.scores.after_decision_function += 1e-14;
    },
    (row: SourceForestRecheck) => {
      row.outcome!.report!.scores.after_prediction = -1;
    },
    (row: SourceForestRecheck) => {
      row.outcome!.report!.scores.before_score_samples = -0.5;
      row.outcome!.report!.scores.before_decision_function = 0;
      row.outcome!.report!.scores.before_prediction = 1;
    },
    (row: SourceForestRecheck) => {
      row.outcome!.report!.model.metadata.random_state += 1;
    },
    (row: SourceForestRecheck) => {
      row.outcome!.report!.scores.model_id = id(9);
    },
    (row: SourceForestRecheck) => {
      row.outcome!.report!.scores.after_score_samples = Infinity;
    },
    (row: SourceForestRecheck) => {
      row.intent.after.device_id = id(9);
    },
    (row: SourceForestRecheck) => {
      row.intent.request.allow_local_model_context = false;
    },
    (row: SourceForestRecheck) => {
      row.intent.request.before_analysis_sha256 = hash(8);
    },
    (row: SourceForestRecheck) => {
      Object.assign(row.intent.before, { total_lines: 1 });
    },
    (row: SourceForestRecheck) => {
      row.outcome!.failure_reason =
        "original_baseline_or_numeric_result_unavailable";
    },
  ]) {
    const row = recheck();
    change(row);
    expect(sourceForestRecheckSchema.safeParse(row).success).toBe(false);
  }
});
it("does not round sub-millisecond source binding or intent chronology", async () => {
  const row = recheck();
  expect(
    sourceForestSelectionBound(
      {
        ...selection,
        before: {
          ...selection.before,
          created_at: "2026-10-18T00:00:01.000002Z",
        },
      },
      draft,
    ),
  ).toBe(false);
  row.outcome!.completed_at = "2026-10-18T00:00:04.000000Z";
  expect(sourceForestRecheckSchema.safeParse(row).success).toBe(false);
  expect(
    sourceForestSelectionSchema.safeParse({
      ...selection,
      before_analysis_created_at: "invalid",
    }).success,
  ).toBe(false);
});
it("checks raw proof, duplicate escaped keys and nested intent digest", async () => {
  const row = recheck();
  expect(
    await savedReviewProofMatches({ ...row, review_sha256: hash(8) }),
  ).toBe(false);
  expect(
    await savedReviewProofMatches({
      ...row,
      review_json: row.review_json + " ",
    }),
  ).toBe(false);
  const duplicate = row.review_json.replace(
    '"approved":false',
    '"approved":false,"\\u0061pproved":false',
  );
  expect(
    await savedReviewProofMatches({
      ...row,
      review_json: duplicate,
      review_sha256: digest(duplicate),
    }),
  ).toBe(false);
  const { review_json: _raw, review_sha256: _hash, ...body } = row;
  body.outcome!.intent_sha256 = hash(8);
  const raw = normative(body);
  expect(
    await savedReviewProofMatches({
      ...body,
      review_json: raw,
      review_sha256: digest(raw),
    }),
  ).toBe(false);
});
it("binds draft, request, selected metadata and history independently of currently available models", async () => {
  const row = recheck(),
    index = summary(row);
  expect(
    await sourceForestRecheckBound(row, { ...draft, draft_sha256: hash(9) }),
  ).toBe(false);
  expect(
    await sourceForestRecheckBound(row, draft, { ...request, model_id: id(9) }),
  ).toBe(false);
  expect(
    await sourceForestRecheckBound(row, draft, undefined, {
      ...index,
      before_analysis_id: id(9),
    }),
  ).toBe(false);
  expect(
    await sourceForestRecheckBound(row, draft, undefined, undefined, {
      ...selection,
      before_analysis_sha256: hash(8),
    }),
  ).toBe(false);
  expect(sourceForestSummaryBound({ ...index, patch_id: id(9) }, draft)).toBe(
    false,
  );
  expect(
    sourceForestSummarySchema.safeParse({ ...index, completed_at: null })
      .success,
  ).toBe(false);
});
const transport = (value: unknown) =>
  vi.fn(
    async (_url: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(value)),
  );
it("uses the four authenticated v2 endpoints without model capability or network checks", async () => {
  const row = recheck(),
    send = transport(selection),
    client = new ApiClient("x".repeat(32), send);
  expect(
    await client.sourceForestSelection(draft, selection.before_analysis_id),
  ).toEqual(selection);
  send.mockResolvedValueOnce(new Response(JSON.stringify(row)));
  expect(
    await client.runSourceForestRecheck(draft, request, selection),
  ).toEqual(row);
  send.mockResolvedValueOnce(new Response(JSON.stringify(row)));
  await client.sourceForestRecheck(draft, row.recheck_id, request);
  send.mockResolvedValueOnce(new Response(JSON.stringify([summary(row)])));
  await client.sourceForestRechecks(draft, 20);
  expect(send.mock.calls.map(([url]) => url)).toEqual([
    `/api/v2/patches/${draft.patch_id}/statistical-selection/${selection.before_analysis_id}`,
    `/api/v2/patches/${draft.patch_id}/statistical-rechecks`,
    `/api/v2/patches/${draft.patch_id}/statistical-rechecks/${row.recheck_id}`,
    `/api/v2/patches/${draft.patch_id}/statistical-rechecks?limit=20&offset=20`,
  ]);
  expect(send.mock.calls[1]![1]).toMatchObject({
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    headers: { Authorization: `Bearer ${"x".repeat(32)}` },
  });
  expect(JSON.parse(send.mock.calls[1]![1]!.body as string)).toEqual(request);
});
it("refuses stale intent and absent consent before transport, never repeats a lost POST", async () => {
  const send = transport(recheck()),
    client = new ApiClient("x".repeat(32), send);
  await expect(
    client.runSourceForestRecheck(
      draft,
      { ...request, allow_local_model_context: false },
      selection,
    ),
  ).rejects.toMatchObject({ status: 403 });
  await expect(
    client.runSourceForestRecheck(
      draft,
      { ...request, before_analysis_sha256: hash(8) },
      selection,
    ),
  ).rejects.toMatchObject({ status: 409 });
  expect(send).not.toHaveBeenCalled();
  send.mockRejectedValueOnce(new TypeError("lost"));
  await expect(
    client.runSourceForestRecheck(draft, request, selection),
  ).rejects.toMatchObject({ status: 0 });
  expect(send).toHaveBeenCalledTimes(1);
});
it("refuses foreign selection, tampered successful records and duplicated summary IDs", async () => {
  const row = recheck(),
    send = transport({ ...selection, before_analysis_id: id(9) }),
    client = new ApiClient("x".repeat(32), send);
  await expect(
    client.sourceForestSelection(draft, selection.before_analysis_id),
  ).rejects.toMatchObject({ status: 0 });
  send.mockResolvedValueOnce(
    new Response(JSON.stringify({ ...row, review_sha256: hash(8) })),
  );
  await expect(
    client.runSourceForestRecheck(draft, request, selection),
  ).rejects.toMatchObject({ status: 0 });
  send.mockResolvedValueOnce(
    new Response(JSON.stringify([summary(row), summary(row)])),
  );
  await expect(client.sourceForestRechecks(draft)).rejects.toMatchObject({
    status: 0,
  });
  send.mockResolvedValueOnce(new Response(JSON.stringify(row)));
  await expect(client.sourceForestRecheck(draft, id(9))).rejects.toMatchObject({
    status: 0,
  });
});
