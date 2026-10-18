import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { stableJson } from "./contracts";
import { patchDraftSchema } from "./patches";
import type { ConfigurationInferenceReport } from "./configurationModels";
import { savedReviewProofMatches } from "./savedReviewProof";
import {
  configurationPairSchema,
  runSourceMlRecheckSchema,
  sourceMlBlockers,
  sourceMlCapabilitiesSchema,
  sourceMlRecheckBound,
  sourceMlRecheckSchema,
  sourceMlSummaryBound,
  sourceMlSummarySchema,
} from "./sourceMlRecheck";
import type { SourceMlRecheck, SourceMlSummary } from "./sourceMlRecheck";

const id = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const hash = (n: number) => String(n).repeat(64);
const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const member = (n: number) => ({
  configuration_id: id(n),
  device_id: id(3),
  source_sha256: hash(n),
  canonical_sha256: hash(n + 3),
  total_lines: n,
  created_at: `2026-10-18T00:00:0${n}Z`,
});
const before = member(1),
  after = member(2);
const snapshot = ({
  canonical_sha256: _canonical,
  total_lines: _lines,
  ...binding
}: typeof before) => ({
  ...binding,
  hostname: "source-pair",
  vendor: "cisco",
  platform: "ios",
  projection_sha256: binding.source_sha256,
  parser_confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
});
const draft = patchDraftSchema.parse({
  version: "snapshot-patch-draft-0.1.0",
  patch_id: id(4),
  created_at: "2026-10-18T00:00:03Z",
  draft_sha256: hash(8),
  status: "draft",
  representation: "normalized_objects",
  requires_human_review: true,
  diff: {
    version: "snapshot-diff-0.1.0",
    representation: "normalized_objects",
    before: snapshot(before),
    after: snapshot(after),
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
const request = runSourceMlRecheckSchema.parse({
  recheck_id: id(5),
  draft_sha256: draft.draft_sha256,
  model_sha256: hash(9),
  allow_local_model_context: true,
});
function report(source = before, anomaly = 1): ConfigurationInferenceReport {
  return {
    version: "configuration-inference-0.1.0",
    runtime_torch_version: "owned-pair-fixture",
    sanitization_version: "config-sanitizer-0.1.0",
    risk_fused: false,
    calibrated: false,
    quality_evaluated: false,
    production_quality_proven: false,
    model: {
      version: "config-model-card-0.1.0",
      kind: "native",
      model_sha256: request.model_sha256,
      training_format: "multitask-training-0.1.0",
      report_sha256: hash(6),
      encoder_sha256: hash(6),
      tokenizer_sha256: hash(6),
      source_manifest_sha256: null,
      train_fingerprint: hash(6),
      selection_fingerprint: hash(7),
      classes: ["telnet_enabled"],
      enabled_heads: {
        anomaly: true,
        category: true,
        severity: false,
        localization: true,
        contrastive: false,
      },
      parameter_count: 200,
      trainable_parameters: 100,
      train_examples: 4,
      selection_examples: 2,
      target_semantics: "injected_mutation",
      external_pretraining_exposure: "not_applicable",
      status: "experimental",
      calibrated: false,
      production_quality_proven: false,
      activated: false,
    },
    prediction: {
      raw_source_sha256: source.source_sha256,
      sanitized_source_sha256: hash(7),
      model_sha256: request.model_sha256,
      total_lines: source.total_lines,
      anomaly_score: anomaly,
      category_scores: { telnet_enabled: 0.4 },
      severity_scores: null,
      line_scores: Array.from({ length: source.total_lines }, () => 0.2),
      block_attention: [1],
      embedding_sha256: null,
      embedding_dimensions: 0,
      replacement_counts: {},
      calibrated: false,
    },
  };
}
function normative(value: unknown) {
  return stableJson(value)
    .replace(/"block_attention":\[1\]/g, '"block_attention":[1.0]')
    .replace(/"anomaly_score":1(?=[,}])/g, '"anomaly_score":1.0')
    .replace(
      /[\u007f-\uffff]/g,
      (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
}
function seal(row: Omit<SourceMlRecheck, "review_json" | "review_sha256">) {
  if (row.outcome) row.outcome.intent_sha256 = digest(normative(row.intent));
  const raw = normative(row);
  return { ...row, review_json: raw, review_sha256: digest(raw) };
}
function recheck(
  state: "completed" | "failed" | "pending_unknown" = "completed",
): SourceMlRecheck {
  const row: Omit<SourceMlRecheck, "review_json" | "review_sha256"> = {
    version: "source-ml-recheck-0.1.0",
    recheck_id: request.recheck_id,
    patch_id: draft.patch_id,
    draft_sha256: draft.draft_sha256,
    model_sha256: request.model_sha256,
    intent: {
      version: "source-ml-intent-0.1.0",
      patch_id: draft.patch_id,
      request: { ...request },
      before: { ...before },
      after: { ...after },
      created_at: "2026-10-18T00:00:04Z",
    },
    outcome:
      state === "pending_unknown"
        ? null
        : {
            version: "source-ml-outcome-0.1.0",
            recheck_id: request.recheck_id,
            intent_sha256: hash(0),
            completed_at: "2026-10-18T00:00:05Z",
            execution_status: state,
            failure_reason:
              state === "failed" ? "worker_failed_or_unavailable" : null,
            report:
              state === "failed"
                ? null
                : {
                    version: "configuration-pair-inference-0.1.0",
                    before: report(),
                    after: report(after, 0.2),
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
  row.validation_blockers = sourceMlBlockers(row.outcome);
  return sourceMlRecheckSchema.parse(seal(row));
}
function summary(row = recheck()): SourceMlSummary {
  return sourceMlSummarySchema.parse({
    version: "source-ml-summary-0.1.0",
    recheck_id: row.recheck_id,
    patch_id: row.patch_id,
    draft_sha256: row.draft_sha256,
    model_sha256: row.model_sha256,
    review_sha256: row.review_sha256,
    created_at: row.intent.created_at,
    completed_at: row.outcome?.completed_at ?? null,
    execution_status: row.execution_status,
    status: "needs_review",
  });
}
const caps = {
  version: "source-ml-capabilities-0.1.0",
  inference: "configured",
  model_sha256: hash(9),
  health_checked: false,
  exact_retained_sources_required: true,
  request_consent_required: true,
  formal_verification: "not_run",
};
it("accepts paired numeric reports with one card/runtime and verifies normative wire bytes", async () => {
  const row = recheck();
  expect(row.review_json).toContain('"anomaly_score":1.0');
  expect(row.review_json).toContain('"block_attention":[1.0]');
  expect(digest(stableJson(JSON.parse(row.review_json)))).not.toBe(
    row.review_sha256,
  );
  expect(await savedReviewProofMatches(row)).toBe(true);
  expect(await sourceMlRecheckBound(row, draft, request, summary(row))).toBe(
    true,
  );
  expect(row.intent.before.canonical_sha256).not.toBe(
    draft.diff.before.projection_sha256,
  );
  expect(row.outcome!.report!.before.prediction.severity_scores).toBeNull();
  expect(row.outcome!.report!.after.prediction.anomaly_score).toBe(0.2);
});
it.each(["completed", "failed", "pending_unknown"] as const)(
  "keeps %s separate from formal/quality/approval claims",
  async (state) => {
    const row = recheck(state);
    expect(await sourceMlRecheckBound(row, draft, request, summary(row))).toBe(
      true,
    );
    expect(row).toMatchObject({
      status: "needs_review",
      formal_verification: "not_run",
      risk_fused: false,
      calibrated: false,
      quality_proven: false,
      approved: false,
      applied: false,
    });
    expect(row.validation_blockers.includes("ml_execution_unknown")).toBe(
      state === "pending_unknown",
    );
    expect(row.validation_blockers.includes("selected_ml_unavailable")).toBe(
      state === "failed",
    );
    if (state !== "completed") expect(row.outcome?.report ?? null).toBeNull();
  },
);
it.each([
  { quality_proven: true },
  { approved: true },
  { approved: 0 },
  { applied: true },
  { risk_fused: true },
  { calibrated: true },
  { formal_verification: "passed" },
  { status: "validated" },
  { validation_blockers: [] },
  { unexpected: true },
])("rejects false promotion or projection changes %j", (update) =>
  expect(
    sourceMlRecheckSchema.safeParse({ ...recheck(), ...update }).success,
  ).toBe(false),
);
it("rejects request coercion and capabilities which imply a health check or omit a configured pin", () => {
  for (const update of [
    { allow_local_model_context: "true" },
    { before: before },
    { model_sha256: "9" },
    { version: "source-ml-request-9.0" },
  ])
    expect(
      runSourceMlRecheckSchema.safeParse({ ...request, ...update }).success,
    ).toBe(false);
  for (const update of [
    { health_checked: true },
    { model_sha256: null },
    { inference: "disabled" },
    { formal_verification: "passed" },
  ])
    expect(
      sourceMlCapabilitiesSchema.safeParse({ ...caps, ...update }).success,
    ).toBe(false);
  expect(
    sourceMlCapabilitiesSchema.parse({
      ...caps,
      inference: "disabled",
      model_sha256: null,
    }).inference,
  ).toBe("disabled");
});
it("requires identical model/card/head inventory, runtime and sanitizer before comparing reports", () => {
  const pair = recheck().outcome!.report!;
  for (const update of [
    { runtime_torch_version: "different-runtime" },
    { sanitization_version: "wrong" },
    { model: { ...pair.after.model, report_sha256: hash(7) } },
    { model: { ...pair.after.model, classes: ["other_class"] } },
  ])
    expect(
      configurationPairSchema.safeParse({
        ...pair,
        after: { ...pair.after, ...update },
      }).success,
    ).toBe(false);
  const disabled = structuredClone(pair);
  disabled.before.model.enabled_heads.severity =
    disabled.after.model.enabled_heads.severity = true;
  expect(configurationPairSchema.safeParse(disabled).success).toBe(false);
  expect(
    configurationPairSchema.safeParse({ ...pair, interpretation: "patch_safe" })
      .success,
  ).toBe(false);
});
it("rejects source/model/line-count substitutions and contradictory outcome states", () => {
  for (const change of [
    (row: SourceMlRecheck) => {
      row.outcome!.report!.after.prediction.raw_source_sha256 = hash(7);
    },
    (row: SourceMlRecheck) => {
      row.intent.after.total_lines = 1;
    },
    (row: SourceMlRecheck) => {
      row.model_sha256 = row.intent.request.model_sha256 = hash(7);
    },
    (row: SourceMlRecheck) => {
      row.outcome!.execution_status = "failed";
    },
    (row: SourceMlRecheck) => {
      row.intent.after.device_id = id(9);
    },
    (row: SourceMlRecheck) => {
      row.intent.request.allow_local_model_context = false;
    },
    (row: SourceMlRecheck) => {
      row.intent.created_at = before.created_at;
    },
  ]) {
    const row = recheck();
    change(row);
    expect(sourceMlRecheckSchema.safeParse(row).success).toBe(false);
  }
  const failed = recheck("failed");
  expect(
    sourceMlRecheckSchema.safeParse({
      ...failed,
      outcome: { ...failed.outcome!, failure_reason: null },
    }).success,
  ).toBe(false);
  expect(
    sourceMlSummarySchema.safeParse({ ...summary(), completed_at: null })
      .success,
  ).toBe(false);
});
it("rejects altered raw proof, duplicate keys, typed projection and nested raw-intent proof", async () => {
  const row = recheck();
  for (const changed of [
    { ...row, review_sha256: hash(7) },
    { ...row, review_json: row.review_json + " " },
    {
      ...row,
      intent: {
        ...row.intent,
        after: { ...row.intent.after, canonical_sha256: hash(7) },
      },
    },
  ])
    expect(await savedReviewProofMatches(changed)).toBe(false);
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
  const { review_json: _json, review_sha256: _hash, ...body } = row;
  body.outcome!.intent_sha256 = hash(7);
  const raw = normative(body);
  expect(
    await savedReviewProofMatches({
      ...body,
      review_json: raw,
      review_sha256: digest(raw),
    }),
  ).toBe(false);
});
it("binds exact draft/request/model-pin and history summary independently of the current operator pin", async () => {
  const row = recheck(),
    index = summary(row);
  for (const wrong of [
    { ...draft, patch_id: id(9) },
    { ...draft, draft_sha256: hash(7) },
    {
      ...draft,
      diff: {
        ...draft.diff,
        after: { ...draft.diff.after, configuration_id: id(9) },
      },
    },
  ])
    expect(await sourceMlRecheckBound(row, wrong)).toBe(false);
  for (const wrong of [
    { ...request, recheck_id: id(9) },
    { ...request, model_sha256: hash(7) },
    { ...request, allow_local_model_context: false },
  ])
    expect(await sourceMlRecheckBound(row, draft, wrong)).toBe(false);
  for (const wrong of [
    { ...index, recheck_id: id(9) },
    { ...index, review_sha256: hash(7) },
    { ...index, model_sha256: hash(7) },
    { ...index, execution_status: "failed" as const },
  ])
    expect(await sourceMlRecheckBound(row, draft, undefined, wrong)).toBe(
      false,
    );
  expect(sourceMlSummaryBound({ ...index, draft_sha256: hash(7) }, draft)).toBe(
    false,
  );
});
const transport = (value: unknown) =>
  vi.fn(
    async (_url: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(value)),
  );
it("uses authenticated v2 ML endpoints, exact intent and paginated history without network operations", async () => {
  const row = recheck(),
    send = transport(row),
    client = new ApiClient("x".repeat(32), send);
  expect(await client.runSourceMlRecheck(draft, request)).toEqual(row);
  expect(send.mock.calls[0]?.[0]).toBe(
    `/api/v2/patches/${draft.patch_id}/ml-rechecks`,
  );
  const options = send.mock.calls[0]![1]!;
  expect(options).toMatchObject({
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  expect(options.headers).toMatchObject({
    Authorization: `Bearer ${"x".repeat(32)}`,
  });
  expect(JSON.parse(options.body as string)).toEqual(request);
  await client.sourceMlRecheck(draft, row.recheck_id, request);
  expect(send.mock.calls[1]?.[0]).toBe(
    `/api/v2/patches/${draft.patch_id}/ml-rechecks/${row.recheck_id}`,
  );
  send.mockResolvedValueOnce(new Response(JSON.stringify([summary(row)])));
  await client.sourceMlRechecks(draft, 20);
  expect(send.mock.calls[2]?.[0]).toBe(
    `/api/v2/patches/${draft.patch_id}/ml-rechecks?limit=20&offset=20`,
  );
  send.mockResolvedValueOnce(new Response(JSON.stringify(caps)));
  await client.sourceMlCapabilities();
  expect(send.mock.calls[3]?.[0]).toBe("/api/v2/patches/ml-capabilities");
});
it("refuses consent/draft substitutions before transport and never repeats a lost POST", async () => {
  const send = transport(recheck()),
    client = new ApiClient("x".repeat(32), send);
  await expect(
    client.runSourceMlRecheck(draft, {
      ...request,
      allow_local_model_context: false,
    }),
  ).rejects.toMatchObject({ status: 403 });
  await expect(
    client.runSourceMlRecheck(draft, { ...request, draft_sha256: hash(7) }),
  ).rejects.toMatchObject({ status: 409 });
  expect(send).not.toHaveBeenCalled();
  send.mockRejectedValueOnce(new TypeError("lost"));
  await expect(client.runSourceMlRecheck(draft, request)).rejects.toMatchObject(
    { status: 0 },
  );
  expect(send).toHaveBeenCalledTimes(1);
});
it("rejects foreign/altered successful API records, duplicate summaries and a changed request pin", async () => {
  const row = recheck(),
    send = transport(row),
    client = new ApiClient("x".repeat(32), send);
  await expect(client.sourceMlRecheck(draft, id(9))).rejects.toMatchObject({
    status: 0,
  });
  await expect(
    client.sourceMlRecheck(draft, row.recheck_id, {
      ...request,
      model_sha256: hash(7),
    }),
  ).rejects.toMatchObject({ status: 0 });
  await expect(
    client.sourceMlRecheck(draft, row.recheck_id, undefined, {
      ...summary(row),
      review_sha256: hash(7),
    }),
  ).rejects.toMatchObject({ status: 0 });
  send.mockResolvedValueOnce(
    new Response(JSON.stringify({ ...row, review_sha256: hash(7) })),
  );
  await expect(client.runSourceMlRecheck(draft, request)).rejects.toMatchObject(
    { status: 0 },
  );
  send.mockResolvedValueOnce(
    new Response(JSON.stringify([summary(row), summary(row)])),
  );
  await expect(client.sourceMlRechecks(draft)).rejects.toMatchObject({
    status: 0,
  });
  send.mockResolvedValueOnce(
    new Response(JSON.stringify([{ ...summary(row), draft_sha256: hash(7) }])),
  );
  await expect(client.sourceMlRechecks(draft)).rejects.toMatchObject({
    status: 0,
  });
});
