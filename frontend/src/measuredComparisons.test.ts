import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
import { z } from "zod";
import fixture from "./test-fixtures/measured-peer-api.json";
import {
  analysisSchema,
  explanationBundleSchema,
  findingSchema,
  modelExplanationSchema,
} from "./contracts";
import {
  makeMeasuredComparisonSchema,
  measuredPeerBaselineSchema,
} from "./measuredComparisons";
import { comparisonOptions } from "./comparison";
import { AnalysisView } from "./AnalysisView";
import { ApiClient } from "./api";

const contextSchema = makeMeasuredComparisonSchema(
  z.strictObject({
    configuration_id: z.guid(),
    device_id: z.guid(),
    source_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    created_at: z.iso.datetime({ offset: true }),
  }),
  findingSchema,
);

// Captured from owned raw-text API requests, not an independent quality corpus.
it.each(["completed", "partial", "emptyPartial"] as const)(
  "accepts the actual saved API contract: %s",
  (name) => {
    const result = analysisSchema.parse(fixture[name]);
    expect(result.version).toBe("analysis-api-0.5.0");
    expect(result.comparison).toEqual(fixture[name].comparison);
    expect(result.risk === null).toBe(name !== "completed");
  },
);

const corruptions: [string, (value: typeof fixture.partial) => void][] = [
  ["wire version", (v) => (v.version = "analysis-api-0.4.0")],
  [
    "context version",
    (v) => (v.comparison.version = "comparison-context-0.2.0"),
  ],
  [
    "profile version",
    (v) => (v.comparison.peer_baseline.model_version = "peer-baseline-0.2.0"),
  ],
  [
    "missing profile",
    (v) => Object.assign(v.comparison, { peer_baseline: null }),
  ],
  [
    "missing report",
    (v) => Object.assign(v.comparison, { peer_evaluation: null }),
  ],
  [
    "extra context",
    (v) => Object.assign(v.comparison, { private_source: "not allowed" }),
  ],
  [
    "peer binding",
    (v) => (v.comparison.peers[0]!.source_sha256 = "f".repeat(64)),
  ],
  ["duplicate peer", (v) => (v.comparison.peers[1] = v.comparison.peers[0]!)],
  [
    "future sample",
    (v) =>
      (v.comparison.peer_baseline.properties.samples[0]!.collected_at =
        "2099-01-01T00:00:00Z"),
  ],
  ["coverage order", (v) => v.comparison.peer_baseline.coverage.reverse()],
  ["coverage count", (v) => v.comparison.peer_baseline.coverage.pop()],
  [
    "proxy must be inert",
    (v) =>
      (v.comparison.peer_baseline.properties.unsupported_ratio_limit = 0.05),
  ],
  [
    "peer numerator",
    (v) => (v.comparison.peer_baseline.coverage[0]!.unparsed_units = 1),
  ],
  [
    "invalid median",
    (v) => (v.comparison.peer_baseline.unparsed_fraction_median = 0.2),
  ],
  [
    "threshold binding",
    (v) => (v.comparison.peer_baseline.unparsed_fraction_limit = 0.2),
  ],
  [
    "boolean threshold",
    (v) =>
      Object.assign(v.comparison.peer_baseline, {
        unparsed_fraction_limit: true,
      }),
  ],
  [
    "source binding",
    (v) => (v.comparison.peer_evaluation.source_sha256 = "f".repeat(64)),
  ],
  [
    "device binding",
    (v) =>
      (v.comparison.peer_evaluation.device_id =
        v.comparison.peers[0]!.device_id),
  ],
  [
    "report version",
    (v) =>
      (v.comparison.peer_evaluation.version = "peer-comparison-report-0.2.0"),
  ],
  [
    "fraction count",
    (v) => (v.comparison.peer_evaluation.coverage.unparsed_units = 0),
  ],
  [
    "fraction value",
    (v) => (v.comparison.peer_evaluation.coverage.unparsed_fraction = 0.12),
  ],
  ["unit order", (v) => v.comparison.peer_evaluation.coverage.units.reverse()],
  [
    "completed partial",
    (v) => (v.comparison.peer_evaluation.status = "completed"),
  ],
  [
    "partial properties compared",
    (v) =>
      Object.assign(v.comparison.peer_evaluation, {
        compared_features: v.comparison.peer_evaluation.profile_features,
      }),
  ],
  ["missing skips", (v) => v.comparison.peer_evaluation.skipped_features.pop()],
  [
    "missing fraction finding",
    (v) => (v.comparison.peer_evaluation.findings = []),
  ],
  [
    "duplicate fraction finding",
    (v) =>
      v.comparison.peer_evaluation.findings.push(
        v.comparison.peer_evaluation.findings[0]!,
      ),
  ],
  [
    "finding version",
    (v) =>
      (v.comparison.peer_evaluation.findings[0]!.model_version =
        "peer-baseline-0.2.0"),
  ],
  [
    "finding source",
    (v) =>
      (v.comparison.peer_evaluation.findings[0]!.observed.source_sha256 =
        "f".repeat(64)),
  ],
  [
    "coverage hash format",
    (v) =>
      (v.comparison.peer_evaluation.findings[0]!.observed.coverage_report_sha256 =
        "unknown"),
  ],
  [
    "fraction confidence",
    (v) => (v.comparison.peer_evaluation.findings[0]!.confidence = 0.8),
  ],
  [
    "fraction score",
    (v) => (v.comparison.peer_evaluation.findings[0]!.anomaly_score = 0.9),
  ],
  [
    "baseline binding",
    (v) =>
      (v.comparison.peer_evaluation.findings[0]!.expected.baseline_sha256 =
        "f".repeat(64)),
  ],
  [
    "evidence line hash",
    (v) =>
      (v.comparison.peer_evaluation.findings[0]!.evidence[0]!.source_location!.raw_text_hash =
        "f".repeat(64)),
  ],
  [
    "evidence outside unknown lines",
    (v) =>
      (v.comparison.peer_evaluation.findings[0]!.evidence[0]!.source_location!.source_lines =
        [1]),
  ],
  [
    "unknown affected line",
    (v) => (v.comparison.peer_evaluation.findings[0]!.affected_lines = [1]),
  ],
  ["analysis status", (v) => (v.status = "completed")],
];
it.each(corruptions)(
  "rejects inconsistent measured contracts: %s",
  (_, change) => {
    const changed = structuredClone(fixture.partial);
    change(changed);
    expect(analysisSchema.safeParse(changed).success).toBe(false);
    if (!["wire version", "analysis status"].includes(_))
      expect(contextSchema.safeParse(changed.comparison).success).toBe(false);
  },
);

it.each([NaN, Infinity, -0.01, 1.01, true, null])(
  "bounds a measured profile threshold independently of correctness: %s",
  (limit) => {
    expect(
      measuredPeerBaselineSchema.safeParse({
        ...fixture.partial.comparison.peer_baseline,
        unparsed_fraction_limit: limit,
      }).success,
    ).toBe(false);
  },
);
it.each(["support", "expected", "score", "omitted", "partial"])(
  "rejects inconsistent completed property findings: %s",
  (change) => {
    const value = structuredClone(fixture.completed);
    const finding = value.comparison.peer_evaluation.findings[0]!;
    if (change === "support") finding.expected.peer_support_count = 2;
    if (change === "expected") finding.expected.value = ["192.0.2.77"];
    if (change === "score") finding.anomaly_score = 0.3;
    if (change === "omitted") finding.expected.feature = "unknown";
    if (change === "partial")
      value.comparison.peer_evaluation.status = "partial";
    expect(analysisSchema.safeParse(value).success).toBe(false);
    expect(contextSchema.safeParse(value.comparison).success).toBe(false);
  },
);

it("binds measured deterministic sources to the new historical release", () => {
  expect(explanationBundleSchema.parse(fixture.bundle).knowledge_version).toBe(
    "project-knowledge-0.4.0",
  );
  expect(
    explanationBundleSchema.safeParse({
      ...fixture.bundle,
      knowledge_version: "project-knowledge-0.3.0",
    }).success,
  ).toBe(false);
});
it("keeps the same release binding for a synthetic model-provider wire contract", () => {
  // This validates a wire shape only; no language model is called.
  const model = {
    ...fixture.bundle,
    version: "model-explanation-0.1.0",
    provider: "loopback_language_model",
    llm_status: "draft",
    privacy_version: "finding-context-redaction-0.1.0",
    context_sha256: "a".repeat(64),
    model_alias: "owned-wire-fixture",
    answer: {
      summary: "Owned schema fixture, not model quality.",
      technical_explanation: "Source accounting needs engineer review.",
      recommendation: "Inspect unsupported source units.",
      possible_impact: [],
      patch_draft: null,
      assumptions: [],
      missing_information: [],
      citations: [fixture.bundle.documents[0]!.citation],
      requires_human_review: true,
    },
  };
  expect(modelExplanationSchema.safeParse(model).success).toBe(true);
  expect(
    modelExplanationSchema.safeParse({
      ...model,
      knowledge_version: "project-knowledge-0.3.0",
    }).success,
  ).toBe(false);
  expect(
    modelExplanationSchema.safeParse({
      ...model,
      answer: { ...model.answer, citations: ["docs/not-provided.md"] },
    }).success,
  ).toBe(false);
});

const current = {
  id: "target",
  device: "target-device",
  hostname: "target",
  hash: "target-hash",
  created: "2026-10-02T00:00:00Z",
  group: "owned",
  complete: true,
  measured: true,
};
const peers = [0, 1, 2].map((n) => ({
  ...current,
  id: `peer-${n}`,
  device: `device-${n}`,
  hostname: `host-${n}`,
  hash: `hash-${n}`,
  created: "2026-10-01T00:00:00Z",
}));
it("requires an explicit 0.3 selection and selected inputs", () => {
  expect(comparisonOptions(current, null, peers, "0.3.0")).toEqual({
    comparison_version: "0.3.0",
    peer_configuration_ids: peers.map((p) => p.id),
  });
  expect(
    comparisonOptions(current, null, peers)?.comparison_version,
  ).toBeUndefined();
  expect(comparisonOptions(current, null, [], "0.3.0")).toBeUndefined();
});
it.each(["target", "peer"])(
  "refuses unmeasured %s before sending a request",
  (which) => {
    expect(() =>
      comparisonOptions(
        { ...current, measured: which !== "target" },
        null,
        peers.map((p, n) => ({ ...p, measured: which !== "peer" || n > 0 })),
        "0.3.0",
      ),
    ).toThrow("Исторические снимки не пересчитываются");
  },
);
it.each(["hostname", "source"])(
  "excludes target self-selection by %s",
  (which) => {
    const changed = peers.map((p) => ({ ...p }));
    if (which === "hostname") changed[0]!.hostname = "TARGET";
    else changed[0]!.hash = current.hash;
    expect(() => comparisonOptions(current, null, changed, "0.3.0")).toThrow();
  },
);
it("allows reference-only 0.3 without reconstructing historical coverage", () => {
  const reference = {
    ...current,
    id: "reference",
    created: "2026-10-01T00:00:00Z",
    measured: false,
  };
  expect(
    comparisonOptions({ ...current, measured: false }, reference, [], "0.3.0"),
  ).toEqual({
    comparison_version: "0.3.0",
    reference_configuration_id: "reference",
  });
});
it.each(["completed", "partial", "emptyPartial"] as const)(
  "renders source counts separately from parser confidence: %s",
  (name) => {
    const transport = vi.fn(() => {
      throw new Error("SSR must not call the API");
    });
    const markup = renderToStaticMarkup(
      createElement(AnalysisView, {
        result: analysisSchema.parse(fixture[name]),
        snapshot: null,
        client: new ApiClient(
          "owned-ssr-token-at-least-32-characters",
          transport,
        ),
        busy: false,
        onError: vi.fn(),
        onFeedback: async () => null,
      }),
    );
    const text = markup.replace(/<[^>]*>/g, "");
    expect(text).toContain("Измеренное сравнение 0.3.0");
    expect(text).toContain("Измеренная доля неразобранных строк");
    const coverage = fixture[name].comparison.peer_evaluation.coverage;
    expect(text).toContain(
      `Неразобранных: ${coverage.unparsed_units} из ${coverage.command_units} учитываемых строк`,
    );
    expect(text).toContain("Это не доверие парсера, не вероятность ошибки");
    expect(text).not.toContain("Дефицит доверия парсера:");
    expect(text).toContain(
      name === "completed" ? "Сравнено: 19" : "Пропущено из-за разбора: 19",
    );
    expect(transport).not.toHaveBeenCalled();
  },
);
