import { expect, it } from "vitest";
import {
  analysisSchema,
  feedbackSchema,
  feedbackSubmissionSchema,
} from "./contracts";
import {
  feedbackMatches,
  feedbackTarget,
  prepareFeedback,
  sameSubmission,
} from "./feedback";
import type { FeedbackTarget } from "./feedback";

const guid = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const target: FeedbackTarget = {
  analysis_id: guid(1),
  configuration_id: guid(2),
  device_id: guid(3),
  finding_id: guid(4),
  source_sha256: "a".repeat(64),
  finding_sha256: "b".repeat(64),
};
const submission = {
  feedback_id: guid(5),
  analysis_id: target.analysis_id,
  finding_sha256: target.finding_sha256,
  verdict: "needs_investigation" as const,
  comment: "Check the maintenance exception.\nNo secrets included.",
};
const record = {
  ...target,
  ...submission,
  version: "finding-feedback-0.1.0" as const,
  created_at: "2026-10-02T00:00:00Z",
  actor: "shared_service_token" as const,
};

it("accepts only an explicitly bound assessment, not an approval or ground truth", () => {
  expect(feedbackSchema.parse(record)).toEqual(record);
  expect(feedbackSubmissionSchema.parse(submission)).toEqual(submission);
});
it.each([
  { actor: "verified_engineer" },
  { verdict: "patch_approved" },
  { version: "unsupported" },
  { source_sha256: "invalid" },
  { created_at: "2026-10-02T00:00:00" },
  { ground_truth: true },
  { approval: true },
])("rejects false authority and incompatible records: %j", (change) => {
  expect(feedbackSchema.safeParse({ ...record, ...change }).success).toBe(
    false,
  );
});
it.each([
  "",
  " ",
  " x",
  "x ",
  "x\0",
  "x\u202e",
  "x\u00a0y",
  "x\ud800",
  "x".repeat(2001),
])("rejects invalid comments: %j", (comment) => {
  expect(
    feedbackSubmissionSchema.safeParse({ ...submission, comment }).success,
  ).toBe(false);
});
it("accepts printable multilingual text and line breaks, including HTML as plain text", () => {
  const comment = "Нужна проверка 🙂\r\n\t<img src=x onerror=alert(1)>";
  expect(
    feedbackSubmissionSchema.parse({ ...submission, comment }).comment,
  ).toBe(comment);
  expect(
    feedbackSubmissionSchema.safeParse({
      ...submission,
      comment: "🙂".repeat(2000),
    }).success,
  ).toBe(true);
  expect(
    feedbackSubmissionSchema.safeParse({
      ...submission,
      comment: "🙂".repeat(2001),
    }).success,
  ).toBe(false);
});
it.each(Object.keys(target) as (keyof FeedbackTarget)[])(
  "compares every history binding: %s",
  (key) => {
    expect(feedbackMatches(record, target)).toBe(true);
    expect(feedbackMatches({ ...record, [key]: "different" }, target)).toBe(
      false,
    );
  },
);
it.each(Object.keys(submission) as (keyof typeof submission)[])(
  "compares every idempotent request field: %s",
  (key) => {
    expect(sameSubmission(record, submission)).toBe(true);
    expect(
      sameSubmission({ ...submission, [key]: "different" }, submission),
    ).toBe(false);
  },
);
it("retains the exact submission ID for an uncertain retry, but assigns a new ID for changed intent", () => {
  const first = prepareFeedback(
    target,
    "needs_investigation",
    "  Check exception.  ",
    null,
  );
  expect(first.comment).toBe("Check exception.");
  expect(prepareFeedback(target, first.verdict, first.comment, first)).toBe(
    first,
  );
  const changed = prepareFeedback(
    target,
    "false_positive",
    first.comment,
    first,
  );
  expect(changed.feedback_id).not.toBe(first.feedback_id);
  const revised = prepareFeedback(
    target,
    first.verdict,
    "Updated evidence.",
    first,
  );
  expect(revised.feedback_id).not.toBe(first.feedback_id);
  const otherAnalysis = prepareFeedback(
    { ...target, analysis_id: guid(8) },
    first.verdict,
    first.comment,
    first,
  );
  expect(otherAnalysis.feedback_id).not.toBe(first.feedback_id);
  expect(() => prepareFeedback(target, first.verdict, "x\0", first)).toThrow(
    "1–2000",
  );
});
it("derives scope from the selected immutable analysis and refuses foreign findings", () => {
  const finding = {
    finding_id: target.finding_id,
    device_id: target.device_id,
    detector: "policy_engine",
    category: "test",
    title: "Test",
    severity: "high",
    confidence: 1,
    anomaly_score: 0,
    affected_lines: [],
    evidence: [],
    observed: {},
    expected: {},
    remediation: null,
    references: [],
    limitations: [],
    model_version: "test",
  };
  const analysis = analysisSchema.parse({
    ...target,
    version: "analysis-api-0.1.0",
    created_at: record.created_at,
    status: "partial",
    policy_catalog_version: "test",
    findings: [finding],
    risk: null,
    limitations: [],
    explanations: [
      {
        version: "local-explanation-0.1.0",
        provider: "deterministic_local",
        ...target,
        detector_version: "test",
        severity: "high",
        confidence: 1,
        anomaly_score: 0,
        summary: "Test",
        technical_explanation: "Test",
        recommendation: "Check",
        anchors: [],
        citations: [],
        limitations: [],
        formal_verification: "not_run",
        patch_draft: null,
        requires_human_review: true,
      },
    ],
  });
  expect(feedbackTarget(analysis, analysis.findings[0]!)).toEqual(target);
  expect(() =>
    feedbackTarget(analysis, { ...analysis.findings[0]!, finding_id: guid(9) }),
  ).toThrow("не принадлежит");
});
