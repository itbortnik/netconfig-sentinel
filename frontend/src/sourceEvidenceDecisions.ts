import { z } from "zod";
import { snapshotBindingSchema, stableJson } from "./contracts";
import {
  evidenceInstant,
  evidenceRawJsonAt,
  sourceEvidenceProofMatches,
} from "./sourceEvidenceReports";
import type { SourceEvidenceReport } from "./sourceEvidenceReports";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
const member = snapshotBindingSchema
  .strict()
  .extend({ canonical_sha256: hash });
const verdict = z.enum(["rejected", "needs_more_information"]);
const role = z.enum(["engineer", "admin"]);
const flags = {
  individual_identity_verified: z.literal(false),
  approved: z.literal(false),
  applied: z.literal(false),
};
export const evidenceCommentLength = (value: string) =>
  Array.from(value).length;
// Python str.isprintable permits ASCII space, but excludes other separators
// and every Other category. Newline/tab are the contract's explicit exceptions.
export const sourceEvidenceCommentSchema = z.string().refine((value) => {
  const length = evidenceCommentLength(value);
  return (
    length >= 1 &&
    length <= 1200 &&
    !!value.trim() &&
    !/[\p{C}\p{Z}]/u.test(value.replace(/[ \n\t]/g, ""))
  );
});
export const reviewSourceEvidenceReportSchema = z.strictObject({
  version: z
    .literal("source-evidence-decision-request-0.1.0")
    .default("source-evidence-decision-request-0.1.0"),
  decision_id: id,
  report_sha256: hash,
  verdict,
  comment: sourceEvidenceCommentSchema,
});
export type ReviewSourceEvidenceReport = z.infer<
  typeof reviewSourceEvidenceReportSchema
>;
export const sourceEvidenceDecisionSchema = z
  .strictObject({
    version: z.literal("source-evidence-decision-0.1.0"),
    request: reviewSourceEvidenceReportSchema,
    decision_id: id,
    patch_id: id,
    draft_sha256: hash,
    report_id: id,
    report_sha256: hash,
    report_version: z.literal("source-evidence-report-0.1.0"),
    before: member,
    after: member,
    before_analysis_id: id,
    before_analysis_sha256: hash,
    created_at: timestamp,
    service_role: role,
    ...flags,
    decision_json: z
      .string()
      .min(1)
      .max(32 * 1024),
    decision_sha256: hash,
  })
  .refine(
    (row) =>
      row.decision_id === row.request.decision_id &&
      row.report_sha256 === row.request.report_sha256 &&
      row.before.device_id === row.after.device_id &&
      row.before.configuration_id !== row.after.configuration_id &&
      row.before.source_sha256 !== row.after.source_sha256 &&
      new TextEncoder().encode(row.decision_json).length <= 32 * 1024 &&
      new TextEncoder().encode(JSON.stringify(row)).length <= 128 * 1024,
  );
export type SourceEvidenceDecision = z.infer<
  typeof sourceEvidenceDecisionSchema
>;
export const sourceEvidenceDecisionSummarySchema = z.strictObject({
  version: z.literal("source-evidence-decision-summary-0.1.0"),
  decision_id: id,
  patch_id: id,
  report_id: id,
  report_sha256: hash,
  decision_sha256: hash,
  created_at: timestamp,
  verdict,
  service_role: role,
  ...flags,
});
export type SourceEvidenceDecisionSummary = z.infer<
  typeof sourceEvidenceDecisionSummarySchema
>;
export function sourceEvidenceDecisionSummaryBound(
  row: SourceEvidenceDecisionSummary,
  report: SourceEvidenceReport,
) {
  return (
    row.patch_id === report.patch_id &&
    row.report_id === report.report_id &&
    row.report_sha256 === report.review_sha256 &&
    evidenceInstant(row.created_at) >= evidenceInstant(report.created_at)
  );
}
export async function sourceEvidenceDecisionProofMatches(
  row: SourceEvidenceDecision,
) {
  try {
    const { decision_json, decision_sha256, ...body } = row;
    if (
      evidenceRawJsonAt(decision_json, []) === undefined ||
      !same(JSON.parse(decision_json), body)
    )
      return false;
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(decision_json),
    );
    return (
      [...new Uint8Array(digest)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("") === decision_sha256
    );
  } catch {
    return false;
  }
}
export async function sourceEvidenceDecisionBound(
  row: SourceEvidenceDecision,
  report: SourceEvidenceReport,
  expected?: ReviewSourceEvidenceReport,
  summary?: SourceEvidenceDecisionSummary,
) {
  if (
    !(await sourceEvidenceDecisionProofMatches(row)) ||
    !(await sourceEvidenceProofMatches(report)) ||
    row.patch_id !== report.patch_id ||
    row.draft_sha256 !== report.draft_sha256 ||
    row.report_id !== report.report_id ||
    row.report_sha256 !== report.review_sha256 ||
    row.report_version !== report.version ||
    !same(row.before, report.before) ||
    !same(row.after, report.after) ||
    row.before_analysis_id !== report.before_analysis_id ||
    row.before_analysis_sha256 !== report.before_analysis_sha256 ||
    evidenceInstant(row.created_at) < evidenceInstant(report.created_at) ||
    (expected && !same(row.request, expected))
  )
    return false;
  return (
    !summary ||
    (sourceEvidenceDecisionSummaryBound(summary, report) &&
      same(summary, {
        version: "source-evidence-decision-summary-0.1.0",
        decision_id: row.decision_id,
        patch_id: row.patch_id,
        report_id: row.report_id,
        report_sha256: row.report_sha256,
        decision_sha256: row.decision_sha256,
        created_at: row.created_at,
        verdict: row.request.verdict,
        service_role: row.service_role,
        individual_identity_verified: false,
        approved: false,
        applied: false,
      }))
  );
}
