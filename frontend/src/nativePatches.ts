import { z } from "zod";
import { findingSchema, snapshotBindingSchema, stableJson } from "./contracts";
import type { AnalysisResult, Finding } from "./contracts";
import { localBlockers, preflightSchema } from "./patches";
import { evidenceInstant, evidenceRawJsonAt } from "./sourceEvidenceReports";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const catalog = z.literal("policy-rules-0.7.0");
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
const binding = snapshotBindingSchema
  .strict()
  .extend({ created_at: timestamp });
const finding = findingSchema.strict().extend({
  evidence: z.array(
    findingSchema.shape.evidence.element.strict().extend({
      source_location:
        findingSchema.shape.evidence.element.shape.source_location
          .unwrap()
          .strict()
          .nullable(),
    }),
  ),
});
export const nativePatchBlockers = [
  "formal_verification_not_run",
  "device_syntax_not_verified",
  "management_access_not_verified",
  "rollback_not_verified",
  "baseline_approval_not_proven",
  "independent_quality_not_proven",
  "individual_engineer_review_required",
] as const;
export const generateNativePatchSchema = z.strictObject({
  version: z.literal("native-patch-request-0.1.0"),
  candidate_id: id,
  analysis_id: id,
  finding_id: id,
  analysis_sha256: hash,
  finding_sha256: hash,
  source_sha256: hash,
  canonical_sha256: hash,
  policy_catalog_version: catalog,
  allow_local_native_generation: z.literal(true),
  allow_private_candidate_retention: z.literal(true),
});
export type GenerateNativePatch = z.infer<typeof generateNativePatchSchema>;
export const nativePatchSelectionSchema = z
  .strictObject({
    version: z.literal("native-patch-selection-0.1.0"),
    configuration_id: id,
    source: binding,
    canonical_sha256: hash,
    analysis_id: id,
    analysis_sha256: hash,
    analysis_created_at: timestamp,
    policy_catalog_version: catalog,
    finding_pins: z
      .array(z.strictObject({ finding_id: id, finding_sha256: hash }))
      .max(128),
  })
  .refine(
    (row) =>
      row.configuration_id === row.source.configuration_id &&
      evidenceInstant(row.source.created_at) <=
        evidenceInstant(row.analysis_created_at) &&
      new Set(row.finding_pins.map((pin) => pin.finding_id)).size ===
        row.finding_pins.length,
  );
export type NativePatchSelection = z.infer<typeof nativePatchSelectionSchema>;

const range = z
  .strictObject({
    first: z.number().int().min(0).max(9999),
    last: z.number().int().min(0).max(9999),
  })
  .refine((row) => row.first <= row.last);
const edit = z
  .strictObject({
    kind: z.enum(["cisco_vty_ssh_only", "junos_remove_telnet"]),
    source_line: z.number().int().min(1).max(10000),
    before_line_sha256: hash,
    after_line_sha256: hash.nullable(),
    vty: range.nullable(),
  })
  .refine(
    (row) =>
      (row.kind === "cisco_vty_ssh_only") === (row.vty !== null) &&
      (row.kind === "junos_remove_telnet") === (row.after_line_sha256 === null),
  );
const index = z.number().int().min(0).max(10000);
const changeSpan = z
  .strictObject({
    operation: z.enum(["insert", "delete", "replace"]),
    before_start: index,
    before_end: index,
    after_start: index,
    after_end: index,
  })
  .refine((row) => {
    const old = row.before_end - row.before_start,
      next = row.after_end - row.after_start;
    return (
      old >= 0 &&
      next >= 0 &&
      old + next > 0 &&
      row.operation ===
        (old === 0 ? "insert" : next === 0 ? "delete" : "replace")
    );
  });
const proposalSchema = z
  .strictObject({
    version: z.literal("patch-proposal-0.1.0"),
    proposal_id: id,
    device_id: id,
    reference_id: id,
    vendor: z.enum(["cisco", "juniper"]),
    platform: z.enum(["ios", "junos"]),
    before_sha256: hash,
    after_sha256: hash,
    before_line_count: z.number().int().min(1).max(10000),
    after_line_count: z.number().int().min(1).max(10000),
    changes: z.array(changeSpan).min(1).max(128),
    status: z.literal("draft"),
  })
  .refine((row) => {
    if (
      row.before_sha256 === row.after_sha256 ||
      row.platform !== (row.vendor === "cisco" ? "ios" : "junos")
    )
      return false;
    let old = 0,
      next = 0;
    for (const span of row.changes) {
      if (
        span.before_start < old ||
        span.after_start < next ||
        span.before_start - old !== span.after_start - next ||
        span.before_end > row.before_line_count ||
        span.after_end > row.after_line_count
      )
        return false;
      old = span.before_end;
      next = span.after_end;
    }
    return row.before_line_count - old === row.after_line_count - next;
  });
const reviewSchema = z
  .strictObject({
    version: z.literal("patch-review-0.1.0"),
    proposal: proposalSchema,
    preflight: preflightSchema,
    status: z.literal("needs_review"),
    validation_blockers: z.array(z.string()).max(16),
  })
  .refine((row) => {
    const p = row.proposal,
      r = row.preflight;
    return (
      p.device_id === r.device_id &&
      p.reference_id === r.reference_id &&
      p.before_sha256 === r.before.source_sha256 &&
      p.after_sha256 === r.after.source_sha256 &&
      same(row.validation_blockers, localBlockers(r))
    );
  });
export const nativeVendorDraftSchema = z
  .strictObject({
    version: z.literal("vendor-patch-draft-0.1.0"),
    category: z.literal("management.telnet_enabled"),
    selected_finding_sha256: hash,
    policy_catalog_version: catalog,
    edits: z.array(edit).min(1).max(128),
    review: reviewSchema,
    application_supported: z.literal(false),
    device_syntax_verified: z.literal(false),
    management_access_verified: z.literal(false),
    rollback_plan: z.literal("retain_and_review_exact_before_snapshot"),
  })
  .refine((row) => {
    const report = row.review.preflight,
      proposal = row.review.proposal;
    const selected = report.before_policy_findings.filter(
      (f) => f.category === row.category,
    );
    const lines = row.edits.map((e) => e.source_line);
    return (
      selected.length === 1 &&
      report.policy_catalog_version === row.policy_catalog_version &&
      report.before.complete &&
      report.after.complete &&
      report.policy_changes !== null &&
      report.policy_changes.introduced.length === 0 &&
      !report.after_policy_findings.some((f) => f.category === row.category) &&
      same(selected[0]!.affected_lines, lines) &&
      lines.every((n, i) => i === 0 || n > lines[i - 1]!) &&
      row.edits.every(
        (e) =>
          e.source_line <= proposal.before_line_count &&
          e.kind ===
            (proposal.vendor === "cisco"
              ? "cisco_vty_ssh_only"
              : "junos_remove_telnet"),
      ) &&
      (proposal.vendor !== "juniper" || row.edits.length === 1) &&
      row.edits.every(
        (e, i) =>
          !e.vty ||
          row.edits
            .slice(0, i)
            .every(
              (old) =>
                !old.vty ||
                e.vty!.first > old.vty.last ||
                e.vty!.last < old.vty.first,
            ),
      )
    );
  });
export type NativeVendorDraft = z.infer<typeof nativeVendorDraftSchema>;
// Derive commands only from typed edit kinds and numeric VTY ranges. Server text is never executable presentation.
export function nativeCommands(metadata: NativeVendorDraft): string[] {
  return metadata.edits.flatMap((e) =>
    e.kind === "cisco_vty_ssh_only" && e.vty
      ? [`line vty ${e.vty.first} ${e.vty.last}`, "transport input ssh", "exit"]
      : ["delete system services telnet"],
  );
}
export const nativePatchCandidateSchema = z
  .strictObject({
    version: z.literal("native-patch-candidate-0.1.0"),
    candidate_id: id,
    configuration_id: id,
    request: generateNativePatchSchema,
    source: binding,
    analysis_created_at: timestamp,
    selected_finding: finding,
    created_at: timestamp,
    service_role: z.enum(["engineer", "admin"]),
    generator_kind: z.literal("deterministic_vendor"),
    generator_version: z.literal("native-telnet-generator-0.1.0"),
    metadata: nativeVendorDraftSchema,
    native_commands: z.array(z.string().max(80)).min(1).max(384),
    local_reference: z.literal("selected_original_not_approved_baseline"),
    status: z.literal("needs_review"),
    formal_qualification: z.literal("not_proven"),
    calibrated: z.literal(false),
    quality_proven: z.literal(false),
    individual_identity_verified: z.literal(false),
    approved: z.literal(false),
    applied: z.literal(false),
    validation_blockers: z.array(z.string()).length(nativePatchBlockers.length),
    review_json: z
      .string()
      .min(2)
      .max(512 * 1024),
    review_sha256: hash,
  })
  .refine((row) => {
    const request = row.request,
      source = row.source,
      metadata = row.metadata;
    const proposal = metadata.review.proposal,
      report = metadata.review.preflight,
      selected = row.selected_finding;
    return (
      request.candidate_id === row.candidate_id &&
      row.configuration_id === source.configuration_id &&
      request.source_sha256 === source.source_sha256 &&
      proposal.before_sha256 === source.source_sha256 &&
      proposal.reference_id === row.configuration_id &&
      proposal.device_id === source.device_id &&
      selected.device_id === source.device_id &&
      selected.finding_id === request.finding_id &&
      selected.category === "management.telnet_enabled" &&
      selected.detector === "policy_engine" &&
      selected.model_version === request.policy_catalog_version &&
      metadata.selected_finding_sha256 === request.finding_sha256 &&
      report.before_policy_findings.some((f) => same(f, selected)) &&
      new Set(report.before_policy_findings.map((f) => f.finding_id)).size ===
        report.before_policy_findings.length &&
      new Set(report.after_policy_findings.map((f) => f.finding_id)).size ===
        report.after_policy_findings.length &&
      same(row.native_commands, nativeCommands(metadata)) &&
      same(row.validation_blockers, nativePatchBlockers) &&
      evidenceInstant(source.created_at) <=
        evidenceInstant(row.analysis_created_at) &&
      evidenceInstant(row.analysis_created_at) <=
        evidenceInstant(row.created_at) &&
      new TextEncoder().encode(row.review_json).length <= 512 * 1024 &&
      new TextEncoder().encode(JSON.stringify(row)).length <= 2 * 1024 * 1024
    );
  });
export type NativePatchCandidate = z.infer<typeof nativePatchCandidateSchema>;
export const nativePatchSummarySchema = z.strictObject({
  version: z.literal("native-patch-summary-0.1.0"),
  candidate_id: id,
  configuration_id: id,
  analysis_id: id,
  finding_id: id,
  created_at: timestamp,
  service_role: z.enum(["engineer", "admin"]),
  generator_version: z.literal("native-telnet-generator-0.1.0"),
  review_sha256: hash,
  status: z.literal("needs_review"),
  formal_qualification: z.literal("not_proven"),
  individual_identity_verified: z.literal(false),
  approved: z.literal(false),
  applied: z.literal(false),
});
export type NativePatchSummary = z.infer<typeof nativePatchSummarySchema>;
export function nativeSelectionBound(
  row: NativePatchSelection,
  analysis: AnalysisResult,
) {
  const telnet = analysis.findings.filter(
    (f) =>
      f.detector === "policy_engine" &&
      f.category === "management.telnet_enabled",
  );
  return (
    row.configuration_id === analysis.configuration_id &&
    row.source.device_id === analysis.device_id &&
    row.source.source_sha256 === analysis.source_sha256 &&
    row.analysis_id === analysis.analysis_id &&
    evidenceInstant(row.analysis_created_at) ===
      evidenceInstant(analysis.created_at) &&
    row.policy_catalog_version === analysis.policy_catalog_version &&
    same(
      row.finding_pins.map((f) => f.finding_id).sort(),
      telnet.map((f) => f.finding_id).sort(),
    ) &&
    row.finding_pins.every((pin) =>
      analysis.explanations.some(
        (e) =>
          e.finding_id === pin.finding_id &&
          e.finding_sha256 === pin.finding_sha256,
      ),
    )
  );
}
export function nativePatchRequest(
  selection: NativePatchSelection,
  selected: Finding,
  candidate_id: string,
): GenerateNativePatch {
  const pin = selection.finding_pins.find(
    (row) => row.finding_id === selected.finding_id,
  );
  return generateNativePatchSchema.parse({
    version: "native-patch-request-0.1.0",
    candidate_id,
    analysis_id: selection.analysis_id,
    finding_id: selected.finding_id,
    finding_sha256: pin?.finding_sha256,
    analysis_sha256: selection.analysis_sha256,
    source_sha256: selection.source.source_sha256,
    canonical_sha256: selection.canonical_sha256,
    policy_catalog_version: selection.policy_catalog_version,
    allow_local_native_generation: true,
    allow_private_candidate_retention: true,
  });
}
export function nativeCandidateBound(
  row: NativePatchCandidate,
  analysis: AnalysisResult,
  selected: Finding,
  selection?: NativePatchSelection,
) {
  return (
    row.configuration_id === analysis.configuration_id &&
    row.source.device_id === analysis.device_id &&
    row.source.source_sha256 === analysis.source_sha256 &&
    row.request.analysis_id === analysis.analysis_id &&
    evidenceInstant(row.analysis_created_at) ===
      evidenceInstant(analysis.created_at) &&
    same(row.selected_finding, selected) &&
    row.request.policy_catalog_version === analysis.policy_catalog_version &&
    same(
      row.metadata.review.preflight.before_policy_findings
        .map(stableJson)
        .sort(),
      analysis.findings
        .filter((f) => f.detector === "policy_engine")
        .map(stableJson)
        .sort(),
    ) &&
    (!selection ||
      (nativeSelectionBound(selection, analysis) &&
        same(row.source, selection.source) &&
        row.request.analysis_sha256 === selection.analysis_sha256 &&
        row.request.canonical_sha256 === selection.canonical_sha256 &&
        selection.finding_pins.some(
          (p) =>
            p.finding_id === selected.finding_id &&
            p.finding_sha256 === row.request.finding_sha256,
        )))
  );
}
export function nativeSummaryMatches(
  row: NativePatchCandidate,
  summary: NativePatchSummary,
) {
  return (
    summary.candidate_id === row.candidate_id &&
    summary.configuration_id === row.configuration_id &&
    summary.analysis_id === row.request.analysis_id &&
    summary.finding_id === row.request.finding_id &&
    evidenceInstant(summary.created_at) === evidenceInstant(row.created_at) &&
    summary.service_role === row.service_role &&
    summary.generator_version === row.generator_version &&
    summary.review_sha256 === row.review_sha256
  );
}
async function digest(raw: string, algorithm = "SHA-256") {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest(algorithm, new TextEncoder().encode(raw)),
    ),
  ]
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
}
export async function nativeProofMatches(row: NativePatchCandidate) {
  try {
    const { review_json, review_sha256, ...body } = row;
    if (
      evidenceRawJsonAt(review_json, []) === undefined ||
      !same(JSON.parse(review_json), body) ||
      (await digest(review_json)) !== review_sha256
    )
      return false;
    const rawFinding = evidenceRawJsonAt(review_json, ["selected_finding"]);
    // Python finding fingerprints use ensure_ascii=True; preserve its numeric wire tokens.
    if (
      !rawFinding ||
      (await digest(
        rawFinding.replace(
          /[\u007f-\uffff]/g,
          (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
        ),
      )) !== row.request.finding_sha256
    )
      return false;
    const { proposal_id, ...proposal } = row.metadata.review.proposal;
    const namespace = "2fbda00ae6a44e899666c961c61b3a18";
    const ns = Uint8Array.from(namespace.match(/../g)!, (n) =>
      Number.parseInt(n, 16),
    );
    const json = new TextEncoder().encode(stableJson(proposal));
    const bytes = new Uint8Array(ns.length + json.length);
    bytes.set(ns);
    bytes.set(json, ns.length);
    const uuid = new Uint8Array(
      await crypto.subtle.digest("SHA-1", bytes),
    ).slice(0, 16);
    uuid[6] = (uuid[6]! & 15) | 80;
    uuid[8] = (uuid[8]! & 63) | 128;
    const h = [...uuid].map((n) => n.toString(16).padStart(2, "0")).join("");
    return (
      proposal_id ===
      `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
    );
  } catch {
    return false;
  }
}
