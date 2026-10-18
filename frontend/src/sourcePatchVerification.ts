import { z } from "zod";
import { stableJson } from "./contracts";
import type { ConfigurationSummary } from "./contracts";
import { preflightSchema } from "./patches";
import type { PatchDraft } from "./patches";
import { batfishSchema, scopeSchema } from "./modelReviews";

const id = z.guid();
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true });
const same = (left: unknown, right: unknown) =>
  stableJson(left) === stableJson(right);
export const sourcePatchCapabilitiesSchema = z.strictObject({
  version: z.literal("source-patch-capabilities-0.1.0"),
  network_engine: z.enum(["disabled", "configured"]),
  health_checked: z.literal(false),
  exact_retained_sources_required: z.literal(true),
  request_consent_required: z.literal(true),
  maximum_devices: z.literal(32),
  maximum_network_bytes: z.literal(8388608),
  ml_status: z.literal("not_run"),
});
export type SourcePatchCapabilities = z.infer<
  typeof sourcePatchCapabilitiesSchema
>;
export const verifySourcePatchSchema = z
  .strictObject({
    version: z
      .literal("source-patch-request-0.1.0")
      .default("source-patch-request-0.1.0"),
    verification_id: id,
    draft_sha256: hash,
    companions: z
      .array(z.strictObject({ configuration_id: id, source_sha256: hash }))
      .max(31)
      .default([]),
    scope: scopeSchema,
    allow_local_engine_upload: z.boolean().default(false),
  })
  .refine(
    (value) =>
      new Set(value.companions.map((row) => row.configuration_id)).size ===
      value.companions.length,
  );
export type VerifySourcePatch = z.infer<typeof verifySourcePatchSchema>;
const memberSchema = z.strictObject({
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
  canonical_sha256: hash,
  hostname: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  platform: z.enum(["ios", "junos"]),
});
type SourcePatchMember = z.infer<typeof memberSchema>;
const intentSchema = z
  .strictObject({
    version: z.literal("source-patch-intent-0.1.0"),
    patch_id: id,
    request: verifySourcePatchSchema,
    created_at: timestamp,
    before: memberSchema,
    after: memberSchema,
    companions: z.array(memberSchema).max(31),
    before_network_sha256: hash,
    after_network_sha256: hash,
    preflight: preflightSchema,
  })
  .refine((value) => {
    const { before, after, companions, request, preflight } = value;
    const members = [before, ...companions];
    return (
      before.configuration_id !== after.configuration_id &&
      before.device_id === after.device_id &&
      before.hostname === after.hostname &&
      before.platform === after.platform &&
      before.source_sha256 !== after.source_sha256 &&
      Date.parse(before.created_at) <= Date.parse(after.created_at) &&
      [...members, after].every(
        (row) => Date.parse(row.created_at) <= Date.parse(value.created_at),
      ) &&
      request.allow_local_engine_upload === true &&
      new Set(members.map((row) => row.device_id)).size === members.length &&
      new Set(members.map((row) => row.hostname.toLowerCase())).size ===
        members.length &&
      same(
        companions.map(({ configuration_id, source_sha256 }) => ({
          configuration_id,
          source_sha256,
        })),
        request.companions,
      ) &&
      members.some((row) => row.hostname === request.scope.start_node) &&
      preflight.device_id === before.device_id &&
      preflight.reference_id === before.configuration_id &&
      preflight.before.source_sha256 === before.source_sha256 &&
      preflight.after.source_sha256 === after.source_sha256 &&
      preflight.before.complete &&
      preflight.after.complete
    );
  });
const outcomeSchema = z.strictObject({
  version: z.literal("source-patch-outcome-0.1.0"),
  verification_id: id,
  intent_sha256: hash,
  completed_at: timestamp,
  network_result: batfishSchema,
});
export const sourcePatchVerificationSchema = z
  .strictObject({
    version: z.literal("source-patch-verification-0.1.0"),
    verification_id: id,
    patch_id: id,
    draft_sha256: hash,
    intent: intentSchema,
    outcome: outcomeSchema.nullable(),
    execution_status: z.enum(["pending_unknown", "completed"]),
    validation_blockers: z.array(z.string().min(1)).max(64),
    review_json: z
      .string()
      .min(1)
      .max(4 * 1024 * 1024),
    review_sha256: hash,
    status: z.literal("needs_review"),
    ml_status: z.literal("not_run"),
    approved: z.literal(false),
    applied: z.literal(false),
  })
  .refine((value) => {
    const { intent, outcome } = value;
    return (
      value.verification_id === intent.request.verification_id &&
      value.patch_id === intent.patch_id &&
      value.draft_sha256 === intent.request.draft_sha256 &&
      value.execution_status === (outcome ? "completed" : "pending_unknown") &&
      same(value.validation_blockers, sourceValidationBlockers(value)) &&
      (!outcome ||
        (outcome.verification_id === value.verification_id &&
          Date.parse(outcome.completed_at) >= Date.parse(intent.created_at) &&
          outcome.network_result.before_sha256 ===
            intent.before_network_sha256 &&
          outcome.network_result.after_sha256 === intent.after_network_sha256 &&
          same(outcome.network_result.scope, intent.request.scope)))
    );
  });
export type SourcePatchVerification = z.infer<
  typeof sourcePatchVerificationSchema
>;
export function sourceValidationBlockers(value: {
  intent: z.infer<typeof intentSchema>;
  outcome: z.infer<typeof outcomeSchema> | null;
}): string[] {
  const result = [
    "device_syntax_not_verified",
    "management_access_not_verified",
    "rollback_not_verified",
    "selected_ml_not_run",
    "baseline_approval_not_proven",
    "individual_engineer_review_required",
  ];
  const network = value.outcome?.network_result;
  if (!network) result.push("network_execution_unknown");
  else if (network.status !== "no_differences_in_scope")
    result.push("formal_scope_not_passed");
  if (network?.cleanup_complete !== true)
    result.push("engine_cleanup_not_confirmed");
  if (
    !value.intent.preflight.policy_changes ||
    value.intent.preflight.policy_changes.introduced.length
  )
    result.push("policy_regression_or_missing_comparison");
  return result;
}
export const sourcePatchVerificationSummarySchema = z
  .strictObject({
    version: z.literal("source-patch-verification-summary-0.1.0"),
    verification_id: id,
    patch_id: id,
    draft_sha256: hash,
    review_sha256: hash,
    created_at: timestamp,
    completed_at: timestamp.nullable(),
    execution_status: z.enum(["pending_unknown", "completed"]),
    network_status: batfishSchema.shape.status.nullable(),
    cleanup_complete: z.boolean().nullable(),
    status: z.literal("needs_review"),
  })
  .refine((value) =>
    value.execution_status === "completed"
      ? value.network_status !== null &&
        value.completed_at !== null &&
        Date.parse(value.completed_at) >= Date.parse(value.created_at)
      : value.network_status === null &&
        value.completed_at === null &&
        value.cleanup_complete === null,
  );
export type SourcePatchVerificationSummary = z.infer<
  typeof sourcePatchVerificationSummarySchema
>;
export async function sourceNetworkDigest(members: SourcePatchMember[]) {
  const rows = [...members]
    .sort((a, b) =>
      a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0,
    )
    .map((row) => [
      row.device_id,
      row.hostname,
      row.platform,
      row.source_sha256,
    ]);
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(rows)),
  );
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
export function sourceSummaryBound(
  row: SourcePatchVerificationSummary,
  draft: PatchDraft,
) {
  return (
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    Date.parse(row.created_at) >= Date.parse(draft.created_at)
  );
}
export async function sourceVerificationBound(
  row: SourcePatchVerification,
  draft: PatchDraft,
  expected?: VerifySourcePatch,
  summary?: SourcePatchVerificationSummary,
) {
  const { intent, outcome } = row;
  const pair = [
    [intent.before, draft.diff.before, intent.preflight.before],
    [intent.after, draft.diff.after, intent.preflight.after],
  ] as const;
  return (
    (await sourceReviewProofMatches(row)) &&
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    Date.parse(intent.created_at) >= Date.parse(draft.created_at) &&
    pair.every(
      ([member, target, parsed]) =>
        member.configuration_id === target.configuration_id &&
        member.device_id === target.device_id &&
        member.source_sha256 === target.source_sha256 &&
        Date.parse(member.created_at) === Date.parse(target.created_at) &&
        member.hostname === target.hostname &&
        member.platform === target.platform &&
        parsed.confidence === target.parser_confidence &&
        parsed.warning_count === target.warning_count &&
        parsed.unparsed_count === target.unparsed_count,
    ) &&
    (!expected || same(intent.request, expected)) &&
    (!summary ||
      (sourceSummaryBound(summary, draft) &&
        summary.verification_id === row.verification_id &&
        summary.review_sha256 === row.review_sha256 &&
        Date.parse(summary.created_at) === Date.parse(intent.created_at) &&
        summary.completed_at === (outcome?.completed_at ?? null) &&
        summary.execution_status === row.execution_status &&
        summary.network_status === (outcome?.network_result.status ?? null) &&
        summary.cleanup_complete ===
          (outcome?.network_result.cleanup_complete ?? null))) &&
    (await sourceNetworkDigest([intent.before, ...intent.companions])) ===
      intent.before_network_sha256 &&
    (await sourceNetworkDigest([intent.after, ...intent.companions])) ===
      intent.after_network_sha256
  );
}
async function textDigest(value: string) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
export async function sourceReviewProofMatches(row: SourcePatchVerification) {
  const { review_json, review_sha256, ...body } = row;
  try {
    const objects: (Set<string> | null)[] = [];
    const tokens = [
      ...review_json.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,]+/gu),
    ];
    let intentStart = -1,
      rawIntent: string | undefined;
    for (let i = 0; i < tokens.length; i++) {
      const match = tokens[i]!,
        token = match[0];
      if (token === "{") objects.push(new Set());
      else if (token === "[") objects.push(null);
      else if (token === "}" || token === "]") {
        if (objects.length === 2 && intentStart >= 0 && rawIntent === undefined)
          rawIntent = review_json.slice(intentStart, match.index + 1);
        objects.pop();
      } else if (token.startsWith('"') && tokens[i + 1]?.[0] === ":") {
        const keys = objects.at(-1);
        const key = JSON.parse(token) as string;
        if (!keys || keys.has(key)) return false;
        keys.add(key);
        if (objects.length === 1 && key === "intent") {
          const start = tokens[i + 2];
          if (start?.[0] !== "{") return false;
          intentStart = start.index;
        }
      }
    }
    if (!same(JSON.parse(review_json), body)) return false;
    // The server's normative JSON is the proof. Re-encoding floats or Unicode
    // with JavaScript would change valid Python wire bytes (for example 1.0).
    return (
      rawIntent !== undefined &&
      (await textDigest(review_json)) === review_sha256 &&
      (!row.outcome ||
        (await textDigest(rawIntent)) === row.outcome.intent_sha256)
    );
  } catch {
    return false;
  }
}
export function sourceCompanionEligible(
  row: ConfigurationSummary,
  draft: PatchDraft,
  selected: ConfigurationSummary[],
) {
  return (
    row.device_id !== draft.diff.before.device_id &&
    row.hostname !== null &&
    /^[A-Za-z0-9_-]{1,128}$/.test(row.hostname) &&
    row.hostname.toLowerCase() !== draft.diff.before.hostname?.toLowerCase() &&
    ["ios", "junos"].includes(row.platform) &&
    row.parser_confidence === 1 &&
    row.warning_count === 0 &&
    row.unparsed_count === 0 &&
    selected.every(
      (item) =>
        item.configuration_id === row.configuration_id ||
        (item.device_id !== row.device_id &&
          item.hostname?.toLowerCase() !== row.hostname?.toLowerCase()),
    ) &&
    (selected.length < 31 ||
      selected.some((item) => item.configuration_id === row.configuration_id))
  );
}
export const sourceNetworkStatusNames = {
  unavailable: "Сетевой движок недоступен",
  error: "Ошибка сетевой проверки",
  incomplete: "Сетевой разбор неполон",
  inconclusive: "Достижимая область пуста: вывод не определён",
  differences_found: "В выбранной области найдены различия достижимости",
  no_differences_in_scope: "В выбранной достижимой области различий нет",
};
