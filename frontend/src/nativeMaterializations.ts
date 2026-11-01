import { z } from "zod";
import { snapshotBindingSchema, stableJson } from "./contracts";
import type { ConfigurationSnapshot } from "./contracts";
import type { NativePatchCandidate } from "./nativePatches";
import type { PatchDraft } from "./patches";
import { evidenceInstant, evidenceRawJsonAt } from "./sourceEvidenceReports";

const id = z.guid(),
  hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
const binding = snapshotBindingSchema
  .strict()
  .extend({ created_at: timestamp });
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
export const createNativeMaterializationSchema = z.strictObject({
  version: z.literal("native-materialization-request-0.1.0"),
  after_configuration_id: id,
  patch_id: id,
  native_review_sha256: hash,
  allow_local_source_materialization: z.literal(true),
  allow_private_candidate_source_retention: z.literal(true),
});
export type CreateNativeMaterialization = z.infer<
  typeof createNativeMaterializationSchema
>;
export const nativeMaterializationSchema = z
  .strictObject({
    version: z.literal("native-materialization-0.1.0"),
    candidate_id: id,
    configuration_id: id,
    request: createNativeMaterializationSchema,
    native_review_sha256: hash,
    created_at: timestamp,
    service_role: z.enum(["engineer", "admin"]),
    before: binding,
    after: binding,
    after_canonical_sha256: hash,
    patch_id: id,
    draft_sha256: hash,
    representation: z.literal("normalized_objects"),
    origin: z.literal("generated_native_candidate"),
    status: z.literal("draft_created"),
    formal_qualification: z.literal("not_proven"),
    fresh_policy_recheck_performed: z.literal(false),
    model_recheck_performed: z.literal(false),
    network_verification_performed: z.literal(false),
    individual_identity_verified: z.literal(false),
    approved: z.literal(false),
    applied: z.literal(false),
    review_json: z
      .string()
      .min(2)
      .max(512 * 1024),
    review_sha256: hash,
  })
  .refine(
    (row) =>
      row.configuration_id === row.before.configuration_id &&
      row.after.configuration_id === row.request.after_configuration_id &&
      row.patch_id === row.request.patch_id &&
      row.native_review_sha256 === row.request.native_review_sha256 &&
      row.before.configuration_id !== row.after.configuration_id &&
      row.before.device_id === row.after.device_id &&
      row.before.source_sha256 !== row.after.source_sha256 &&
      evidenceInstant(row.before.created_at) <=
        evidenceInstant(row.created_at) &&
      evidenceInstant(row.after.created_at) ===
        evidenceInstant(row.created_at) &&
      new TextEncoder().encode(row.review_json).length <= 512 * 1024 &&
      new TextEncoder().encode(JSON.stringify(row)).length <= 1024 * 1024,
  );
export type NativeMaterialization = z.infer<typeof nativeMaterializationSchema>;
export function nativeMaterializationRequest(
  candidate: NativePatchCandidate,
): CreateNativeMaterialization {
  return createNativeMaterializationSchema.parse({
    version: "native-materialization-request-0.1.0",
    after_configuration_id: crypto.randomUUID(),
    patch_id: crypto.randomUUID(),
    native_review_sha256: candidate.review_sha256,
    allow_local_source_materialization: true,
    allow_private_candidate_source_retention: true,
  });
}
export function nativeMaterializationBound(
  row: NativeMaterialization,
  candidate: NativePatchCandidate,
) {
  return (
    row.candidate_id === candidate.candidate_id &&
    row.configuration_id === candidate.configuration_id &&
    same(row.before, candidate.source) &&
    row.native_review_sha256 === candidate.review_sha256 &&
    row.after.source_sha256 ===
      candidate.metadata.review.proposal.after_sha256 &&
    evidenceInstant(row.created_at) >= evidenceInstant(candidate.created_at) &&
    evidenceInstant(row.created_at) >=
      evidenceInstant(candidate.analysis_created_at)
  );
}
export function nativeOriginSnapshotBound(
  row: NativeMaterialization,
  snapshot: ConfigurationSnapshot,
) {
  return (
    row.after.configuration_id === snapshot.configuration_id &&
    row.after.device_id === snapshot.device_id &&
    row.after.source_sha256 === snapshot.canonical.source.sha256 &&
    evidenceInstant(row.after.created_at) ===
      evidenceInstant(snapshot.created_at)
  );
}
export function nativeOriginDraftBound(
  row: NativeMaterialization,
  draft: PatchDraft,
) {
  const bound = (a: typeof row.before, b: typeof draft.diff.before) =>
    a.configuration_id === b.configuration_id &&
    a.device_id === b.device_id &&
    a.source_sha256 === b.source_sha256 &&
    evidenceInstant(a.created_at) === evidenceInstant(b.created_at);
  return (
    row.patch_id === draft.patch_id &&
    row.draft_sha256 === draft.draft_sha256 &&
    evidenceInstant(row.created_at) === evidenceInstant(draft.created_at) &&
    bound(row.before, draft.diff.before) &&
    bound(row.after, draft.diff.after)
  );
}
export async function nativeMaterializationProofMatches(
  row: NativeMaterialization,
) {
  try {
    const { review_json, review_sha256, ...body } = row;
    if (
      evidenceRawJsonAt(review_json, []) === undefined ||
      review_json !== stableJson(body)
    )
      return false;
    const digest = [
      ...new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(review_json),
        ),
      ),
    ]
      .map((n) => n.toString(16).padStart(2, "0"))
      .join("");
    return digest === review_sha256;
  } catch {
    return false;
  }
}
