import { createHash } from "node:crypto";
import { stableJson, snapshotSchema } from "../../src/contracts";
import { nativePatchCandidateSchema } from "../../src/nativePatches";
import { nativeMaterializationSchema } from "../../src/nativeMaterializations";
import { patchDraftSchema } from "../../src/patches";
import { diffSelection } from "../../src/diff";
import { nativeControls } from "./native-patches-fixtures";

// Authored transport controls. They do not establish backend execution or quality.
export function materializationControl(index = 0) {
  const control = nativeControls[index]!;
  const candidate = nativePatchCandidateSchema.parse(
    structuredClone(control.candidate),
  );
  const afterId = index
    ? "cc4d4e88-ed8f-4862-a6ce-a91f5d85a31a"
    : "b19270f2-e8a9-46fe-b31d-012d08895733";
  const patchId = index
    ? "736866ab-2f76-428b-a02f-cd5f76690556"
    : "a7c014ef-724a-43a2-a299-be9b042ce13a";
  const created_at = "2026-10-26T11:00:00.123456Z";
  const after = snapshotSchema.parse(structuredClone(control.snapshot));
  after.configuration_id = afterId;
  after.created_at = created_at;
  after.canonical.source.sha256 =
    candidate.metadata.review.proposal.after_sha256;
  after.canonical.source.filename = "native-candidate.cfg";
  if (after.parser_coverage)
    after.parser_coverage.source_sha256 = after.canonical.source.sha256;
  (after.canonical.management as Record<string, unknown>).telnet_enabled =
    false;
  const draft = patchDraftSchema.parse({
    version: "snapshot-patch-draft-0.1.0",
    patch_id: patchId,
    created_at,
    draft_sha256: "d".repeat(64),
    status: "draft",
    representation: "normalized_objects",
    requires_human_review: true,
    diff: {
      version: "snapshot-diff-0.1.0",
      representation: "normalized_objects",
      before: {
        ...diffSelection(snapshotSchema.parse(control.snapshot)),
        projection_sha256: "a".repeat(64),
      },
      after: { ...diffSelection(after), projection_sha256: "b".repeat(64) },
      coverage: "supported_complete",
      source_changed: true,
      added_count: 0,
      removed_count: 0,
      modified_count: 1,
      changes: [
        {
          section: "management",
          object_key: ["management"],
          kind: "modified",
          before_value: { telnet_enabled: true },
          after_value: { telnet_enabled: false },
          before_locations: [],
          after_locations: [],
        },
      ],
      limitations: ["Authored normalized-object transport control."],
    },
  });
  const body = {
    version: "native-materialization-0.1.0",
    candidate_id: candidate.candidate_id,
    configuration_id: candidate.configuration_id,
    request: {
      version: "native-materialization-request-0.1.0",
      after_configuration_id: afterId,
      patch_id: patchId,
      native_review_sha256: candidate.review_sha256,
      allow_local_source_materialization: true,
      allow_private_candidate_source_retention: true,
    },
    native_review_sha256: candidate.review_sha256,
    created_at,
    service_role: "engineer",
    before: candidate.source,
    after: {
      configuration_id: afterId,
      device_id: after.device_id,
      source_sha256: after.canonical.source.sha256,
      created_at,
    },
    after_canonical_sha256: "c".repeat(64),
    patch_id: patchId,
    draft_sha256: draft.draft_sha256,
    representation: "normalized_objects",
    origin: "generated_native_candidate",
    status: "draft_created",
    formal_qualification: "not_proven",
    fresh_policy_recheck_performed: false,
    model_recheck_performed: false,
    network_verification_performed: false,
    individual_identity_verified: false,
    approved: false,
    applied: false,
  };
  const review_json = stableJson(body);
  const materialization = nativeMaterializationSchema.parse({
    ...body,
    review_json,
    review_sha256: createHash("sha256").update(review_json).digest("hex"),
  });
  return { ...control, candidate, after, draft, materialization };
}
