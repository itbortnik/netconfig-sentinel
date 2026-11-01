import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { rolePermissions, stableJson } from "./contracts";
import {
  createNativeMaterializationSchema,
  nativeMaterializationSchema,
  nativeMaterializationBound,
  nativeOriginSnapshotBound,
  nativeOriginDraftBound,
  nativeMaterializationProofMatches,
  nativeMaterializationRequest,
} from "./nativeMaterializations";
import { materializationControl } from "../tests/browser/native-materialization-fixtures";

const sha = (wire: string) => createHash("sha256").update(wire).digest("hex");
it.each([0, 1])(
  "binds authored vendor %i transport, nested snapshots and draft without promoting assurances",
  async (index) => {
    const c = materializationControl(index),
      r = c.materialization;
    expect(await nativeMaterializationProofMatches(r)).toBe(true);
    expect(nativeMaterializationBound(r, c.candidate)).toBe(true);
    expect(nativeOriginSnapshotBound(r, c.after)).toBe(true);
    expect(nativeOriginDraftBound(r, c.draft)).toBe(true);
    expect(nativeMaterializationRequest(c.candidate)).toMatchObject({
      native_review_sha256: c.candidate.review_sha256,
      allow_local_source_materialization: true,
      allow_private_candidate_source_retention: true,
    });
  },
);
it.each([
  { version: undefined },
  { version: "native-materialization-request-0.2.0" },
  { allow_local_source_materialization: false },
  { allow_local_source_materialization: 1 },
  { allow_private_candidate_source_retention: false },
  { allow_private_candidate_source_retention: "true" },
  { after_configuration_id: "invalid" },
  { native_review_sha256: "a".repeat(63) },
  { candidate_text: "secret" },
  { approved: true },
  { origin: "observed" },
])(
  "rejects invalid consent, arbitrary text and caller assertions %j",
  (update) => {
    expect(
      createNativeMaterializationSchema.safeParse({
        ...materializationControl().materialization.request,
        ...update,
      }).success,
    ).toBe(false);
  },
);
it.each([
  { fresh_policy_recheck_performed: true },
  { fresh_policy_recheck_performed: 0 },
  { model_recheck_performed: "false" },
  { network_verification_performed: true },
  { individual_identity_verified: 0 },
  { approved: true },
  { applied: false, extra: true },
  { formal_qualification: "passed" },
  { status: "validated" },
  { origin: "uploaded" },
  { created_at: "2026-10-26T11:00:00" },
  { created_at: "2000-01-01T00:00:00Z" },
  { patch_id: "a7c014ef-724a-43a2-a299-be9b042ce13b" },
  { native_review_sha256: "a".repeat(64) },
])("rejects assurance, binding and timestamp drift %j", (update) => {
  expect(
    nativeMaterializationSchema.safeParse({
      ...materializationControl().materialization,
      ...update,
    }).success,
  ).toBe(false);
});
it("rejects nested extra keys and changed device, source, identity or microsecond time", () => {
  const c = materializationControl();
  for (const update of [
    { device_id: crypto.randomUUID() },
    { configuration_id: c.materialization.configuration_id },
    { source_sha256: c.materialization.before.source_sha256 },
    { created_at: "2026-10-26T11:00:00.123455Z" },
    { extra: "secret" },
  ])
    expect(
      nativeMaterializationSchema.safeParse({
        ...c.materialization,
        after: { ...c.materialization.after, ...update },
      }).success,
    ).toBe(false);
  expect(
    nativeMaterializationSchema.safeParse({
      ...c.materialization,
      request: { ...c.materialization.request, extra: true },
    }).success,
  ).toBe(false);
  expect(
    nativeMaterializationBound(
      { ...c.materialization, native_review_sha256: "f".repeat(64) },
      c.candidate,
    ),
  ).toBe(false);
  expect(
    nativeOriginSnapshotBound(c.materialization, {
      ...c.after,
      configuration_id: crypto.randomUUID(),
    }),
  ).toBe(false);
  expect(
    nativeOriginDraftBound(c.materialization, {
      ...c.draft,
      draft_sha256: "f".repeat(64),
    }),
  ).toBe(false);
});
it("rejects malformed, duplicate, noncanonical, oversized and mismatched proof", async () => {
  const original = materializationControl().materialization;
  for (const proof of [
    original.review_json + " ",
    original.review_json.replace('{"after":', '{"approved":false,"after":'),
    "{",
    original.review_json.replace('"not_proven"', '"proven"'),
  ])
    expect(
      await nativeMaterializationProofMatches({
        ...original,
        review_json: proof,
        review_sha256: sha(proof),
      }),
    ).toBe(false);
  expect(
    await nativeMaterializationProofMatches({
      ...original,
      review_sha256: "f".repeat(64),
    }),
  ).toBe(false);
  expect(
    nativeMaterializationSchema.safeParse({
      ...original,
      review_json: "я".repeat(300000),
    }).success,
  ).toBe(false);
});
it("uses exact v2 routes and stable explicit create/read intent; reader cannot create", async () => {
  const c = materializationControl(),
    r = c.materialization;
  const transport = vi
    .fn()
    .mockImplementation(async () => new Response(JSON.stringify(r)));
  const client = new ApiClient(
    "authored-native-materialization-unit-token",
    transport,
  );
  await expect(
    client.createNativeMaterialization(
      r.configuration_id,
      r.candidate_id,
      r.request,
    ),
  ).rejects.toMatchObject({ status: 403 });
  expect(transport).not.toHaveBeenCalled();
  transport.mockResolvedValueOnce(
    new Response(
      JSON.stringify({
        version: "service-access-0.3.0",
        role: "engineer",
        permissions: rolePermissions.engineer,
        individual_identity_verified: false,
        device_scope: "all_saved_devices",
      }),
    ),
  );
  await client.access();
  await expect(
    client.createNativeMaterialization(
      r.configuration_id,
      r.candidate_id,
      r.request,
    ),
  ).resolves.toEqual(r);
  expect(transport.mock.calls.at(-1)?.[0]).toBe(
    `/api/v2/configurations/${r.configuration_id}/native-patches/${r.candidate_id}/materialization`,
  );
  expect(transport.mock.calls.at(-1)?.[1]).toMatchObject({
    method: "POST",
    body: JSON.stringify(r.request),
  });
  await expect(
    client.getNativeMaterialization(r.configuration_id, r.candidate_id),
  ).resolves.toEqual(r);
  expect(transport.mock.calls.at(-1)?.[1]).toMatchObject({ method: "GET" });
  await expect(
    client.getNativeOrigin(r.after.configuration_id),
  ).resolves.toEqual(r);
  expect(transport.mock.calls.at(-1)?.[0]).toBe(
    `/api/v2/configurations/${r.after.configuration_id}/native-origin`,
  );
  await expect(
    client.getNativeOrigin(crypto.randomUUID()),
  ).rejects.toMatchObject({ status: 0 });
  await expect(
    client.getNativeMaterialization(crypto.randomUUID(), r.candidate_id),
  ).rejects.toMatchObject({ status: 0 });
});
it("rejects public proof body tampering, wrong IDs and changed intent from API", async () => {
  const r = materializationControl().materialization;
  for (const update of [
    { candidate_id: crypto.randomUUID() },
    { approved: true },
    { review_sha256: "f".repeat(64) },
    { before: { ...r.before, extra: true } },
  ]) {
    const client = new ApiClient(
      "authored-native-materialization-unit-token",
      vi
        .fn()
        .mockResolvedValue(new Response(JSON.stringify({ ...r, ...update }))),
    );
    await expect(
      client.getNativeMaterialization(r.configuration_id, r.candidate_id),
    ).rejects.toMatchObject({ status: 0 });
  }
  const modified = structuredClone(r);
  modified.service_role = "admin";
  const { review_json: _json, review_sha256: _sha, ...body } = modified;
  modified.review_json = stableJson(body);
  modified.review_sha256 = sha(modified.review_json);
  expect(await nativeMaterializationProofMatches(modified)).toBe(true);
});
