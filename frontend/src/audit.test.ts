import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import {
  operationPageSchema,
  operationRecordSchema,
  verifyReceiptBinding,
} from "./audit";
import { ApiClient } from "./api";

const id = "00000000-0000-0000-0000-000000000001";
const other = "00000000-0000-0000-0000-000000000002";
const token = "synthetic-audit-client-test-token-00000001";
const receipt = {
  version: "operation-receipt-0.1.0",
  operation_id: id,
  started_at: "2026-10-07T10:00:00.123456Z",
  operation: "list_configurations",
  method: "GET",
  service_role: "admin",
  individual_identity_verified: false,
} as const;
const sha = (value: object) =>
  createHash("sha256")
    .update(
      JSON.stringify(
        Object.fromEntries(
          Object.entries(value).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        ),
      ),
    )
    .digest("hex");
const result = {
  metadata_sha256: "a".repeat(64),
  result_count: 1,
  resource_ids: [other],
  source_sha256: null,
  finding_sha256: null,
  versions: ["analysis-api-0.1.0"],
  knowledge_sha256: null,
  document_index_sha256: null,
  document_encoder_sha256: null,
  context_sha256: null,
  model_alias_sha256: null,
  retrieval: null,
};
const completion = {
  version: "operation-completion-0.1.0",
  operation_id: id,
  receipt_sha256: sha(receipt),
  completed_at: "2026-10-07T10:00:01.123456Z",
  status_code: 200,
  duration_ms: 1000,
  permissions: [{ permission: "read", granted: true }],
  result,
} as const;
const record = {
  version: "operation-record-0.1.0",
  receipt,
  completion,
  outcome: "successful_response",
  authorization: "allowed",
} as const;

it("checks a complete receipt fingerprint and leaves pending outcomes unconfirmed", async () => {
  const valid = operationRecordSchema.parse(record);
  expect(await verifyReceiptBinding(valid)).toBe(true);
  expect(
    await verifyReceiptBinding({
      ...valid,
      receipt: { ...valid.receipt, method: "POST" },
    }),
  ).toBe(false);
  const pending = operationRecordSchema.parse({
    ...record,
    completion: null,
    outcome: "pending",
    authorization: "not_checked",
  });
  expect(await verifyReceiptBinding(pending)).toBe(true);
});
it.each([
  "generate_model_patch",
  "list_model_patches",
  "get_model_patch",
  "verify_model_patch",
  "list_model_patch_verifications",
  "get_model_patch_verification",
  "decide_model_patch",
  "list_model_patch_decisions",
  "get_model_patch_decision",
])(
  "reads an immutable saved model workflow audit receipt: %s",
  async (operation) => {
    const selected = { ...receipt, operation };
    const value = operationRecordSchema.parse({
      ...record,
      receipt: selected,
      completion: { ...completion, receipt_sha256: sha(selected) },
    });
    expect(await verifyReceiptBinding(value)).toBe(true);
  },
);
it.each([
  { outcome: "pending" },
  { authorization: "denied" },
  { approved: true },
  { receipt: { ...receipt, individual_identity_verified: true } },
  { receipt: { ...receipt, operation: "/private/source" } },
  { completion: { ...completion, operation_id: other } },
  {
    completion: { ...completion, completed_at: "2026-10-07T10:00:00.123455Z" },
  },
  { completion: { ...completion, status_code: 503 } },
  { completion: { ...completion, duration_ms: -1 } },
  {
    completion: {
      ...completion,
      permissions: [...completion.permissions, ...completion.permissions],
    },
  },
  {
    completion: {
      ...completion,
      permissions: [{ permission: "read", granted: false }],
    },
  },
  {
    receipt: { ...receipt, service_role: "reader" },
    completion: {
      ...completion,
      permissions: [{ permission: "read_audit", granted: true }],
    },
  },
  {
    completion: { ...completion, result: { ...result, versions: ["z", "a"] } },
  },
  {
    completion: {
      ...completion,
      result: { ...result, resource_ids: [other, other] },
    },
  },
  {
    completion: {
      ...completion,
      result: { ...result, retrieval: "semantic_supplement" },
    },
  },
  { completion: { ...completion, result: { ...result, comment: "private" } } },
])("rejects misleading, unbound or private audit fields %j", (update) => {
  expect(
    operationRecordSchema.safeParse({ ...record, ...update }).success,
  ).toBe(false);
});
it("orders submillisecond records exactly and binds the next cursor", () => {
  const earlier = {
    ...record,
    receipt: {
      ...receipt,
      operation_id: other,
      started_at: "2026-10-07T10:00:00.123455Z",
    },
    completion: null,
    outcome: "pending",
    authorization: "not_checked",
  };
  const page = {
    version: "operation-page-0.1.0",
    records: [record, earlier],
    next_before: other,
  };
  expect(operationPageSchema.safeParse(page).success).toBe(true);
  expect(
    operationPageSchema.safeParse({ ...page, records: [earlier, record] })
      .success,
  ).toBe(false);
  expect(
    operationPageSchema.safeParse({ ...page, records: [record, record] })
      .success,
  ).toBe(false);
  expect(
    operationPageSchema.safeParse({ ...page, next_before: id }).success,
  ).toBe(false);
});
it("uses bounded keyset URLs and never accepts a mismatched operation detail", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          version: "operation-page-0.1.0",
          records: [record],
          next_before: id,
        }),
      ),
    )
    .mockResolvedValueOnce(new Response(JSON.stringify(record)));
  const api = new ApiClient(token, transport);
  expect((await api.operationAudit(other)).records).toHaveLength(1);
  expect(transport.mock.calls[0]![0]).toBe(
    `/api/v1/operation-audit?limit=20&before=${other}`,
  );
  await expect(api.operation(other)).rejects.toMatchObject({ status: 0 });
  api.close();
});
it("rejects an authenticated-looking but incorrectly hashed receipt", async () => {
  const api = new ApiClient(
    token,
    vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          ...record,
          completion: { ...completion, receipt_sha256: "f".repeat(64) },
        }),
      ),
    ),
  );
  await expect(api.operation(id)).rejects.toMatchObject({ status: 0 });
  api.close();
});
it("does not expose a late audit response from a disconnected session", async () => {
  let release!: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const api = new ApiClient(
    token,
    vi.fn<typeof fetch>().mockReturnValue(pending),
  );
  const request = api.operation(id);
  api.close();
  release(new Response(JSON.stringify(record)));
  await expect(request).rejects.toMatchObject({ name: "AbortError" });
});
