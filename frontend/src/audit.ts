import { z } from "zod";
import { rolePermissions } from "./contracts";

const id = z.guid();
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.iso.datetime({ offset: true }).max(40);
export const operationNames = [
  "upload_configuration",
  "list_configurations",
  "get_configuration",
  "analyze_configuration",
  "list_analyses",
  "get_analysis",
  "get_findings",
  "train_model",
  "list_models",
  "get_model",
  "submit_feedback",
  "list_feedback",
  "create_patch",
  "list_patches",
  "get_patch",
  "verify_patch",
  "list_verifications",
  "get_verification",
  "snapshot_diff",
  "explain_finding",
  "explanation_capabilities",
  "session_access",
  "list_operation_audit",
  "get_operation_audit",
  "unmatched_api",
] as const;
const receiptSchema = z.strictObject({
  version: z.literal("operation-receipt-0.1.0"),
  operation_id: id,
  started_at: timestamp,
  operation: z.enum(operationNames),
  method: z.enum([
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "OTHER",
  ]),
  service_role: z.enum(["reader", "analyst", "engineer", "admin"]).nullable(),
  individual_identity_verified: z.literal(false),
});
const resultSchema = z
  .strictObject({
    metadata_sha256: hash,
    result_count: z.number().int().min(0).max(100_000),
    resource_ids: z.array(id).max(16),
    source_sha256: hash.nullable(),
    finding_sha256: hash.nullable(),
    versions: z
      .array(
        z
          .string()
          .min(1)
          .max(100)
          .regex(/^[A-Za-z0-9._-]+$/),
      )
      .max(128),
    knowledge_sha256: hash.nullable(),
    document_index_sha256: hash.nullable(),
    document_encoder_sha256: hash.nullable(),
    context_sha256: hash.nullable(),
    model_alias_sha256: hash.nullable(),
    retrieval: z.enum(["explicit_reference", "semantic_supplement"]).nullable(),
  })
  .refine(
    (value) =>
      new Set(value.resource_ids).size === value.resource_ids.length &&
      JSON.stringify(value.versions) ===
        JSON.stringify([...new Set(value.versions)].sort()) &&
      (value.retrieval !== "semantic_supplement" ||
        (value.document_index_sha256 !== null &&
          value.document_encoder_sha256 !== null)),
  );
const completionSchema = z
  .strictObject({
    version: z.literal("operation-completion-0.1.0"),
    operation_id: id,
    receipt_sha256: hash,
    completed_at: timestamp,
    status_code: z.number().int().min(200).max(599),
    duration_ms: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    permissions: z
      .array(
        z.strictObject({
          permission: z.enum(rolePermissions.admin),
          granted: z.boolean(),
        }),
      )
      .max(16),
    result: resultSchema.nullable(),
  })
  .refine(
    (value) =>
      new Set(value.permissions.map((item) => item.permission)).size ===
        value.permissions.length &&
      (value.status_code < 400 || value.result === null),
  );

function instant(value: string): bigint {
  const fraction = (value.match(/\.(\d+)/)?.[1] ?? "").padEnd(9, "0");
  return BigInt(Date.parse(value)) * 1_000_000n + BigInt(fraction.slice(3, 9));
}
export const operationRecordSchema = z
  .strictObject({
    version: z.literal("operation-record-0.1.0"),
    receipt: receiptSchema,
    completion: completionSchema.nullable(),
    outcome: z.enum([
      "pending",
      "successful_response",
      "rejected_response",
      "failed_response",
    ]),
    authorization: z.enum([
      "allowed",
      "denied",
      "not_authenticated",
      "not_checked",
    ]),
  })
  .refine((record) => {
    const { receipt, completion } = record;
    if (!completion)
      return (
        record.outcome === "pending" && record.authorization === "not_checked"
      );
    if (
      completion.operation_id !== receipt.operation_id ||
      instant(completion.completed_at) < instant(receipt.started_at)
    )
      return false;
    if (
      completion.permissions.some(
        (decision) =>
          decision.granted !==
          (receipt.service_role !== null &&
            rolePermissions[receipt.service_role].some(
              (permission) => permission === decision.permission,
            )),
      )
    )
      return false;
    const authorization =
      receipt.service_role === null
        ? "not_authenticated"
        : completion.permissions.some((item) => !item.granted)
          ? "denied"
          : completion.permissions.length
            ? "allowed"
            : "not_checked";
    const outcome =
      completion.status_code < 400
        ? "successful_response"
        : completion.status_code < 500
          ? "rejected_response"
          : "failed_response";
    return record.authorization === authorization && record.outcome === outcome;
  });
export type OperationRecord = z.infer<typeof operationRecordSchema>;
export const operationPageSchema = z
  .strictObject({
    version: z.literal("operation-page-0.1.0"),
    records: z.array(operationRecordSchema).max(100),
    next_before: id.nullable(),
  })
  .refine((page) => {
    if (
      page.next_before !== null &&
      page.next_before !== page.records.at(-1)?.receipt.operation_id
    )
      return false;
    return (
      new Set(page.records.map((item) => item.receipt.operation_id)).size ===
        page.records.length &&
      page.records.every((item, index) => {
        if (!index) return true;
        const prev = page.records[index - 1]!.receipt;
        return (
          instant(prev.started_at) > instant(item.receipt.started_at) ||
          (instant(prev.started_at) === instant(item.receipt.started_at) &&
            prev.operation_id > item.receipt.operation_id)
        );
      })
    );
  });
export type OperationPage = z.infer<typeof operationPageSchema>;

export async function verifyReceiptBinding(
  record: OperationRecord,
): Promise<boolean> {
  if (!record.completion) return true;
  const ordered = Object.fromEntries(
    Object.entries(record.receipt).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    ),
  );
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(ordered)),
  );
  const sha = [...new Uint8Array(bytes)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
  return record.completion.receipt_sha256 === sha;
}
