import { z } from "zod";
import { stableJson } from "./contracts";
import { batfishSchema, scopeSchema } from "./modelReviews";
import { reachabilityImpactSchema } from "./sourceReachabilityImpact";

export const ingressScopeLimitations = [
  "Selection and concrete IPv4 origination eligibility are observed, not a complete ingress universe.",
  "Active is a modeled property, not operational link state; missing concrete IPv4 remains unknown.",
  "Source IP assignments are opaque engine renderings; equality and IP-set semantics are unverified.",
  "After-context assignments for common eligible identities do not prove complete flow coverage.",
  "Removed ingress, management access, external delivery, approval and safety are not established.",
  "Admission byte limits are post-download checks, not hard HTTP receive-memory bounds.",
] as const;
const hash = z.string().regex(/^[0-9a-f]{64}(?![\s\S])/);
const same = (a: unknown, b: unknown) => stableJson(a) === stableJson(b);
const bytes = (s: string) => new TextEncoder().encode(s).length;
const orderedUnique = (s: string[]) => s.every((v, i) => !i || s[i - 1]! < v);
const opaque = z
  .string()
  .min(1)
  .max(4096)
  .refine((s) => bytes(s) <= 4096 && !/[\x00-\x1f\x7f]/u.test(s));
const prefix = z
  .string()
  .max(18)
  .refine((s) => {
    const match =
      /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\/(0|[1-9]\d?)$/.exec(
        s,
      );
    return (
      !!match &&
      match.slice(1, 5).every((n) => Number(n) <= 255) &&
      Number(match[5]) <= 32
    );
  });
const interfaceSchema = z
  .strictObject({
    node: z.string().regex(/^[A-Za-z0-9_-]{1,128}(?![\s\S])/),
    interface: z.string().regex(/^[A-Za-z0-9_.:/-]{1,128}(?![\s\S])/),
    canonical_id_sha256: hash,
    location_rendering: z.string().min(1).max(512),
    active: z.boolean(),
    switchport: z.boolean(),
    interface_type: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}(?![\s\S])/),
    concrete_ipv4_prefixes: z.array(prefix).max(64).refine(orderedUnique),
    eligible: z.boolean().nullable(),
    eligibility_reason: z.enum([
      "active_concrete_ipv4",
      "inactive",
      "switchport",
      "no_concrete_ipv4",
    ]),
    source_ip_rendering: opaque,
    source_ip_sha256: hash,
  })
  .refine((r) => {
    const eligible =
      !r.active || r.switchport
        ? false
        : r.concrete_ipv4_prefixes.length
          ? true
          : null;
    const reason = !r.active
      ? "inactive"
      : r.switchport
        ? "switchport"
        : r.concrete_ipv4_prefixes.length
          ? "active_concrete_ipv4"
          : "no_concrete_ipv4";
    return (
      r.eligible === eligible &&
      r.eligibility_reason === reason &&
      r.location_rendering ===
        `InterfaceLocation{nodeName=${r.node}, interfaceName=${r.interface}}`
    );
  });
const sideSchema = z
  .strictObject({ interfaces: z.array(interfaceSchema).max(256) })
  .refine((r) => orderedUnique(r.interfaces.map((i) => i.canonical_id_sha256)));
const assignmentSchema = z.strictObject({
  canonical_id_sha256: hash,
  source_ip_rendering: opaque,
  source_ip_sha256: hash,
});
const ids = z.array(hash).max(256).refine(orderedUnique).nullable();
export const ingressScopeSchema = z
  .strictObject({
    version: z.literal("ingress-scope-0.1.0"),
    before_sha256: hash,
    after_sha256: hash,
    scope: scopeSchema,
    network_name: z
      .string()
      .regex(/^sentinel-[0-9a-f]{32}(?![\s\S])/)
      .nullable(),
    acquisition_state: z.enum(["observed", "unknown", "not_observed"]),
    reason: z.enum([
      "query_completed",
      "not_run",
      "query_failed",
      "unsupported_answer",
      "unsupported_location",
      "incomplete_assignment",
      "budget_exceeded",
      "cleanup_unconfirmed",
    ]),
    before: sideSchema.nullable(),
    after: sideSchema.nullable(),
    eligibility_complete: z.boolean().nullable(),
    selected_before_only: ids,
    selected_after_only: ids,
    common_eligible: ids,
    before_eligible_only: ids,
    after_eligible_only: ids,
    after_common_assignments: z.array(assignmentSchema).max(256).nullable(),
    semantic_ip_sets_verified: z.literal(false),
    complete_flow_coverage: z.literal(false),
    source_assignment_context: z.literal("after"),
    method: z.literal("selected-interface-concrete-ipv4-origination-0.1.0"),
    limitations: z.array(z.string()).length(6),
  })
  .refine((r) => {
    if (
      bytes(stableJson(r)) > 65536 ||
      !same(r.limitations, ingressScopeLimitations)
    )
      return false;
    const derived = [
      r.eligibility_complete,
      r.selected_before_only,
      r.selected_after_only,
      r.common_eligible,
      r.before_eligible_only,
      r.after_eligible_only,
      r.after_common_assignments,
    ];
    if (r.acquisition_state !== "observed")
      return (
        r.before === null &&
        r.after === null &&
        derived.every((v) => v === null) &&
        (r.acquisition_state === "not_observed"
          ? r.reason === "not_run"
          : !["query_completed", "not_run"].includes(r.reason))
      );
    if (
      r.reason !== "query_completed" ||
      !r.before ||
      !r.after ||
      !r.network_name
    )
      return false;
    const before = r.before.interfaces,
      after = r.after.interfaces;
    if ([...before, ...after].some((i) => i.node !== r.scope.start_node))
      return false;
    const beforeIds = before.map((i) => i.canonical_id_sha256),
      afterIds = after.map((i) => i.canonical_id_sha256);
    const difference = (a: string[], b: string[]) =>
      a.filter((i) => !b.includes(i));
    if (
      !same(r.selected_before_only, difference(beforeIds, afterIds)) ||
      !same(r.selected_after_only, difference(afterIds, beforeIds))
    )
      return false;
    const complete = [...before, ...after].every((i) => i.eligible !== null);
    if (r.eligibility_complete !== complete) return false;
    if (!complete)
      return [
        r.common_eligible,
        r.before_eligible_only,
        r.after_eligible_only,
        r.after_common_assignments,
      ].every((v) => v === null);
    const b = before
        .filter((i) => i.eligible)
        .map((i) => i.canonical_id_sha256),
      a = after.filter((i) => i.eligible).map((i) => i.canonical_id_sha256),
      common = b.filter((i) => a.includes(i));
    return (
      same(r.common_eligible, common) &&
      same(r.before_eligible_only, difference(b, a)) &&
      same(r.after_eligible_only, difference(a, b)) &&
      same(
        r.after_common_assignments,
        after
          .filter((i) => common.includes(i.canonical_id_sha256))
          .map(
            ({
              canonical_id_sha256,
              source_ip_rendering,
              source_ip_sha256,
            }) => ({
              canonical_id_sha256,
              source_ip_rendering,
              source_ip_sha256,
            }),
          ),
      )
    );
  });
export type IngressScope = z.infer<typeof ingressScopeSchema>;
export const batfishScopeExecutionSchema = z
  .strictObject({
    version: z.literal("batfish-execution-0.4.0"),
    result: batfishSchema,
    sdk_version: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}(?![\s\S])/)
      .nullable(),
    sdk_observation: z.enum([
      "observed",
      "not_observed",
      "metadata_unavailable",
    ]),
    reachability_impact: reachabilityImpactSchema,
    ingress_scope: ingressScopeSchema,
  })
  .refine((r) => {
    const result = r.result,
      impact = r.reachability_impact,
      ingress = r.ingress_scope;
    if (
      (r.sdk_observation === "observed") !== (r.sdk_version !== null) ||
      ([
        "upload_not_authorized",
        "sdk_missing",
        "worker_failed",
        "timeout",
      ].includes(result.reason) &&
        r.sdk_observation !== "not_observed") ||
      (r.sdk_observation === "not_observed" &&
        !["unavailable", "error"].includes(result.status))
    )
      return false;
    if (
      ingress.before_sha256 !== result.before_sha256 ||
      ingress.after_sha256 !== result.after_sha256 ||
      ingress.network_name !== result.network_name ||
      !same(ingress.scope, result.scope)
    )
      return false;
    const queried = [
      "inconclusive",
      "differences_found",
      "no_differences_in_scope",
    ].includes(result.status);
    if (!queried)
      return (
        impact.state === "not_observed" &&
        impact.reason === "not_run" &&
        ingress.acquisition_state === "not_observed" &&
        ingress.reason === "not_run"
      );
    if (result.cleanup_complete !== true)
      return (
        impact.state === "unknown" &&
        impact.reason === "cleanup_unconfirmed" &&
        ingress.acquisition_state === "unknown" &&
        ingress.reason === "cleanup_unconfirmed"
      );
    if (
      ingress.acquisition_state === "not_observed" ||
      ingress.reason === "cleanup_unconfirmed"
    )
      return false;
    if (result.status === "inconclusive")
      return (
        impact.state === "inconclusive" &&
        impact.reason === "empty_reachable_scope"
      );
    return impact.state === "observed"
      ? impact.witnesses.length === result.difference_count
      : impact.state === "unknown" && impact.reason !== "cleanup_unconfirmed";
  });
async function digest(s: string) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(s),
  );
  return Array.from(new Uint8Array(hash), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
// Identity and opaque-text hashes are checked independently of the outer review.
export async function ingressScopeProofMatches(value: IngressScope) {
  if (!ingressScopeSchema.safeParse(value).success) return false;
  for (const side of [value.before, value.after])
    for (const r of side?.interfaces ?? []) {
      if (
        r.canonical_id_sha256 !==
          (await digest(
            stableJson({
              version: "ingress-location-0.1.0",
              kind: "interface",
              node: r.node,
              interface: r.interface,
            }),
          )) ||
        r.source_ip_sha256 !== (await digest(r.source_ip_rendering))
      )
        return false;
    }
  return true;
}
