import { z } from "zod";
import type { Finding } from "./contracts";

export const expandedPeerFields = [
  "management.ssh_enabled",
  "management.ssh_version",
  "management.telnet_enabled",
  "management.aaa_enabled",
  "management.snmp_versions",
  "management.ntp_servers",
  "management.syslog_servers",
  "local_users.patterns",
  "interfaces.patterns",
  "vlans.set",
  "acls.patterns",
  "prefix_lists.patterns",
  "bgp.present",
  "bgp.local_as",
  "bgp.router_id_configured",
  "bgp.neighbor_patterns",
  "ospf.present",
  "ospf.process_patterns",
  "static_routes.targets",
] as const;
const field = z.enum(expandedPeerFields);
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const time = z.iso.datetime({ offset: true });
const label = z
  .string()
  .min(1)
  .max(64)
  .refine(
    (value) => value === value.trim() && !/[\p{C}\p{Zl}\p{Zp}]/u.test(value),
  );
const count = z.number().int().min(3).max(20);
const booleanFields = new Set<string>([
  "management.ssh_enabled",
  "management.telnet_enabled",
  "management.aaa_enabled",
  "bgp.present",
  "bgp.router_id_configured",
  "ospf.present",
]);
const feature = z
  .strictObject({
    field,
    expected: z.union([
      z.boolean(),
      z.number().int(),
      z.string(),
      z.array(z.string()),
      z.null(),
    ]),
    support_count: z.number().int().min(1).max(20),
    sample_count: count,
  })
  .refine((item) => {
    if (item.support_count > item.sample_count) return false;
    if (
      new TextEncoder().encode(JSON.stringify(item.expected)).byteLength >
      512 * 1024
    )
      return false;
    if (booleanFields.has(item.field))
      return typeof item.expected === "boolean";
    if (item.field === "management.ssh_version")
      return item.expected === null || typeof item.expected === "string";
    if (item.field === "bgp.local_as")
      return item.expected === null || typeof item.expected === "number";
    return Array.isArray(item.expected);
  });
const sample = z.strictObject({
  hostname: z
    .string()
    .min(1)
    .max(255)
    .refine(
      (value) => value === value.trim() && !/[\p{C}\p{Zl}\p{Zp}]/u.test(value),
    ),
  source_sha256: hash,
  collected_at: time,
});
export const expandedPeerBaselineSchema = z
  .strictObject({
    model_version: z.literal("peer-baseline-0.2.0"),
    group: z.strictObject({
      vendor: z.enum(["cisco", "juniper"]),
      platform: z.string().min(1),
      device_role: label,
      site_class: label,
      service_profile: label,
    }),
    sample_count: count,
    samples: z.array(sample).min(3).max(20),
    consensus_threshold: z.number().gt(0.5).max(1),
    features: z.array(feature).max(19),
    omitted_features: z.array(field).max(19),
    unsupported_ratio_median: z.literal(0),
    unsupported_ratio_limit: z.number().min(0).max(1),
  })
  .refine((profile) => {
    const fields = profile.features.map((item) => item.field);
    const inventory = [...fields, ...profile.omitted_features];
    return (
      profile.samples.length === profile.sample_count &&
      new Set(profile.samples.map((item) => item.hostname.toLowerCase()))
        .size === profile.sample_count &&
      new Set(profile.samples.map((item) => item.source_sha256)).size ===
        profile.sample_count &&
      profile.samples.map((item) => item.source_sha256).join() ===
        profile.samples
          .map((item) => item.source_sha256)
          .sort()
          .join() &&
      inventory.length === 19 &&
      new Set(inventory).size === 19 &&
      fields.join() === [...fields].sort().join() &&
      profile.omitted_features.join() ===
        [...profile.omitted_features].sort().join() &&
      profile.features.every(
        (item) =>
          item.sample_count === profile.sample_count &&
          item.support_count / item.sample_count >= profile.consensus_threshold,
      ) &&
      new TextEncoder().encode(JSON.stringify(profile)).byteLength <=
        8 * 1024 * 1024
    );
  });

type Binding = {
  configuration_id: string;
  device_id: string;
  source_sha256: string;
  created_at: string;
};

// Reuse the common finding/binding contracts without a runtime circular import.
export function makeExpandedComparisonSchema(
  binding: z.ZodType<Binding>,
  finding: z.ZodType<Finding>,
) {
  const report = z
    .strictObject({
      version: z.literal("peer-comparison-report-0.2.0"),
      device_id: z.guid(),
      source_sha256: hash,
      baseline_sha256: hash,
      status: z.enum(["completed", "partial"]),
      unsupported_ratio: z.number().min(0).max(1),
      profile_features: z.array(field).max(19),
      compared_features: z.array(field).max(19),
      skipped_features: z.array(field).max(19),
      findings: z.array(finding).max(20),
      limitations: z.array(z.string()),
    })
    .refine((item) => {
      const fields = item.profile_features;
      return (
        new Set(fields).size === fields.length &&
        fields.join() === [...fields].sort().join() &&
        (item.status === "completed"
          ? item.unsupported_ratio === 0 &&
            !item.skipped_features.length &&
            item.compared_features.join() === fields.join()
          : !item.compared_features.length &&
            item.skipped_features.join() === fields.join()) &&
        new Set(item.findings.map((value) => value.finding_id)).size ===
          item.findings.length &&
        item.findings.every(
          (value) =>
            value.device_id === item.device_id &&
            value.detector === "peer_baseline" &&
            value.model_version === "peer-baseline-0.2.0" &&
            value.observed.source_sha256 === item.source_sha256 &&
            value.expected.baseline_sha256 === item.baseline_sha256 &&
            (item.status !== "partial" ||
              value.category === "baseline.parser.unsupported_ratio_high"),
        )
      );
    });
  return z
    .strictObject({
      version: z.literal("comparison-context-0.2.0"),
      reference: binding.nullable(),
      peers: z.array(binding).max(20),
      peer_baseline: expandedPeerBaselineSchema.nullable(),
      peer_evaluation: report.nullable(),
    })
    .refine((context) => {
      if (!context.reference && !context.peers.length) return false;
      if (
        !!context.peers.length !== !!context.peer_baseline ||
        !!context.peers.length !== !!context.peer_evaluation
      )
        return false;
      const profile = context.peer_baseline,
        evaluation = context.peer_evaluation;
      if (!profile || !evaluation) return true;
      const selected = new Map(
        context.peers.map((item) => [item.source_sha256, item]),
      );
      return (
        context.peers.length === profile.sample_count &&
        ["configuration_id", "device_id", "source_sha256"].every(
          (key) =>
            new Set(context.peers.map((item) => item[key as keyof Binding]))
              .size === context.peers.length,
        ) &&
        profile.samples.every(
          (item) =>
            selected.has(item.source_sha256) &&
            Date.parse(item.collected_at) <=
              Date.parse(selected.get(item.source_sha256)!.created_at),
        ) &&
        profile.features.map((item) => item.field).join() ===
          evaluation.profile_features.join() &&
        evaluation.findings.filter(
          (item) => item.category === "baseline.parser.unsupported_ratio_high",
        ).length ===
          Number(
            evaluation.unsupported_ratio > profile.unsupported_ratio_limit,
          ) &&
        evaluation.findings.every((item) => {
          if (item.category === "baseline.parser.unsupported_ratio_high")
            return (
              evaluation.status === "partial" &&
              evaluation.unsupported_ratio > profile.unsupported_ratio_limit &&
              item.observed.value === evaluation.unsupported_ratio &&
              item.expected.maximum_unsupported_ratio ===
                profile.unsupported_ratio_limit &&
              item.expected.peer_median === profile.unsupported_ratio_median &&
              item.confidence === 1 &&
              item.anomaly_score ===
                Math.min(
                  1,
                  (evaluation.unsupported_ratio -
                    profile.unsupported_ratio_limit) /
                    Math.max(1 - profile.unsupported_ratio_limit, 0.01),
                )
            );
          const expected = profile.features.find(
            (value) => value.field === item.expected.feature,
          );
          return (
            !!expected &&
            item.category === `baseline.${expected.field}_deviation` &&
            item.expected.peer_support_count === expected.support_count &&
            item.expected.peer_sample_count === expected.sample_count &&
            item.confidence ===
              expected.support_count / expected.sample_count &&
            item.anomaly_score === item.confidence &&
            JSON.stringify(item.expected.value) ===
              JSON.stringify(expected.expected)
          );
        })
      );
    });
}
