import { z } from "zod";

const id = z.guid();
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const score = z.number().min(0).max(1);
const timestamp = z.iso.datetime({ offset: true });
const inventoryLabel = z
  .string()
  .min(1)
  .max(64)
  .refine(
    (value) => value.trim() === value && !/[\p{C}\p{Zl}\p{Zp}]/u.test(value),
  );
export const inventorySchema = z.object({
  device_role: inventoryLabel,
  site_class: inventoryLabel,
  service_profile: inventoryLabel,
});
export const severitySchema = z.enum([
  "info",
  "low",
  "medium",
  "high",
  "critical",
]);
const location = z.object({
  source_lines: z.array(z.number().int().positive()),
  raw_text_hash: hash,
  parser_confidence: score,
});
const jsonObject = z.record(z.string(), z.json());

export const snapshotSchema = z.object({
  configuration_id: id,
  device_id: id,
  created_at: timestamp,
  canonical: z.looseObject({
    schema_version: z.literal("1.0"),
    source: z.object({
      filename: z.string(),
      sha256: hash,
      collected_at: timestamp,
    }),
    device: z.looseObject({
      hostname: z.string().nullable(),
      vendor: z.enum(["cisco", "juniper"]),
      platform: z.string(),
      role: z.string().nullable().optional(),
      site_class: z.string().nullable().optional(),
      service_profile: z.string().nullable().optional(),
    }),
    parser_confidence: score,
    parse_warnings: z.array(z.string()),
    unparsed_fragments: z.array(z.object({ raw_text: z.string(), location })),
    interfaces: z.array(jsonObject),
    vlans: z.array(jsonObject),
    acls: z.array(jsonObject),
    static_routes: z.array(jsonObject),
  }),
});
export const configurationSummarySchema = z.object({
  configuration_id: id,
  device_id: id,
  created_at: timestamp,
  filename: z.string(),
  source_sha256: hash,
  hostname: z.string().nullable(),
  vendor: z.string(),
  platform: z.string(),
  parser_confidence: score,
  warning_count: z.number().int().nonnegative(),
  unparsed_count: z.number().int().nonnegative(),
});
export const findingSchema = z.object({
  finding_id: id,
  device_id: id,
  detector: z.enum([
    "policy_engine",
    "expected_configuration",
    "peer_baseline",
  ]),
  category: z.string(),
  title: z.string(),
  severity: severitySchema,
  confidence: score,
  anomaly_score: score,
  affected_lines: z.array(z.number().int().positive()),
  evidence: z.array(
    z.object({
      kind: z.string(),
      message: z.string(),
      source_location: location.nullable(),
    }),
  ),
  observed: jsonObject,
  expected: jsonObject,
  remediation: z.string().nullable(),
  references: z.array(z.string()),
  limitations: z.array(z.string()),
  model_version: z.string(),
});
const explanation = z.object({
  version: z.literal("local-explanation-0.1.0"),
  provider: z.literal("deterministic_local"),
  finding_id: id,
  device_id: id,
  finding_sha256: hash,
  source_sha256: hash,
  detector_version: z.string(),
  severity: severitySchema,
  confidence: score,
  anomaly_score: score,
  summary: z.string(),
  technical_explanation: z.string(),
  recommendation: z.string(),
  anchors: z.array(
    z.object({
      source_sha256: hash,
      lines: z.array(z.number().int().positive()),
      statement_sha256: hash,
    }),
  ),
  citations: z.array(z.string()),
  limitations: z.array(z.string()),
  formal_verification: z.literal("not_run"),
  patch_draft: z.null(),
  requires_human_review: z.literal(true),
});
const snapshotBindingSchema = z.object({
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
});
const peerBaselineSchema = z
  .object({
    model_version: z.literal("peer-baseline-0.1.0"),
    group: z.object({
      vendor: z.enum(["cisco", "juniper"]),
      platform: z.string().min(1),
      ...inventorySchema.shape,
    }),
    sample_count: z.number().int().min(3).max(20),
    consensus_threshold: z.number().gt(0.5).max(1),
    features: z.array(
      z.object({
        field: z.enum([
          "management.ssh_enabled",
          "management.ssh_version",
          "management.telnet_enabled",
          "management.aaa_enabled",
          "management.snmp_versions",
          "management.ntp_configured",
          "management.syslog_configured",
          "vlans.set",
          "acls.patterns",
          "bgp.present",
          "bgp.local_as",
          "ospf.present",
          "ospf.areas",
          "static_routes.destinations",
        ]),
        expected: z.json(),
        support_count: z.number().int().positive(),
        sample_count: z.number().int().min(3).max(20),
      }),
    ),
    unsupported_ratio_median: score,
    unsupported_ratio_limit: score,
  })
  .refine(
    (profile) =>
      profile.unsupported_ratio_limit >= profile.unsupported_ratio_median &&
      new Set(profile.features.map((item) => item.field)).size ===
        profile.features.length &&
      profile.features.every(
        (item) =>
          item.sample_count === profile.sample_count &&
          item.support_count <= item.sample_count &&
          item.support_count / item.sample_count >= profile.consensus_threshold,
      ),
  );
const comparisonSchema = z
  .object({
    reference: snapshotBindingSchema.nullable(),
    peers: z.array(snapshotBindingSchema).max(20),
    peer_baseline: peerBaselineSchema.nullable(),
  })
  .refine((context) => {
    if (!context.reference && context.peers.length === 0) return false;
    if (context.peers.length > 0 !== (context.peer_baseline !== null))
      return false;
    if (context.peers.length === 0) return true;
    return (
      context.peers.length >= 3 &&
      context.peer_baseline?.sample_count === context.peers.length &&
      ["configuration_id", "device_id", "source_sha256"].every(
        (key) =>
          new Set(context.peers.map((item) => item[key as keyof typeof item]))
            .size === context.peers.length,
      )
    );
  });
export const analysisSchema = z
  .object({
    version: z.enum(["analysis-api-0.1.0", "analysis-api-0.2.0"]),
    analysis_id: id,
    configuration_id: id,
    device_id: id,
    source_sha256: hash,
    created_at: timestamp,
    status: z.enum(["completed", "partial"]),
    policy_catalog_version: z.string(),
    findings: z.array(findingSchema),
    explanations: z.array(explanation),
    risk: z
      .object({
        assessment_id: id,
        device_id: id,
        score,
        level: z.enum(["low", "medium", "high", "critical"]),
        components: z.array(
          z.object({
            source: z.enum([
              "policy",
              "peer_group",
              "statistical",
              "transformer",
              "verification",
            ]),
            status: z.enum(["completed", "unavailable"]),
            raw_score: score.nullable(),
            configured_weight: score,
            effective_weight: score,
            finding_ids: z.array(id),
          }),
        ),
        guardrails: z.array(z.string()),
        limitations: z.array(z.string()),
        model_version: z.string(),
      })
      .nullable(),
    limitations: z.array(z.string()),
    comparison: comparisonSchema.nullable().optional(),
  })
  .refine((result) => {
    const comparison = result.comparison;
    if ((result.version === "analysis-api-0.2.0") !== !!comparison)
      return false;
    if (
      comparison?.reference &&
      (comparison.reference.device_id !== result.device_id ||
        comparison.reference.configuration_id === result.configuration_id)
    )
      return false;
    if (comparison?.peers.some((item) => item.device_id === result.device_id))
      return false;
    if ((result.status === "completed") !== (result.risk !== null))
      return false;
    if (result.risk && result.risk.device_id !== result.device_id) return false;
    if (
      result.risk &&
      (result.risk.components.length !== 5 ||
        new Set(result.risk.components.map((item) => item.source)).size !== 5)
    )
      return false;
    if (
      result.risk &&
      result.risk.components.some((item) =>
        item.source === "policy" ||
        (item.source === "peer_group" && comparison?.peer_baseline)
          ? item.status !== "completed" ||
            item.raw_score === null ||
            Math.abs(
              item.effective_weight -
                (comparison?.peer_baseline
                  ? item.source === "policy"
                    ? 0.7
                    : 0.3
                  : 1),
            ) > 1e-9 ||
            [...item.finding_ids].sort().join() !==
              result.findings
                .filter(
                  (finding) =>
                    finding.detector ===
                    (item.source === "policy"
                      ? "policy_engine"
                      : "peer_baseline"),
                )
                .map((finding) => finding.finding_id)
                .sort()
                .join()
          : item.status !== "unavailable" ||
            item.raw_score !== null ||
            item.effective_weight !== 0 ||
            item.finding_ids.length !== 0,
      )
    )
      return false;
    if (result.findings.length !== result.explanations.length) return false;
    if (
      new Set(result.findings.map((item) => item.finding_id)).size !==
      result.findings.length
    )
      return false;
    return result.findings.every((finding, index) => {
      const exp = result.explanations[index];
      const version =
        finding.detector === "policy_engine"
          ? result.policy_catalog_version
          : finding.detector === "expected_configuration" &&
              comparison?.reference
            ? "expected-config-0.1.0"
            : finding.detector === "peer_baseline"
              ? comparison?.peer_baseline?.model_version
              : undefined;
      if (!version) return false;
      if (
        finding.detector === "expected_configuration" &&
        (finding.expected.reference_id !==
          comparison?.reference?.configuration_id ||
          finding.expected.source_sha256 !==
            comparison?.reference?.source_sha256 ||
          finding.observed.source_sha256 !== result.source_sha256)
      )
        return false;
      return (
        exp &&
        finding.device_id === result.device_id &&
        exp.device_id === result.device_id &&
        finding.finding_id === exp.finding_id &&
        exp.source_sha256 === result.source_sha256 &&
        finding.model_version === version &&
        exp.detector_version === finding.model_version &&
        finding.severity === exp.severity &&
        finding.confidence === exp.confidence &&
        finding.anomaly_score === exp.anomaly_score
      );
    });
  }, "inconsistent analysis binding");
export const analysisSummarySchema = z.object({
  analysis_id: id,
  configuration_id: id,
  device_id: id,
  created_at: timestamp,
  status: z.enum(["completed", "partial"]),
  finding_count: z.number().int().nonnegative(),
  policy_catalog_version: z.string(),
});
export type ConfigurationSnapshot = z.infer<typeof snapshotSchema>;
export type ConfigurationSummary = z.infer<typeof configurationSummarySchema>;
export type AnalysisResult = z.infer<typeof analysisSchema>;
export type AnalysisSummary = z.infer<typeof analysisSummarySchema>;
export type Finding = z.infer<typeof findingSchema>;
export type Severity = z.infer<typeof severitySchema>;
export type Inventory = z.infer<typeof inventorySchema>;
export type Upload = {
  device_id: string;
  filename: string;
  content: string;
  inventory?: Inventory;
};
export type AnalysisOptions = {
  reference_configuration_id?: string;
  peer_configuration_ids?: string[];
};
