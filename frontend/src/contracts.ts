import { z } from "zod";

const id = z.guid();
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const score = z.number().min(0).max(1);
const timestamp = z.iso.datetime({ offset: true });
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
  detector: z.literal("policy_engine"),
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
export const analysisSchema = z
  .object({
    version: z.literal("analysis-api-0.1.0"),
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
  })
  .refine((result) => {
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
        item.source === "policy"
          ? item.status !== "completed" ||
            item.raw_score === null ||
            item.effective_weight !== 1
          : item.status !== "unavailable" ||
            item.raw_score !== null ||
            item.effective_weight !== 0,
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
      return (
        exp &&
        finding.device_id === result.device_id &&
        exp.device_id === result.device_id &&
        finding.finding_id === exp.finding_id &&
        exp.source_sha256 === result.source_sha256 &&
        finding.model_version === result.policy_catalog_version &&
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
export type Upload = { device_id: string; filename: string; content: string };
