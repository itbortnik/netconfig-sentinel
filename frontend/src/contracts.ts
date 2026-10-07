import { z } from "zod";

export const rolePermissions = {
  reader: ["read"],
  analyst: ["read", "upload", "analyze"],
  engineer: [
    "read",
    "upload",
    "analyze",
    "feedback",
    "draft",
    "verify",
    "model_explanation",
  ],
  admin: [
    "read",
    "upload",
    "analyze",
    "train_model",
    "feedback",
    "draft",
    "verify",
    "model_explanation",
  ],
} as const;
export type Permission = (typeof rolePermissions.admin)[number];
export const sessionAccessSchema = z
  .strictObject({
    version: z.literal("service-access-0.1.0"),
    role: z.enum(["reader", "analyst", "engineer", "admin"]),
    permissions: z.array(z.enum(rolePermissions.admin)).min(1).max(8),
    individual_identity_verified: z.literal(false),
    device_scope: z.literal("all_saved_devices"),
  })
  .refine(
    (access) =>
      new Set(access.permissions).size === access.permissions.length &&
      access.permissions.length === rolePermissions[access.role].length &&
      rolePermissions[access.role].every((permission) =>
        access.permissions.includes(permission),
      ),
  );
export type SessionAccess = z.infer<typeof sessionAccessSchema>;

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
export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "undefined";
}
export const diffSnapshotSchema = z.strictObject({
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
  vendor: z.enum(["cisco", "juniper"]),
  platform: z.string(),
  hostname: z.string().nullable(),
  projection_sha256: hash,
  parser_confidence: score,
  warning_count: z.number().int().nonnegative(),
  unparsed_count: z.number().int().nonnegative(),
});
export const objectChangeSchema = z
  .strictObject({
    section: z.enum([
      "device",
      "management",
      "local_users",
      "interfaces",
      "vlans",
      "acls",
      "prefix_lists",
      "static_routes",
      "bgp",
      "bgp_neighbors",
      "ospf",
    ]),
    object_key: z.array(z.string()).min(1).max(3),
    kind: z.enum(["added", "removed", "modified"]),
    before_value: jsonObject.nullable(),
    after_value: jsonObject.nullable(),
    before_locations: z.array(location),
    after_locations: z.array(location),
  })
  .refine((item) => {
    if (stableJson(item.before_value) === stableJson(item.after_value))
      return false;
    const kind =
      item.before_value === null
        ? "added"
        : item.after_value === null
          ? "removed"
          : "modified";
    return (
      item.kind === kind &&
      (item.before_value !== null || item.before_locations.length === 0) &&
      (item.after_value !== null || item.after_locations.length === 0)
    );
  }, "inconsistent object change");
export const snapshotDiffSchema = z
  .strictObject({
    version: z.literal("snapshot-diff-0.1.0"),
    representation: z.literal("normalized_objects"),
    before: diffSnapshotSchema,
    after: diffSnapshotSchema,
    coverage: z.enum(["supported_complete", "partial"]),
    source_changed: z.boolean(),
    added_count: z.number().int().nonnegative(),
    removed_count: z.number().int().nonnegative(),
    modified_count: z.number().int().nonnegative(),
    changes: z.array(objectChangeSchema).max(500),
    limitations: z.array(z.string()).min(1),
  })
  .refine((result) => {
    const a = result.before,
      b = result.after;
    const complete = (item: typeof a) =>
      item.parser_confidence === 1 &&
      item.warning_count === 0 &&
      item.unparsed_count === 0;
    const keys = result.changes.map((item) =>
      JSON.stringify([item.section, item.object_key]),
    );
    return (
      a.configuration_id !== b.configuration_id &&
      a.device_id === b.device_id &&
      a.vendor === b.vendor &&
      a.platform === b.platform &&
      a.hostname === b.hostname &&
      Date.parse(a.created_at) <= Date.parse(b.created_at) &&
      result.coverage ===
        (complete(a) && complete(b) ? "supported_complete" : "partial") &&
      result.source_changed === (a.source_sha256 !== b.source_sha256) &&
      result.added_count ===
        result.changes.filter((item) => item.kind === "added").length &&
      result.removed_count ===
        result.changes.filter((item) => item.kind === "removed").length &&
      result.modified_count ===
        result.changes.filter((item) => item.kind === "modified").length &&
      keys.length === new Set(keys).size &&
      (a.projection_sha256 === b.projection_sha256) ===
        (result.changes.length === 0)
    );
  }, "inconsistent diff binding");
export type SnapshotDiff = z.infer<typeof snapshotDiffSchema>;
export type ObjectChange = z.infer<typeof objectChangeSchema>;
export type DiffSnapshot = z.infer<typeof diffSnapshotSchema>;
export const feedbackVerdictSchema = z.enum([
  "confirmed_anomaly",
  "false_positive",
  "needs_investigation",
]);
const feedbackComment = z
  .string()
  .refine(
    (value) =>
      Array.from(value).length >= 1 &&
      Array.from(value).length <= 2000 &&
      value.trim() === value &&
      !/[\p{C}\p{Zs}\p{Zl}\p{Zp}]/u.test(value.replace(/[ \r\n\t]/g, "")),
  );
export const feedbackSubmissionSchema = z.strictObject({
  feedback_id: id,
  analysis_id: id,
  finding_sha256: hash,
  verdict: feedbackVerdictSchema,
  comment: feedbackComment,
});
export const feedbackSchema = z.strictObject({
  ...feedbackSubmissionSchema.shape,
  version: z.literal("finding-feedback-0.1.0"),
  finding_id: id,
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
  actor: z.literal("shared_service_token"),
});
export type FeedbackRecord = z.infer<typeof feedbackSchema>;
export type FeedbackSubmission = z.infer<typeof feedbackSubmissionSchema>;
export type FeedbackVerdict = z.infer<typeof feedbackVerdictSchema>;

const accountName = z.string().regex(/^[A-Za-z0-9_.@+-]{1,64}$/);
export const localAuthenticationSchema = z
  .strictObject({
    kind: z.enum(["password", "secret", "ssh_public_key", "none"]),
    encoding: z
      .enum([
        "unspecified",
        "0",
        "4",
        "5",
        "7",
        "8",
        "9",
        "encrypted",
        "ssh-rsa",
        "ssh-ecdsa",
        "ssh-ed25519",
      ])
      .nullable(),
    provenance: location,
  })
  .refine((item) => {
    if (item.kind === "none") return item.encoding === null;
    const allowed: Record<"password" | "secret" | "ssh_public_key", string[]> =
      {
        password: ["unspecified", "0", "7"],
        secret: ["unspecified", "0", "4", "5", "8", "9", "encrypted"],
        ssh_public_key: ["ssh-rsa", "ssh-ecdsa", "ssh-ed25519"],
      };
    return item.encoding !== null && allowed[item.kind].includes(item.encoding);
  });
export const localUserSchema = z
  .strictObject({
    name: accountName,
    privilege: z.number().int().min(0).max(15).nullable(),
    login_class: accountName.nullable(),
    uid: z.number().int().min(100).max(64000).nullable(),
    authentication: z.array(localAuthenticationSchema).max(8),
    provenance: z.record(z.string(), location),
  })
  .refine(
    (user) =>
      new Set(
        user.authentication.map((item) => `${item.kind}:${item.encoding}`),
      ).size === user.authentication.length,
  );

export const snapshotSchema = z.object({
  configuration_id: id,
  device_id: id,
  created_at: timestamp,
  canonical: z
    .looseObject({
      schema_version: z.enum(["1.0", "1.1"]),
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
      local_users: z.array(localUserSchema).optional(),
    })
    .refine(
      (config) =>
        (config.schema_version === "1.0"
          ? !config.local_users?.length
          : config.local_users !== undefined) &&
        new Set(config.local_users?.map((user) => user.name)).size ===
          (config.local_users?.length ?? 0),
    ),
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
    "isolation_forest",
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
export const knowledgeDocumentIds = [
  "docs/policies/management-plane.md",
  "docs/policies/observability.md",
  "docs/policies/access-control.md",
  "docs/policies/routing.md",
  "docs/policies/layer2.md",
  "docs/expected-configuration.md",
  "docs/baseline.md",
  "docs/statistical-baseline.md",
] as const;
export const documentChunkSchema = z
  .strictObject({
    document_id: z.enum(knowledgeDocumentIds),
    document_title: z.string().min(1).max(200),
    section: z.string().min(1).max(200),
    section_title: z.string().min(1).max(200),
    citation: z.string().min(1).max(330),
    document_sha256: hash,
    content_sha256: hash,
    content: z.string().min(1).max(8192),
    authority: z.literal("internal_project_document"),
  })
  .refine(
    (chunk) =>
      chunk.citation === `${chunk.document_id}#${chunk.section}` &&
      new TextEncoder().encode(chunk.content).byteLength <= 8192,
  );
const knowledgeReleaseByDetectorVersion: Record<string, string> = {
  "policy-rules-0.6.0": "project-knowledge-0.1.0",
  "policy-rules-0.7.0": "project-knowledge-0.2.0",
  "expected-config-0.1.0": "project-knowledge-0.1.0",
  "peer-baseline-0.1.0": "project-knowledge-0.1.0",
  "isolation-forest-0.1.0": "project-knowledge-0.1.0",
};
const embeddingIdentitySchema = z
  .strictObject({
    model_id: z.string().min(1).max(200),
    revision: z.string().regex(/^[0-9a-f]{40}$/),
    files_sha256: hash,
    pipeline_version: z.string().min(1).max(100),
    dimensions: z.number().int().min(1).max(1024),
    runtime_versions: z.array(z.string().min(1).max(100)).min(1).max(8),
  })
  .refine((item) =>
    [item.model_id, item.pipeline_version, ...item.runtime_versions].every(
      (value) => !/[\p{C}\p{Zl}\p{Zp}]/u.test(value),
    ),
  );
const semanticRetrievalSchema = z.strictObject({
  index_sha256: hash,
  encoder: embeddingIdentitySchema,
  query_source: z.literal("public_detector_metadata"),
  query_sha256: hash,
  required_citations: z.array(z.string().min(1).max(330)).min(1).max(4),
  matches: z
    .array(
      z.strictObject({
        citation: z.string().min(1).max(330),
        content_sha256: hash,
        cosine_similarity: z.number().min(-1).max(1),
      }),
    )
    .max(4),
});
function semanticBindings(bundle: {
  version: string;
  retrieval: "explicit_reference" | "semantic_supplement";
  semantic_retrieval?: z.infer<typeof semanticRetrievalSchema> | null;
  documents: { citation: string; content_sha256: string }[];
  explanation: { citations: string[] };
}) {
  const metadata = bundle.semantic_retrieval;
  if (bundle.retrieval === "explicit_reference")
    return metadata == null && bundle.version.endsWith("0.1.0");
  if (metadata == null || !bundle.version.endsWith("0.2.0")) return false;
  const citations = [
    ...metadata.required_citations,
    ...metadata.matches.map((item) => item.citation),
  ];
  return (
    new Set(citations).size === citations.length &&
    JSON.stringify(citations) ===
      JSON.stringify(bundle.documents.map((item) => item.citation)) &&
    metadata.matches.every((match) =>
      bundle.documents.some(
        (chunk) =>
          chunk.citation === match.citation &&
          chunk.content_sha256 === match.content_sha256,
      ),
    ) &&
    bundle.explanation.citations.every((citation) =>
      metadata.required_citations.some((required) =>
        citation.includes("#")
          ? required === citation
          : required.startsWith(`${citation}#`),
      ),
    )
  );
}
export const explanationBundleSchema = z
  .strictObject({
    version: z.enum(["finding-context-0.1.0", "finding-context-0.2.0"]),
    analysis_id: id,
    configuration_id: id,
    device_id: id,
    source_sha256: hash,
    finding_id: id,
    finding_sha256: hash,
    knowledge_version: z.enum([
      "project-knowledge-0.1.0",
      "project-knowledge-0.2.0",
    ]),
    knowledge_sha256: hash,
    retrieval: z.enum(["explicit_reference", "semantic_supplement"]),
    semantic_retrieval: semanticRetrievalSchema.nullable().optional(),
    provider: z.literal("deterministic_local"),
    llm_status: z.literal("unavailable"),
    explanation: z.strictObject(explanation.shape),
    documents: z.array(documentChunkSchema).min(1).max(4),
    limitations: z.array(z.string()).min(1),
  })
  .refine((bundle) => {
    const item = bundle.explanation;
    return (
      semanticBindings(bundle) &&
      item.finding_id === bundle.finding_id &&
      item.device_id === bundle.device_id &&
      item.source_sha256 === bundle.source_sha256 &&
      item.finding_sha256 === bundle.finding_sha256 &&
      knowledgeReleaseByDetectorVersion[item.detector_version] ===
        bundle.knowledge_version &&
      new Set(bundle.documents.map((chunk) => chunk.citation)).size ===
        bundle.documents.length
    );
  });
export type ExplanationBundle = z.infer<typeof explanationBundleSchema>;
const modelText = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine(
      (value) =>
        value.trim().length > 0 &&
        !/[\p{C}\p{Zl}\p{Zp}]/u.test(value.replace(/[\n\t]/g, "")),
    );
export const modelDraftSchema = z
  .strictObject({
    summary: modelText(1000),
    technical_explanation: modelText(8000),
    recommendation: modelText(4000),
    possible_impact: z.array(modelText(8000)).max(10),
    patch_draft: z.null(),
    assumptions: z.array(modelText(8000)).max(20),
    missing_information: z.array(modelText(8000)).max(20),
    citations: z.array(modelText(330)).min(1).max(4),
    requires_human_review: z.literal(true),
  })
  .refine(
    (answer) =>
      new Set(answer.citations).size === answer.citations.length &&
      new TextEncoder().encode(JSON.stringify(answer)).byteLength <= 32768,
  );
export const modelExplanationSchema = z
  .strictObject({
    ...explanationBundleSchema.shape,
    version: z.enum(["model-explanation-0.1.0", "model-explanation-0.2.0"]),
    provider: z.literal("loopback_language_model"),
    llm_status: z.literal("draft"),
    privacy_version: z.literal("finding-context-redaction-0.1.0"),
    context_sha256: hash,
    model_alias: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/),
    answer: modelDraftSchema,
  })
  .refine((bundle) => {
    const item = bundle.explanation;
    return (
      semanticBindings(bundle) &&
      item.finding_id === bundle.finding_id &&
      item.device_id === bundle.device_id &&
      item.source_sha256 === bundle.source_sha256 &&
      item.finding_sha256 === bundle.finding_sha256 &&
      knowledgeReleaseByDetectorVersion[item.detector_version] ===
        bundle.knowledge_version &&
      new Set(bundle.documents.map((chunk) => chunk.citation)).size ===
        bundle.documents.length &&
      bundle.answer.citations.every((citation) =>
        bundle.documents.some((chunk) => chunk.citation === citation),
      )
    );
  });
export type ModelExplanation = z.infer<typeof modelExplanationSchema>;
export const explanationCapabilitiesSchema = z.strictObject({
  version: z.enum([
    "explanation-capabilities-0.1.0",
    "explanation-capabilities-0.2.0",
  ]),
  local_model: z.enum(["disabled", "configured"]),
  model_health_checked: z.literal(false),
  transport: z.literal("literal_loopback_only"),
  explicit_request_permission_required: z.literal(true),
  semantic_retrieval: z.enum(["disabled", "configured"]).default("disabled"),
  retrieval_health_checked: z.literal(false).default(false),
});
export type ExplanationCapabilities = z.infer<
  typeof explanationCapabilitiesSchema
>;
export type ExplainFinding = {
  analysis_id: string;
  finding_sha256: string;
  provider?: "local" | "llm";
  allow_local_model_context?: boolean;
  retrieval?: "explicit_reference" | "semantic_supplement";
};
const snapshotBindingSchema = z.object({
  configuration_id: id,
  device_id: id,
  source_sha256: hash,
  created_at: timestamp,
});
const forestMetadataSchema = z
  .object({
    model_version: z.literal("isolation-forest-0.1.0"),
    library_version: z.string().min(1),
    feature_schema_version: z.literal("structured-features-0.1.0"),
    feature_names: z.array(z.string()).length(33),
    group: z.object({
      vendor: z.enum(["cisco", "juniper"]),
      platform: z.string(),
      device_role: z.string(),
      site_class: z.string(),
      service_profile: z.string(),
    }),
    sample_count: z.number().int().min(8).max(100),
    contamination: z.number().positive().max(0.5),
    random_state: z.number().int(),
    estimator_count: z.number().int().min(1).max(200),
    training_score_min: score,
    training_score_max: score,
    feature_medians: z.array(z.number()).length(33),
    feature_scales: z.array(z.number().positive()).length(33),
  })
  .refine(
    (metadata) =>
      metadata.training_score_min <= metadata.training_score_max &&
      new Set(metadata.feature_names).size === 33,
  );
export const modelSchema = z
  .object({
    version: z.literal("model-registry-0.1.0"),
    model_id: id,
    created_at: timestamp,
    status: z.literal("experimental"),
    artifact_sha256: hash,
    decision_offset: z.number().min(-1).max(0),
    metadata: forestMetadataSchema,
    training: z.array(snapshotBindingSchema).min(8).max(100),
    training_hostnames: z.array(z.string().min(1)).min(8).max(100),
  })
  .refine(
    (model) =>
      model.training.length === model.metadata.sample_count &&
      model.training.length === model.training_hostnames.length &&
      new Set(model.training_hostnames).size === model.training.length &&
      model.training.every(
        (item) => Date.parse(item.created_at) <= Date.parse(model.created_at),
      ) &&
      ["configuration_id", "device_id", "source_sha256"].every(
        (key) =>
          new Set(model.training.map((item) => item[key as keyof typeof item]))
            .size === model.training.length,
      ),
  );
const statisticalSchema = z
  .object({
    model: modelSchema,
    score_samples: z.number().min(-1).max(0),
    decision_function: z.number().min(-1).max(1),
    prediction: z.union([z.literal(-1), z.literal(1)]),
  })
  .refine(
    (context) =>
      context.prediction === (context.decision_function < 0 ? -1 : 1) &&
      Math.abs(
        context.decision_function -
          (context.score_samples - context.model.decision_offset),
      ) <= 1e-14,
  );
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
    version: z.enum([
      "analysis-api-0.1.0",
      "analysis-api-0.2.0",
      "analysis-api-0.3.0",
    ]),
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
    statistical: statisticalSchema.nullable().optional(),
  })
  .refine((result) => {
    const comparison = result.comparison;
    const statistical = result.statistical;
    if (
      result.version !== "analysis-api-0.3.0" &&
      (result.version === "analysis-api-0.2.0") !== !!comparison
    )
      return false;
    if ((result.version === "analysis-api-0.3.0") !== !!statistical)
      return false;
    if (statistical) {
      if (result.status !== "completed") return false;
      if (
        statistical.model.training.some(
          (item) =>
            item.device_id === result.device_id ||
            item.source_sha256 === result.source_sha256,
        )
      )
        return false;
      const outliers = result.findings.filter(
        (item) => item.detector === "isolation_forest",
      );
      if (outliers.length !== (statistical.prediction === -1 ? 1 : 0))
        return false;
      if (
        outliers.some(
          (item) =>
            item.observed.model_id !== statistical.model.model_id ||
            item.observed.artifact_sha256 !==
              statistical.model.artifact_sha256 ||
            item.observed.raw_anomaly_score !== -statistical.score_samples ||
            item.observed.decision_function !== statistical.decision_function,
        )
      )
        return false;
    }
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
        (item.source === "peer_group" && comparison?.peer_baseline) ||
        (item.source === "statistical" && statistical)
          ? item.status !== "completed" ||
            item.raw_score === null ||
            Math.abs(
              item.effective_weight -
                {
                  policy: 0.35,
                  peer_group: 0.15,
                  statistical: 0.1,
                  transformer: 0.1,
                  verification: 0.3,
                }[item.source] /
                  (0.35 +
                    (comparison?.peer_baseline ? 0.15 : 0) +
                    (statistical ? 0.1 : 0)),
            ) > 1e-9 ||
            [...item.finding_ids].sort().join() !==
              result.findings
                .filter(
                  (finding) =>
                    finding.detector ===
                    (item.source === "policy"
                      ? "policy_engine"
                      : item.source === "statistical"
                        ? "isolation_forest"
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
              : finding.detector === "isolation_forest"
                ? statistical?.model.metadata.model_version
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
export type ModelSummary = z.infer<typeof modelSchema>;
export type TrainModel = {
  configuration_ids: string[];
  contamination?: number;
};
export type Upload = {
  device_id: string;
  filename: string;
  content: string;
  inventory?: Inventory;
};
export type AnalysisOptions = {
  reference_configuration_id?: string;
  peer_configuration_ids?: string[];
  statistical_model_id?: string;
};
