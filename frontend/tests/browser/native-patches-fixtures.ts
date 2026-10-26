// Authored actual retained-source HTTP controls, 2026-10-26; two reused template families.
// Browser transport is mocked; no independent quality or device/model/engine execution claim.
export const nativeControls = [
  {
    vendor: "cisco",
    snapshot: {
      canonical: {
        acls: [],
        bgp: null,
        device: {
          hostname: "owned",
          os_version: null,
          platform: "ios",
          provenance: {
            hostname: {
              parser_confidence: 1,
              raw_text_hash:
                "21c25660191548f04dc2eaf4bda9eb754834a9fdedf2212fb9e6b47d872affdd",
              source_lines: [1],
            },
          },
          role: null,
          service_profile: null,
          site: null,
          site_class: null,
          vendor: "cisco",
        },
        interfaces: [],
        local_users: [
          {
            authentication: [
              {
                encoding: "0",
                kind: "secret",
                provenance: {
                  parser_confidence: 1,
                  raw_text_hash:
                    "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                  source_lines: [3],
                },
              },
            ],
            login_class: null,
            name: "operator",
            privilege: 15,
            provenance: {
              name: {
                parser_confidence: 1,
                raw_text_hash:
                  "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                source_lines: [3],
              },
              privilege: {
                parser_confidence: 1,
                raw_text_hash:
                  "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                source_lines: [3],
              },
            },
            uid: null,
          },
        ],
        management: {
          aaa_enabled: false,
          ntp_servers: [],
          provenance: {
            snmp_versions: {
              parser_confidence: 1,
              raw_text_hash:
                "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
              source_lines: [4],
            },
            ssh_enabled: {
              parser_confidence: 1,
              raw_text_hash:
                "94f5d7313c741c70b9ffdb3a79374172a71215e6a259d6c84a30adbcf5a78962",
              source_lines: [2, 6],
            },
            ssh_version: {
              parser_confidence: 1,
              raw_text_hash:
                "33c3964de1156489b449ffdf1e5232356b439f525708b3370b3d24d9e5d36f6a",
              source_lines: [2],
            },
            telnet_enabled: {
              parser_confidence: 1,
              raw_text_hash:
                "3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65",
              source_lines: [6],
            },
          },
          snmp_versions: ["v1", "v2c"],
          ssh_enabled: true,
          ssh_version: "2",
          syslog_servers: [],
          telnet_enabled: true,
        },
        ospf: [],
        parse_warnings: [],
        parser_confidence: 1,
        prefix_lists: [],
        schema_version: "1.1",
        source: {
          collected_at: "2026-10-26T09:38:43.918249Z",
          filename: "owned.cfg",
          sha256:
            "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
        },
        static_routes: [],
        unparsed_fragments: [],
        vlans: [],
      },
      configuration_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
      created_at: "2026-10-26T09:38:43.918624Z",
      device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
      parser_coverage: {
        accepted_units: 6,
        adapter_version: "cisco-ios-source-lines-0.1.0",
        command_units: 6,
        ignored_lines: 1,
        platform: "ios",
        proves_vendor_syntax: false,
        source_line_count: 7,
        source_sha256:
          "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
        structural_units: 0,
        unit: "adapter_source_lines",
        units: [
          {
            disposition: "accepted",
            raw_text_sha256:
              "21c25660191548f04dc2eaf4bda9eb754834a9fdedf2212fb9e6b47d872affdd",
            source_line: 1,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "33c3964de1156489b449ffdf1e5232356b439f525708b3370b3d24d9e5d36f6a",
            source_line: 2,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
            source_line: 3,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
            source_line: 4,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "0227bdc1e1e5f634dc9946498be346adb042f575781242a9b84f6a7e7b058ced",
            source_line: 5,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65",
            source_line: 6,
          },
          {
            disposition: "ignored",
            raw_text_sha256:
              "bb7208bc9b5d7c04f1236a82a0093a5e33f40423d5ba8d4266f7092c3ba43b62",
            source_line: 7,
          },
        ],
        unparsed_fraction: 0,
        unparsed_units: 0,
        vendor: "cisco",
        version: "parser-coverage-0.1.0",
      },
    },
    analysis: {
      analysis_id: "d8225e48-7408-4ce2-88a1-bd725dc3ee95",
      comparison: null,
      configuration_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
      created_at: "2026-10-26T09:38:43.940479Z",
      device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
      explanations: [
        {
          anchors: [
            {
              lines: [6],
              source_sha256:
                "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
              statement_sha256:
                "3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65",
            },
          ],
          anomaly_score: 0,
          citations: [
            "docs/policies/management-plane.md#telnet-must-be-disabled",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
          finding_sha256:
            "7c4438e370825c31c858428428fd81f154dd91ec79c254a41aad04d7444cb077",
          formal_verification: "not_run",
          limitations: [
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Disable Telnet and permit SSH for remote administrative access.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
          summary: "Telnet is enabled on the management plane",
          technical_explanation:
            "Telnet permits unencrypted remote management sessions.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [],
          anomaly_score: 0,
          citations: [
            "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          finding_id: "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
          finding_sha256:
            "f14a3cad37a869642878e895d58a6fcca57a41d6e1432a5833d8ef3999fbfc0f",
          formal_verification: "not_run",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
            "No current source line proves an absent parameter; no line anchor was invented.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Enable centralized AAA with an explicitly tested local fallback.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
          summary: "Centralized AAA is not enabled",
          technical_explanation:
            "No supported centralized AAA enablement statement was found.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [
            {
              lines: [4],
              source_sha256:
                "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
              statement_sha256:
                "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
            },
          ],
          anomaly_score: 0,
          citations: [
            "docs/policies/observability.md#legacy-snmp-must-be-disabled",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          finding_id: "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
          finding_sha256:
            "f65df346d3f43a321da8ea5f655aa674888477aae347d54049d74b151e3a54f7",
          formal_verification: "not_run",
          limitations: [
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Migrate monitoring to SNMPv3 and remove legacy communities.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
          summary: "Legacy SNMP is enabled",
          technical_explanation:
            "SNMPv1 or SNMPv2c is configured without modern protection.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [],
          anomaly_score: 0,
          citations: [
            "docs/policies/observability.md#time-synchronization-is-required",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          finding_id: "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
          finding_sha256:
            "a403922c73732e53df29fc935689367d1319ce221468fbe66bfa55359b0ca9b7",
          formal_verification: "not_run",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
            "No current source line proves an absent parameter; no line anchor was invented.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation: "Configure approved redundant NTP servers.",
          requires_human_review: true,
          severity: "medium",
          source_sha256:
            "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
          summary: "NTP is not configured",
          technical_explanation: "No supported NTP server statement was found.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [],
          anomaly_score: 0,
          citations: [
            "docs/policies/observability.md#remote-audit-logging-is-required",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          finding_id: "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
          finding_sha256:
            "d1d154450c01f2e0cd85c893c3761ae6add1dd6fa99936004a13b7c3cb943aba",
          formal_verification: "not_run",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
            "No current source line proves an absent parameter; no line anchor was invented.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Send security and operational events to approved remote collectors.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
          summary: "Remote Syslog is not configured",
          technical_explanation:
            "No supported remote Syslog destination was found.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [
            {
              lines: [3],
              source_sha256:
                "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
              statement_sha256:
                "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
            },
          ],
          anomaly_score: 0,
          citations: [
            "docs/policies/management-plane.md#local-credentials-must-not-use-type-0",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          finding_id: "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
          finding_sha256:
            "680a7fca5dd388a2d612a3d0f65308d6e92cc7ef51947add0da01ae597591b59",
          formal_verification: "not_run",
          limitations: [
            "Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified.",
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Replace the credential with an approved non-reversible format and protect source files.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
          summary: "Local credential is explicitly stored as type 0",
          technical_explanation:
            "The account explicitly declares unencrypted credential storage type 0.",
          version: "local-explanation-0.1.0",
        },
      ],
      findings: [
        {
          affected_lines: [6],
          anomaly_score: 0,
          category: "management.telnet_enabled",
          confidence: 1,
          detector: "policy_engine",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          evidence: [
            {
              kind: "policy_violation",
              message: "Telnet permits unencrypted remote management sessions.",
              source_location: {
                parser_confidence: 1,
                raw_text_hash:
                  "3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65",
                source_lines: [6],
              },
            },
          ],
          expected: {
            "management.telnet_enabled": false,
          },
          finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
          limitations: [],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.telnet_enabled": true,
          },
          references: [
            "docs/policies/management-plane.md#telnet-must-be-disabled",
          ],
          remediation:
            "Disable Telnet and permit SSH for remote administrative access.",
          severity: "high",
          title: "Telnet is enabled on the management plane",
        },
        {
          affected_lines: [],
          anomaly_score: 0,
          category: "management.aaa_disabled",
          confidence: 1,
          detector: "policy_engine",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          evidence: [
            {
              kind: "policy_violation",
              message:
                "No supported centralized AAA enablement statement was found.",
              source_location: null,
            },
          ],
          expected: {
            "management.aaa_enabled": true,
          },
          finding_id: "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
          ],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.aaa_enabled": false,
          },
          references: [
            "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
          ],
          remediation:
            "Enable centralized AAA with an explicitly tested local fallback.",
          severity: "high",
          title: "Centralized AAA is not enabled",
        },
        {
          affected_lines: [4],
          anomaly_score: 0,
          category: "management.snmp_legacy_enabled",
          confidence: 1,
          detector: "policy_engine",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          evidence: [
            {
              kind: "policy_violation",
              message:
                "SNMPv1 or SNMPv2c is configured without modern protection.",
              source_location: {
                parser_confidence: 1,
                raw_text_hash:
                  "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
                source_lines: [4],
              },
            },
          ],
          expected: {
            "management.snmp_versions": "SNMPv3 only, or SNMP disabled",
          },
          finding_id: "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
          limitations: [],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.snmp_versions": ["v1", "v2c"],
          },
          references: [
            "docs/policies/observability.md#legacy-snmp-must-be-disabled",
          ],
          remediation:
            "Migrate monitoring to SNMPv3 and remove legacy communities.",
          severity: "high",
          title: "Legacy SNMP is enabled",
        },
        {
          affected_lines: [],
          anomaly_score: 0,
          category: "management.ntp_not_configured",
          confidence: 1,
          detector: "policy_engine",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          evidence: [
            {
              kind: "policy_violation",
              message: "No supported NTP server statement was found.",
              source_location: null,
            },
          ],
          expected: {
            "management.ntp_servers": "At least one approved NTP server",
          },
          finding_id: "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
          ],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.ntp_servers": [],
          },
          references: [
            "docs/policies/observability.md#time-synchronization-is-required",
          ],
          remediation: "Configure approved redundant NTP servers.",
          severity: "medium",
          title: "NTP is not configured",
        },
        {
          affected_lines: [],
          anomaly_score: 0,
          category: "management.syslog_not_configured",
          confidence: 1,
          detector: "policy_engine",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          evidence: [
            {
              kind: "policy_violation",
              message: "No supported remote Syslog destination was found.",
              source_location: null,
            },
          ],
          expected: {
            "management.syslog_servers":
              "At least one approved remote Syslog server",
          },
          finding_id: "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
          ],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.syslog_servers": [],
          },
          references: [
            "docs/policies/observability.md#remote-audit-logging-is-required",
          ],
          remediation:
            "Send security and operational events to approved remote collectors.",
          severity: "high",
          title: "Remote Syslog is not configured",
        },
        {
          affected_lines: [3],
          anomaly_score: 0,
          category: "account.cleartext_credential",
          confidence: 1,
          detector: "policy_engine",
          device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
          evidence: [
            {
              kind: "policy_violation",
              message:
                "The account explicitly declares unencrypted credential storage type 0.",
              source_location: {
                parser_confidence: 1,
                raw_text_hash:
                  "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                source_lines: [3],
              },
            },
          ],
          expected: {
            "account.cleartext_credential":
              "No explicitly stored type-0 credentials",
          },
          finding_id: "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
          limitations: [
            "Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified.",
          ],
          model_version: "policy-rules-0.7.0",
          observed: {
            "account.cleartext_credential": {
              account: "operator",
              declared_authentication: [
                {
                  encoding: "0",
                  kind: "secret",
                },
              ],
            },
          },
          references: [
            "docs/policies/management-plane.md#local-credentials-must-not-use-type-0",
          ],
          remediation:
            "Replace the credential with an approved non-reversible format and protect source files.",
          severity: "high",
          title: "Local credential is explicitly stored as type 0",
        },
      ],
      limitations: [
        "Only the recorded deterministic detectors were run; ML and formal verification were not run.",
        "Reference differences are review information and are excluded from risk fusion.",
        "Inventory labels and comparison inputs were explicitly selected by the operator; they are not independently verified or approved security baselines.",
        "Scores are uncalibrated; the result requires engineer review.",
      ],
      policy_catalog_version: "policy-rules-0.7.0",
      risk: {
        assessment_id: "9f9668f8-c3e3-5370-b86d-92a2ff1cf3ea",
        components: [
          {
            configured_weight: 0.35,
            effective_weight: 1,
            finding_ids: [
              "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
              "36dc9858-d8c8-54bd-b664-276a24519cae",
              "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
              "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
              "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
              "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
            ],
            raw_score: 0.75,
            source: "policy",
            status: "completed",
          },
          {
            configured_weight: 0.15,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "peer_group",
            status: "unavailable",
          },
          {
            configured_weight: 0.1,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "statistical",
            status: "unavailable",
          },
          {
            configured_weight: 0.1,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "transformer",
            status: "unavailable",
          },
          {
            configured_weight: 0.3,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "verification",
            status: "unavailable",
          },
        ],
        device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
        guardrails: [],
        level: "high",
        limitations: [
          "peer_group signal was not available and its weight was redistributed.",
          "statistical signal was not available and its weight was redistributed.",
          "transformer signal was not available and its weight was redistributed.",
          "verification signal was not available and its weight was redistributed.",
        ],
        model_version: "risk-fusion-0.1.0",
        score: 0.75,
      },
      source_sha256:
        "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
      statistical: null,
      status: "completed",
      version: "analysis-api-0.1.0",
    },
    selection: {
      analysis_created_at: "2026-10-26T09:38:43.940479Z",
      analysis_id: "d8225e48-7408-4ce2-88a1-bd725dc3ee95",
      analysis_sha256:
        "1db27f16406a0192c7ec72d0e966b35c589da1a68803f763511f142495cd0efe",
      canonical_sha256:
        "8e0775a858f6fa6f1514866ca7424fa511831e92719f46b318a0f245a07578e4",
      configuration_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
      finding_pins: [
        {
          finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
          finding_sha256:
            "7c4438e370825c31c858428428fd81f154dd91ec79c254a41aad04d7444cb077",
        },
      ],
      policy_catalog_version: "policy-rules-0.7.0",
      source: {
        configuration_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
        created_at: "2026-10-26T09:38:43.918624Z",
        device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
        source_sha256:
          "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
      },
      version: "native-patch-selection-0.1.0",
    },
    candidate: {
      analysis_created_at: "2026-10-26T09:38:43.940479Z",
      applied: false,
      approved: false,
      calibrated: false,
      candidate_id: "aee5b9f2-27f6-4bfe-83ea-3768f0b6a78f",
      configuration_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
      created_at: "2026-10-26T09:38:44.044553Z",
      formal_qualification: "not_proven",
      generator_kind: "deterministic_vendor",
      generator_version: "native-telnet-generator-0.1.0",
      individual_identity_verified: false,
      local_reference: "selected_original_not_approved_baseline",
      metadata: {
        application_supported: false,
        category: "management.telnet_enabled",
        device_syntax_verified: false,
        edits: [
          {
            after_line_sha256:
              "9b36c5f265a640375d400e8a7d004443aa385112bdaed82c48f893b04bb55eca",
            before_line_sha256:
              "7db9550004777f3f9a91f5d52d77feecab9641774fd065de0a781f0606c26beb",
            kind: "cisco_vty_ssh_only",
            source_line: 6,
            vty: {
              first: 0,
              last: 4,
            },
          },
        ],
        management_access_verified: false,
        policy_catalog_version: "policy-rules-0.7.0",
        review: {
          preflight: {
            after: {
              complete: true,
              confidence: 1,
              source_sha256:
                "e90f6f54d46304d68c562ebd3d032843ec923d82721450f15633a74bb76c274e",
              unparsed_count: 0,
              warning_count: 0,
            },
            after_policy_findings: [
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.aaa_disabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported centralized AAA enablement statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.aaa_enabled": true,
                },
                finding_id: "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.aaa_enabled": false,
                },
                references: [
                  "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                ],
                remediation:
                  "Enable centralized AAA with an explicitly tested local fallback.",
                severity: "high",
                title: "Centralized AAA is not enabled",
              },
              {
                affected_lines: [4],
                anomaly_score: 0,
                category: "management.snmp_legacy_enabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "SNMPv1 or SNMPv2c is configured without modern protection.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
                      source_lines: [4],
                    },
                  },
                ],
                expected: {
                  "management.snmp_versions": "SNMPv3 only, or SNMP disabled",
                },
                finding_id: "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
                limitations: [],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.snmp_versions": ["v1", "v2c"],
                },
                references: [
                  "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                ],
                remediation:
                  "Migrate monitoring to SNMPv3 and remove legacy communities.",
                severity: "high",
                title: "Legacy SNMP is enabled",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.ntp_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message: "No supported NTP server statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.ntp_servers": "At least one approved NTP server",
                },
                finding_id: "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.ntp_servers": [],
                },
                references: [
                  "docs/policies/observability.md#time-synchronization-is-required",
                ],
                remediation: "Configure approved redundant NTP servers.",
                severity: "medium",
                title: "NTP is not configured",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.syslog_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported remote Syslog destination was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.syslog_servers":
                    "At least one approved remote Syslog server",
                },
                finding_id: "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.syslog_servers": [],
                },
                references: [
                  "docs/policies/observability.md#remote-audit-logging-is-required",
                ],
                remediation:
                  "Send security and operational events to approved remote collectors.",
                severity: "high",
                title: "Remote Syslog is not configured",
              },
              {
                affected_lines: [3],
                anomaly_score: 0,
                category: "account.cleartext_credential",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "The account explicitly declares unencrypted credential storage type 0.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                      source_lines: [3],
                    },
                  },
                ],
                expected: {
                  "account.cleartext_credential":
                    "No explicitly stored type-0 credentials",
                },
                finding_id: "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
                limitations: [
                  "Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "account.cleartext_credential": {
                    account: "operator",
                    declared_authentication: [
                      {
                        encoding: "0",
                        kind: "secret",
                      },
                    ],
                  },
                },
                references: [
                  "docs/policies/management-plane.md#local-credentials-must-not-use-type-0",
                ],
                remediation:
                  "Replace the credential with an approved non-reversible format and protect source files.",
                severity: "high",
                title: "Local credential is explicitly stored as type 0",
              },
            ],
            before: {
              complete: true,
              confidence: 1,
              source_sha256:
                "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
              unparsed_count: 0,
              warning_count: 0,
            },
            before_policy_findings: [
              {
                affected_lines: [6],
                anomaly_score: 0,
                category: "management.telnet_enabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "Telnet permits unencrypted remote management sessions.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65",
                      source_lines: [6],
                    },
                  },
                ],
                expected: {
                  "management.telnet_enabled": false,
                },
                finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
                limitations: [],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.telnet_enabled": true,
                },
                references: [
                  "docs/policies/management-plane.md#telnet-must-be-disabled",
                ],
                remediation:
                  "Disable Telnet and permit SSH for remote administrative access.",
                severity: "high",
                title: "Telnet is enabled on the management plane",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.aaa_disabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported centralized AAA enablement statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.aaa_enabled": true,
                },
                finding_id: "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.aaa_enabled": false,
                },
                references: [
                  "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                ],
                remediation:
                  "Enable centralized AAA with an explicitly tested local fallback.",
                severity: "high",
                title: "Centralized AAA is not enabled",
              },
              {
                affected_lines: [4],
                anomaly_score: 0,
                category: "management.snmp_legacy_enabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "SNMPv1 or SNMPv2c is configured without modern protection.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
                      source_lines: [4],
                    },
                  },
                ],
                expected: {
                  "management.snmp_versions": "SNMPv3 only, or SNMP disabled",
                },
                finding_id: "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
                limitations: [],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.snmp_versions": ["v1", "v2c"],
                },
                references: [
                  "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                ],
                remediation:
                  "Migrate monitoring to SNMPv3 and remove legacy communities.",
                severity: "high",
                title: "Legacy SNMP is enabled",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.ntp_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message: "No supported NTP server statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.ntp_servers": "At least one approved NTP server",
                },
                finding_id: "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.ntp_servers": [],
                },
                references: [
                  "docs/policies/observability.md#time-synchronization-is-required",
                ],
                remediation: "Configure approved redundant NTP servers.",
                severity: "medium",
                title: "NTP is not configured",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.syslog_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported remote Syslog destination was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.syslog_servers":
                    "At least one approved remote Syslog server",
                },
                finding_id: "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.syslog_servers": [],
                },
                references: [
                  "docs/policies/observability.md#remote-audit-logging-is-required",
                ],
                remediation:
                  "Send security and operational events to approved remote collectors.",
                severity: "high",
                title: "Remote Syslog is not configured",
              },
              {
                affected_lines: [3],
                anomaly_score: 0,
                category: "account.cleartext_credential",
                confidence: 1,
                detector: "policy_engine",
                device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "The account explicitly declares unencrypted credential storage type 0.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                      source_lines: [3],
                    },
                  },
                ],
                expected: {
                  "account.cleartext_credential":
                    "No explicitly stored type-0 credentials",
                },
                finding_id: "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
                limitations: [
                  "Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "account.cleartext_credential": {
                    account: "operator",
                    declared_authentication: [
                      {
                        encoding: "0",
                        kind: "secret",
                      },
                    ],
                  },
                },
                references: [
                  "docs/policies/management-plane.md#local-credentials-must-not-use-type-0",
                ],
                remediation:
                  "Replace the credential with an approved non-reversible format and protect source files.",
                severity: "high",
                title: "Local credential is explicitly stored as type 0",
              },
            ],
            current_policy_risk: {
              assessment_id: "62345c0b-fa6a-59d5-b1e6-669d153453eb",
              components: [
                {
                  configured_weight: 0.35,
                  effective_weight: 1,
                  finding_ids: [
                    "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
                    "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
                    "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
                    "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
                    "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
                  ],
                  raw_score: 0.75,
                  source: "policy",
                  status: "completed",
                },
                {
                  configured_weight: 0.15,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "peer_group",
                  status: "unavailable",
                },
                {
                  configured_weight: 0.1,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "statistical",
                  status: "unavailable",
                },
                {
                  configured_weight: 0.1,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "transformer",
                  status: "unavailable",
                },
                {
                  configured_weight: 0.3,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "verification",
                  status: "unavailable",
                },
              ],
              device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
              guardrails: [],
              level: "high",
              limitations: [
                "peer_group signal was not available and its weight was redistributed.",
                "statistical signal was not available and its weight was redistributed.",
                "transformer signal was not available and its weight was redistributed.",
                "verification signal was not available and its weight was redistributed.",
              ],
              model_version: "risk-fusion-0.1.0",
              score: 0.75,
            },
            device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
            formal_verification: "not_run",
            limitations: [
              "Local checks only: no reachability simulation, formal validation or approval.",
              "The selected reference may itself contain violations; review all current findings.",
              "Policy changes match exact observations, not line numbers or finding IDs. Changed observations appear as resolved/introduced pairs; resolved is not proof of repair.",
              "Reference differences are separate from the policy-only, uncalibrated risk score.",
              "ML, peer-group and statistical detectors were not run.",
              "Addresses and parameter values may be sensitive; keep this report private.",
            ],
            ml_status: "not_run",
            policy_catalog_version: "policy-rules-0.7.0",
            policy_changes: {
              introduced: [],
              persistent: [
                {
                  after: {
                    affected_lines: [3],
                    anomaly_score: 0,
                    category: "account.cleartext_credential",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "The account explicitly declares unencrypted credential storage type 0.",
                        source_location: {
                          parser_confidence: 1,
                          raw_text_hash:
                            "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                          source_lines: [3],
                        },
                      },
                    ],
                    expected: {
                      "account.cleartext_credential":
                        "No explicitly stored type-0 credentials",
                    },
                    finding_id: "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
                    limitations: [
                      "Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "account.cleartext_credential": {
                        account: "operator",
                        declared_authentication: [
                          {
                            encoding: "0",
                            kind: "secret",
                          },
                        ],
                      },
                    },
                    references: [
                      "docs/policies/management-plane.md#local-credentials-must-not-use-type-0",
                    ],
                    remediation:
                      "Replace the credential with an approved non-reversible format and protect source files.",
                    severity: "high",
                    title: "Local credential is explicitly stored as type 0",
                  },
                  before: {
                    affected_lines: [3],
                    anomaly_score: 0,
                    category: "account.cleartext_credential",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "The account explicitly declares unencrypted credential storage type 0.",
                        source_location: {
                          parser_confidence: 1,
                          raw_text_hash:
                            "86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0",
                          source_lines: [3],
                        },
                      },
                    ],
                    expected: {
                      "account.cleartext_credential":
                        "No explicitly stored type-0 credentials",
                    },
                    finding_id: "014ba24d-ca2b-548c-a363-9cfbe52ecccd",
                    limitations: [
                      "Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "account.cleartext_credential": {
                        account: "operator",
                        declared_authentication: [
                          {
                            encoding: "0",
                            kind: "secret",
                          },
                        ],
                      },
                    },
                    references: [
                      "docs/policies/management-plane.md#local-credentials-must-not-use-type-0",
                    ],
                    remediation:
                      "Replace the credential with an approved non-reversible format and protect source files.",
                    severity: "high",
                    title: "Local credential is explicitly stored as type 0",
                  },
                },
                {
                  after: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.aaa_disabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported centralized AAA enablement statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.aaa_enabled": true,
                    },
                    finding_id: "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.aaa_enabled": false,
                    },
                    references: [
                      "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                    ],
                    remediation:
                      "Enable centralized AAA with an explicitly tested local fallback.",
                    severity: "high",
                    title: "Centralized AAA is not enabled",
                  },
                  before: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.aaa_disabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported centralized AAA enablement statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.aaa_enabled": true,
                    },
                    finding_id: "9de3e1f7-cbe4-5525-87e3-5339e07aa3d1",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.aaa_enabled": false,
                    },
                    references: [
                      "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                    ],
                    remediation:
                      "Enable centralized AAA with an explicitly tested local fallback.",
                    severity: "high",
                    title: "Centralized AAA is not enabled",
                  },
                },
                {
                  after: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.ntp_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message: "No supported NTP server statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.ntp_servers":
                        "At least one approved NTP server",
                    },
                    finding_id: "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.ntp_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#time-synchronization-is-required",
                    ],
                    remediation: "Configure approved redundant NTP servers.",
                    severity: "medium",
                    title: "NTP is not configured",
                  },
                  before: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.ntp_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message: "No supported NTP server statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.ntp_servers":
                        "At least one approved NTP server",
                    },
                    finding_id: "a31455b1-4e3a-5884-8a9a-2dcc43f37789",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.ntp_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#time-synchronization-is-required",
                    ],
                    remediation: "Configure approved redundant NTP servers.",
                    severity: "medium",
                    title: "NTP is not configured",
                  },
                },
                {
                  after: {
                    affected_lines: [4],
                    anomaly_score: 0,
                    category: "management.snmp_legacy_enabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "SNMPv1 or SNMPv2c is configured without modern protection.",
                        source_location: {
                          parser_confidence: 1,
                          raw_text_hash:
                            "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
                          source_lines: [4],
                        },
                      },
                    ],
                    expected: {
                      "management.snmp_versions":
                        "SNMPv3 only, or SNMP disabled",
                    },
                    finding_id: "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
                    limitations: [],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.snmp_versions": ["v1", "v2c"],
                    },
                    references: [
                      "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                    ],
                    remediation:
                      "Migrate monitoring to SNMPv3 and remove legacy communities.",
                    severity: "high",
                    title: "Legacy SNMP is enabled",
                  },
                  before: {
                    affected_lines: [4],
                    anomaly_score: 0,
                    category: "management.snmp_legacy_enabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "SNMPv1 or SNMPv2c is configured without modern protection.",
                        source_location: {
                          parser_confidence: 1,
                          raw_text_hash:
                            "83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc",
                          source_lines: [4],
                        },
                      },
                    ],
                    expected: {
                      "management.snmp_versions":
                        "SNMPv3 only, or SNMP disabled",
                    },
                    finding_id: "dcfeb7db-8e52-59f8-86c4-c261aa17165a",
                    limitations: [],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.snmp_versions": ["v1", "v2c"],
                    },
                    references: [
                      "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                    ],
                    remediation:
                      "Migrate monitoring to SNMPv3 and remove legacy communities.",
                    severity: "high",
                    title: "Legacy SNMP is enabled",
                  },
                },
                {
                  after: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.syslog_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported remote Syslog destination was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.syslog_servers":
                        "At least one approved remote Syslog server",
                    },
                    finding_id: "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.syslog_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#remote-audit-logging-is-required",
                    ],
                    remediation:
                      "Send security and operational events to approved remote collectors.",
                    severity: "high",
                    title: "Remote Syslog is not configured",
                  },
                  before: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.syslog_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported remote Syslog destination was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.syslog_servers":
                        "At least one approved remote Syslog server",
                    },
                    finding_id: "d9244c88-524f-56d4-91c9-6ad3c4c63bd2",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.syslog_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#remote-audit-logging-is-required",
                    ],
                    remediation:
                      "Send security and operational events to approved remote collectors.",
                    severity: "high",
                    title: "Remote Syslog is not configured",
                  },
                },
              ],
              resolved: [
                {
                  affected_lines: [6],
                  anomaly_score: 0,
                  category: "management.telnet_enabled",
                  confidence: 1,
                  detector: "policy_engine",
                  device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
                  evidence: [
                    {
                      kind: "policy_violation",
                      message:
                        "Telnet permits unencrypted remote management sessions.",
                      source_location: {
                        parser_confidence: 1,
                        raw_text_hash:
                          "3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65",
                        source_lines: [6],
                      },
                    },
                  ],
                  expected: {
                    "management.telnet_enabled": false,
                  },
                  finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
                  limitations: [],
                  model_version: "policy-rules-0.7.0",
                  observed: {
                    "management.telnet_enabled": true,
                  },
                  references: [
                    "docs/policies/management-plane.md#telnet-must-be-disabled",
                  ],
                  remediation:
                    "Disable Telnet and permit SSH for remote administrative access.",
                  severity: "high",
                  title: "Telnet is enabled on the management plane",
                },
              ],
            },
            reference_findings: [],
            reference_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
            reference_status: "completed",
            report_id: "b078f23c-5325-5ea5-b9dc-b62f0675e72c",
            requires_human_review: true,
            review_status: "needs_review",
            version: "preflight-0.1.0",
          },
          proposal: {
            after_line_count: 7,
            after_sha256:
              "e90f6f54d46304d68c562ebd3d032843ec923d82721450f15633a74bb76c274e",
            before_line_count: 7,
            before_sha256:
              "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
            changes: [
              {
                after_end: 6,
                after_start: 5,
                before_end: 6,
                before_start: 5,
                operation: "replace",
              },
            ],
            device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
            platform: "ios",
            proposal_id: "58011b0f-93eb-523c-b03e-b46da7a11776",
            reference_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
            status: "draft",
            vendor: "cisco",
            version: "patch-proposal-0.1.0",
          },
          status: "needs_review",
          validation_blockers: [
            "formal_verification_not_run",
            "human_review_required",
            "current_policy_findings",
          ],
          version: "patch-review-0.1.0",
        },
        rollback_plan: "retain_and_review_exact_before_snapshot",
        selected_finding_sha256:
          "7c4438e370825c31c858428428fd81f154dd91ec79c254a41aad04d7444cb077",
        version: "vendor-patch-draft-0.1.0",
      },
      native_commands: ["line vty 0 4", "transport input ssh", "exit"],
      quality_proven: false,
      request: {
        allow_local_native_generation: true,
        allow_private_candidate_retention: true,
        analysis_id: "d8225e48-7408-4ce2-88a1-bd725dc3ee95",
        analysis_sha256:
          "1db27f16406a0192c7ec72d0e966b35c589da1a68803f763511f142495cd0efe",
        candidate_id: "aee5b9f2-27f6-4bfe-83ea-3768f0b6a78f",
        canonical_sha256:
          "8e0775a858f6fa6f1514866ca7424fa511831e92719f46b318a0f245a07578e4",
        finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
        finding_sha256:
          "7c4438e370825c31c858428428fd81f154dd91ec79c254a41aad04d7444cb077",
        policy_catalog_version: "policy-rules-0.7.0",
        source_sha256:
          "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
        version: "native-patch-request-0.1.0",
      },
      review_json:
        '{"analysis_created_at":"2026-10-26T09:38:43.940479Z","applied":false,"approved":false,"calibrated":false,"candidate_id":"aee5b9f2-27f6-4bfe-83ea-3768f0b6a78f","configuration_id":"428dffef-ca84-4d2e-846f-57ef02af00f6","created_at":"2026-10-26T09:38:44.044553Z","formal_qualification":"not_proven","generator_kind":"deterministic_vendor","generator_version":"native-telnet-generator-0.1.0","individual_identity_verified":false,"local_reference":"selected_original_not_approved_baseline","metadata":{"application_supported":false,"category":"management.telnet_enabled","device_syntax_verified":false,"edits":[{"after_line_sha256":"9b36c5f265a640375d400e8a7d004443aa385112bdaed82c48f893b04bb55eca","before_line_sha256":"7db9550004777f3f9a91f5d52d77feecab9641774fd065de0a781f0606c26beb","kind":"cisco_vty_ssh_only","source_line":6,"vty":{"first":0,"last":4}}],"management_access_verified":false,"policy_catalog_version":"policy-rules-0.7.0","review":{"preflight":{"after":{"complete":true,"confidence":1.0,"source_sha256":"e90f6f54d46304d68c562ebd3d032843ec923d82721450f15633a74bb76c274e","unparsed_count":0,"warning_count":0},"after_policy_findings":[{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"9de3e1f7-cbe4-5525-87e3-5339e07aa3d1","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"},{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"dcfeb7db-8e52-59f8-86c4-c261aa17165a","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"a31455b1-4e3a-5884-8a9a-2dcc43f37789","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"d9244c88-524f-56d4-91c9-6ad3c4c63bd2","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"},{"affected_lines":[3],"anomaly_score":0.0,"category":"account.cleartext_credential","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"The account explicitly declares unencrypted credential storage type 0.","source_location":{"parser_confidence":1.0,"raw_text_hash":"86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0","source_lines":[3]}}],"expected":{"account.cleartext_credential":"No explicitly stored type-0 credentials"},"finding_id":"014ba24d-ca2b-548c-a363-9cfbe52ecccd","limitations":["Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified."],"model_version":"policy-rules-0.7.0","observed":{"account.cleartext_credential":{"account":"operator","declared_authentication":[{"encoding":"0","kind":"secret"}]}},"references":["docs/policies/management-plane.md#local-credentials-must-not-use-type-0"],"remediation":"Replace the credential with an approved non-reversible format and protect source files.","severity":"high","title":"Local credential is explicitly stored as type 0"}],"before":{"complete":true,"confidence":1.0,"source_sha256":"0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec","unparsed_count":0,"warning_count":0},"before_policy_findings":[{"affected_lines":[6],"anomaly_score":0.0,"category":"management.telnet_enabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"Telnet permits unencrypted remote management sessions.","source_location":{"parser_confidence":1.0,"raw_text_hash":"3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65","source_lines":[6]}}],"expected":{"management.telnet_enabled":false},"finding_id":"36dc9858-d8c8-54bd-b664-276a24519cae","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.telnet_enabled":true},"references":["docs/policies/management-plane.md#telnet-must-be-disabled"],"remediation":"Disable Telnet and permit SSH for remote administrative access.","severity":"high","title":"Telnet is enabled on the management plane"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"9de3e1f7-cbe4-5525-87e3-5339e07aa3d1","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"},{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"dcfeb7db-8e52-59f8-86c4-c261aa17165a","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"a31455b1-4e3a-5884-8a9a-2dcc43f37789","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"d9244c88-524f-56d4-91c9-6ad3c4c63bd2","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"},{"affected_lines":[3],"anomaly_score":0.0,"category":"account.cleartext_credential","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"The account explicitly declares unencrypted credential storage type 0.","source_location":{"parser_confidence":1.0,"raw_text_hash":"86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0","source_lines":[3]}}],"expected":{"account.cleartext_credential":"No explicitly stored type-0 credentials"},"finding_id":"014ba24d-ca2b-548c-a363-9cfbe52ecccd","limitations":["Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified."],"model_version":"policy-rules-0.7.0","observed":{"account.cleartext_credential":{"account":"operator","declared_authentication":[{"encoding":"0","kind":"secret"}]}},"references":["docs/policies/management-plane.md#local-credentials-must-not-use-type-0"],"remediation":"Replace the credential with an approved non-reversible format and protect source files.","severity":"high","title":"Local credential is explicitly stored as type 0"}],"current_policy_risk":{"assessment_id":"62345c0b-fa6a-59d5-b1e6-669d153453eb","components":[{"configured_weight":0.35,"effective_weight":1.0,"finding_ids":["014ba24d-ca2b-548c-a363-9cfbe52ecccd","9de3e1f7-cbe4-5525-87e3-5339e07aa3d1","a31455b1-4e3a-5884-8a9a-2dcc43f37789","d9244c88-524f-56d4-91c9-6ad3c4c63bd2","dcfeb7db-8e52-59f8-86c4-c261aa17165a"],"raw_score":0.75,"source":"policy","status":"completed"},{"configured_weight":0.15,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"peer_group","status":"unavailable"},{"configured_weight":0.1,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"statistical","status":"unavailable"},{"configured_weight":0.1,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"transformer","status":"unavailable"},{"configured_weight":0.3,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"verification","status":"unavailable"}],"device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","guardrails":[],"level":"high","limitations":["peer_group signal was not available and its weight was redistributed.","statistical signal was not available and its weight was redistributed.","transformer signal was not available and its weight was redistributed.","verification signal was not available and its weight was redistributed."],"model_version":"risk-fusion-0.1.0","score":0.75},"device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","formal_verification":"not_run","limitations":["Local checks only: no reachability simulation, formal validation or approval.","The selected reference may itself contain violations; review all current findings.","Policy changes match exact observations, not line numbers or finding IDs. Changed observations appear as resolved/introduced pairs; resolved is not proof of repair.","Reference differences are separate from the policy-only, uncalibrated risk score.","ML, peer-group and statistical detectors were not run.","Addresses and parameter values may be sensitive; keep this report private."],"ml_status":"not_run","policy_catalog_version":"policy-rules-0.7.0","policy_changes":{"introduced":[],"persistent":[{"after":{"affected_lines":[3],"anomaly_score":0.0,"category":"account.cleartext_credential","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"The account explicitly declares unencrypted credential storage type 0.","source_location":{"parser_confidence":1.0,"raw_text_hash":"86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0","source_lines":[3]}}],"expected":{"account.cleartext_credential":"No explicitly stored type-0 credentials"},"finding_id":"014ba24d-ca2b-548c-a363-9cfbe52ecccd","limitations":["Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified."],"model_version":"policy-rules-0.7.0","observed":{"account.cleartext_credential":{"account":"operator","declared_authentication":[{"encoding":"0","kind":"secret"}]}},"references":["docs/policies/management-plane.md#local-credentials-must-not-use-type-0"],"remediation":"Replace the credential with an approved non-reversible format and protect source files.","severity":"high","title":"Local credential is explicitly stored as type 0"},"before":{"affected_lines":[3],"anomaly_score":0.0,"category":"account.cleartext_credential","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"The account explicitly declares unencrypted credential storage type 0.","source_location":{"parser_confidence":1.0,"raw_text_hash":"86b132c2e16c3065542223779c2def5d4c8eae0870410bb7db14dbf38cd1cde0","source_lines":[3]}}],"expected":{"account.cleartext_credential":"No explicitly stored type-0 credentials"},"finding_id":"014ba24d-ca2b-548c-a363-9cfbe52ecccd","limitations":["Only explicit storage metadata is checked; credential validity, effective authentication and login are not verified."],"model_version":"policy-rules-0.7.0","observed":{"account.cleartext_credential":{"account":"operator","declared_authentication":[{"encoding":"0","kind":"secret"}]}},"references":["docs/policies/management-plane.md#local-credentials-must-not-use-type-0"],"remediation":"Replace the credential with an approved non-reversible format and protect source files.","severity":"high","title":"Local credential is explicitly stored as type 0"}},{"after":{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"9de3e1f7-cbe4-5525-87e3-5339e07aa3d1","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"},"before":{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"9de3e1f7-cbe4-5525-87e3-5339e07aa3d1","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"}},{"after":{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"a31455b1-4e3a-5884-8a9a-2dcc43f37789","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"},"before":{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"a31455b1-4e3a-5884-8a9a-2dcc43f37789","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"}},{"after":{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"dcfeb7db-8e52-59f8-86c4-c261aa17165a","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"},"before":{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"83a2cbbe327c712a3dd5118e4eae46f81ee70625f6b12b1ab2128261b1c0a5dc","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"dcfeb7db-8e52-59f8-86c4-c261aa17165a","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"}},{"after":{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"d9244c88-524f-56d4-91c9-6ad3c4c63bd2","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"},"before":{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"d9244c88-524f-56d4-91c9-6ad3c4c63bd2","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"}}],"resolved":[{"affected_lines":[6],"anomaly_score":0.0,"category":"management.telnet_enabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"Telnet permits unencrypted remote management sessions.","source_location":{"parser_confidence":1.0,"raw_text_hash":"3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65","source_lines":[6]}}],"expected":{"management.telnet_enabled":false},"finding_id":"36dc9858-d8c8-54bd-b664-276a24519cae","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.telnet_enabled":true},"references":["docs/policies/management-plane.md#telnet-must-be-disabled"],"remediation":"Disable Telnet and permit SSH for remote administrative access.","severity":"high","title":"Telnet is enabled on the management plane"}]},"reference_findings":[],"reference_id":"428dffef-ca84-4d2e-846f-57ef02af00f6","reference_status":"completed","report_id":"b078f23c-5325-5ea5-b9dc-b62f0675e72c","requires_human_review":true,"review_status":"needs_review","version":"preflight-0.1.0"},"proposal":{"after_line_count":7,"after_sha256":"e90f6f54d46304d68c562ebd3d032843ec923d82721450f15633a74bb76c274e","before_line_count":7,"before_sha256":"0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec","changes":[{"after_end":6,"after_start":5,"before_end":6,"before_start":5,"operation":"replace"}],"device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","platform":"ios","proposal_id":"58011b0f-93eb-523c-b03e-b46da7a11776","reference_id":"428dffef-ca84-4d2e-846f-57ef02af00f6","status":"draft","vendor":"cisco","version":"patch-proposal-0.1.0"},"status":"needs_review","validation_blockers":["formal_verification_not_run","human_review_required","current_policy_findings"],"version":"patch-review-0.1.0"},"rollback_plan":"retain_and_review_exact_before_snapshot","selected_finding_sha256":"7c4438e370825c31c858428428fd81f154dd91ec79c254a41aad04d7444cb077","version":"vendor-patch-draft-0.1.0"},"native_commands":["line vty 0 4","transport input ssh","exit"],"quality_proven":false,"request":{"allow_local_native_generation":true,"allow_private_candidate_retention":true,"analysis_id":"d8225e48-7408-4ce2-88a1-bd725dc3ee95","analysis_sha256":"1db27f16406a0192c7ec72d0e966b35c589da1a68803f763511f142495cd0efe","candidate_id":"aee5b9f2-27f6-4bfe-83ea-3768f0b6a78f","canonical_sha256":"8e0775a858f6fa6f1514866ca7424fa511831e92719f46b318a0f245a07578e4","finding_id":"36dc9858-d8c8-54bd-b664-276a24519cae","finding_sha256":"7c4438e370825c31c858428428fd81f154dd91ec79c254a41aad04d7444cb077","policy_catalog_version":"policy-rules-0.7.0","source_sha256":"0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec","version":"native-patch-request-0.1.0"},"selected_finding":{"affected_lines":[6],"anomaly_score":0.0,"category":"management.telnet_enabled","confidence":1.0,"detector":"policy_engine","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","evidence":[{"kind":"policy_violation","message":"Telnet permits unencrypted remote management sessions.","source_location":{"parser_confidence":1.0,"raw_text_hash":"3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65","source_lines":[6]}}],"expected":{"management.telnet_enabled":false},"finding_id":"36dc9858-d8c8-54bd-b664-276a24519cae","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.telnet_enabled":true},"references":["docs/policies/management-plane.md#telnet-must-be-disabled"],"remediation":"Disable Telnet and permit SSH for remote administrative access.","severity":"high","title":"Telnet is enabled on the management plane"},"service_role":"engineer","source":{"configuration_id":"428dffef-ca84-4d2e-846f-57ef02af00f6","created_at":"2026-10-26T09:38:43.918624Z","device_id":"4b1bd4cc-8384-4ba8-966f-3ea33efafff2","source_sha256":"0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec"},"status":"needs_review","validation_blockers":["formal_verification_not_run","device_syntax_not_verified","management_access_not_verified","rollback_not_verified","baseline_approval_not_proven","independent_quality_not_proven","individual_engineer_review_required"],"version":"native-patch-candidate-0.1.0"}',
      review_sha256:
        "dc7fcefb43019a33edeebaaf10f9b769a53004e149fe27c3cd2b6a467911f3d0",
      selected_finding: {
        affected_lines: [6],
        anomaly_score: 0,
        category: "management.telnet_enabled",
        confidence: 1,
        detector: "policy_engine",
        device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
        evidence: [
          {
            kind: "policy_violation",
            message: "Telnet permits unencrypted remote management sessions.",
            source_location: {
              parser_confidence: 1,
              raw_text_hash:
                "3105bc0cd8d3ea4e9216c4d2b52db3e095ac95231119324fcd7de5d211fa7e65",
              source_lines: [6],
            },
          },
        ],
        expected: {
          "management.telnet_enabled": false,
        },
        finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
        limitations: [],
        model_version: "policy-rules-0.7.0",
        observed: {
          "management.telnet_enabled": true,
        },
        references: [
          "docs/policies/management-plane.md#telnet-must-be-disabled",
        ],
        remediation:
          "Disable Telnet and permit SSH for remote administrative access.",
        severity: "high",
        title: "Telnet is enabled on the management plane",
      },
      service_role: "engineer",
      source: {
        configuration_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
        created_at: "2026-10-26T09:38:43.918624Z",
        device_id: "4b1bd4cc-8384-4ba8-966f-3ea33efafff2",
        source_sha256:
          "0b53878958b4089a00797288d3c38ec1e124758bbaa856f1a819b5f2ba68c4ec",
      },
      status: "needs_review",
      validation_blockers: [
        "formal_verification_not_run",
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
        "baseline_approval_not_proven",
        "independent_quality_not_proven",
        "individual_engineer_review_required",
      ],
      version: "native-patch-candidate-0.1.0",
    },
    summary: {
      analysis_id: "d8225e48-7408-4ce2-88a1-bd725dc3ee95",
      applied: false,
      approved: false,
      candidate_id: "aee5b9f2-27f6-4bfe-83ea-3768f0b6a78f",
      configuration_id: "428dffef-ca84-4d2e-846f-57ef02af00f6",
      created_at: "2026-10-26T09:38:44.044553Z",
      finding_id: "36dc9858-d8c8-54bd-b664-276a24519cae",
      formal_qualification: "not_proven",
      generator_version: "native-telnet-generator-0.1.0",
      individual_identity_verified: false,
      review_sha256:
        "dc7fcefb43019a33edeebaaf10f9b769a53004e149fe27c3cd2b6a467911f3d0",
      service_role: "engineer",
      status: "needs_review",
      version: "native-patch-summary-0.1.0",
    },
  },
  {
    vendor: "juniper",
    snapshot: {
      canonical: {
        acls: [],
        bgp: null,
        device: {
          hostname: "owned",
          os_version: null,
          platform: "junos",
          provenance: {
            hostname: {
              parser_confidence: 1,
              raw_text_hash:
                "bc25daab139fdede699fba8635822d8fbb93387d21d7c64c94aa11e2a4be153e",
              source_lines: [1],
            },
          },
          role: null,
          service_profile: null,
          site: null,
          site_class: null,
          vendor: "juniper",
        },
        interfaces: [],
        local_users: [
          {
            authentication: [
              {
                encoding: "encrypted",
                kind: "secret",
                provenance: {
                  parser_confidence: 1,
                  raw_text_hash:
                    "c783da3af35547d6f1e5fb71fe75607cf23e65aa72ee969feaf7d433e3717cf2",
                  source_lines: [3],
                },
              },
            ],
            login_class: null,
            name: "operator",
            privilege: null,
            provenance: {
              name: {
                parser_confidence: 1,
                raw_text_hash:
                  "c783da3af35547d6f1e5fb71fe75607cf23e65aa72ee969feaf7d433e3717cf2",
                source_lines: [3],
              },
            },
            uid: null,
          },
        ],
        management: {
          aaa_enabled: false,
          ntp_servers: [],
          provenance: {
            snmp_versions: {
              parser_confidence: 1,
              raw_text_hash:
                "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
              source_lines: [4],
            },
            ssh_enabled: {
              parser_confidence: 1,
              raw_text_hash:
                "091f17c1bf69faf9529dda227a42d7b6f1d4c87b8d6cef51617cbc208952c763",
              source_lines: [2],
            },
            telnet_enabled: {
              parser_confidence: 1,
              raw_text_hash:
                "854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979",
              source_lines: [5],
            },
          },
          snmp_versions: ["v1", "v2c"],
          ssh_enabled: true,
          ssh_version: null,
          syslog_servers: [],
          telnet_enabled: true,
        },
        ospf: [],
        parse_warnings: [],
        parser_confidence: 1,
        prefix_lists: [],
        schema_version: "1.1",
        source: {
          collected_at: "2026-10-26T09:38:44.108138Z",
          filename: "owned.cfg",
          sha256:
            "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
        },
        static_routes: [],
        unparsed_fragments: [],
        vlans: [],
      },
      configuration_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
      created_at: "2026-10-26T09:38:44.108230Z",
      device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
      parser_coverage: {
        accepted_units: 5,
        adapter_version: "junos-source-lines-0.1.0",
        command_units: 5,
        ignored_lines: 0,
        platform: "junos",
        proves_vendor_syntax: false,
        source_line_count: 5,
        source_sha256:
          "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
        structural_units: 0,
        unit: "adapter_source_lines",
        units: [
          {
            disposition: "accepted",
            raw_text_sha256:
              "bc25daab139fdede699fba8635822d8fbb93387d21d7c64c94aa11e2a4be153e",
            source_line: 1,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "091f17c1bf69faf9529dda227a42d7b6f1d4c87b8d6cef51617cbc208952c763",
            source_line: 2,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "c783da3af35547d6f1e5fb71fe75607cf23e65aa72ee969feaf7d433e3717cf2",
            source_line: 3,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
            source_line: 4,
          },
          {
            disposition: "accepted",
            raw_text_sha256:
              "854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979",
            source_line: 5,
          },
        ],
        unparsed_fraction: 0,
        unparsed_units: 0,
        vendor: "juniper",
        version: "parser-coverage-0.1.0",
      },
    },
    analysis: {
      analysis_id: "36b827bd-7fbb-4e4b-9443-d6fc0f0a5f92",
      comparison: null,
      configuration_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
      created_at: "2026-10-26T09:38:44.126247Z",
      device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
      explanations: [
        {
          anchors: [
            {
              lines: [5],
              source_sha256:
                "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
              statement_sha256:
                "854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979",
            },
          ],
          anomaly_score: 0,
          citations: [
            "docs/policies/management-plane.md#telnet-must-be-disabled",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
          finding_sha256:
            "ccc201bb6d4f381c873354ba4b9f0a6211f92f2a8a6deafee7b4a3125fdc52f6",
          formal_verification: "not_run",
          limitations: [
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Disable Telnet and permit SSH for remote administrative access.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
          summary: "Telnet is enabled on the management plane",
          technical_explanation:
            "Telnet permits unencrypted remote management sessions.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [],
          anomaly_score: 0,
          citations: [
            "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          finding_id: "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
          finding_sha256:
            "f35dfd31fb4cf265e1d18ff7659781c4a3fe463d8e18fa7fc34fbe9266ce8752",
          formal_verification: "not_run",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
            "No current source line proves an absent parameter; no line anchor was invented.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Enable centralized AAA with an explicitly tested local fallback.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
          summary: "Centralized AAA is not enabled",
          technical_explanation:
            "No supported centralized AAA enablement statement was found.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [
            {
              lines: [4],
              source_sha256:
                "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
              statement_sha256:
                "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
            },
          ],
          anomaly_score: 0,
          citations: [
            "docs/policies/observability.md#legacy-snmp-must-be-disabled",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          finding_id: "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
          finding_sha256:
            "4917290b51a7b4028504cb2c9b2ab10858926a944eaf1e7f9404e73b6ac3e0df",
          formal_verification: "not_run",
          limitations: [
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Migrate monitoring to SNMPv3 and remove legacy communities.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
          summary: "Legacy SNMP is enabled",
          technical_explanation:
            "SNMPv1 or SNMPv2c is configured without modern protection.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [],
          anomaly_score: 0,
          citations: [
            "docs/policies/observability.md#time-synchronization-is-required",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          finding_id: "49793d24-477c-533c-a5be-601474b1b105",
          finding_sha256:
            "5e33e86851289125944232855be927cd6ecf748ace5617b62542b8108b05444d",
          formal_verification: "not_run",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
            "No current source line proves an absent parameter; no line anchor was invented.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation: "Configure approved redundant NTP servers.",
          requires_human_review: true,
          severity: "medium",
          source_sha256:
            "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
          summary: "NTP is not configured",
          technical_explanation: "No supported NTP server statement was found.",
          version: "local-explanation-0.1.0",
        },
        {
          anchors: [],
          anomaly_score: 0,
          citations: [
            "docs/policies/observability.md#remote-audit-logging-is-required",
          ],
          confidence: 1,
          detector_version: "policy-rules-0.7.0",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          finding_id: "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
          finding_sha256:
            "488bd83fed9aa210fcc4ab57f9b6a99f32e9a9b17ced233565d118506501292a",
          formal_verification: "not_run",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
            "This explanation uses local detector facts and catalog text; no language model was called.",
            "Citations identify internal policies, not retrieved or independently validated documents.",
            "Network impact was not simulated; any corrective action requires engineer review.",
            "No current source line proves an absent parameter; no line anchor was invented.",
          ],
          patch_draft: null,
          provider: "deterministic_local",
          recommendation:
            "Send security and operational events to approved remote collectors.",
          requires_human_review: true,
          severity: "high",
          source_sha256:
            "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
          summary: "Remote Syslog is not configured",
          technical_explanation:
            "No supported remote Syslog destination was found.",
          version: "local-explanation-0.1.0",
        },
      ],
      findings: [
        {
          affected_lines: [5],
          anomaly_score: 0,
          category: "management.telnet_enabled",
          confidence: 1,
          detector: "policy_engine",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          evidence: [
            {
              kind: "policy_violation",
              message: "Telnet permits unencrypted remote management sessions.",
              source_location: {
                parser_confidence: 1,
                raw_text_hash:
                  "854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979",
                source_lines: [5],
              },
            },
          ],
          expected: {
            "management.telnet_enabled": false,
          },
          finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
          limitations: [],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.telnet_enabled": true,
          },
          references: [
            "docs/policies/management-plane.md#telnet-must-be-disabled",
          ],
          remediation:
            "Disable Telnet and permit SSH for remote administrative access.",
          severity: "high",
          title: "Telnet is enabled on the management plane",
        },
        {
          affected_lines: [],
          anomaly_score: 0,
          category: "management.aaa_disabled",
          confidence: 1,
          detector: "policy_engine",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          evidence: [
            {
              kind: "policy_violation",
              message:
                "No supported centralized AAA enablement statement was found.",
              source_location: null,
            },
          ],
          expected: {
            "management.aaa_enabled": true,
          },
          finding_id: "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
          ],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.aaa_enabled": false,
          },
          references: [
            "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
          ],
          remediation:
            "Enable centralized AAA with an explicitly tested local fallback.",
          severity: "high",
          title: "Centralized AAA is not enabled",
        },
        {
          affected_lines: [4],
          anomaly_score: 0,
          category: "management.snmp_legacy_enabled",
          confidence: 1,
          detector: "policy_engine",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          evidence: [
            {
              kind: "policy_violation",
              message:
                "SNMPv1 or SNMPv2c is configured without modern protection.",
              source_location: {
                parser_confidence: 1,
                raw_text_hash:
                  "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
                source_lines: [4],
              },
            },
          ],
          expected: {
            "management.snmp_versions": "SNMPv3 only, or SNMP disabled",
          },
          finding_id: "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
          limitations: [],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.snmp_versions": ["v1", "v2c"],
          },
          references: [
            "docs/policies/observability.md#legacy-snmp-must-be-disabled",
          ],
          remediation:
            "Migrate monitoring to SNMPv3 and remove legacy communities.",
          severity: "high",
          title: "Legacy SNMP is enabled",
        },
        {
          affected_lines: [],
          anomaly_score: 0,
          category: "management.ntp_not_configured",
          confidence: 1,
          detector: "policy_engine",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          evidence: [
            {
              kind: "policy_violation",
              message: "No supported NTP server statement was found.",
              source_location: null,
            },
          ],
          expected: {
            "management.ntp_servers": "At least one approved NTP server",
          },
          finding_id: "49793d24-477c-533c-a5be-601474b1b105",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
          ],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.ntp_servers": [],
          },
          references: [
            "docs/policies/observability.md#time-synchronization-is-required",
          ],
          remediation: "Configure approved redundant NTP servers.",
          severity: "medium",
          title: "NTP is not configured",
        },
        {
          affected_lines: [],
          anomaly_score: 0,
          category: "management.syslog_not_configured",
          confidence: 1,
          detector: "policy_engine",
          device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
          evidence: [
            {
              kind: "policy_violation",
              message: "No supported remote Syslog destination was found.",
              source_location: null,
            },
          ],
          expected: {
            "management.syslog_servers":
              "At least one approved remote Syslog server",
          },
          finding_id: "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
          limitations: [
            "The violation is inferred from the absence of supported configuration syntax.",
          ],
          model_version: "policy-rules-0.7.0",
          observed: {
            "management.syslog_servers": [],
          },
          references: [
            "docs/policies/observability.md#remote-audit-logging-is-required",
          ],
          remediation:
            "Send security and operational events to approved remote collectors.",
          severity: "high",
          title: "Remote Syslog is not configured",
        },
      ],
      limitations: [
        "Only the recorded deterministic detectors were run; ML and formal verification were not run.",
        "Reference differences are review information and are excluded from risk fusion.",
        "Inventory labels and comparison inputs were explicitly selected by the operator; they are not independently verified or approved security baselines.",
        "Scores are uncalibrated; the result requires engineer review.",
      ],
      policy_catalog_version: "policy-rules-0.7.0",
      risk: {
        assessment_id: "b8924eb6-5c12-5694-a365-fefab2b2f86c",
        components: [
          {
            configured_weight: 0.35,
            effective_weight: 1,
            finding_ids: [
              "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
              "49793d24-477c-533c-a5be-601474b1b105",
              "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
              "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
              "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
            ],
            raw_score: 0.75,
            source: "policy",
            status: "completed",
          },
          {
            configured_weight: 0.15,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "peer_group",
            status: "unavailable",
          },
          {
            configured_weight: 0.1,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "statistical",
            status: "unavailable",
          },
          {
            configured_weight: 0.1,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "transformer",
            status: "unavailable",
          },
          {
            configured_weight: 0.3,
            effective_weight: 0,
            finding_ids: [],
            raw_score: null,
            source: "verification",
            status: "unavailable",
          },
        ],
        device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
        guardrails: [],
        level: "high",
        limitations: [
          "peer_group signal was not available and its weight was redistributed.",
          "statistical signal was not available and its weight was redistributed.",
          "transformer signal was not available and its weight was redistributed.",
          "verification signal was not available and its weight was redistributed.",
        ],
        model_version: "risk-fusion-0.1.0",
        score: 0.75,
      },
      source_sha256:
        "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
      statistical: null,
      status: "completed",
      version: "analysis-api-0.1.0",
    },
    selection: {
      analysis_created_at: "2026-10-26T09:38:44.126247Z",
      analysis_id: "36b827bd-7fbb-4e4b-9443-d6fc0f0a5f92",
      analysis_sha256:
        "5bed073aa3f6af6fcea89e7a6a84fcd44d8211e9564c2d4b08b7fbdd735216de",
      canonical_sha256:
        "712c2464f6229e6a367e8f8eeac1591b3b09ee37c87bb06fa0b6ca9183b98668",
      configuration_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
      finding_pins: [
        {
          finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
          finding_sha256:
            "ccc201bb6d4f381c873354ba4b9f0a6211f92f2a8a6deafee7b4a3125fdc52f6",
        },
      ],
      policy_catalog_version: "policy-rules-0.7.0",
      source: {
        configuration_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
        created_at: "2026-10-26T09:38:44.108230Z",
        device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
        source_sha256:
          "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
      },
      version: "native-patch-selection-0.1.0",
    },
    candidate: {
      analysis_created_at: "2026-10-26T09:38:44.126247Z",
      applied: false,
      approved: false,
      calibrated: false,
      candidate_id: "05718698-96a6-4980-964e-386c4dac3425",
      configuration_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
      created_at: "2026-10-26T09:38:44.178247Z",
      formal_qualification: "not_proven",
      generator_kind: "deterministic_vendor",
      generator_version: "native-telnet-generator-0.1.0",
      individual_identity_verified: false,
      local_reference: "selected_original_not_approved_baseline",
      metadata: {
        application_supported: false,
        category: "management.telnet_enabled",
        device_syntax_verified: false,
        edits: [
          {
            after_line_sha256: null,
            before_line_sha256:
              "2365c7aad680a5c237d6407595371f4c09b82b8a1ec660f54d3c3484a98889a1",
            kind: "junos_remove_telnet",
            source_line: 5,
            vty: null,
          },
        ],
        management_access_verified: false,
        policy_catalog_version: "policy-rules-0.7.0",
        review: {
          preflight: {
            after: {
              complete: true,
              confidence: 1,
              source_sha256:
                "1c2ed29f832fdf0550e17e0bec2b657df29e2c93f8b54e7730f7b55c8dc4a4b0",
              unparsed_count: 0,
              warning_count: 0,
            },
            after_policy_findings: [
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.aaa_disabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported centralized AAA enablement statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.aaa_enabled": true,
                },
                finding_id: "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.aaa_enabled": false,
                },
                references: [
                  "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                ],
                remediation:
                  "Enable centralized AAA with an explicitly tested local fallback.",
                severity: "high",
                title: "Centralized AAA is not enabled",
              },
              {
                affected_lines: [4],
                anomaly_score: 0,
                category: "management.snmp_legacy_enabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "SNMPv1 or SNMPv2c is configured without modern protection.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
                      source_lines: [4],
                    },
                  },
                ],
                expected: {
                  "management.snmp_versions": "SNMPv3 only, or SNMP disabled",
                },
                finding_id: "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
                limitations: [],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.snmp_versions": ["v1", "v2c"],
                },
                references: [
                  "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                ],
                remediation:
                  "Migrate monitoring to SNMPv3 and remove legacy communities.",
                severity: "high",
                title: "Legacy SNMP is enabled",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.ntp_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message: "No supported NTP server statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.ntp_servers": "At least one approved NTP server",
                },
                finding_id: "49793d24-477c-533c-a5be-601474b1b105",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.ntp_servers": [],
                },
                references: [
                  "docs/policies/observability.md#time-synchronization-is-required",
                ],
                remediation: "Configure approved redundant NTP servers.",
                severity: "medium",
                title: "NTP is not configured",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.syslog_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported remote Syslog destination was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.syslog_servers":
                    "At least one approved remote Syslog server",
                },
                finding_id: "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.syslog_servers": [],
                },
                references: [
                  "docs/policies/observability.md#remote-audit-logging-is-required",
                ],
                remediation:
                  "Send security and operational events to approved remote collectors.",
                severity: "high",
                title: "Remote Syslog is not configured",
              },
            ],
            before: {
              complete: true,
              confidence: 1,
              source_sha256:
                "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
              unparsed_count: 0,
              warning_count: 0,
            },
            before_policy_findings: [
              {
                affected_lines: [5],
                anomaly_score: 0,
                category: "management.telnet_enabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "Telnet permits unencrypted remote management sessions.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979",
                      source_lines: [5],
                    },
                  },
                ],
                expected: {
                  "management.telnet_enabled": false,
                },
                finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
                limitations: [],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.telnet_enabled": true,
                },
                references: [
                  "docs/policies/management-plane.md#telnet-must-be-disabled",
                ],
                remediation:
                  "Disable Telnet and permit SSH for remote administrative access.",
                severity: "high",
                title: "Telnet is enabled on the management plane",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.aaa_disabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported centralized AAA enablement statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.aaa_enabled": true,
                },
                finding_id: "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.aaa_enabled": false,
                },
                references: [
                  "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                ],
                remediation:
                  "Enable centralized AAA with an explicitly tested local fallback.",
                severity: "high",
                title: "Centralized AAA is not enabled",
              },
              {
                affected_lines: [4],
                anomaly_score: 0,
                category: "management.snmp_legacy_enabled",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "SNMPv1 or SNMPv2c is configured without modern protection.",
                    source_location: {
                      parser_confidence: 1,
                      raw_text_hash:
                        "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
                      source_lines: [4],
                    },
                  },
                ],
                expected: {
                  "management.snmp_versions": "SNMPv3 only, or SNMP disabled",
                },
                finding_id: "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
                limitations: [],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.snmp_versions": ["v1", "v2c"],
                },
                references: [
                  "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                ],
                remediation:
                  "Migrate monitoring to SNMPv3 and remove legacy communities.",
                severity: "high",
                title: "Legacy SNMP is enabled",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.ntp_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message: "No supported NTP server statement was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.ntp_servers": "At least one approved NTP server",
                },
                finding_id: "49793d24-477c-533c-a5be-601474b1b105",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.ntp_servers": [],
                },
                references: [
                  "docs/policies/observability.md#time-synchronization-is-required",
                ],
                remediation: "Configure approved redundant NTP servers.",
                severity: "medium",
                title: "NTP is not configured",
              },
              {
                affected_lines: [],
                anomaly_score: 0,
                category: "management.syslog_not_configured",
                confidence: 1,
                detector: "policy_engine",
                device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                evidence: [
                  {
                    kind: "policy_violation",
                    message:
                      "No supported remote Syslog destination was found.",
                    source_location: null,
                  },
                ],
                expected: {
                  "management.syslog_servers":
                    "At least one approved remote Syslog server",
                },
                finding_id: "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
                limitations: [
                  "The violation is inferred from the absence of supported configuration syntax.",
                ],
                model_version: "policy-rules-0.7.0",
                observed: {
                  "management.syslog_servers": [],
                },
                references: [
                  "docs/policies/observability.md#remote-audit-logging-is-required",
                ],
                remediation:
                  "Send security and operational events to approved remote collectors.",
                severity: "high",
                title: "Remote Syslog is not configured",
              },
            ],
            current_policy_risk: {
              assessment_id: "d566f773-1324-5222-935b-d62d2c2bac5c",
              components: [
                {
                  configured_weight: 0.35,
                  effective_weight: 1,
                  finding_ids: [
                    "49793d24-477c-533c-a5be-601474b1b105",
                    "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
                    "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
                    "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
                  ],
                  raw_score: 0.75,
                  source: "policy",
                  status: "completed",
                },
                {
                  configured_weight: 0.15,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "peer_group",
                  status: "unavailable",
                },
                {
                  configured_weight: 0.1,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "statistical",
                  status: "unavailable",
                },
                {
                  configured_weight: 0.1,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "transformer",
                  status: "unavailable",
                },
                {
                  configured_weight: 0.3,
                  effective_weight: 0,
                  finding_ids: [],
                  raw_score: null,
                  source: "verification",
                  status: "unavailable",
                },
              ],
              device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
              guardrails: [],
              level: "high",
              limitations: [
                "peer_group signal was not available and its weight was redistributed.",
                "statistical signal was not available and its weight was redistributed.",
                "transformer signal was not available and its weight was redistributed.",
                "verification signal was not available and its weight was redistributed.",
              ],
              model_version: "risk-fusion-0.1.0",
              score: 0.75,
            },
            device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
            formal_verification: "not_run",
            limitations: [
              "Local checks only: no reachability simulation, formal validation or approval.",
              "The selected reference may itself contain violations; review all current findings.",
              "Policy changes match exact observations, not line numbers or finding IDs. Changed observations appear as resolved/introduced pairs; resolved is not proof of repair.",
              "Reference differences are separate from the policy-only, uncalibrated risk score.",
              "ML, peer-group and statistical detectors were not run.",
              "Addresses and parameter values may be sensitive; keep this report private.",
            ],
            ml_status: "not_run",
            policy_catalog_version: "policy-rules-0.7.0",
            policy_changes: {
              introduced: [],
              persistent: [
                {
                  after: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.aaa_disabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported centralized AAA enablement statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.aaa_enabled": true,
                    },
                    finding_id: "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.aaa_enabled": false,
                    },
                    references: [
                      "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                    ],
                    remediation:
                      "Enable centralized AAA with an explicitly tested local fallback.",
                    severity: "high",
                    title: "Centralized AAA is not enabled",
                  },
                  before: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.aaa_disabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported centralized AAA enablement statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.aaa_enabled": true,
                    },
                    finding_id: "7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.aaa_enabled": false,
                    },
                    references: [
                      "docs/policies/management-plane.md#centralized-aaa-must-be-enabled",
                    ],
                    remediation:
                      "Enable centralized AAA with an explicitly tested local fallback.",
                    severity: "high",
                    title: "Centralized AAA is not enabled",
                  },
                },
                {
                  after: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.ntp_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message: "No supported NTP server statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.ntp_servers":
                        "At least one approved NTP server",
                    },
                    finding_id: "49793d24-477c-533c-a5be-601474b1b105",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.ntp_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#time-synchronization-is-required",
                    ],
                    remediation: "Configure approved redundant NTP servers.",
                    severity: "medium",
                    title: "NTP is not configured",
                  },
                  before: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.ntp_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message: "No supported NTP server statement was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.ntp_servers":
                        "At least one approved NTP server",
                    },
                    finding_id: "49793d24-477c-533c-a5be-601474b1b105",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.ntp_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#time-synchronization-is-required",
                    ],
                    remediation: "Configure approved redundant NTP servers.",
                    severity: "medium",
                    title: "NTP is not configured",
                  },
                },
                {
                  after: {
                    affected_lines: [4],
                    anomaly_score: 0,
                    category: "management.snmp_legacy_enabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "SNMPv1 or SNMPv2c is configured without modern protection.",
                        source_location: {
                          parser_confidence: 1,
                          raw_text_hash:
                            "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
                          source_lines: [4],
                        },
                      },
                    ],
                    expected: {
                      "management.snmp_versions":
                        "SNMPv3 only, or SNMP disabled",
                    },
                    finding_id: "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
                    limitations: [],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.snmp_versions": ["v1", "v2c"],
                    },
                    references: [
                      "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                    ],
                    remediation:
                      "Migrate monitoring to SNMPv3 and remove legacy communities.",
                    severity: "high",
                    title: "Legacy SNMP is enabled",
                  },
                  before: {
                    affected_lines: [4],
                    anomaly_score: 0,
                    category: "management.snmp_legacy_enabled",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "SNMPv1 or SNMPv2c is configured without modern protection.",
                        source_location: {
                          parser_confidence: 1,
                          raw_text_hash:
                            "9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb",
                          source_lines: [4],
                        },
                      },
                    ],
                    expected: {
                      "management.snmp_versions":
                        "SNMPv3 only, or SNMP disabled",
                    },
                    finding_id: "7852ee64-e63f-5598-ad5f-9e65c31ffefc",
                    limitations: [],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.snmp_versions": ["v1", "v2c"],
                    },
                    references: [
                      "docs/policies/observability.md#legacy-snmp-must-be-disabled",
                    ],
                    remediation:
                      "Migrate monitoring to SNMPv3 and remove legacy communities.",
                    severity: "high",
                    title: "Legacy SNMP is enabled",
                  },
                },
                {
                  after: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.syslog_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported remote Syslog destination was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.syslog_servers":
                        "At least one approved remote Syslog server",
                    },
                    finding_id: "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.syslog_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#remote-audit-logging-is-required",
                    ],
                    remediation:
                      "Send security and operational events to approved remote collectors.",
                    severity: "high",
                    title: "Remote Syslog is not configured",
                  },
                  before: {
                    affected_lines: [],
                    anomaly_score: 0,
                    category: "management.syslog_not_configured",
                    confidence: 1,
                    detector: "policy_engine",
                    device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                    evidence: [
                      {
                        kind: "policy_violation",
                        message:
                          "No supported remote Syslog destination was found.",
                        source_location: null,
                      },
                    ],
                    expected: {
                      "management.syslog_servers":
                        "At least one approved remote Syslog server",
                    },
                    finding_id: "9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12",
                    limitations: [
                      "The violation is inferred from the absence of supported configuration syntax.",
                    ],
                    model_version: "policy-rules-0.7.0",
                    observed: {
                      "management.syslog_servers": [],
                    },
                    references: [
                      "docs/policies/observability.md#remote-audit-logging-is-required",
                    ],
                    remediation:
                      "Send security and operational events to approved remote collectors.",
                    severity: "high",
                    title: "Remote Syslog is not configured",
                  },
                },
              ],
              resolved: [
                {
                  affected_lines: [5],
                  anomaly_score: 0,
                  category: "management.telnet_enabled",
                  confidence: 1,
                  detector: "policy_engine",
                  device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
                  evidence: [
                    {
                      kind: "policy_violation",
                      message:
                        "Telnet permits unencrypted remote management sessions.",
                      source_location: {
                        parser_confidence: 1,
                        raw_text_hash:
                          "854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979",
                        source_lines: [5],
                      },
                    },
                  ],
                  expected: {
                    "management.telnet_enabled": false,
                  },
                  finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
                  limitations: [],
                  model_version: "policy-rules-0.7.0",
                  observed: {
                    "management.telnet_enabled": true,
                  },
                  references: [
                    "docs/policies/management-plane.md#telnet-must-be-disabled",
                  ],
                  remediation:
                    "Disable Telnet and permit SSH for remote administrative access.",
                  severity: "high",
                  title: "Telnet is enabled on the management plane",
                },
              ],
            },
            reference_findings: [],
            reference_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
            reference_status: "completed",
            report_id: "9c93a570-7d71-5ce1-b186-d4ae6f7e8791",
            requires_human_review: true,
            review_status: "needs_review",
            version: "preflight-0.1.0",
          },
          proposal: {
            after_line_count: 4,
            after_sha256:
              "1c2ed29f832fdf0550e17e0bec2b657df29e2c93f8b54e7730f7b55c8dc4a4b0",
            before_line_count: 5,
            before_sha256:
              "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
            changes: [
              {
                after_end: 4,
                after_start: 4,
                before_end: 5,
                before_start: 4,
                operation: "delete",
              },
            ],
            device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
            platform: "junos",
            proposal_id: "0dc6648c-7e22-555b-af09-097ea3450845",
            reference_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
            status: "draft",
            vendor: "juniper",
            version: "patch-proposal-0.1.0",
          },
          status: "needs_review",
          validation_blockers: [
            "formal_verification_not_run",
            "human_review_required",
            "current_policy_findings",
          ],
          version: "patch-review-0.1.0",
        },
        rollback_plan: "retain_and_review_exact_before_snapshot",
        selected_finding_sha256:
          "ccc201bb6d4f381c873354ba4b9f0a6211f92f2a8a6deafee7b4a3125fdc52f6",
        version: "vendor-patch-draft-0.1.0",
      },
      native_commands: ["delete system services telnet"],
      quality_proven: false,
      request: {
        allow_local_native_generation: true,
        allow_private_candidate_retention: true,
        analysis_id: "36b827bd-7fbb-4e4b-9443-d6fc0f0a5f92",
        analysis_sha256:
          "5bed073aa3f6af6fcea89e7a6a84fcd44d8211e9564c2d4b08b7fbdd735216de",
        candidate_id: "05718698-96a6-4980-964e-386c4dac3425",
        canonical_sha256:
          "712c2464f6229e6a367e8f8eeac1591b3b09ee37c87bb06fa0b6ca9183b98668",
        finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
        finding_sha256:
          "ccc201bb6d4f381c873354ba4b9f0a6211f92f2a8a6deafee7b4a3125fdc52f6",
        policy_catalog_version: "policy-rules-0.7.0",
        source_sha256:
          "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
        version: "native-patch-request-0.1.0",
      },
      review_json:
        '{"analysis_created_at":"2026-10-26T09:38:44.126247Z","applied":false,"approved":false,"calibrated":false,"candidate_id":"05718698-96a6-4980-964e-386c4dac3425","configuration_id":"d3275ce0-6a22-4a29-ae9c-f25880574aa6","created_at":"2026-10-26T09:38:44.178247Z","formal_qualification":"not_proven","generator_kind":"deterministic_vendor","generator_version":"native-telnet-generator-0.1.0","individual_identity_verified":false,"local_reference":"selected_original_not_approved_baseline","metadata":{"application_supported":false,"category":"management.telnet_enabled","device_syntax_verified":false,"edits":[{"after_line_sha256":null,"before_line_sha256":"2365c7aad680a5c237d6407595371f4c09b82b8a1ec660f54d3c3484a98889a1","kind":"junos_remove_telnet","source_line":5,"vty":null}],"management_access_verified":false,"policy_catalog_version":"policy-rules-0.7.0","review":{"preflight":{"after":{"complete":true,"confidence":1.0,"source_sha256":"1c2ed29f832fdf0550e17e0bec2b657df29e2c93f8b54e7730f7b55c8dc4a4b0","unparsed_count":0,"warning_count":0},"after_policy_findings":[{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"},{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"7852ee64-e63f-5598-ad5f-9e65c31ffefc","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"49793d24-477c-533c-a5be-601474b1b105","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"}],"before":{"complete":true,"confidence":1.0,"source_sha256":"c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117","unparsed_count":0,"warning_count":0},"before_policy_findings":[{"affected_lines":[5],"anomaly_score":0.0,"category":"management.telnet_enabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"Telnet permits unencrypted remote management sessions.","source_location":{"parser_confidence":1.0,"raw_text_hash":"854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979","source_lines":[5]}}],"expected":{"management.telnet_enabled":false},"finding_id":"31614da9-8b6d-5b93-9657-2ad25cef0ab2","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.telnet_enabled":true},"references":["docs/policies/management-plane.md#telnet-must-be-disabled"],"remediation":"Disable Telnet and permit SSH for remote administrative access.","severity":"high","title":"Telnet is enabled on the management plane"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"},{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"7852ee64-e63f-5598-ad5f-9e65c31ffefc","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"49793d24-477c-533c-a5be-601474b1b105","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"},{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"}],"current_policy_risk":{"assessment_id":"d566f773-1324-5222-935b-d62d2c2bac5c","components":[{"configured_weight":0.35,"effective_weight":1.0,"finding_ids":["49793d24-477c-533c-a5be-601474b1b105","7852ee64-e63f-5598-ad5f-9e65c31ffefc","7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615","9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12"],"raw_score":0.75,"source":"policy","status":"completed"},{"configured_weight":0.15,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"peer_group","status":"unavailable"},{"configured_weight":0.1,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"statistical","status":"unavailable"},{"configured_weight":0.1,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"transformer","status":"unavailable"},{"configured_weight":0.3,"effective_weight":0.0,"finding_ids":[],"raw_score":null,"source":"verification","status":"unavailable"}],"device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","guardrails":[],"level":"high","limitations":["peer_group signal was not available and its weight was redistributed.","statistical signal was not available and its weight was redistributed.","transformer signal was not available and its weight was redistributed.","verification signal was not available and its weight was redistributed."],"model_version":"risk-fusion-0.1.0","score":0.75},"device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","formal_verification":"not_run","limitations":["Local checks only: no reachability simulation, formal validation or approval.","The selected reference may itself contain violations; review all current findings.","Policy changes match exact observations, not line numbers or finding IDs. Changed observations appear as resolved/introduced pairs; resolved is not proof of repair.","Reference differences are separate from the policy-only, uncalibrated risk score.","ML, peer-group and statistical detectors were not run.","Addresses and parameter values may be sensitive; keep this report private."],"ml_status":"not_run","policy_catalog_version":"policy-rules-0.7.0","policy_changes":{"introduced":[],"persistent":[{"after":{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"},"before":{"affected_lines":[],"anomaly_score":0.0,"category":"management.aaa_disabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported centralized AAA enablement statement was found.","source_location":null}],"expected":{"management.aaa_enabled":true},"finding_id":"7fcf6bd6-d3e7-5095-a9ed-0b6cf403a615","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.aaa_enabled":false},"references":["docs/policies/management-plane.md#centralized-aaa-must-be-enabled"],"remediation":"Enable centralized AAA with an explicitly tested local fallback.","severity":"high","title":"Centralized AAA is not enabled"}},{"after":{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"49793d24-477c-533c-a5be-601474b1b105","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"},"before":{"affected_lines":[],"anomaly_score":0.0,"category":"management.ntp_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported NTP server statement was found.","source_location":null}],"expected":{"management.ntp_servers":"At least one approved NTP server"},"finding_id":"49793d24-477c-533c-a5be-601474b1b105","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.ntp_servers":[]},"references":["docs/policies/observability.md#time-synchronization-is-required"],"remediation":"Configure approved redundant NTP servers.","severity":"medium","title":"NTP is not configured"}},{"after":{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"7852ee64-e63f-5598-ad5f-9e65c31ffefc","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"},"before":{"affected_lines":[4],"anomaly_score":0.0,"category":"management.snmp_legacy_enabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"SNMPv1 or SNMPv2c is configured without modern protection.","source_location":{"parser_confidence":1.0,"raw_text_hash":"9859ed1a2736bf07e31b6ef71688833ccf18b6a2d06cae1eaaee0519078624fb","source_lines":[4]}}],"expected":{"management.snmp_versions":"SNMPv3 only, or SNMP disabled"},"finding_id":"7852ee64-e63f-5598-ad5f-9e65c31ffefc","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.snmp_versions":["v1","v2c"]},"references":["docs/policies/observability.md#legacy-snmp-must-be-disabled"],"remediation":"Migrate monitoring to SNMPv3 and remove legacy communities.","severity":"high","title":"Legacy SNMP is enabled"}},{"after":{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"},"before":{"affected_lines":[],"anomaly_score":0.0,"category":"management.syslog_not_configured","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"No supported remote Syslog destination was found.","source_location":null}],"expected":{"management.syslog_servers":"At least one approved remote Syslog server"},"finding_id":"9eac6c5b-f8cf-5e08-8a3b-0c3d11125b12","limitations":["The violation is inferred from the absence of supported configuration syntax."],"model_version":"policy-rules-0.7.0","observed":{"management.syslog_servers":[]},"references":["docs/policies/observability.md#remote-audit-logging-is-required"],"remediation":"Send security and operational events to approved remote collectors.","severity":"high","title":"Remote Syslog is not configured"}}],"resolved":[{"affected_lines":[5],"anomaly_score":0.0,"category":"management.telnet_enabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"Telnet permits unencrypted remote management sessions.","source_location":{"parser_confidence":1.0,"raw_text_hash":"854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979","source_lines":[5]}}],"expected":{"management.telnet_enabled":false},"finding_id":"31614da9-8b6d-5b93-9657-2ad25cef0ab2","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.telnet_enabled":true},"references":["docs/policies/management-plane.md#telnet-must-be-disabled"],"remediation":"Disable Telnet and permit SSH for remote administrative access.","severity":"high","title":"Telnet is enabled on the management plane"}]},"reference_findings":[],"reference_id":"d3275ce0-6a22-4a29-ae9c-f25880574aa6","reference_status":"completed","report_id":"9c93a570-7d71-5ce1-b186-d4ae6f7e8791","requires_human_review":true,"review_status":"needs_review","version":"preflight-0.1.0"},"proposal":{"after_line_count":4,"after_sha256":"1c2ed29f832fdf0550e17e0bec2b657df29e2c93f8b54e7730f7b55c8dc4a4b0","before_line_count":5,"before_sha256":"c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117","changes":[{"after_end":4,"after_start":4,"before_end":5,"before_start":4,"operation":"delete"}],"device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","platform":"junos","proposal_id":"0dc6648c-7e22-555b-af09-097ea3450845","reference_id":"d3275ce0-6a22-4a29-ae9c-f25880574aa6","status":"draft","vendor":"juniper","version":"patch-proposal-0.1.0"},"status":"needs_review","validation_blockers":["formal_verification_not_run","human_review_required","current_policy_findings"],"version":"patch-review-0.1.0"},"rollback_plan":"retain_and_review_exact_before_snapshot","selected_finding_sha256":"ccc201bb6d4f381c873354ba4b9f0a6211f92f2a8a6deafee7b4a3125fdc52f6","version":"vendor-patch-draft-0.1.0"},"native_commands":["delete system services telnet"],"quality_proven":false,"request":{"allow_local_native_generation":true,"allow_private_candidate_retention":true,"analysis_id":"36b827bd-7fbb-4e4b-9443-d6fc0f0a5f92","analysis_sha256":"5bed073aa3f6af6fcea89e7a6a84fcd44d8211e9564c2d4b08b7fbdd735216de","candidate_id":"05718698-96a6-4980-964e-386c4dac3425","canonical_sha256":"712c2464f6229e6a367e8f8eeac1591b3b09ee37c87bb06fa0b6ca9183b98668","finding_id":"31614da9-8b6d-5b93-9657-2ad25cef0ab2","finding_sha256":"ccc201bb6d4f381c873354ba4b9f0a6211f92f2a8a6deafee7b4a3125fdc52f6","policy_catalog_version":"policy-rules-0.7.0","source_sha256":"c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117","version":"native-patch-request-0.1.0"},"selected_finding":{"affected_lines":[5],"anomaly_score":0.0,"category":"management.telnet_enabled","confidence":1.0,"detector":"policy_engine","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","evidence":[{"kind":"policy_violation","message":"Telnet permits unencrypted remote management sessions.","source_location":{"parser_confidence":1.0,"raw_text_hash":"854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979","source_lines":[5]}}],"expected":{"management.telnet_enabled":false},"finding_id":"31614da9-8b6d-5b93-9657-2ad25cef0ab2","limitations":[],"model_version":"policy-rules-0.7.0","observed":{"management.telnet_enabled":true},"references":["docs/policies/management-plane.md#telnet-must-be-disabled"],"remediation":"Disable Telnet and permit SSH for remote administrative access.","severity":"high","title":"Telnet is enabled on the management plane"},"service_role":"engineer","source":{"configuration_id":"d3275ce0-6a22-4a29-ae9c-f25880574aa6","created_at":"2026-10-26T09:38:44.108230Z","device_id":"9a75e487-7f89-48de-8522-03d9803d05c2","source_sha256":"c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117"},"status":"needs_review","validation_blockers":["formal_verification_not_run","device_syntax_not_verified","management_access_not_verified","rollback_not_verified","baseline_approval_not_proven","independent_quality_not_proven","individual_engineer_review_required"],"version":"native-patch-candidate-0.1.0"}',
      review_sha256:
        "3077896f099aed86c9035d98b0d164c83c2b96c2f401524e82c374149e026a8a",
      selected_finding: {
        affected_lines: [5],
        anomaly_score: 0,
        category: "management.telnet_enabled",
        confidence: 1,
        detector: "policy_engine",
        device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
        evidence: [
          {
            kind: "policy_violation",
            message: "Telnet permits unencrypted remote management sessions.",
            source_location: {
              parser_confidence: 1,
              raw_text_hash:
                "854199d8f8cd454cd458311b44c96fbaee83853e945ffc400ac85e0c9fcd1979",
              source_lines: [5],
            },
          },
        ],
        expected: {
          "management.telnet_enabled": false,
        },
        finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
        limitations: [],
        model_version: "policy-rules-0.7.0",
        observed: {
          "management.telnet_enabled": true,
        },
        references: [
          "docs/policies/management-plane.md#telnet-must-be-disabled",
        ],
        remediation:
          "Disable Telnet and permit SSH for remote administrative access.",
        severity: "high",
        title: "Telnet is enabled on the management plane",
      },
      service_role: "engineer",
      source: {
        configuration_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
        created_at: "2026-10-26T09:38:44.108230Z",
        device_id: "9a75e487-7f89-48de-8522-03d9803d05c2",
        source_sha256:
          "c0127fcd40e9b8220c4f495ec0310b887f7694acef00436964ffcc0ef114e117",
      },
      status: "needs_review",
      validation_blockers: [
        "formal_verification_not_run",
        "device_syntax_not_verified",
        "management_access_not_verified",
        "rollback_not_verified",
        "baseline_approval_not_proven",
        "independent_quality_not_proven",
        "individual_engineer_review_required",
      ],
      version: "native-patch-candidate-0.1.0",
    },
    summary: {
      analysis_id: "36b827bd-7fbb-4e4b-9443-d6fc0f0a5f92",
      applied: false,
      approved: false,
      candidate_id: "05718698-96a6-4980-964e-386c4dac3425",
      configuration_id: "d3275ce0-6a22-4a29-ae9c-f25880574aa6",
      created_at: "2026-10-26T09:38:44.178247Z",
      finding_id: "31614da9-8b6d-5b93-9657-2ad25cef0ab2",
      formal_qualification: "not_proven",
      generator_version: "native-telnet-generator-0.1.0",
      individual_identity_verified: false,
      review_sha256:
        "3077896f099aed86c9035d98b0d164c83c2b96c2f401524e82c374149e026a8a",
      service_role: "engineer",
      status: "needs_review",
      version: "native-patch-summary-0.1.0",
    },
  },
] as const;
