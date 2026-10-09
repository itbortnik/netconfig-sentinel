import { z } from "zod";
import type { Finding } from "./contracts";
import {
  expandedPeerBaselineSchema,
  expandedPeerFields,
} from "./expandedComparisons";
import { parserCoverageSchema } from "./parserCoverage";

const hash = z.string().regex(/^[0-9a-f]{64}$/);
const field = z.enum(expandedPeerFields);
const fractionCategory = "baseline.parser.unparsed_fraction_high";
const reference = "docs/baseline.md#measured-parser-coverage";
const bounded = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value)).byteLength <= 8 * 1024 * 1024;
export const measuredPeerBaselineSchema = z
  .strictObject({
    model_version: z.literal("peer-baseline-0.3.0"),
    properties: expandedPeerBaselineSchema,
    coverage: z.array(parserCoverageSchema).min(3).max(20),
    unparsed_fraction_median: z.literal(0),
    unparsed_fraction_limit: z.number().min(0).max(1),
  })
  .refine((profile) => {
    const properties = profile.properties;
    return (
      properties.unsupported_ratio_limit === 1 &&
      properties.samples.map((item) => item.source_sha256).join() ===
        profile.coverage.map((item) => item.source_sha256).join() &&
      profile.coverage.every(
        (item) =>
          item.vendor === properties.group.vendor &&
          item.platform === properties.group.platform &&
          item.command_units > 0 &&
          item.unparsed_fraction === 0,
      ) &&
      bounded(profile)
    );
  });

type Binding = {
  configuration_id: string;
  device_id: string;
  source_sha256: string;
  created_at: string;
};

// Common contracts are passed in, keeping runtime imports acyclic.
export function makeMeasuredComparisonSchema(
  binding: z.ZodType<Binding>,
  finding: z.ZodType<Finding>,
) {
  const report = z
    .strictObject({
      version: z.literal("peer-comparison-report-0.3.0"),
      device_id: z.guid(),
      source_sha256: hash,
      baseline_sha256: hash,
      status: z.enum(["completed", "partial"]),
      coverage: parserCoverageSchema,
      unparsed_fraction_limit: z.number().min(0).max(1),
      peer_fraction_median: z.literal(0),
      profile_features: z.array(field).max(19),
      compared_features: z.array(field).max(19),
      skipped_features: z.array(field).max(19),
      findings: z.array(finding).max(20),
      limitations: z.array(z.string()),
    })
    .refine((item) => {
      const fields = item.profile_features;
      const coverage = item.coverage;
      const fraction = coverage.unparsed_fraction;
      if (
        fraction === null ||
        coverage.source_sha256 !== item.source_sha256 ||
        !bounded(item)
      )
        return false;
      if (
        new Set(fields).size !== fields.length ||
        fields.join() !== [...fields].sort().join()
      )
        return false;
      if (
        item.status === "completed"
          ? fraction !== 0 ||
            item.skipped_features.length > 0 ||
            item.compared_features.join() !== fields.join()
          : item.compared_features.length > 0 ||
            item.skipped_features.join() !== fields.join()
      )
        return false;
      if (
        new Set(item.findings.map((value) => value.finding_id)).size !==
        item.findings.length
      )
        return false;
      const unparsed = coverage.units
        .filter((unit) => unit.disposition === "unparsed")
        .map((unit) => unit.source_line);
      const fractionFindings = item.findings.filter(
        (value) => value.category === fractionCategory,
      );
      if (
        fractionFindings.length !==
        Number(fraction > item.unparsed_fraction_limit)
      )
        return false;
      return item.findings.every((value) => {
        if (
          value.device_id !== item.device_id ||
          value.detector !== "peer_baseline" ||
          value.model_version !== "peer-baseline-0.3.0" ||
          value.severity !== "medium" ||
          value.references.join() !== reference ||
          value.observed.source_sha256 !== item.source_sha256 ||
          typeof value.observed.coverage_report_sha256 !== "string" ||
          !hash.safeParse(value.observed.coverage_report_sha256).success ||
          value.expected.baseline_sha256 !== item.baseline_sha256
        )
          return false;
        if (value.category !== fractionCategory)
          return (
            item.status === "completed" &&
            fields.includes(
              value.expected.feature as (typeof fields)[number],
            ) &&
            value.category === `baseline.${value.expected.feature}_deviation` &&
            JSON.stringify(value.observed.value) !==
              JSON.stringify(value.expected.value)
          );
        const locations = value.evidence.map(
          (evidence) => evidence.source_location,
        );
        const lines = [
          ...new Set(
            locations.flatMap((location) => location?.source_lines ?? []),
          ),
        ].sort((a, b) => a - b);
        return (
          item.status === "partial" &&
          value.observed.value === fraction &&
          value.observed.unparsed_units === coverage.unparsed_units &&
          value.observed.command_units === coverage.command_units &&
          value.observed.unit === coverage.unit &&
          value.observed.adapter_version === coverage.adapter_version &&
          value.expected.maximum_unparsed_fraction ===
            item.unparsed_fraction_limit &&
          value.expected.peer_median === item.peer_fraction_median &&
          value.confidence === 1 &&
          value.anomaly_score ===
            Math.min(
              1,
              (fraction - item.unparsed_fraction_limit) /
                Math.max(1 - item.unparsed_fraction_limit, 0.01),
            ) &&
          value.affected_lines.join() === unparsed.join() &&
          lines.join() === unparsed.join() &&
          locations.length > 0 &&
          locations.every(
            (location) =>
              location !== null &&
              location.source_lines.length > 0 &&
              location.source_lines.every((line) => unparsed.includes(line)) &&
              (location.source_lines.length !== 1 ||
                location.raw_text_hash ===
                  coverage.units[location.source_lines[0]! - 1]
                    ?.raw_text_sha256),
          )
        );
      });
    });
  return z
    .strictObject({
      version: z.literal("comparison-context-0.3.0"),
      reference: binding.nullable(),
      peers: z.array(binding).max(20),
      peer_baseline: measuredPeerBaselineSchema.nullable(),
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
      const properties = profile.properties;
      const selected = new Map(
        context.peers.map((item) => [item.source_sha256, item]),
      );
      return (
        context.peers.length === properties.sample_count &&
        ["configuration_id", "device_id", "source_sha256"].every(
          (key) =>
            new Set(context.peers.map((item) => item[key as keyof Binding]))
              .size === context.peers.length,
        ) &&
        properties.samples.every(
          (item) =>
            selected.has(item.source_sha256) &&
            Date.parse(item.collected_at) <=
              Date.parse(selected.get(item.source_sha256)!.created_at),
        ) &&
        properties.features.map((item) => item.field).join() ===
          evaluation.profile_features.join() &&
        evaluation.coverage.vendor === properties.group.vendor &&
        evaluation.coverage.platform === properties.group.platform &&
        evaluation.unparsed_fraction_limit ===
          profile.unparsed_fraction_limit &&
        evaluation.peer_fraction_median === profile.unparsed_fraction_median &&
        evaluation.findings.every((item) => {
          if (item.category === fractionCategory) return true;
          const expected = properties.features.find(
            (value) => value.field === item.expected.feature,
          );
          return (
            !!expected &&
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
