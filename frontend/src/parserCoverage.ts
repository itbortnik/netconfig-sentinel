import { z } from "zod";

const count = z.number().int().min(0).max(10_000);
const hash = z.string().regex(/^[0-9a-f]{64}$/);
export const parserCoverageSchema = z
  .strictObject({
    version: z.literal("parser-coverage-0.1.0"),
    unit: z.literal("adapter_source_lines"),
    adapter_version: z.enum([
      "cisco-ios-source-lines-0.1.0",
      "junos-source-lines-0.1.0",
    ]),
    vendor: z.enum(["cisco", "juniper"]),
    platform: z.enum(["ios", "junos"]),
    source_sha256: hash,
    source_line_count: count.min(1),
    accepted_units: count,
    unparsed_units: count,
    structural_units: count,
    ignored_lines: count,
    command_units: count,
    unparsed_fraction: z.number().min(0).max(1).nullable(),
    proves_vendor_syntax: z.literal(false),
    units: z
      .array(
        z.strictObject({
          source_line: count.min(1),
          raw_text_sha256: hash,
          disposition: z.enum([
            "accepted",
            "unparsed",
            "structural",
            "ignored",
          ]),
        }),
      )
      .min(1)
      .max(10_000),
  })
  .refine((report) => {
    const cisco = report.vendor === "cisco";
    if (
      report.platform !== (cisco ? "ios" : "junos") ||
      report.adapter_version !==
        (cisco ? "cisco-ios-source-lines-0.1.0" : "junos-source-lines-0.1.0") ||
      report.source_line_count !== report.units.length ||
      report.units.some((unit, index) => unit.source_line !== index + 1)
    )
      return false;
    const counts = { accepted: 0, unparsed: 0, structural: 0, ignored: 0 };
    for (const unit of report.units) counts[unit.disposition]++;
    return (
      report.accepted_units === counts.accepted &&
      report.unparsed_units === counts.unparsed &&
      report.structural_units === counts.structural &&
      report.ignored_lines === counts.ignored &&
      report.command_units === counts.accepted + counts.unparsed &&
      report.unparsed_fraction ===
        (report.command_units ? counts.unparsed / report.command_units : null)
    );
  }, "inconsistent adapter source-line coverage");

export type ParserCoverage = z.infer<typeof parserCoverageSchema>;
