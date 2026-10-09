import { expect, it } from "vitest";
import { parserCoverageSchema } from "./parserCoverage";
import { snapshotSchema } from "./contracts";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { ParserCoverageView } from "./ParserCoverageView";

const hash = "a".repeat(64);
const report = {
  version: "parser-coverage-0.1.0",
  unit: "adapter_source_lines",
  adapter_version: "cisco-ios-source-lines-0.1.0",
  vendor: "cisco",
  platform: "ios",
  source_sha256: hash,
  source_line_count: 3,
  accepted_units: 1,
  unparsed_units: 1,
  structural_units: 1,
  ignored_lines: 0,
  command_units: 2,
  unparsed_fraction: 0.5,
  proves_vendor_syntax: false,
  units: [
    { source_line: 1, raw_text_sha256: hash, disposition: "accepted" },
    { source_line: 2, raw_text_sha256: hash, disposition: "unparsed" },
    { source_line: 3, raw_text_sha256: hash, disposition: "structural" },
  ],
};
const id = "00000000-0000-0000-0000-000000000001";
const snapshot = {
  configuration_id: id,
  device_id: id,
  created_at: "2026-10-10T00:00:00Z",
  canonical: {
    schema_version: "1.1",
    source: {
      filename: "owned.cfg",
      sha256: hash,
      collected_at: "2026-10-10T00:00:00Z",
    },
    device: { hostname: "owned", vendor: "cisco", platform: "ios" },
    parser_confidence: 0.8,
    parse_warnings: [],
    unparsed_fragments: [
      {
        raw_text: "unknown OWNED",
        location: {
          source_lines: [2],
          raw_text_hash: hash,
          parser_confidence: 0,
        },
      },
    ],
    interfaces: [],
    vlans: [],
    acls: [],
    static_routes: [],
    local_users: [],
  },
};
it("accepts measured counts independently from confidence and preserves absent legacy coverage", () => {
  expect(parserCoverageSchema.parse(report).unparsed_fraction).toBe(0.5);
  expect(
    snapshotSchema.parse({ ...snapshot, parser_coverage: report }).canonical
      .parser_confidence,
  ).toBe(0.8);
  expect(snapshotSchema.parse(snapshot).parser_coverage).toBeUndefined();
});
it.each([
  { version: "parser-coverage-0.2.0" },
  { unit: "vendor_commands" },
  { adapter_version: "junos-source-lines-0.1.0" },
  { platform: "junos" },
  { accepted_units: true },
  { accepted_units: 2 },
  { unparsed_units: 0 },
  { structural_units: 0 },
  { ignored_lines: 1 },
  { command_units: 3 },
  { source_line_count: 10001 },
  { unparsed_fraction: 0.2 },
  { unparsed_fraction: null },
  { proves_vendor_syntax: 0 },
  { proves_vendor_syntax: true },
  { raw_text: "PRIVATE" },
  { units: [...report.units].reverse() },
  { units: [report.units[0], report.units[0], report.units[2]] },
])("rejects inconsistent report metadata: %j", (changed) => {
  expect(
    parserCoverageSchema.safeParse({ ...report, ...changed }).success,
  ).toBe(false);
});
it.each([
  { source_sha256: "b".repeat(64) },
  {
    units: report.units.map((unit) => ({
      ...unit,
      disposition:
        unit.source_line === 1
          ? "unparsed"
          : unit.source_line === 2
            ? "accepted"
            : "structural",
    })),
  },
])(
  "refuses internally valid coverage for a different source or unparsed anchor",
  (changed) => {
    const modified = { ...report, ...changed };
    expect(parserCoverageSchema.safeParse(modified).success).toBe(true);
    expect(
      snapshotSchema.safeParse({ ...snapshot, parser_coverage: modified })
        .success,
    ).toBe(false);
  },
);
it("renders zero denominator and unmeasured history without inventing zero unknown commands", () => {
  const empty = parserCoverageSchema.parse({
    ...report,
    accepted_units: 0,
    unparsed_units: 0,
    structural_units: 3,
    command_units: 0,
    unparsed_fraction: null,
    units: report.units.map((unit) => ({ ...unit, disposition: "structural" })),
  });
  expect(
    renderToStaticMarkup(createElement(ParserCoverageView, { report: empty })),
  ).toContain("Нет командных строк");
  expect(renderToStaticMarkup(createElement(ParserCoverageView, {}))).toContain(
    "Покрытие не измерено",
  );
  const measured = renderToStaticMarkup(
    createElement(ParserCoverageView, {
      report: parserCoverageSchema.parse(report),
    }),
  );
  expect(measured).toMatch(/50\s*%/u);
  expect(measured).toContain("не означает полную семантическую");
});
