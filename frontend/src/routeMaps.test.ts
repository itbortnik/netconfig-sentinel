import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { routeMapSchema, snapshotSchema } from "./contracts";
import { SnapshotView } from "./SnapshotView";

const id = "00000000-0000-0000-0000-000000000001";
const location = {
  source_lines: [3],
  raw_text_hash: "a".repeat(64),
  parser_confidence: 1,
};
const routeMap = {
  name: "EXPORT",
  normalization_complete: true,
  provenance: { name: location },
  clauses: [
    {
      sequence: 10,
      action: "permit",
      match_ipv4_prefix_lists: ["TRUSTED"],
      set_metric: null,
      normalization_complete: true,
      provenance: { header: location, match_ipv4_prefix_lists: location },
    },
    {
      sequence: 20,
      action: "deny",
      match_ipv4_prefix_lists: [],
      set_metric: 50,
      normalization_complete: true,
      provenance: { header: location, set_metric: location },
    },
  ],
};
const snapshot = {
  configuration_id: id,
  device_id: id,
  created_at: "2026-10-17T00:00:00Z",
  canonical: {
    schema_version: "1.2",
    source: {
      filename: "owned.cfg",
      sha256: "b".repeat(64),
      collected_at: "2026-10-17T00:00:00Z",
    },
    device: { hostname: "owned", vendor: "cisco", platform: "ios" },
    parser_confidence: 1,
    parse_warnings: [] as string[],
    unparsed_fragments: [] as unknown[],
    interfaces: [],
    vlans: [],
    acls: [],
    static_routes: [],
    local_users: [
      {
        name: "engineer",
        privilege: 5,
        login_class: null,
        uid: null,
        authentication: [],
        provenance: { name: location },
      },
    ],
    route_maps: [routeMap],
  },
};

it("reads explicit configured clause order and keeps device accounts visible in schema1.2", () => {
  const parsed = snapshotSchema.parse(snapshot);
  const noop = () => {};
  const html = renderToStaticMarkup(
    createElement(SnapshotView, {
      snapshot: parsed,
      busy: false,
      canAnalyze: false,
      canTrain: false,
      onAnalyze: noop,
      onDevice: noop,
      onReference: noop,
      onPeer: noop,
      onTraining: noop,
      onDiffReference: noop,
    }),
  );
  expect(html).toContain("EXPORT");
  expect(html).toContain("TRUSTED");
  expect(html).toContain("engineer");
  expect(html).toContain("влияние на сеть не проверены");
  expect(html.indexOf("Номер 10")).toBeLessThan(html.indexOf("Номер 20"));
});

it.each([
  { sequence: true },
  { sequence: 65536 },
  { set_metric: "50" },
  { set_metric: -1 },
  { set_metric: 4294967296 },
  { match_ipv4_prefix_lists: ["A", "A"] },
  { match_ipv4_prefix_lists: ["<script>"] },
  { continue: 30 },
  { raw_text: "PRIVATE" },
])("refuses malformed or invented configured clause facts %j", (change) => {
  expect(
    routeMapSchema.safeParse({
      ...routeMap,
      clauses: [{ ...routeMap.clauses[0], ...change }],
    }).success,
  ).toBe(false);
});

it.each([
  { clauses: [routeMap.clauses[1], routeMap.clauses[0]] },
  { clauses: [routeMap.clauses[0], routeMap.clauses[0]] },
  { clauses: [{ ...routeMap.clauses[0], normalization_complete: false }] },
])("refuses duplicate, reordered or falsely complete maps %j", (change) => {
  expect(routeMapSchema.safeParse({ ...routeMap, ...change }).success).toBe(
    false,
  );
});

it.each([
  { schema_version: "1.1" },
  { schema_version: "1.0" },
  { schema_version: "1.3" },
  { route_maps: undefined },
  { route_maps: [routeMap, routeMap] },
  {
    device: { ...snapshot.canonical.device, vendor: "juniper" },
    route_maps: [],
  },
  { route_maps: [{ ...routeMap, normalization_complete: false }] },
])(
  "refuses unversioned, contradictory or cross-vendor route-map projections %j",
  (change) => {
    expect(
      snapshotSchema.safeParse({
        ...snapshot,
        canonical: { ...snapshot.canonical, ...change },
      }).success,
    ).toBe(false);
  },
);

it("retains incomplete maps only with visible parser uncertainty and reads old snapshots", () => {
  const partial = {
    ...snapshot.canonical,
    parser_confidence: 0.8,
    route_maps: [
      {
        ...routeMap,
        normalization_complete: false,
        clauses: [{ ...routeMap.clauses[0], normalization_complete: false }],
      },
    ],
    unparsed_fragments: [{ raw_text: " continue 30", location }],
  };
  expect(
    snapshotSchema.parse({ ...snapshot, canonical: partial }).canonical
      .route_maps?.[0]?.normalization_complete,
  ).toBe(false);
  const legacy = {
    ...snapshot.canonical,
    schema_version: "1.1",
    route_maps: undefined,
  };
  expect(
    snapshotSchema.parse({ ...snapshot, canonical: legacy }).canonical
      .route_maps,
  ).toBeUndefined();
});
