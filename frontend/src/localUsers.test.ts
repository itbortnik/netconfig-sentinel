import { expect, it } from "vitest";
import { localUserSchema, snapshotSchema } from "./contracts";

const id = "00000000-0000-0000-0000-000000000001";
const hash = "a".repeat(64);
const location = {
  source_lines: [2],
  raw_text_hash: hash,
  parser_confidence: 1,
};
const auth = { kind: "secret", encoding: "9", provenance: location };
const user = {
  name: "admin",
  privilege: 15,
  login_class: null,
  uid: null,
  authentication: [auth],
  provenance: { name: location },
};
const snapshot = {
  configuration_id: id,
  device_id: id,
  created_at: "2026-10-04T00:00:00Z",
  canonical: {
    schema_version: "1.1",
    source: {
      filename: "synthetic.cfg",
      sha256: hash,
      collected_at: "2026-10-04T00:00:00Z",
    },
    device: { hostname: "edge", vendor: "cisco", platform: "ios" },
    parser_confidence: 1,
    parse_warnings: [],
    unparsed_fragments: [],
    interfaces: [],
    vlans: [],
    acls: [],
    static_routes: [],
    local_users: [user],
  },
};

it("accepts new device-account schema and readable legacy snapshots without inventing users", () => {
  expect(snapshotSchema.parse(snapshot).canonical.local_users?.[0]).toEqual(
    user,
  );
  const legacy = {
    ...snapshot.canonical,
    schema_version: "1.0",
    local_users: undefined,
  };
  expect(
    snapshotSchema.parse({ ...snapshot, canonical: legacy }).canonical
      .local_users,
  ).toBeUndefined();
});
it.each([
  { schema_version: "1.2" },
  { schema_version: "1.1", local_users: undefined },
  { schema_version: "1.0" },
  { local_users: [user, user] },
])("rejects unsupported or inconsistent account inventories %j", (change) => {
  expect(
    snapshotSchema.safeParse({
      ...snapshot,
      canonical: { ...snapshot.canonical, ...change },
    }).success,
  ).toBe(false);
});
it.each([
  { password: "PRIVATE" },
  { name: "<script>" },
  { privilege: true },
  { privilege: 16 },
  { uid: 99 },
  { authentication: [auth, auth] },
  { authentication: [{ ...auth, value: "PRIVATE" }] },
  { authentication: [{ ...auth, kind: "password" }] },
  { authentication: [{ ...auth, kind: "none" }] },
  { authentication: [{ ...auth, encoding: "executable" }] },
])("rejects secret fields and invalid device-account metadata %j", (change) => {
  expect(localUserSchema.safeParse({ ...user, ...change }).success).toBe(false);
});
