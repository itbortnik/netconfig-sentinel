import { expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./api";
import { objectChangeSchema, snapshotDiffSchema } from "./contracts";
import { diffBound, diffInput } from "./diff";
import type { DiffSelection } from "./diff";

const guid = (n: number) =>
  `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
const before: DiffSelection = {
  configuration_id: guid(1),
  device_id: guid(3),
  source_sha256: "a".repeat(64),
  created_at: "2026-10-03T00:00:00Z",
  vendor: "cisco",
  platform: "ios",
  hostname: "edge",
  parser_confidence: 1,
  warning_count: 0,
  unparsed_count: 0,
};
const after = {
  ...before,
  configuration_id: guid(2),
  source_sha256: "b".repeat(64),
  created_at: "2026-10-03T00:00:01Z",
};
const change = {
  section: "interfaces",
  object_key: ["Gi0/1", ""],
  kind: "added",
  before_value: null,
  after_value: { enabled: true },
  before_locations: [],
  after_locations: [],
};
const fixture = {
  version: "snapshot-diff-0.1.0",
  representation: "normalized_objects",
  before: { ...before, projection_sha256: "c".repeat(64) },
  after: { ...after, projection_sha256: "d".repeat(64) },
  coverage: "supported_complete",
  source_changed: true,
  added_count: 1,
  removed_count: 0,
  modified_count: 0,
  changes: [change],
  limitations: ["Not a raw diff, approval or network verification."],
};
it("validates a read-only bound object difference without approval fields", () => {
  const report = snapshotDiffSchema.parse(fixture);
  expect(diffBound(report, before, after)).toBe(true);
  expect(diffInput(before, after)).toBe(before.configuration_id);
});
it.each([
  { version: "unknown" },
  { representation: "raw_file" },
  { coverage: "partial" },
  { source_changed: false },
  { added_count: 0 },
  { changes: [change, change], added_count: 2 },
  { validated: true },
  { after: { ...fixture.after, device_id: guid(9) } },
  { after: { ...fixture.after, configuration_id: before.configuration_id } },
  {
    after: {
      ...fixture.after,
      projection_sha256: fixture.before.projection_sha256,
    },
  },
  { limitations: [] },
])(
  "rejects inconsistent or authoritative-looking comparisons: %j",
  (altered) => {
    expect(
      snapshotDiffSchema.safeParse({ ...fixture, ...altered }).success,
    ).toBe(false);
  },
);
it.each(Object.keys(before) as (keyof DiffSelection)[])(
  "checks both selected snapshot bindings: %s",
  (key) => {
    const report = snapshotDiffSchema.parse(fixture);
    expect(diffBound(report, { ...before, [key]: "changed" }, after)).toBe(
      false,
    );
    expect(diffBound(report, before, { ...after, [key]: "changed" })).toBe(
      false,
    );
  },
);
it.each([
  { kind: "removed" },
  { after_value: null },
  {
    before_locations: [
      {
        source_lines: [1],
        raw_text_hash: "a".repeat(64),
        parser_confidence: 1,
      },
    ],
  },
  {
    kind: "modified",
    before_value: { a: 1, b: 2 },
    after_value: { b: 2, a: 1 },
  },
])(
  "refuses impossible changes or anchors for absent objects: %j",
  (altered) => {
    expect(
      objectChangeSchema.safeParse({ ...change, ...altered }).success,
    ).toBe(false);
  },
);
it("allows partial selections but never their promotion to complete scope", () => {
  const report = snapshotDiffSchema.parse({
    ...fixture,
    before: { ...fixture.before, unparsed_count: 1 },
    coverage: "partial",
  });
  expect(report.coverage).toBe("partial");
  expect(diffInput({ ...before, unparsed_count: 1 }, after)).toBe(
    before.configuration_id,
  );
});
it.each([
  { ...after, configuration_id: before.configuration_id },
  { ...after, device_id: guid(9) },
  { ...after, hostname: "other" },
  { ...after, created_at: "2026-10-02T00:00:00Z" },
])("rejects a current, foreign or later reference", (current) => {
  expect(() => diffInput(before, current)).toThrow("того же устройства");
});
it("uses a same-origin authenticated GET with explicit reference and no side-effecting POST", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response(JSON.stringify(fixture)));
  const client = new ApiClient(
    "test-only-memory-service-token-32-characters",
    transport,
  );
  expect(
    await client.diff(after.configuration_id, before.configuration_id),
  ).toEqual(fixture);
  const [url, init] = transport.mock.calls[0]!;
  expect(url).toBe(
    `/api/v1/configurations/${after.configuration_id}/diff?reference_configuration_id=${before.configuration_id}`,
  );
  expect(init?.method).toBe("GET");
  expect(init?.body).toBeUndefined();
  expect(init?.cache).toBe("no-store");
  expect(init?.credentials).toBe("omit");
  client.close();
});
it("does not reflect oversized/private comparison error bodies", async () => {
  const client = new ApiClient(
    "test-only-memory-service-token-32-characters",
    vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("private-config", { status: 413 })),
  );
  await expect(client.diff("current", "before")).rejects.toBeInstanceOf(
    ApiError,
  );
  await expect(client.diff("current", "before")).rejects.toThrow(
    "размер или число изменений",
  );
  client.close();
});
