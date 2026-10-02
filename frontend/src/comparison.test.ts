import { expect, it } from "vitest";
import { comparisonOptions } from "./comparison";
import type { SelectedSnapshot } from "./comparison";
import { validateUpload } from "./upload";

const current: SelectedSnapshot = {
  id: "current",
  device: "target",
  hostname: "edge",
  hash: "current-hash",
  created: "2026-10-02T02:00:00Z",
  group: "explicit-group",
  complete: true,
};
const reference = {
  ...current,
  id: "reference",
  hash: "old-hash",
  created: "2026-10-02T01:00:00Z",
};
const peers = [0, 1, 2].map((index) => ({
  ...reference,
  id: `peer-${index}`,
  device: `device-${index}`,
  hostname: `host-${index}`,
  hash: `hash-${index}`,
}));
it("does not choose a reference or peers automatically", () => {
  expect(comparisonOptions(current, null, [])).toBeUndefined();
});
it("binds explicit reference and peers without sending source text", () => {
  expect(comparisonOptions(current, reference, peers)).toEqual({
    reference_configuration_id: "reference",
    peer_configuration_ids: ["peer-0", "peer-1", "peer-2"],
  });
});
it.each([
  { ...reference, device: "other" },
  current,
  { ...reference, complete: false },
  { ...reference, created: "2026-10-02T03:00:00Z" },
])("rejects an incompatible reference before a POST", (selected) => {
  expect(() => comparisonOptions(current, selected, [])).toThrow(
    "Эталон должен",
  );
});
it.each(
  [
    peers.slice(0, 2),
    [peers[0]!, peers[0]!, peers[2]!],
    [{ ...peers[0]!, group: "other" }, ...peers.slice(1)],
    [{ ...peers[0]!, device: "target" }, ...peers.slice(1)],
    [{ ...peers[0]!, hostname: "edge" }, ...peers.slice(1)],
    [{ ...peers[0]!, complete: false }, ...peers.slice(1)],
    [{ ...peers[0]!, created: "2026-10-02T03:00:00Z" }, ...peers.slice(1)],
  ].map((selected) => ({ selected })),
)("rejects inappropriate or non-independent peers", ({ selected }) => {
  expect(() => comparisonOptions(current, null, selected)).toThrow();
});
it("permits peer triage but not exact reference comparison on a partial target", () => {
  expect(
    comparisonOptions({ ...current, complete: false }, null, peers)
      ?.peer_configuration_ids,
  ).toHaveLength(3);
  expect(() =>
    comparisonOptions({ ...current, complete: false }, reference, []),
  ).toThrow();
});
it.each([
  "",
  " padded",
  "private\nlabel",
  "private\u0085label",
  "private\u200blabel",
  "x".repeat(65),
])("validates all explicit inventory labels", (label) => {
  expect(
    validateUpload({
      device_id: "00000000-0000-0000-0000-000000000001",
      filename: "a.cfg",
      content: "hostname a\n",
      inventory: {
        device_role: label,
        site_class: "branch",
        service_profile: "profile",
      },
    }),
  ).toContain("метки");
});
