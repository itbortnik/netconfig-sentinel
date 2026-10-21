import { z } from "zod";
import { location, stableJson } from "./contracts";

// Data-only historical reference validation. This module never projects or compares sources.
const fields = [
  "management.ssh_enabled",
  "management.ssh_version",
  "management.telnet_enabled",
  "management.aaa_enabled",
  "management.snmp_versions",
  "management.ntp_servers",
  "management.syslog_servers",
  "local_user.present",
  "local_user.privilege",
  "local_user.login_class",
  "local_user.uid",
  "local_user.authentication",
  "interface.present",
  "interface.enabled",
  "interface.mode",
  "interface.access_vlan",
  "interface.native_vlan",
  "interface.allowed_vlans",
  "interface.addresses",
  "vlans.set",
  "acls.present",
  "acls.rules",
  "prefix_lists.present",
  "prefix_lists.rules",
  "bgp.present",
  "bgp.local_as",
  "bgp.router_id",
  "bgp.neighbor.present",
  "bgp.neighbor.remote_as",
  "bgp.neighbor.group",
  "bgp.neighbor.session_type",
  "bgp.neighbor.update_source",
  "bgp.neighbor.enabled",
  "bgp.neighbor.family",
  "ospf.present",
  "ospf.process.present",
  "ospf.process.version",
  "ospf.process.router_id",
  "ospf.process.passive_default",
  "ospf.network.area",
  "ospf.interface.present",
  "ospf.interface.area",
  "ospf.interface.passive",
  "ospf.interface.cost",
  "static_routes.targets",
] as const;
const booleans = new Set<string>([
  "management.ssh_enabled",
  "management.telnet_enabled",
  "management.aaa_enabled",
  "local_user.present",
  "interface.present",
  "acls.present",
  "prefix_lists.present",
  "bgp.present",
  "bgp.neighbor.present",
  "ospf.present",
  "ospf.process.present",
  "ospf.process.passive_default",
  "ospf.interface.present",
]);
const optionalBooleans = new Set<string>([
  "interface.enabled",
  "bgp.neighbor.enabled",
  "ospf.interface.passive",
]);
const integers = new Set<string>(["bgp.local_as", "bgp.neighbor.remote_as"]);
const optionalIntegers = new Set<string>([
  "local_user.privilege",
  "local_user.uid",
  "ospf.interface.cost",
]);
const tuples = new Set<string>([
  "management.snmp_versions",
  "management.ntp_servers",
  "management.syslog_servers",
  "local_user.authentication",
  "interface.addresses",
  "vlans.set",
  "acls.rules",
  "prefix_lists.rules",
  "static_routes.targets",
]);
const twoPart = new Set<string>([
  ...fields.filter((field) => field.startsWith("interface.")),
  "prefix_lists.present",
  "prefix_lists.rules",
  "ospf.network.area",
  "ospf.interface.present",
  "ospf.interface.area",
  "ospf.interface.passive",
  "ospf.interface.cost",
  "static_routes.targets",
]);
const roots = new Set<string>([
  ...fields.filter((field) => field.startsWith("management.")),
  "vlans.set",
  "bgp.present",
  "ospf.present",
]);
const rootKeys = new Set([...roots, "bgp.local_as", "bgp.router_id"]);
const setFields = new Set<string>(
  [...tuples].filter(
    (field) => field !== "acls.rules" && field !== "prefix_lists.rules",
  ),
);
const ranges: Record<string, readonly [number, number]> = {
  "local_user.privilege": [0, 15],
  "local_user.uid": [100, 64000],
  "bgp.local_as": [1, 4294967295],
  "bgp.neighbor.remote_as": [1, 4294967295],
  "ospf.interface.cost": [1, 65535],
};
const choices: Record<string, readonly (string | null)[]> = {
  "management.ssh_version": [null, "1", "2"],
  "interface.mode": [null, "access", "trunk"],
  "bgp.neighbor.session_type": [null, "internal", "external"],
  "bgp.neighbor.family": ["ipv4", "ipv6"],
  "ospf.process.version": ["ospfv2"],
};
const routingIds = new Set<string>([
  "bgp.router_id",
  "ospf.process.router_id",
  "ospf.network.area",
  "ospf.interface.area",
]);
// Python compares Unicode code points; UTF-16 sorting would reorder non-BMP keys.
function compareText(a: string, b: string) {
  const left = [...a],
    right = [...b];
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const delta = left[i]!.codePointAt(0)! - right[i]!.codePointAt(0)!;
    if (delta) return delta;
  }
  return left.length - right.length;
}
const canonicalSet = (values: string[]) =>
  values.every(
    (value, index) => index === 0 || compareText(values[index - 1]!, value) < 0,
  );
const strictLocation = location
  .strict()
  .refine(
    (row) =>
      row.source_lines.length > 0 &&
      row.source_lines.every(
        (line, index) => index === 0 || line > row.source_lines[index - 1]!,
      ),
  );
const value = z.union([
  z.boolean(),
  z.number().int(),
  z.string(),
  z.array(z.string()),
  z.null(),
]);
function asciiBytes(input: unknown) {
  return stableJson(input).replace(
    /[\u007f-\uffff]/g,
    (letter) => `\\u${letter.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ).length;
}
const expandedFact = z
  .strictObject({
    field: z.enum(fields),
    object_key: z.array(z.string()).min(1).max(3),
    value,
    locations: z.array(strictLocation).max(10000),
  })
  .refine((row) => {
    const field = row.field,
      value = row.value,
      key = row.object_key;
    const size = field.startsWith("acls.") ? 3 : twoPart.has(field) ? 2 : 1;
    if (
      key.length !== size ||
      !key[0] ||
      key.some(
        (part) =>
          [...part].length > 512 ||
          /[\p{C}\p{Z}]/u.test(part.replace(/ /g, "")),
      ) ||
      (!field.startsWith("interface.") && key.slice(1).some((part) => !part)) ||
      (rootKeys.has(field) && stableJson(key) !== '["device"]')
    )
      return false;
    const valid = booleans.has(field)
      ? typeof value === "boolean"
      : optionalBooleans.has(field)
        ? value === null || typeof value === "boolean"
        : integers.has(field)
          ? typeof value === "number" && Number.isInteger(value)
          : optionalIntegers.has(field)
            ? value === null ||
              (typeof value === "number" && Number.isInteger(value))
            : tuples.has(field)
              ? Array.isArray(value)
              : [
                    "bgp.neighbor.family",
                    "ospf.process.version",
                    "ospf.network.area",
                  ].includes(field)
                ? typeof value === "string"
                : value === null || typeof value === "string";
    if (
      !valid ||
      (field.endsWith(".present") &&
        field !== "bgp.present" &&
        field !== "ospf.present" &&
        value !== true)
    )
      return false;
    if (choices[field] && !choices[field]!.includes(value as string | null))
      return false;
    const range = ranges[field];
    if (
      range &&
      typeof value === "number" &&
      (value < range[0] || value > range[1])
    )
      return false;
    if (
      routingIds.has(field) &&
      value !== null &&
      (typeof value !== "string" || !z.ipv4().safeParse(value).success)
    )
      return false;
    if (setFields.has(field) && (!Array.isArray(value) || !canonicalSet(value)))
      return false;
    if (
      field === "management.snmp_versions" &&
      Array.isArray(value) &&
      value.some((item) => !["v1", "v2c", "v3"].includes(item))
    )
      return false;
    return asciiBytes(value) <= 512 * 1024;
  });
const metadata = {
  reference_id: z.string().min(1).max(256),
  device_id: z.guid(),
  vendor: z.enum(["cisco", "juniper"]),
  source_sha256: z.string().regex(/^[0-9a-f]{64}$/),
};
const legacy = z
  .strictObject({
    ...metadata,
    version: z.literal("expected-config-0.1.0"),
    platform: z.string(),
    hostname: z.string().nullable(),
    facts: z.array(
      z.strictObject({
        field: z.enum([
          "bgp.remote_as",
          "interface.mode",
          "interface.access_vlan",
          "interface.addresses",
          "ospf.network_area",
          "ospf.interface_area",
        ]),
        object_key: z.array(z.string()).min(1),
        value: z.union([
          z.string(),
          z.number().int(),
          z.array(z.string()),
          z.null(),
        ]),
        locations: z.array(strictLocation),
      }),
    ),
  })
  .refine(
    (row) =>
      new Set(row.facts.map((f) => stableJson([f.field, f.object_key])))
        .size === row.facts.length,
  );
const expanded = z
  .strictObject({
    ...metadata,
    version: z.literal("expected-config-0.2.0"),
    platform: z.string().min(1).max(128),
    hostname: z.string().max(255).nullable(),
    facts: z.array(expandedFact).min(1).max(50000),
  })
  .refine((row) => {
    const indexed = new Map(
      row.facts.map((f) => [stableJson([f.field, f.object_key]), f]),
    );
    if (indexed.size !== row.facts.length) return false;
    const has = (field: string, key: string[]) =>
      indexed.has(stableJson([field, key]));
    const keyCompare = (
      left: (typeof row.facts)[number],
      right: (typeof row.facts)[number],
    ) => {
      const field = compareText(left.field, right.field);
      if (field) return field;
      for (
        let i = 0;
        i < Math.min(left.object_key.length, right.object_key.length);
        i++
      ) {
        const part = compareText(left.object_key[i]!, right.object_key[i]!);
        if (part) return part;
      }
      return left.object_key.length - right.object_key.length;
    };
    if (
      row.facts.some(
        (fact, index) =>
          index > 0 && keyCompare(row.facts[index - 1]!, fact) >= 0,
      )
    )
      return false;
    if ([...roots].some((field) => !has(field, ["device"]))) return false;
    for (const prefix of [
      "local_user.",
      "interface.",
      "acls.",
      "prefix_lists.",
      "bgp.neighbor.",
      "ospf.process.",
      "ospf.interface.",
    ]) {
      const expected = fields.filter((field) => field.startsWith(prefix));
      const keys = row.facts
        .filter((f) => f.field.startsWith(prefix))
        .map((f) => f.object_key);
      if (keys.some((key) => expected.some((field) => !has(field, key))))
        return false;
    }
    const bgp = indexed.get(stableJson(["bgp.present", ["device"]]))!.value;
    const bgpDetails = row.facts.filter(
      (f) => f.field.startsWith("bgp.") && f.field !== "bgp.present",
    );
    if (
      bgp
        ? ["bgp.local_as", "bgp.router_id"].some(
            (field) => !has(field, ["device"]),
          )
        : bgpDetails.length > 0
    )
      return false;
    const ospf = indexed.get(stableJson(["ospf.present", ["device"]]))!.value;
    const processes = new Set(
      row.facts
        .filter((f) => f.field === "ospf.process.present")
        .map((f) => f.object_key[0]),
    );
    if (
      Boolean(processes.size) !== ospf ||
      row.facts.some(
        (f) =>
          f.field.startsWith("ospf.") &&
          f.field !== "ospf.present" &&
          !processes.has(f.object_key[0]),
      )
    )
      return false;
    return (
      row.facts.reduce(
        (size, fact) =>
          size + new TextEncoder().encode(JSON.stringify(fact)).byteLength,
        0,
      ) <=
      8 * 1024 * 1024
    );
  });
export const deterministicReferenceSchema = z.discriminatedUnion("version", [
  legacy,
  expanded,
]);
