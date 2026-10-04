import { expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { rolePermissions, sessionAccessSchema } from "./contracts";

const token = "synthetic-access-unit-token-000000001";
const session = (role: keyof typeof rolePermissions) => ({
  version: "service-access-0.1.0",
  role,
  permissions: [...rolePermissions[role]],
  individual_identity_verified: false,
  device_scope: "all_saved_devices",
});
it.each(Object.keys(rolePermissions) as (keyof typeof rolePermissions)[])(
  "accepts exact %s permissions and clears them on close",
  async (role) => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(JSON.stringify(session(role))));
    const api = new ApiClient(token, transport);
    expect(api.permits("read")).toBe(false);
    expect(await api.access()).toEqual(session(role));
    for (const permission of rolePermissions.admin)
      expect(api.permits(permission)).toBe(
        session(role).permissions.includes(permission),
      );
    expect(transport.mock.calls[0]![0]).toBe("/api/v1/session");
    expect(transport.mock.calls[0]![1]?.cache).toBe("no-store");
    api.close();
    expect(api.permits("read")).toBe(false);
  },
);
it.each([
  { role: "owner" },
  { approved: true },
  { individual_identity_verified: true },
  { device_scope: "tenant" },
  { permissions: ["read", "upload"] },
  { permissions: ["read", "read"] },
  { permissions: [] },
  { version: "unknown" },
])("rejects unsupported or misleading access %j", (update) => {
  expect(
    sessionAccessSchema.safeParse({ ...session("reader"), ...update }).success,
  ).toBe(false);
});
it("does not restore a closed client's permissions from a late response", async () => {
  let release!: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const api = new ApiClient(
    token,
    vi.fn<typeof fetch>().mockReturnValue(pending),
  );
  const result = api.access();
  api.close();
  release(new Response(JSON.stringify(session("admin"))));
  await expect(result).rejects.toMatchObject({ name: "AbortError" });
  expect(api.permits("train_model")).toBe(false);
});
it("never defaults to administrator on an unavailable session endpoint", async () => {
  const api = new ApiClient(
    token,
    vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response("private-config", { status: 503 })),
  );
  await expect(api.access()).rejects.toMatchObject({ status: 503 });
  expect(api.permits("read")).toBe(false);
  api.close();
});
it("rejects oversized credentials before any request", () => {
  expect(() => new ApiClient("x".repeat(513))).toThrow();
});
