import { describe, expect, it } from "vitest";
import type { Upload } from "./contracts";
import {
  MAX_TEXT_BYTES,
  readConfigurationFile,
  validateUpload,
} from "./upload";

const good = {
  device_id: "00000000-0000-0000-0000-000000000001",
  filename: "edge.cfg",
  content: "hostname edge\n",
};
describe("bounded UTF-8 uploads", () => {
  it("accepts only explicit boolean retention, default remains absent", () => {
    expect(validateUpload(good)).toBeNull();
    expect(
      validateUpload({ ...good, retain_original_source: false }),
    ).toBeNull();
    expect(
      validateUpload({ ...good, retain_original_source: true }),
    ).toBeNull();
    for (const flag of [1, 0, null, "true"])
      expect(
        validateUpload({
          ...good,
          retain_original_source: flag,
        } as unknown as Upload),
      ).not.toBeNull();
  });
  it("accepts a valid request and exactly 10000 terminated lines", () => {
    expect(validateUpload(good)).toBeNull();
    expect(
      validateUpload({
        ...good,
        content: "hostname edge\n" + "!\n".repeat(9999),
      }),
    ).toBeNull();
  });
  it.each([
    { device_id: "invalid" },
    { filename: "../edge.cfg" },
    { filename: "C:\\edge.cfg" },
    { filename: "edge.exe" },
    { filename: "edge\0.cfg" },
    { content: "   \n" },
    { content: "hostname edge\u0001" },
    { content: "я".repeat(MAX_TEXT_BYTES / 2 + 1) },
    { content: "!\n".repeat(10001) },
    { content: "!\u2028".repeat(10001) },
  ])("rejects invalid or excessive input", (change) => {
    expect(validateUpload({ ...good, ...change })).not.toBeNull();
  });
  it("validates the serialized request byte budget too", () => {
    expect(
      validateUpload({
        ...good,
        content: "\t".repeat(MAX_TEXT_BYTES - 20) + "x",
      }),
    ).toContain("3 MiB");
  });
  it("reads UTF-8 and strips a UTF-8 BOM", async () => {
    const file = new File(
      [new Uint8Array([239, 187, 191]), good.content],
      "edge.cfg",
    );
    expect(await readConfigurationFile(file)).toBe(good.content);
  });
  it("rejects malformed UTF-8, oversized files and non-text extensions", async () => {
    await expect(
      readConfigurationFile(new File([new Uint8Array([255])], "edge.cfg")),
    ).rejects.toThrow("UTF-8");
    await expect(
      readConfigurationFile(
        new File([new Uint8Array(MAX_TEXT_BYTES + 1)], "edge.cfg"),
      ),
    ).rejects.toThrow("2 MiB");
    await expect(
      readConfigurationFile(new File([good.content], "archive.zip")),
    ).rejects.toThrow(".cfg");
  });
});
