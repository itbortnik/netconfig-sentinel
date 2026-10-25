import { defineConfig, devices } from "@playwright/test";

const python =
  process.env.NETCONFIG_TEST_PYTHON ??
  (process.platform === "win32" ? "../.venv/Scripts/python.exe" : "python");
const run = process.env.NETCONFIG_PARTIAL_HTTP_ATTEMPT ?? "verified";
if (!/^[a-z0-9-]+$/.test(run))
  throw new Error("Invalid partial HTTP artifact suffix");
export default defineConfig({
  testDir: "tests/browser",
  testMatch: "sourcePartialDiagnosticHttp.spec.ts",
  outputDir: `../artifacts/partial-http-browser-${run}`,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    [
      "junit",
      { outputFile: `../artifacts/partial-http-browser-${run}-junit.xml` },
    ],
  ],
  use: {
    baseURL: "http://127.0.0.1:8301",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: `"${python}" tests/serve_test_backend.py`,
    url: "http://127.0.0.1:8301/health",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
