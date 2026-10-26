import { defineConfig, devices } from "@playwright/test";

const python =
  process.env.NETCONFIG_TEST_PYTHON ??
  (process.platform === "win32" ? "../.venv/Scripts/python.exe" : "python");
const attempt =
  process.env.NETCONFIG_NATIVE_HTTP_ATTEMPT ??
  new Date()
    .toISOString()
    .replace(/[^a-z0-9]/gi, "")
    .toLowerCase();
if (!/^[a-z0-9-]+$/.test(attempt))
  throw new Error("Invalid native HTTP attempt suffix");
process.env.NETCONFIG_NATIVE_HTTP_ATTEMPT = attempt;

export default defineConfig({
  testDir: "tests/browser",
  testMatch: "native-patches-http.spec.ts",
  outputDir: `../artifacts/native-http-browser-${attempt}`,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    [
      "junit",
      { outputFile: `../artifacts/native-http-browser-${attempt}-junit.xml` },
    ],
  ],
  use: {
    baseURL: "http://127.0.0.1:8311",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: `"${python}" tests/serve_native_test_backend.py`,
    url: "http://127.0.0.1:8311/health",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
