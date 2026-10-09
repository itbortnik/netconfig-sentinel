import { defineConfig, devices } from "@playwright/test";

const python =
  process.env.NETCONFIG_TEST_PYTHON ??
  (process.platform === "win32" ? "../.venv/Scripts/python.exe" : "python");
// This profile always owns its ephemeral backend; never target a deployed database/provider.
export default defineConfig({
  testDir: "tests/browser",
  testMatch: "modelPatches.spec.ts",
  outputDir: "../artifacts/browser-model-patches",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    ["junit", { outputFile: "../artifacts/browser-model-patches-junit.xml" }],
  ],
  use: {
    baseURL: "http://127.0.0.1:8302",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: `"${python}" tests/serve_test_backend.py --model-patch-fixture`,
    url: "http://127.0.0.1:8302/health",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
