import { defineConfig, devices } from "@playwright/test";

const python =
  process.env.NETCONFIG_TEST_PYTHON ??
  (process.platform === "win32" ? "../.venv/Scripts/python.exe" : "python");
export default defineConfig({
  testDir: "tests/browser",
  testMatch: "sourceIngress.spec.ts",
  outputDir: "../artifacts/browser-source-ingress",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    [
      "junit",
      {
        outputFile: "../artifacts/browser-source-ingress-junit.xml",
      },
    ],
  ],
  use: {
    baseURL: "http://127.0.0.1:8310",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: `"${python}" tests/serve_test_backend.py --source-ingress-fixture`,
    url: "http://127.0.0.1:8310/health",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
