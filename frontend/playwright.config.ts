import { defineConfig, devices } from "@playwright/test";

const python =
  process.env.NETCONFIG_TEST_PYTHON ??
  (process.platform === "win32" ? "../.venv/Scripts/python.exe" : "python");
const deployed = process.env.NETCONFIG_E2E_BASE_URL;
if (deployed && !/^http:\/\/127\.0\.0\.1:\d+$/.test(deployed))
  throw new Error("Browser tests are restricted to explicit loopback servers.");
export default defineConfig({
  testDir: "tests/browser",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: deployed ?? "http://127.0.0.1:8301",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: deployed
    ? undefined
    : {
        command: `"${python}" tests/serve_test_backend.py`,
        url: "http://127.0.0.1:8301/health",
        reuseExistingServer: false,
        timeout: 60_000,
      },
});
