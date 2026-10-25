import { defineConfig, devices } from "@playwright/test";
const run = process.env.NETCONFIG_PARTIAL_UI_ATTEMPT ?? "verified";
if (!/^[a-z0-9-]+$/.test(run))
  throw new Error("Invalid partial UI artifact suffix");

export default defineConfig({
  testDir: "tests/browser",
  testMatch: "sourcePartialDiagnostic.spec.ts",
  outputDir: `../artifacts/partial-ui-browser-${run}`,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    [
      "junit",
      { outputFile: `../artifacts/partial-ui-browser-${run}-junit.xml` },
    ],
  ],
  use: {
    baseURL: "http://127.0.0.1:5188",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command:
      "node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5188 --strictPort",
    url: "http://127.0.0.1:5188/ui/",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
