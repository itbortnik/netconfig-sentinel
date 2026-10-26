import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "tests/browser",
  testMatch: "native-patches.spec.ts",
  outputDir: "../artifacts/browser-native-patches",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    ["junit", { outputFile: "../artifacts/browser-native-patches-junit.xml" }],
  ],
  use: {
    baseURL: "http://127.0.0.1:5189",
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
      "node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5189 --strictPort",
    url: "http://127.0.0.1:5189/ui/",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
