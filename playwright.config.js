const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests/e2e",
  timeout: 45_000,
  expect: { timeout: 8_000 },
  reporter: [["list"]],
  webServer: {
    command: "python3 pm_server.py",
    url: (process.env.PM_BASE_URL || "http://127.0.0.1:8765") + "/pm",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  use: {
    baseURL: process.env.PM_BASE_URL || "http://127.0.0.1:8765",
    headless: true,
    trace: "retain-on-failure",
  },
});
