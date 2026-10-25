import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: 'tests/browser',
  workers: 1,
  use: {
    baseURL: process.env.CONSOLE_BASE_URL ?? 'http://localhost:3000',
    channel: process.env.BROWSER_CHANNEL ?? 'chrome',
    viewport: { width: 1440, height: 1000 },
    trace: 'retain-on-failure',
  },
  reporter: 'list',
  outputDir: process.env.CONSOLE_BASE_URL ? '.local/playwright-oidc' : '.local/playwright-demo',
});
