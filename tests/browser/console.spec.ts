import { test, expect } from '@playwright/test';
test('console signs in, executes MCP, verifies audit, and simulates a denial', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await page.getByRole('button', { name: 'Open demo workspace' }).click();
  await expect(
    page.getByRole('heading', { name: 'Every tool call. Accounted for.' }),
  ).toBeVisible();
  await expect(page.getByText('Support triage', { exact: true })).toBeVisible();
  await page.screenshot({ path: '.local/reports/console-overview.png', fullPage: true });
  await page.getByRole('button', { name: 'Workbench', exact: true }).click();
  await page.getByRole('button', { name: 'Execute call' }).click();
  await expect(page.locator('.output')).toContainText('resultType');
  await page.getByRole('button', { name: 'Audit trail', exact: true }).click();
  await page.getByRole('button', { name: 'Verify hash chain' }).click();
  await expect(page.getByRole('status')).toContainText('"valid":true');
  await page.getByRole('button', { name: 'Policies', exact: true }).click();
  await page.getByLabel('Repository', { exact: true }).fill('unapproved/private');
  await page.getByRole('button', { name: 'Simulate', exact: true }).click();
  await expect(page.locator('.simulator pre')).toContainText('"allowed": false');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: '.local/reports/console-mobile.png', fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  expect(errors).toEqual([]);
});
