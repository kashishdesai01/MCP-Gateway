import { test, expect } from '@playwright/test';
test('real Keycloak authorization code PKCE login and authenticated gateway access', async ({
  page,
}) => {
  const password = process.env.KEYCLOAK_TEST_PASSWORD;
  if (!password) throw new Error('KEYCLOAK_TEST_PASSWORD required; start npm run demo:oidc');
  await page.goto('/');
  await page.getByRole('button', { name: 'Sign in with your organization' }).click();
  await expect(page).toHaveURL(/localhost:18090/);
  const oauth = new URL(page.url());
  expect(oauth.searchParams.get('code_challenge_method')).toBe('S256');
  expect(oauth.searchParams.get('resource')).toBe('http://localhost:3100/mcp');
  await page.getByLabel('Username or email').fill('operator');
  await page.getByLabel('Password', { exact: true }).fill(password);
  const tokenResponse = page.waitForResponse((response) =>
    response.url().endsWith('/protocol/openid-connect/token'),
  );
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  const body = await (await tokenResponse).json();
  const claims = JSON.parse(Buffer.from(body.access_token.split('.')[1], 'base64url').toString());
  expect(claims.iss).toBe('http://localhost:18090/realms/gateway');
  expect(claims.sub).toBe('demo-owner');
  expect(claims.aud).toBe('http://localhost:3100/mcp');
  expect(claims.azp).toBe('gateway-console');
  expect(claims.realm_access.roles).toContain('gateway-admin');
  await expect(page).toHaveURL('http://localhost:3100/');
  await expect(page.getByText('Support triage', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Workbench', exact: true }).click();
  await page.getByRole('button', { name: 'Execute call' }).click();
  await expect(page.locator('.output')).toContainText('resultType');
  expect(await page.locator('.alert.error').count()).toBe(0);
  await page.screenshot({ path: '.local/reports/oidc-login.png', fullPage: true });
});
