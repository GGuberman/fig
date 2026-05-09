import { test, expect } from '@playwright/test';

test.describe('Finance page', () => {
  // Each test gets a fresh BrowserContext, so localStorage and IndexedDB start
  // empty. We deliberately don't register an addInitScript clearer — it would
  // re-fire on every navigation and wipe state we set deliberately during a test
  // (e.g. picking a theme on / and then navigating to /finance.html).

  test('shows onboarding on fresh state', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));

    await page.goto('/finance.html');
    await expect(page.locator('#app-loading')).toBeHidden({ timeout: 15000 });
    await expect(page.locator('#onboarding')).toBeVisible();
    await expect(page.locator('.ob-logo')).toContainText('Fig Finance');

    await page.waitForTimeout(500);
    expect(errors, `pageerrors: ${errors.join('; ')}`).toEqual([]);
  });

  test('emergency Reset button is always visible', async ({ page }) => {
    await page.goto('/finance.html');
    await expect(page.locator('button[onclick="figEmergencyReset()"]')).toBeVisible();
  });

  test('back-link returns to home', async ({ page }) => {
    await page.goto('/finance.html');
    await page.click('button[onclick*="navigateTo"]');
    await expect(page).toHaveURL(/index\.html$/);
    await expect(page.locator('.wordmark')).toHaveText('Fig');
  });

  test('inherits Fig Light theme from home', async ({ page }) => {
    await page.goto('/index.html');
    // Dismiss first-visit overlay
    await page.evaluate(() => window.figDismissLauncher());
    await page.click('button[onclick="openTheme()"]');
    await page.click('text=Fig Light');
    await page.goto('/finance.html');
    const bg = await page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()
    );
    expect(bg).toBe('#f5f7f2');
  });
});
