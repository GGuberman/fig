import { test, expect } from '@playwright/test';

const cssVar = (name: string) =>
  `getComputedStyle(document.documentElement).getPropertyValue('${name}').trim()`;

test.describe('Theme switcher', () => {
  test.beforeEach(async ({ page }) => {
    // Each test gets a fresh BrowserContext, so localStorage starts empty.
    // We deliberately do NOT use addInitScript to clear, because that handler
    // re-fires on every reload/navigation and would wipe the theme we just set
    // mid-test.
    await page.goto('/index.html');
    // Dismiss first-visit overlay
    await page.evaluate(() => window.figDismissLauncher());
  });

  test('opens and closes the modal', async ({ page }) => {
    await page.click('button[onclick="openTheme()"]');
    await expect(page.locator('#theme-modal')).toHaveClass(/open/);
    await page.click('#theme-modal .modal-close');
    await expect(page.locator('#theme-modal')).not.toHaveClass(/open/);
  });

  test('switches to Fig Light', async ({ page }) => {
    await page.click('button[onclick="openTheme()"]');
    await page.click('text=Fig Light');
    const bg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
    expect(bg).toBe('#f5f7f2');
    const accent = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--accent').trim());
    expect(accent).toBe('#2f7d4a');
  });

  test('persists theme across reload', async ({ page }) => {
    await page.click('button[onclick="openTheme()"]');
    await page.click('text=Fig Light');
    await page.reload();
    const bg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
    expect(bg).toBe('#f5f7f2');
  });

  test('finance inherits the saved theme', async ({ page }) => {
    await page.click('button[onclick="openTheme()"]');
    await page.click('text=Fig Light');
    await page.goto('/finance.html');
    const bg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
    expect(bg).toBe('#f5f7f2');
  });

  test('theme picker lists Fig Light alongside Fig Dark', async ({ page }) => {
    await page.click('button[onclick="openTheme()"]');
    await expect(page.locator('.preset-item:has-text("Fig Light")')).toBeVisible();
    await expect(page.locator('.preset-item:has-text("Fig Dark")')).toBeVisible();
  });
});
