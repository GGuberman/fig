import { test, expect } from '@playwright/test';

test.describe('Health page', () => {
  test('React root mounts something', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));

    await page.goto('/index.html#health');
    // Wait for React bundle to mount and render content
    await expect(page.locator('#root')).not.toBeEmpty({ timeout: 15000 });

    expect(errors, `pageerrors: ${errors.join('; ')}`).toEqual([]);
  });

  test('back link present', async ({ page }) => {
    await page.goto('/index.html#health');
    await expect(page.locator('#view-health button:has-text("← Fig")')).toBeVisible();
  });

  test('uses the new font stack (no Georgia / DM Mono)', async ({ page }) => {
    await page.goto('/index.html#health');
    const head = await page.locator('head').innerHTML();
    expect(head).toContain('Fraunces');
    expect(head).toContain('Inter');
    const html = await page.content();
    expect(html).not.toContain('Georgia,serif');
    expect(html).not.toContain('DM+Mono');
  });
});
