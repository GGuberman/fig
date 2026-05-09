import { test, expect } from '@playwright/test';

test.describe('Health page', () => {
  test('React root mounts something', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));

    await page.goto('/health.html');
    // Give the bundled React app time to mount
    await page.waitForTimeout(2500);

    const root = page.locator('#root');
    const text = await root.textContent();
    expect((text || '').trim().length).toBeGreaterThan(20);

    expect(errors, `pageerrors: ${errors.join('; ')}`).toEqual([]);
  });

  test('back link present', async ({ page }) => {
    await page.goto('/health.html');
    await expect(page.locator('button[onclick*="navigateTo"]').first()).toContainText('Fig');
  });

  test('uses the new font stack (no Georgia / DM Mono)', async ({ page }) => {
    await page.goto('/health.html');
    const head = await page.locator('head').innerHTML();
    expect(head).toContain('Fraunces');
    expect(head).toContain('Inter');
    const html = await page.content();
    expect(html).not.toContain('Georgia,serif');
    expect(html).not.toContain('DM+Mono');
  });
});
