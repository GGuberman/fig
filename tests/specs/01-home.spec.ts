import { test, expect } from '@playwright/test';

test.describe('Home page', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.clear();
      try { indexedDB.deleteDatabase('fig_v1'); } catch {}
    });
  });

  test('loads with all expected sections', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));

    await page.goto('/index.html');

    await expect(page.locator('.wordmark')).toHaveText('Fig');
    await expect(page.locator('.wordmark-tag')).toHaveText('Your own personal wiki');
    await expect(page.locator('.wiki-card')).toBeVisible();
    await expect(page.locator('.tracker-card')).toHaveCount(3);
    await expect(page.locator('.earn-section')).toBeVisible();
    await expect(page.locator('.dash-footer')).toBeVisible();

    // No JS exceptions during init
    await page.waitForTimeout(500);
    expect(errors, `pageerrors: ${errors.join('; ')}`).toEqual([]);
  });

  test('three trackers in correct order', async ({ page }) => {
    await page.goto('/index.html');
    const cards = page.locator('.tracker-card');
    await expect(cards.nth(0)).toContainText('Health');
    await expect(cards.nth(1)).toContainText('Finance');
    await expect(cards.nth(2)).toContainText('Create your tracker');
  });

  test('does not include the old Brain card', async ({ page }) => {
    await page.goto('/index.html');
    const text = await page.locator('main').textContent();
    expect(text).not.toContain('Brain');
  });

  test('uses Inter + Fraunces, not Playfair / DM Mono', async ({ page }) => {
    await page.goto('/index.html');
    const head = await page.locator('head').innerHTML();
    expect(head).toContain('Fraunces');
    expect(head).toContain('Inter');
    expect(head).not.toContain('Playfair');
    expect(head).not.toContain('DM+Mono');
  });

  test('on fresh state, both trackers show "not set up"', async ({ page }) => {
    await page.goto('/index.html');
    await expect(page.locator('#health-badge')).toContainText('not set up');
    await expect(page.locator('#finance-badge')).toContainText('not set up');
  });

  test('wiki summary shows placeholder on fresh state', async ({ page }) => {
    await page.goto('/index.html');
    await expect(page.locator('.wiki-summary .placeholder')).toBeVisible();
    await expect(page.locator('#wiki-streak')).toHaveText('0');
    await expect(page.locator('#wiki-entries')).toHaveText('0');
  });
});
