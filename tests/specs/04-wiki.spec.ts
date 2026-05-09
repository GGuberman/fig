import { test, expect } from '@playwright/test';

test.describe('Wiki input', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.clear());
    await page.goto('/index.html');
    // Dismiss first-visit overlay
    await page.evaluate(() => window.figDismissLauncher());
  });

  test('saves an entry to the inbox', async ({ page }) => {
    await page.fill('#wiki-text', 'Slept 8 hours, ran 5k, ate well');
    await page.click('text=Add to wiki');
    await expect(page.locator('#wiki-toast')).toContainText('Saved');

    const inbox = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('fig_wiki_inbox') || '[]')
    );
    expect(inbox.length).toBe(1);
    expect(inbox[0].text).toBe('Slept 8 hours, ran 5k, ate well');
    expect(typeof inbox[0].ts).toBe('number');
  });

  test('rejects empty input', async ({ page }) => {
    await page.click('text=Add to wiki');
    await expect(page.locator('#wiki-toast')).toContainText('Type something');
    const inbox = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('fig_wiki_inbox') || '[]')
    );
    expect(inbox.length).toBe(0);
  });

  test('appends multiple entries', async ({ page }) => {
    for (const t of ['ran 5k', 'cooked dinner', 'paid rent']) {
      await page.fill('#wiki-text', t);
      await page.click('text=Add to wiki');
      await page.waitForTimeout(50);
    }
    const inbox = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('fig_wiki_inbox') || '[]')
    );
    expect(inbox.map((e: any) => e.text)).toEqual(['ran 5k', 'cooked dinner', 'paid rent']);
  });

  test('clears the textarea after submit', async ({ page }) => {
    await page.fill('#wiki-text', 'something');
    await page.click('text=Add to wiki');
    await expect(page.locator('#wiki-text')).toHaveValue('');
  });
});
