import { test, expect } from '@playwright/test';

test.describe('Settings modal', () => {
  test.beforeEach(async ({ page }) => {
    // Fresh context starts with empty storage; no need for an init-script clearer
    // (which re-fires on every navigation and would wipe state set mid-test).
    await page.goto('/index.html');
    // Dismiss first-visit overlay
    await page.evaluate(() => window.figDismissLauncher());
    await page.click('button[onclick="openSettings()"]');
    await expect(page.locator('#settings-modal')).toHaveClass(/open/);
  });

  test('renders three tabs and three sections on Identity', async ({ page }) => {
    await expect(page.locator('.settings-tab')).toHaveCount(3);
    await expect(page.locator('#sec-worker')).toBeVisible();
    await expect(page.locator('#sec-bsky')).toBeVisible();
    await expect(page.locator('#sec-wid')).toBeVisible();
  });

  test('switches to LLM tab and lists 4 providers', async ({ page }) => {
    await page.click('.settings-tab[data-tab="llm"]');
    await expect(page.locator('#pane-llm')).toHaveClass(/active/);
    await expect(page.locator('.provider-pick')).toHaveCount(4);
    await expect(page.locator('.provider-pick:has-text("Claude")')).toBeVisible();
    await expect(page.locator('.provider-pick:has-text("OpenRouter")')).toBeVisible();
    await expect(page.locator('.provider-pick:has-text("GPT")')).toBeVisible();
    await expect(page.locator('.provider-pick:has-text("Ollama")')).toBeVisible();
  });

  test('Ollama hides the API key field', async ({ page }) => {
    await page.click('.settings-tab[data-tab="llm"]');
    await page.click('.provider-pick:has-text("Ollama")');
    await expect(page.locator('#llm-key')).toHaveCount(0);
    await expect(page.locator('#llm-base')).toHaveValue('http://localhost:11434');
  });

  test('Anthropic shows the API key field with the right help text', async ({ page }) => {
    await page.click('.settings-tab[data-tab="llm"]');
    await page.click('.provider-pick:has-text("Claude")');
    await expect(page.locator('#llm-key')).toBeVisible();
    // The key-help link to console.anthropic.com is in the href attribute, not
    // visible text — assert against the anchor's href, not innerText.
    await expect(
      page.locator('#llm-fields a[href*="console.anthropic.com"]')
    ).toBeVisible();
  });

  test('saving a key mirrors to legacy fig_provider / fig_key', async ({ page }) => {
    await page.click('.settings-tab[data-tab="llm"]');
    await page.click('.provider-pick:has-text("Claude")');
    await page.fill('#llm-key', 'sk-ant-test-fake');
    // Specific selector: the primary Save button inside the LLM pane.
    // text=Save can pick up other "Save"-substring matches in real Chromium.
    await page.locator('#pane-llm button.s-btn.primary:has-text("Save")').click();
    await expect(page.locator('#llm-toast')).toContainText('Saved');

    const legacy = await page.evaluate(() => ({
      provider: JSON.parse(localStorage.getItem('fig_provider') || 'null'),
      key: JSON.parse(localStorage.getItem('fig_key') || 'null'),
    }));
    expect(legacy.provider).toBe('anthropic');
    expect(legacy.key).toBe('sk-ant-test-fake');
  });

  test('switches to Cloud sync tab', async ({ page }) => {
    await page.click('.settings-tab[data-tab="sync"]');
    await expect(page.locator('#pane-sync')).toHaveClass(/active/);
    await expect(page.locator('#sync-url')).toBeVisible();
    await expect(page.locator('#sync-auto')).toBeVisible();
  });

  test('Bluesky form requires both fields', async ({ page }) => {
    await page.click('text=Connect Bluesky');
    await expect(page.locator('#bsky-toast')).toContainText('Need both');
  });

  test('worker handle is rejected with bad characters', async ({ page }) => {
    await page.fill('#worker-handle', 'has spaces!');
    await page.click('text=Create / sign in');
    await expect(page.locator('#worker-toast')).toContainText('Letters, numbers');
  });

  test('worker connect needs a Worker URL set on the Sync tab', async ({ page }) => {
    await page.fill('#worker-handle', 'gg');
    await page.click('text=Create / sign in');
    await expect(page.locator('#worker-toast')).toContainText('Worker URL');
  });

  test('connected state shows the auth chip', async ({ page }) => {
    // Simulate a connected worker without hitting the network
    await page.evaluate(() => {
      localStorage.setItem('fig_account', JSON.stringify({
        worker: { handle: 'testuser', token: 'fake-token', createdAt: new Date().toISOString() },
      }));
    });
    await page.locator('#settings-modal .modal-close').click();
    await page.click('button[onclick="openSettings()"]');
    await expect(page.locator('#auth-chip')).toBeVisible();
    await expect(page.locator('#auth-chip')).toContainText('testuser');
    await expect(page.locator('#sec-worker.connected')).toBeVisible();
  });
});
