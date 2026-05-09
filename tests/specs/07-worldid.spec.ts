import { test, expect } from '@playwright/test';

/**
 * World ID identity + attestations beta.
 *
 * These tests do not actually hit Worldcoin or the Worker — they mock the
 * network responses and assert that the frontend pipeline renders the right
 * states for: not-set-up, connect-failure, connected, mint-attestation.
 */

test.describe('World ID — Settings UI', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/index.html');
    // Dismiss first-visit overlay
    await page.evaluate(() => window.figDismissLauncher());
    await page.click('button[onclick="openSettings()"]');
    await expect(page.locator('#settings-modal')).toHaveClass(/open/);
  });

  test('section is shipped (no longer "coming soon")', async ({ page }) => {
    await expect(page.locator('#sec-wid')).toBeVisible();
    await expect(page.locator('#sec-wid h4')).toContainText('World ID');
    await expect(page.locator('#sec-wid .coming-pill')).toHaveCount(0);
    await expect(page.locator('#sec-wid button:has-text("Sign in with World ID")')).toBeEnabled();
  });

  test('refuses to start without an App ID or Worker URL', async ({ page }) => {
    await page.click('#sec-wid button:has-text("Sign in with World ID")');
    await expect(page.locator('#wid-toast')).toContainText('World ID App ID');
  });

  test('accepts App ID directly without Worker', async ({ page }) => {
    // Fill in an App ID directly — should pass App ID validation
    await page.fill('#wid-app-id', 'app_staging_fake');
    await page.click('#sec-wid button:has-text("Sign in with World ID")');
    // Should NOT show the "App ID required" error — IDKit failing is expected in test env
    await expect(page.locator('#wid-toast')).not.toContainText('World ID App ID');
  });

  test('connected state renders the verified pill, nullifier, and chip', async ({ page }) => {
    await page.evaluate(() => {
      localStorage.setItem('fig_account', JSON.stringify({
        worker: { handle: 'gg', token: 'fake', createdAt: new Date().toISOString() },
        worldid: {
          nullifier_hash: '0x' + 'a'.repeat(64),
          verification_level: 'orb',
          verifiedAt: new Date().toISOString(),
        },
      }));
      localStorage.setItem('fig_sync', JSON.stringify({
        workerUrl: 'https://fig-sync.example.workers.dev',
      }));
    });
    await page.locator('#settings-modal .modal-close').click();
    await page.click('button[onclick="openSettings()"]');

    await expect(page.locator('#sec-wid.connected')).toBeVisible();
    await expect(page.locator('#wid-status')).toContainText('verified');
    await expect(page.locator('#wid-status')).toContainText('orb');
    await expect(page.locator('#wid-form')).toBeHidden();
    await expect(page.locator('#wid-connected')).toBeVisible();
    await expect(page.locator('#wid-nullifier-display')).toContainText('aaaaaaa');
    await expect(page.locator('#auth-chip')).toContainText('gg');
    await expect(page.locator('#auth-chip')).toContainText('✓');
  });
});

test.describe('World ID — attestations pipeline (mocked Worker)', () => {
  test.beforeEach(async ({ page }) => {
    // Mock /attestations + /attestations/:nullifier on the Worker URL
    await page.route('**/auth/worldid/verify', route =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          nullifier_hash: '0x' + 'b'.repeat(64),
          verification_level: 'orb',
        }),
      })
    );
    await page.route('**/attestations', route =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          attestation: {
            nullifier_hash: '0x' + 'b'.repeat(64),
            kind: 'demo.fig.beta',
            value: 1,
            issued_at: new Date().toISOString(),
            signature: 'deadbeef'.repeat(8),
            issuer: 'fig-worker-v1',
          },
          public_url: 'https://fig-sync.example.workers.dev/attestations/0x' + 'b'.repeat(64),
        }),
      })
    );
    await page.route('**/attestations/0x*', route =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          nullifier_hash: '0x' + 'b'.repeat(64),
          attestations: [
            {
              kind: 'demo.fig.beta',
              issued_at: new Date().toISOString(),
              signature: 'deadbeef'.repeat(8),
              issuer: 'fig-worker-v1',
            },
          ],
          signer: 'worker:hmac-sha256-v1',
        }),
      })
    );

    await page.goto('/index.html');
    // Dismiss first-visit overlay
    await page.evaluate(() => window.figDismissLauncher());
    await page.evaluate(() => {
      localStorage.setItem('fig_account', JSON.stringify({
        worker: { handle: 'gg', token: 'fake', createdAt: new Date().toISOString() },
        worldid: {
          nullifier_hash: '0x' + 'b'.repeat(64),
          verification_level: 'orb',
          verifiedAt: new Date().toISOString(),
        },
      }));
      localStorage.setItem('fig_sync', JSON.stringify({
        workerUrl: 'https://fig-sync.example.workers.dev',
      }));
    });
    await page.click('button[onclick="openSettings()"]');
  });

  test('mint sample attestation hits Worker and refreshes list', async ({ page }) => {
    await page.click('text=Mint a sample attestation');
    await expect(page.locator('#attest-toast')).toContainText('Minted');
    await expect(page.locator('#attest-list')).toContainText('demo.fig.beta');
  });

  test('refresh attestation list reads public endpoint', async ({ page }) => {
    await page.click('text=Refresh attestation list');
    await expect(page.locator('#attest-list')).toContainText('1 attestation');
    await expect(page.locator('#attest-list')).toContainText('demo.fig.beta');
  });
});
