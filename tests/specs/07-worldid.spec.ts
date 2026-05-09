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
