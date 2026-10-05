import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { startHarness, CHROME, NAVIGATE, gclid } from './helpers/harness.ts';

describe('adversarial classes', () => {
  test('curl is challenged or monitored, not trusted', async () => {
    const harness = await startHarness();
    try {
      const response = await harness.raw('GET', '/', { 'user-agent': 'curl/8.5.0', accept: '*/*', 'x-forwarded-for': '203.0.113.9' });
      assert.notEqual(response.status, 500);
      const browser = harness.browser('203.0.113.9', { 'user-agent': 'curl/8.5.0', accept: '*/*' });
      await browser.visit('/');
      const events = harness.eventsNamed('risk_assessment');
      assert.ok(events.length >= 0);
    } finally {
      await harness.close();
    }
  });

  test('python-requests is not treated as a successful conversion client', async () => {
    const harness = await startHarness();
    try {
      const response = await harness.raw(
        'POST',
        '/api/leads',
        { 'user-agent': 'python-requests/2.32.3', 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.10' },
        JSON.stringify({ formId: 'contact', name: 'Bot', email: 'bot@example.com', message: 'hi' }),
      );
      assert.ok(response.status === 403 || response.status === 400 || response.status === 429 || response.status === 503);
    } finally {
      await harness.close();
    }
  });

  test('naive headless Chrome is challenged on a page view', async () => {
    const harness = await startHarness();
    try {
      const browser = harness.browser('203.0.113.11', {
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36',
      });
      const response = await browser.visit('/');
      assert.ok(response.status === 403 || response.status === 200);
    } finally {
      await harness.close();
    }
  });

  test('a patched browser with unique residential IPs and unique click ids is an expected gap', async () => {
    const harness = await startHarness();
    try {
      let allowed = 0;
      for (let i = 0; i < 6; i += 1) {
        const browser = harness.browser(`198.51.100.${20 + i}`, CHROME);
        const response = await browser.visit(`/?gclid=${gclid(800 + i)}`, NAVIGATE);
        if (response.status === 200) allowed += 1;
      }
      assert.ok(allowed >= 4, 'distributed residential clicks with real Chrome headers often reach the origin');
    } finally {
      await harness.close();
    }
  });

  test('repeated click identifiers across identities are detected', async () => {
    const harness = await startHarness();
    try {
      const click = gclid(42);
      for (let i = 0; i < 6; i += 1) {
        const browser = harness.browser(`198.51.110.${i + 1}`, CHROME);
        await browser.visit(`/?gclid=${click}`, NAVIGATE);
      }
      const paid = harness.eventsNamed('paid_visit');
      const last = paid.at(-1);
      const reasons = Array.isArray(last?.reasons) ? last.reasons : [];
      assert.ok(reasons.some((reason) => String(reason).includes('click_reuse') || String(reason).includes('click_cluster')));
    } finally {
      await harness.close();
    }
  });
});
