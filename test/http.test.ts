import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { CHROME, FailingStore, gclid, SAFARI_IPHONE, startHarness, type Browser, type Harness, type HttpResponse } from './helpers/harness.ts';

const HOUR = 3_600_000;
const GOOGLEBOT = { 'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', accept: 'text/html' };
const HEADLESS = { ...CHROME, 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36' };
const SPOOFED_SAFARI = {
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15',
  'sec-ch-ua': CHROME['sec-ch-ua'],
  'sec-ch-ua-platform': '"macOS"',
};

const isChallenge = (response: HttpResponse): boolean => response.status === 403 && response.text.includes('id="challenge"');

async function burst(browser: Browser, count: number): Promise<number[]> {
  const statuses: number[] = [];
  for (let i = 0; i < count; i += 1) statuses.push((await browser.visit('/')).status);
  return statuses;
}

async function withHarness(run: (harness: Harness) => Promise<void>, options: Parameters<typeof startHarness>[0] = {}): Promise<void> {
  const harness = await startHarness(options);
  try {
    await run(harness);
  } finally {
    await harness.close();
  }
}

describe('traffic protection over HTTP', () => {
  test('an ordinary visitor browses without friction and receives one durable identity', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.10');
      const first = await browser.visit('/');
      assert.equal(first.status, 200);
      assert.match(first.text, /Request a free quote/);
      assert.ok(browser.jar.has('vid') && browser.jar.has('sid'));
      const second = await browser.visit('/');
      assert.equal(second.status, 200);
      assert.equal(second.headers['set-cookie'], undefined);
    }));

  test('a returning paid visitor clicking ads on different days is not challenged', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.11', SAFARI_IPHONE);
      assert.equal((await browser.visit(`/?gclid=${gclid(1)}&gad_source=1&gad_campaignid=111`)).status, 200);
      harness.clock.advance(26 * HOUR);
      assert.equal((await browser.visit(`/?gclid=${gclid(2)}&gad_source=1&gad_campaignid=111`)).status, 200);
      harness.clock.advance(26 * HOUR);
      const third = await browser.visit(`/?gclid=${gclid(3)}&gad_source=1&gad_campaignid=111`);
      assert.equal(third.status, 200);
      const visits = harness.eventsNamed('paid_visit');
      assert.equal(visits.length, 3);
      assert.ok(visits.every((visit) => visit.decision === 'ALLOW'));
    }));

  test('many users behind one NAT are all allowed', () =>
    withHarness(async (harness) => {
      const office = Array.from({ length: 40 }, () => harness.browser('192.0.2.50'));
      for (const person of office) assert.equal((await person.visit('/')).status, 200);
      harness.clock.advance(2 * HOUR);
      for (const person of office) {
        assert.equal((await person.visit('/')).status, 200);
        assert.equal((await person.visit('/')).status, 200);
      }
      assert.equal((await harness.browser('192.0.2.50').visit('/')).status, 200);
    }));

  test('rapid bot requests are restricted and released after the restriction expires', () =>
    withHarness(async (harness) => {
      const bot = harness.browser('198.51.100.12');
      const statuses = await burst(bot, 330);
      assert.equal(statuses[0], 200);
      assert.equal(statuses.at(-1), 429);
      const limited = await bot.visit('/');
      assert.equal(limited.status, 429);
      assert.ok(Number(limited.headers['retry-after']) > 0);
      assert.equal(harness.eventsNamed('temporary_restriction').length, 1);
      assert.ok(harness.eventsNamed('risk_assessment').length < 10, 'a burst does not turn into a log flood');

      harness.clock.advance(11 * 60_000);
      assert.equal((await bot.visit('/')).status, 200);
    }));

  test('repeated paid arrivals from one visitor end in a challenge', () =>
    withHarness(async (harness) => {
      const clicker = harness.browser('198.51.100.13');
      const responses: HttpResponse[] = [];
      for (let i = 1; i <= 7; i += 1) responses.push(await clicker.visit(`/?gclid=${gclid(`v${i}`)}`));
      assert.deepEqual(responses.slice(0, 3).map((r) => r.status), [200, 200, 200]);
      assert.ok(isChallenge(responses.at(-1)!));
      const lastVisit = harness.eventsNamed('paid_visit').at(-1);
      assert.ok((lastVisit?.reasons as string[]).includes('paid.visitor_click_velocity_extreme'));
    }));

  test('a paid-click flood from one network challenges new identities but not an established visitor', () =>
    withHarness(async (harness) => {
      const regular = harness.browser('203.0.113.200');
      await regular.visit('/');
      harness.clock.advance(2 * HOUR);
      await regular.visit('/');

      const results: HttpResponse[] = [];
      for (let i = 1; i <= 50; i += 1) results.push(await harness.browser(`203.0.113.${i}`).visit(`/?gclid=${gclid(`n${i}`)}`));
      assert.equal(results[0]?.status, 200);
      assert.ok(isChallenge(results.at(-1)!));
      assert.ok(harness.eventsNamed('suspicious_network_activity').length >= 1);

      assert.equal((await regular.visit(`/?gclid=${gclid('regular')}`)).status, 200);
    }));

  test('cookie rotation with paid clicks from one address is detected', () =>
    withHarness(async (harness) => {
      const rotator = harness.browser('198.51.100.77');
      let last: HttpResponse | undefined;
      for (let i = 0; i < 50; i += 1) {
        rotator.forgetCookies();
        last = await rotator.visit(`/?gclid=${gclid(`r${i}`)}`);
      }
      assert.ok(last && isChallenge(last));
      const reasons = harness.eventsNamed('paid_visit').at(-1)?.reasons as string[];
      assert.ok(reasons.includes('network.identity_churn_extreme'));
    }));

  test('a fake user agent alone does not interrupt browsing', () =>
    withHarness(async (harness) => {
      const response = await harness.browser('198.51.100.14', SPOOFED_SAFARI).visit('/');
      assert.equal(response.status, 200);
    }));

  test('headless automation from a datacenter is challenged', () =>
    withHarness(async (harness) => {
      assert.ok(isChallenge(await harness.browser('3.5.10.10', HEADLESS).visit('/')));
    }));

  test('a suspicious visitor who passes Turnstile continues, and the clearance expires', () =>
    withHarness(async (harness) => {
      const visitor = harness.browser('3.5.10.20', SPOOFED_SAFARI);
      const challenged = await visitor.visit('/', { 'accept-language': '' });
      assert.ok(isChallenge(challenged));
      const nonce = /data-nonce="([^"]+)"/.exec(challenged.text)?.[1];
      assert.ok(nonce);

      const cleared = await visitor.postJson('/_ti/challenge', { token: 'turnstile-token-1', nonce });
      assert.equal(cleared.status, 204);
      assert.ok(visitor.jar.has('clr'));
      assert.equal(harness.turnstile.calls.at(-1)?.action, 'clearance');
      assert.equal((await visitor.visit('/', { 'accept-language': '' })).status, 200);

      const replay = await visitor.postJson('/_ti/challenge', { token: 'turnstile-token-2', nonce });
      assert.equal(replay.status, 403, 'a challenge nonce is single use');

      harness.clock.advance(31 * 60_000);
      assert.ok(isChallenge(await visitor.visit('/', { 'accept-language': '' })));
    }));

  test('severe abuse is restricted even after passing a challenge', () =>
    withHarness(async (harness) => {
      const visitor = harness.browser('3.5.10.30', SPOOFED_SAFARI);
      const challenged = await visitor.visit('/', { 'accept-language': '' });
      const nonce = /data-nonce="([^"]+)"/.exec(challenged.text)?.[1];
      assert.equal((await visitor.postJson('/_ti/challenge', { token: 'turnstile-token-3', nonce })).status, 204);
      const statuses = await burst(visitor, 330);
      assert.equal(statuses.at(-1), 429);
    }));

  test('a verified crawler is served without cookies or challenges', () =>
    withHarness(async (harness) => {
      const crawler = harness.browser('66.249.64.5', GOOGLEBOT);
      for (let i = 0; i < 400; i += 1) assert.equal((await crawler.request('GET', '/', {})).status, 200);
      assert.equal(crawler.jar.size, 0);
    }));

  test('a spoofed crawler user agent from a residential address is challenged', () =>
    withHarness(async (harness) => {
      assert.ok(isChallenge(await harness.browser('198.51.100.200', GOOGLEBOT).request('GET', '/', {})));
      assert.equal(harness.eventsNamed('crawler_impersonation').length, 1);
    }));

  test('a forged visitor cookie is replaced with a fresh identity', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.15');
      browser.jar.set('vid', 'AAAAAAAAAAAAAAAAAAAAAA.1.1.AAAAAAAAAAAAAAAAAAAAAA');
      const response = await browser.visit('/');
      assert.equal(response.status, 200);
      assert.notEqual(browser.jar.get('vid'), 'AAAAAAAAAAAAAAAAAAAAAA.1.1.AAAAAAAAAAAAAAAAAAAAAA');
    }));

  test('malformed attribution is ignored rather than recorded as a paid visit', () =>
    withHarness(async (harness) => {
      const response = await harness.browser('198.51.100.16').visit('/?gclid=%3Cscript%3E&gad_campaignid=abc&gclid=Cj0KCQjwother');
      assert.equal(response.status, 200);
      assert.equal(harness.eventsNamed('paid_visit').length, 0);
    }));

  test('the site keeps serving and protecting when the shared store is unavailable', () =>
    withHarness(
      async (harness) => {
        const visitor = harness.browser('198.51.100.17');
        assert.equal((await visitor.visit('/')).status, 200);
        const ready = await harness.raw('GET', '/readyz', {});
        assert.equal(ready.json().sharedStore, 'local');
        assert.ok(harness.eventsNamed('security_degraded').length >= 1);
        const statuses = await burst(harness.browser('198.51.100.18'), 330);
        assert.equal(statuses.at(-1), 429, 'the local fallback still enforces limits');
      },
      { store: new FailingStore() },
    ));

  test('one abusive identity on a shared address does not lock out its neighbours', () =>
    withHarness(async (harness) => {
      const neighbours = Array.from({ length: 40 }, () => harness.browser('192.0.2.80'));
      for (const person of neighbours) await person.visit('/');
      harness.clock.advance(2 * HOUR);
      for (const person of neighbours) await person.visit('/');

      const bot = harness.browser('192.0.2.80');
      assert.equal((await burst(bot, 330)).at(-1), 429);
      for (const person of neighbours) assert.equal((await person.visit('/')).status, 200);
    }));

  test('monitor mode records decisions without enforcing them', () =>
    withHarness(
      async (harness) => {
        const statuses = await burst(harness.browser('198.51.100.19'), 330);
        assert.ok(statuses.every((status) => status === 200));
        const restriction = harness.eventsNamed('temporary_restriction')[0];
        assert.equal(restriction?.enforced, false);
      },
      { env: { ENFORCEMENT_MODE: 'monitor' } },
    ));

  test('origin bypass is rejected when Cloudflare is enforced', () =>
    withHarness(
      async (harness) => {
        const direct = await harness.browser('198.51.100.20').visit('/');
        assert.equal(direct.status, 403);
        const edge = await harness.raw('GET', '/', {
          ...CHROME,
          accept: 'text/html',
          'sec-fetch-mode': 'navigate',
          'x-forwarded-for': '203.0.113.9, 172.70.1.1',
          'cf-connecting-ip': '203.0.113.9',
          'x-edge-auth': 'edge-secret-for-tests-0123456789',
        });
        assert.equal(edge.status, 200);
        assert.equal(harness.eventsNamed('origin_bypass').length, 1);
      },
      { env: { CLOUDFLARE_MODE: 'enforce', CLOUDFLARE_EDGE_SECRET: 'edge-secret-for-tests-0123456789' } },
    ));
});
