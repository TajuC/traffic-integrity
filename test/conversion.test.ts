import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import type { SqlClient } from '../src/db/sql.ts';
import { BASE_ENV, CHROME, gclid, sharedDatabase, startHarness, type Browser, type Harness } from './helpers/harness.ts';

const SPOOFED_SAFARI = {
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15',
  'sec-ch-ua': CHROME['sec-ch-ua'],
  'sec-ch-ua-platform': '"macOS"',
  'accept-language': 'en-US',
};

interface FormSettings {
  readonly token: string;
  readonly honeypot: string;
  readonly challenge: string;
  readonly turnstile: { readonly siteKey: string; readonly action: string; readonly cdata: string } | null;
}

interface LeadResponse {
  readonly ok?: boolean;
  readonly leadId?: string;
  readonly conversion?: { readonly id: string | null; readonly fire: boolean };
  readonly error?: string;
  readonly fields?: string[];
}

let db: SqlClient;
before(async () => {
  db = await sharedDatabase();
});
after(async () => {
  await db.close();
});

async function withHarness(run: (harness: Harness) => Promise<void>, env: Readonly<Record<string, string>> = {}): Promise<void> {
  const harness = await startHarness({ db, env });
  try {
    await run(harness);
  } finally {
    await harness.close();
  }
}

async function formSettings(browser: Browser): Promise<FormSettings> {
  const response = await browser.fetchJson('/_ti/form?form=quote');
  assert.equal(response.status, 200);
  return response.json<FormSettings>();
}

function leadBody(settings: FormSettings, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const unique = randomUUID();
  return {
    formId: 'quote',
    name: 'Dana Levi',
    email: `dana.${unique.slice(0, 8)}@example.com`,
    phone: `+972 54 ${String(parseInt(unique.slice(0, 8), 16) % 10_000_000).padStart(7, '0')}`,
    message: `Hello, I would like a quote for a kitchen renovation. Reference ${unique}`,
    formToken: settings.token,
    idempotencyKey: randomUUID(),
    turnstileToken: `turnstile-${unique}`,
    [settings.honeypot]: '',
    ...overrides,
  };
}

async function humanSubmission(harness: Harness, browser: Browser, overrides: Record<string, unknown> = {}) {
  await browser.visit('/');
  const settings = await formSettings(browser);
  harness.clock.advance(25_000);
  const body = leadBody(settings, overrides);
  const response = await browser.postJson('/api/leads', body);
  return { response, body, settings };
}

async function conversionFor(leadId: string) {
  const result = await db.query<{ id: string; status: string; gclid: string | null; gad_campaign_id: string | null; hashed_email: string | null; decision_reason: string | null }>(
    'SELECT id, status, gclid, gad_campaign_id, hashed_email, decision_reason FROM ti_conversions WHERE lead_id = $1',
    [leadId],
  );
  return result.rows[0];
}

describe('conversion integrity', () => {
  test('a qualified conversion flows from a paid click to the Google Ads export', () =>
    withHarness(async (harness) => {
      const click = gclid('qualified');
      const browser = harness.browser('198.51.100.101');
      assert.equal((await browser.visit(`/?gclid=${click}&gad_source=1&gad_campaignid=2233`)).status, 200);

      const nonce = (await browser.fetchJson('/_ti/nonce')).json<{ nonce: string }>().nonce;
      const beacon = await browser.postJson('/_ti/beacon', {
        nonce,
        phase: 'load',
        automation: { webdriver: false, headless: false, languages: 2, phantom: false, selenium: false, playwright: false, viewport: [1280, 800] },
        interaction: { pointer: 12, keys: 30, scroll: 3, touch: 0, firstMs: 900, dwellMs: 20_000 },
      });
      assert.equal(beacon.status, 204);

      const settings = await formSettings(browser);
      assert.equal(settings.challenge, 'always');
      assert.equal(settings.turnstile?.action, 'lead_quote');
      harness.clock.advance(40_000);
      const body = leadBody(settings);
      const response = await browser.postJson('/api/leads', body);
      assert.equal(response.status, 200);
      const result = response.json<LeadResponse>();
      assert.equal(result.ok, true);
      assert.equal(result.conversion?.fire, true);
      assert.equal(harness.leads.length, 1);
      assert.equal(harness.turnstile.calls.at(-1)?.cdata, settings.turnstile?.cdata);

      const conversion = await conversionFor(result.leadId!);
      assert.equal(conversion?.status, 'pending');
      assert.equal(conversion?.gclid, click);
      assert.equal(conversion?.gad_campaign_id, '2233');
      assert.equal(conversion?.hashed_email, createHash('sha256').update(String(body.email)).digest('hex'));

      harness.clock.advance(61 * 60_000);
      const report = await harness.guard.maintenance.runOnce();
      assert.ok(report.qualified >= 1);
      assert.equal((await conversionFor(result.leadId!))?.status, 'qualified');

      const auth = `Basic ${Buffer.from(`${BASE_ENV.EXPORT_USERNAME}:${BASE_ENV.EXPORT_PASSWORD}`).toString('base64')}`;
      assert.equal((await harness.raw('GET', '/_ti/admin/conversions.csv', { authorization: 'Basic d3Jvbmc6d3Jvbmc=' })).status, 401);
      const csv = await harness.raw('GET', '/_ti/admin/conversions.csv', { authorization: auth });
      assert.equal(csv.status, 200);
      const lines = csv.text.trim().split('\r\n');
      assert.equal(lines[0], 'Parameters:TimeZone=UTC');
      assert.equal(lines[1], 'Google Click ID,Conversion Name,Conversion Time,Conversion Value,Conversion Currency,Order ID');
      assert.ok(lines.some((line) => line === `${click},Qualified lead,2026-10-05 12:00:40,,USD,${conversion?.id}`), csv.text);

      const json = await harness.raw('GET', '/_ti/admin/conversions.json', { authorization: `Bearer ${BASE_ENV.ADMIN_TOKEN}` });
      const exported = json.json<{ conversions: Array<{ orderId: string; gclid: string; conversionDateTime: string; hashedEmail: string }> }>();
      const row = exported.conversions.find((entry) => entry.orderId === conversion?.id);
      assert.equal(row?.conversionDateTime, '2026-10-05 12:00:40+00:00');
      assert.equal(row?.hashedEmail, conversion?.hashed_email);

      await harness.runtime.paidVisits.flush();
      const visits = await db.query<{ count: string }>('SELECT count(*) AS count FROM ti_paid_visits WHERE gclid = $1', [click]);
      assert.equal(Number(visits.rows[0]?.count), 1);
    }));

  test('idempotent retries and duplicate submissions never create a second conversion', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.102');
      const { response, body } = await humanSubmission(harness, browser);
      const first = response.json<LeadResponse>();
      assert.equal(response.status, 200);

      const retry = await browser.postJson('/api/leads', body);
      assert.equal(retry.status, 200);
      assert.deepEqual(retry.json(), first, 'the same idempotency key replays the stored response');

      const settings = await formSettings(browser);
      harness.clock.advance(20_000);
      const duplicate = await browser.postJson('/api/leads', leadBody(settings, { email: body.email }));
      assert.equal(duplicate.status, 200);
      assert.deepEqual(duplicate.json(), { ok: true, leadId: first.leadId, conversion: { id: first.conversion?.id, fire: false } });

      const leads = await db.query<{ count: string }>('SELECT count(*) AS count FROM ti_leads WHERE email = $1', [body.email]);
      assert.equal(Number(leads.rows[0]?.count), 1);
      assert.equal(harness.eventsNamed('conversion_duplicate').length, 1);
    }));

  test('a replayed form token is rejected even with a new idempotency key and contact', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.103');
      const { response, settings } = await humanSubmission(harness, browser);
      assert.equal(response.status, 200);
      const replay = await browser.postJson('/api/leads', leadBody(settings));
      assert.ok(replay.status === 429 || replay.status === 403, `status ${replay.status}`);
      const rejected = await db.query<{ reasons: string[] }>(
        "SELECT reasons FROM ti_conversion_attempts WHERE visitor_id = (SELECT visitor_id FROM ti_leads WHERE id = $1) AND status = 'rejected'",
        [response.json<LeadResponse>().leadId],
      );
      assert.ok(rejected.rows[0]?.reasons.includes('behavior.form_token_replayed'));
    }));

  test('a direct API attack without the frontend creates no lead', () =>
    withHarness(async (harness) => {
      const before = await db.query<{ count: string }>('SELECT count(*) AS count FROM ti_leads');
      const attemptsBefore = await db.query<{ count: string }>('SELECT count(*) AS count FROM ti_conversion_attempts');
      const body = JSON.stringify({
        formId: 'quote',
        name: 'Bot',
        email: `bot.${randomUUID().slice(0, 6)}@example.com`,
        message: 'Automated submission straight to the endpoint',
        idempotencyKey: randomUUID(),
      });
      const direct = await harness.raw('POST', '/api/leads', { 'content-type': 'application/json', 'user-agent': 'python-requests/2.32.3', 'x-forwarded-for': '203.0.113.150' }, body);
      assert.equal(direct.status, 403);
      assert.deepEqual(direct.json(), { error: 'request_rejected' });

      const crossSite = await harness.raw('POST', '/api/leads', { 'content-type': 'application/json', origin: 'https://evil.example', 'x-forwarded-for': '203.0.113.151', ...CHROME }, body);
      assert.equal(crossSite.status, 403);

      const after = await db.query<{ count: string }>('SELECT count(*) AS count FROM ti_leads');
      assert.equal(after.rows[0]?.count, before.rows[0]?.count);
      const attemptsAfter = await db.query<{ count: string }>('SELECT count(*) AS count FROM ti_conversion_attempts');
      assert.equal(attemptsAfter.rows[0]?.count, attemptsBefore.rows[0]?.count, 'obvious attacks are refused before any database write');
    }));

  test('during a Turnstile outage low-risk leads are kept for review and risky ones must retry', () =>
    withHarness(async (harness) => {
      harness.turnstile.mode = 'unavailable';
      const { response } = await humanSubmission(harness, harness.browser('198.51.100.104'));
      assert.equal(response.status, 200);
      const accepted = response.json<LeadResponse>();
      assert.equal(accepted.conversion?.fire, false);
      const conversion = await conversionFor(accepted.leadId!);
      assert.equal(conversion?.status, 'review');
      assert.equal(conversion?.decision_reason, 'verification_unavailable');

      const risky = await humanSubmission(harness, harness.browser('3.6.0.10', SPOOFED_SAFARI));
      assert.equal(risky.response.status, 503);
      assert.ok(Number(risky.response.headers['retry-after']) > 0);
    }));

  test('a challenge is requested when the Turnstile token is missing, and the form can retry', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.105');
      await browser.visit('/');
      const settings = await formSettings(browser);
      harness.clock.advance(15_000);
      const body = leadBody(settings, { turnstileToken: undefined });
      const challenged = await browser.postJson('/api/leads', body);
      assert.equal(challenged.status, 403);
      const challenge = challenged.json<{ error: string; turnstile: { action: string; cdata: string } }>();
      assert.equal(challenge.error, 'verification_required');
      assert.equal(challenge.turnstile.cdata, settings.turnstile?.cdata);

      const retried = await browser.postJson('/api/leads', { ...body, turnstileToken: 'turnstile-after-challenge' });
      assert.equal(retried.status, 200);
      assert.equal(retried.json<LeadResponse>().ok, true);
    }));

  test('a filled honeypot keeps the lead off the trusted conversion track', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.106');
      await browser.visit('/');
      const settings = await formSettings(browser);
      harness.clock.advance(15_000);
      const response = await browser.postJson('/api/leads', leadBody(settings, { [settings.honeypot]: 'https://spam.example' }));
      assert.equal(response.status, 200);
      const result = response.json<LeadResponse>();
      assert.equal(result.conversion?.fire, false);
      assert.equal((await conversionFor(result.leadId!))?.status, 'review');
    }));

  test('an expired form token is accepted with a recorded signal', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.107');
      await browser.visit('/');
      const settings = await formSettings(browser);
      harness.clock.advance(3 * 3_600_000);
      const response = await browser.postJson('/api/leads', leadBody(settings));
      assert.equal(response.status, 200);
      const attempt = await db.query<{ reasons: string[] }>('SELECT reasons FROM ti_conversion_attempts WHERE lead_id = $1', [response.json<LeadResponse>().leadId]);
      assert.ok(attempt.rows[0]?.reasons.includes('behavior.form_token_expired'));
    }));

  test('invalid input is reported field by field without storing anything', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.108');
      await browser.visit('/');
      const settings = await formSettings(browser);
      const response = await browser.postJson('/api/leads', leadBody(settings, { name: '', email: 'not-an-email', phone: undefined }));
      assert.equal(response.status, 400);
      assert.deepEqual(response.json<LeadResponse>().fields?.sort(), ['email', 'name']);
      const unsupported = await browser.request('POST', '/api/leads', { 'content-type': 'text/plain', origin: 'http://localhost' }, 'hello');
      assert.equal(unsupported.status, 415);
    }));

  test('a sitewide conversion burst moves new and recent conversions to review', () =>
    withHarness(
      async (harness) => {
        const results: LeadResponse[] = [];
        for (let i = 0; i < 3; i += 1) results.push((await humanSubmission(harness, harness.browser(`198.51.100.${120 + i}`))).response.json<LeadResponse>());
        assert.equal(results[0]?.conversion?.fire, true);
        assert.equal(results[2]?.conversion?.fire, false);
        assert.equal((await conversionFor(results[0].leadId!))?.status, 'review');
        assert.equal((await conversionFor(results[2].leadId!))?.decision_reason, 'conversion_burst');
        assert.equal(harness.eventsNamed('conversion_burst').length, 1);
      },
      { CONVERSION_BURST_PER_HOUR: '2' },
    ));

  test('an operator can disqualify an exported conversion and is told to adjust it', () =>
    withHarness(async (harness) => {
      const browser = harness.browser('198.51.100.109');
      await browser.visit(`/?gclid=${gclid('disqualify')}`);
      const { response } = await humanSubmission(harness, browser);
      const conversionId = response.json<LeadResponse>().conversion?.id;
      const admin = { authorization: `Bearer ${BASE_ENV.ADMIN_TOKEN}`, 'content-type': 'application/json' };
      assert.equal((await harness.raw('POST', `/_ti/admin/conversions/${conversionId}/qualify`, { 'content-type': 'application/json' }, '{}')).status, 401);
      assert.equal((await harness.raw('POST', `/_ti/admin/conversions/${conversionId}/qualify`, admin, '{}')).status, 200);

      const auth = `Basic ${Buffer.from(`${BASE_ENV.EXPORT_USERNAME}:${BASE_ENV.EXPORT_PASSWORD}`).toString('base64')}`;
      assert.match((await harness.raw('GET', '/_ti/admin/conversions.csv', { authorization: auth })).text, new RegExp(String(conversionId)));
      const decision = await harness.raw('POST', `/_ti/admin/conversions/${conversionId}/disqualify`, admin, JSON.stringify({ reason: 'spam call' }));
      assert.deepEqual(decision.json(), { id: conversionId, status: 'disqualified', requiresAdjustment: true });
    }));

  test('crawlers and preview bots cannot submit leads', () =>
    withHarness(async (harness) => {
      const crawler = harness.browser('66.249.64.9', { 'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' });
      const response = await crawler.postJson('/api/leads', { formId: 'quote', name: 'x', email: 'x@example.com', idempotencyKey: randomUUID() });
      assert.equal(response.status, 403);
    }));

  test('the summary and exclusion reports answer the operational questions', () =>
    withHarness(async (harness) => {
      for (let i = 1; i <= 8; i += 1) {
        const bot = harness.browser('198.51.100.250', { ...CHROME, 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/141.0.0.0 Safari/537.36' });
        await bot.visit(`/?gclid=${gclid(`x${i}`)}&gad_campaignid=777`);
      }
      await harness.runtime.paidVisits.flush();
      const admin = { authorization: `Bearer ${BASE_ENV.ADMIN_TOKEN}` };
      const summary = (await harness.raw('GET', '/_ti/admin/summary.json?hours=24', admin)).json<{ campaigns: Array<{ campaign: string; suspicious: number }> }>();
      assert.ok(summary.campaigns.some((row) => row.campaign === '777' && row.suspicious >= 8));
      const exclusions = (await harness.raw('GET', '/_ti/admin/exclusions.json?minScore=30', admin)).json<{ candidates: Array<{ target: string; googleAds: string }> }>();
      assert.ok(exclusions.candidates.some((row) => row.target === '198.51.100.250' && row.googleAds === '198.51.100.250'));
    }));
});

describe('conversion endpoint without a database', () => {
  test('fails closed with a retry hint instead of dropping leads', async () => {
    const harness = await startHarness({ db: null });
    try {
      const browser = harness.browser('198.51.100.110');
      await browser.visit('/');
      const settings = await formSettings(browser);
      const response = await browser.postJson('/api/leads', leadBody(settings));
      assert.equal(response.status, 503);
      assert.ok(Number(response.headers['retry-after']) > 0);
    } finally {
      await harness.close();
    }
  });
});
