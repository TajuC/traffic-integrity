import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { apiConversions, googleAdsCsv, googleAdsExclusion } from '../src/conversion/export.ts';
import type { ExportRow } from '../src/conversion/repository.ts';
import { migrate, pendingMigrations } from '../src/db/migrate.ts';
import { openDatabase, type SqlClient } from '../src/db/sql.ts';
import { buildDataset } from '../src/net/intel-sources.ts';
import { datasetSchema } from '../src/net/network-intel.ts';

describe('migrations', () => {
  let db: SqlClient;
  before(async () => {
    db = await openDatabase({ url: 'pglite://memory', ssl: 'disable', poolMax: 1 });
  });
  after(async () => {
    await db.close();
  });

  test('apply once, report nothing pending and are idempotent', async () => {
    assert.deepEqual(await pendingMigrations(db), ['001_traffic_integrity.sql']);
    assert.deepEqual(await migrate(db), ['001_traffic_integrity.sql']);
    assert.deepEqual(await migrate(db), []);
    assert.deepEqual(await pendingMigrations(db), []);
    const tables = await db.query<{ name: string }>("SELECT tablename AS name FROM pg_tables WHERE tablename LIKE 'ti_%' ORDER BY 1");
    assert.deepEqual(
      tables.rows.map((row) => row.name),
      ['ti_conversion_attempts', 'ti_conversions', 'ti_leads', 'ti_paid_visits', 'ti_schema_migrations'],
    );
  });
});

describe('network intelligence refresh', () => {
  const fixtures: Record<string, string> = {
    'https://www.cloudflare.com/ips-v4': '173.245.48.0/20\n',
    'https://www.cloudflare.com/ips-v6': '2400:cb00::/32\n',
    'https://developers.google.com/static/crawling/ipranges/common-crawlers.json': JSON.stringify({ prefixes: [{ ipv4Prefix: '66.249.64.0/27' }, { ipv6Prefix: '2001:4860:4801:10::/64' }] }),
    'https://developers.google.com/static/crawling/ipranges/special-crawlers.json': JSON.stringify({ prefixes: [{ ipv4Prefix: '66.249.79.0/27' }] }),
    'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json': JSON.stringify({ prefixes: [{ ipv4Prefix: '74.125.0.0/26' }] }),
    'https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json': JSON.stringify({ prefixes: [{ ipv6Prefix: '2001:4860:c::/124' }] }),
    'https://www.bing.com/toolbox/bingbot.json': JSON.stringify({ prefixes: [{ ipv4Prefix: '157.55.39.0/24' }] }),
    'https://ip-ranges.amazonaws.com/ip-ranges.json': JSON.stringify({ prefixes: [{ ip_prefix: '3.4.12.4/32' }, { ip_prefix: 'bogus' }], ipv6_prefixes: [{ ipv6_prefix: '2600:1f00::/24' }] }),
    'https://www.gstatic.com/ipranges/cloud.json': JSON.stringify({ prefixes: [{ ipv4Prefix: '34.1.208.0/20' }] }),
    'https://digitalocean.com/geo/google.csv': '5.101.96.0/21,NL,NL-NH,Amsterdam,1098\n',
    'https://check.torproject.org/torbulkexitlist': '185.220.101.1\n171.25.193.25\n',
  };

  test('builds a valid dataset and reuses previous data for sources that fail', async () => {
    const previous = datasetSchema.parse({
      version: 1,
      generatedAt: '2026-10-01T00:00:00.000Z',
      hosting: [['129.146.0.0/16', 'oracle']],
      relays: [['172.224.226.0/27', 'apple-private-relay']],
    });
    const fetchText = (url: string): Promise<string> => {
      const body = fixtures[url];
      return body === undefined ? Promise.reject(new Error('HTTP 503')) : Promise.resolve(body);
    };
    const { dataset, reports } = await buildDataset(fetchText, previous, { includeOptional: false, now: new Date('2026-10-05T00:00:00Z') });
    assert.doesNotThrow(() => datasetSchema.parse(dataset));
    const status = Object.fromEntries(reports.map((report) => [report.id, report.status]));
    assert.equal(status.aws, 'fetched');
    assert.equal(status.oracle, 'reused');
    assert.equal(status['apple-private-relay'], 'reused');
    assert.deepEqual(dataset.hosting.filter(([, label]) => label === 'amazon').map(([cidr]) => cidr).sort(), ['2600:1f00::/24', '3.4.12.4/32']);
    assert.ok(dataset.hosting.some(([cidr, label]) => cidr === '129.146.0.0/16' && label === 'oracle'));
    assert.ok(dataset.crawlers.some(([cidr, label]) => cidr === '66.249.79.0/27' && label === 'google-special'));
    assert.deepEqual(dataset.tor, ['171.25.193.25/32', '185.220.101.1/32']);
    assert.deepEqual(dataset.cloudflare, ['173.245.48.0/20', '2400:cb00::/32']);
  });
});

describe('Google Ads export formatting', () => {
  const row = (overrides: Partial<ExportRow>): ExportRow => ({
    id: '6f9a3c1e-2b4d-4e8f-9a0b-1c2d3e4f5a6b',
    created_at: new Date('2026-07-01T09:30:00Z'),
    conversion_action: 'Qualified lead',
    value: '120.00',
    currency: 'ILS',
    hashed_email: 'a'.repeat(64),
    hashed_phone: null,
    gclid: 'Cj0KCQjwexample_BwE',
    gbraid: undefined,
    wbraid: undefined,
    gadSource: '1',
    gadCampaignId: '555',
    ...overrides,
  });

  test('writes conversion times in the configured time zone and skips rows without a GCLID', () => {
    const { csv, exported } = googleAdsCsv([row({}), row({ id: 'no-click', gclid: undefined, gbraid: '0AAAAAgbraid' }), row({ id: 'quoted', conversion_action: 'Lead, "phone"' })], 'Asia/Jerusalem');
    const lines = csv.trim().split('\r\n');
    assert.equal(lines[0], 'Parameters:TimeZone=Asia/Jerusalem');
    assert.equal(lines[2], 'Cj0KCQjwexample_BwE,Qualified lead,2026-07-01 12:30:00,120.00,ILS,6f9a3c1e-2b4d-4e8f-9a0b-1c2d3e4f5a6b');
    assert.equal(lines[3], 'Cj0KCQjwexample_BwE,"Lead, ""phone""",2026-07-01 12:30:00,120.00,ILS,quoted');
    assert.deepEqual(exported, ['6f9a3c1e-2b4d-4e8f-9a0b-1c2d3e4f5a6b', 'quoted']);
  });

  test('produces API-ready conversions with one click identifier and an explicit offset', () => {
    const [withGclid, braidOnly] = apiConversions([row({}), row({ gclid: undefined, gbraid: '0AAAAAgbraid', wbraid: '0BBBBwbraid' })], 'Asia/Jerusalem');
    assert.equal(withGclid?.conversionDateTime, '2026-07-01 12:30:00+03:00');
    assert.equal(withGclid?.gbraid, null);
    assert.equal(braidOnly?.gbraid, '0AAAAAgbraid');
    assert.equal(braidOnly?.wbraid, null);
    assert.equal(braidOnly?.conversionValue, 120);
  });

  test('formats IP exclusions in the Google Ads wildcard syntax when possible', () => {
    const candidate = (target: string) => ({ target, suspiciousVisits: 3, visitors: 2, campaigns: [], lastSeen: new Date() });
    assert.equal(googleAdsExclusion(candidate('203.0.113.0/24')), '203.0.113.*');
    assert.equal(googleAdsExclusion(candidate('203.0.113.9')), '203.0.113.9');
    assert.equal(googleAdsExclusion(candidate('2001:db8:1::/48')), '2001:db8:1::/48');
  });
});
