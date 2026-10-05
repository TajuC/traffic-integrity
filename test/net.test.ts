import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { ClientAddressResolver } from '../src/net/client-address.ts';
import { CrawlerVerifier, type DnsResolver } from '../src/net/crawler.ts';
import { formatIp, formatPrefix, networkBucket, parseCidr, parseIp } from '../src/net/ip.ts';
import { NetworkIntel } from '../src/net/network-intel.ts';
import { IpRangeTable } from '../src/net/range-table.ts';
import { parseUserAgent } from '../src/request/user-agent.ts';
import { dataset, START } from './helpers/harness.ts';

describe('ip parsing', () => {
  test('normalizes IPv4, IPv6, mapped addresses, ports and zones', () => {
    assert.equal(formatIp(parseIp('203.0.113.7')!), '203.0.113.7');
    assert.equal(formatIp(parseIp('::ffff:203.0.113.7')!), '203.0.113.7');
    assert.equal(formatIp(parseIp('203.0.113.7:4431')!), '203.0.113.7');
    assert.equal(formatIp(parseIp('[2001:db8::1]:443')!), '2001:db8::1');
    assert.equal(formatIp(parseIp('fe80::1%eth0')!), 'fe80::1');
    assert.equal(formatIp(parseIp('2001:0DB8:0000:0000:0000:ff00:0042:8329')!), '2001:db8::ff00:42:8329');
    assert.equal(parseIp('999.1.1.1'), null);
    assert.equal(parseIp('not-an-ip'), null);
    assert.equal(parseIp(''), null);
  });

  test('computes network buckets used for NAT-aware counting', () => {
    assert.equal(networkBucket(parseIp('198.51.100.77')!), '198.51.100.0/24');
    assert.equal(networkBucket(parseIp('2001:db8:abcd:12:1::5')!), '2001:db8:abcd::/48');
    assert.equal(formatPrefix(parseIp('2001:db8:abcd:12:1::5')!, 64), '2001:db8:abcd:12::/64');
  });

  test('parses CIDRs and rejects invalid prefixes', () => {
    assert.deepEqual(parseCidr('10.1.2.3/8'), { version: 4, start: 167772160, end: 184549375, bits: 8 });
    assert.equal(parseCidr('10.0.0.0/33'), null);
    assert.equal(parseCidr('10.0.0.0/x'), null);
  });
});

describe('ip range table', () => {
  test('returns the most specific label for nested ranges', () => {
    const table = new IpRangeTable([
      { cidr: '10.0.0.0/8', label: 'outer' },
      { cidr: '10.1.0.0/16', label: 'inner' },
      { cidr: '10.1.2.0/24', label: 'innermost' },
      { cidr: '2001:db8::/32', label: 'v6' },
      { cidr: 'garbage', label: 'ignored' },
    ]);
    assert.equal(table.lookup(parseIp('10.9.9.9')), 'outer');
    assert.equal(table.lookup(parseIp('10.1.9.9')), 'inner');
    assert.equal(table.lookup(parseIp('10.1.2.200')), 'innermost');
    assert.equal(table.lookup(parseIp('10.2.0.1')), 'outer');
    assert.equal(table.lookup(parseIp('11.0.0.1')), undefined);
    assert.equal(table.lookup(parseIp('2001:db8:1::1')), 'v6');
    assert.equal(table.rejected, 1);
  });

  test('compacts adjacent ranges into a minimal CIDR cover without changing lookups', () => {
    const table = new IpRangeTable([
      { cidr: '10.0.0.0/25', label: 'a' },
      { cidr: '10.0.0.128/25', label: 'a' },
      { cidr: '10.0.1.1/32', label: 'a' },
      { cidr: '10.0.1.2/31', label: 'a' },
      { cidr: '10.0.2.0/24', label: 'b' },
      { cidr: '2001:db8::/33', label: 'a' },
      { cidr: '2001:db8:8000::/33', label: 'a' },
    ]);
    assert.deepEqual(
      table.minimalEntries().map((entry) => `${entry.cidr}=${entry.label}`),
      ['10.0.0.0/24=a', '10.0.1.1/32=a', '10.0.1.2/31=a', '10.0.2.0/24=b', '2001:db8::/32=a'],
    );
  });
});

describe('client address resolution', () => {
  const edgeSecret = 'edge-secret-value-0123456789';

  test('ignores X-Forwarded-For from an untrusted peer', () => {
    const resolver = new ClientAddressResolver({ trusted: ['loopback'], edgeMode: 'off', edgeSecrets: [] });
    const address = resolver.resolve('198.51.100.20', { 'x-forwarded-for': '1.1.1.1' });
    assert.equal(address.text, '198.51.100.20');
    assert.equal(address.via, 'direct');
  });

  test('walks the forwarded chain from the right through trusted proxies only', () => {
    const resolver = new ClientAddressResolver({ trusted: ['loopback', '10.0.0.0/8'], edgeMode: 'off', edgeSecrets: [] });
    const address = resolver.resolve('127.0.0.1', { 'x-forwarded-for': '6.6.6.6, 203.0.113.9, 10.0.0.4' });
    assert.equal(address.text, '203.0.113.9');
  });

  test('trusts CF-Connecting-IP only when the connecting hop is a Cloudflare address with the edge secret', () => {
    const resolver = new ClientAddressResolver({ trusted: ['loopback'], edgeMode: 'enforce', edgeSecrets: [edgeSecret] });
    const viaCloudflare = resolver.resolve('127.0.0.1', {
      'x-forwarded-for': '203.0.113.50, 172.70.1.1',
      'cf-connecting-ip': '203.0.113.50',
      'x-edge-auth': edgeSecret,
      'x-edge-asn': '64500',
      'cf-ipcountry': 'il',
      'x-edge-bot-score': '12',
    });
    assert.equal(viaCloudflare.text, '203.0.113.50');
    assert.equal(viaCloudflare.edgeVerified, true);
    assert.deepEqual(viaCloudflare.edge, { asn: 64500, country: 'IL', botScore: 12 });

    const wrongSecret = resolver.resolve('127.0.0.1', { 'x-forwarded-for': '172.70.1.1', 'cf-connecting-ip': '203.0.113.50', 'x-edge-auth': 'guess' });
    assert.equal(wrongSecret.edgeVerified, false);
    assert.deepEqual(wrongSecret.edge, {});

    const spoofed = resolver.resolve('198.51.100.1', { 'cf-connecting-ip': '8.8.8.8', 'x-edge-auth': edgeSecret, 'x-edge-bot-score': '99' });
    assert.equal(spoofed.text, '198.51.100.1');
    assert.equal(spoofed.viaEdge, false, 'a direct origin hit is not edge traffic');
    assert.equal(spoofed.edgeVerified, false);
    assert.deepEqual(spoofed.edge, {});
  });

  test('accepts the previous edge secret during a rotation', () => {
    const resolver = new ClientAddressResolver({ trusted: [], edgeMode: 'enforce', edgeSecrets: ['new-edge-secret-0123456789abcdef', 'old-edge-secret-0123456789abcdef'] });
    for (const secret of ['new-edge-secret-0123456789abcdef', 'old-edge-secret-0123456789abcdef']) {
      assert.equal(resolver.resolve('172.70.9.9', { 'cf-connecting-ip': '203.0.113.5', 'x-edge-auth': secret }).edgeVerified, true);
    }
    assert.equal(resolver.resolve('172.70.9.9', { 'cf-connecting-ip': '203.0.113.5', 'x-edge-auth': 'retired-secret-0123456789abcdef' }).viaEdge, false);
  });

  test('without an edge secret, Cloudflare traffic is recognised but its signal headers are never trusted', () => {
    const resolver = new ClientAddressResolver({ trusted: [], edgeMode: 'monitor', edgeSecrets: [] });
    const foreignZone = resolver.resolve('172.70.9.9', { 'cf-connecting-ip': '203.0.113.77', 'x-edge-verified-bot': 'true', 'x-edge-bot-score': '99', 'cf-ray': '8f2a1b3c4d5e6f70-TLV' });
    assert.equal(foreignZone.text, '203.0.113.77');
    assert.equal(foreignZone.viaEdge, true);
    assert.equal(foreignZone.edgeVerified, false);
    assert.deepEqual(foreignZone.edge, {});
    assert.equal(foreignZone.ray, '8f2a1b3c4d5e6f70-TLV');
  });
});

describe('crawler verification', () => {
  const googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

  test('verifies Googlebot by published ranges and flags impersonation outside them', () => {
    const verifier = new CrawlerVerifier({ intel: new NetworkIntel({ dataset: dataset() }), reverseDns: false, now: () => START });
    const claim = parseUserAgent(googlebot).crawler;
    assert.deepEqual(verifier.verify(claim, parseIp('66.249.64.5'), '66.249.64.5', {}), { status: 'verified', operator: 'google', via: 'ranges' });
    assert.deepEqual(verifier.verify(claim, parseIp('198.51.100.9'), '198.51.100.9', {}), { status: 'impersonation', operator: 'google', via: 'ranges' });
  });

  test('stays neutral when range data is stale and confirms through forward-confirmed reverse DNS', async () => {
    const resolver: DnsResolver = {
      reverse: (ip) =>
        Promise.resolve(
          ip === '192.0.2.10' ? ['crawl-192-0-2-10.googlebot.com.'] : ip === '192.0.2.12' ? ['12.2.0.192.bc.googleusercontent.com'] : ['host.example.net'],
        ),
      lookup: (host) =>
        Promise.resolve(
          host === 'crawl-192-0-2-10.googlebot.com' ? ['192.0.2.10'] : host === '12.2.0.192.bc.googleusercontent.com' ? ['192.0.2.12'] : ['192.0.2.99'],
        ),
    };
    const staleIntel = new NetworkIntel({ dataset: dataset(new Date(START - 30 * 86_400_000).toISOString()) });
    const verifier = new CrawlerVerifier({ intel: staleIntel, reverseDns: true, resolver, now: () => START });
    const claim = parseUserAgent(googlebot).crawler;

    for (const ip of ['192.0.2.10', '192.0.2.11', '192.0.2.12']) assert.equal(verifier.verify(claim, parseIp(ip), ip, {}).status, 'unverified');
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(verifier.verify(claim, parseIp('192.0.2.10'), '192.0.2.10', {}).status, 'verified');
    assert.equal(verifier.verify(claim, parseIp('192.0.2.11'), '192.0.2.11', {}).status, 'impersonation');
    assert.equal(
      verifier.verify(claim, parseIp('192.0.2.12'), '192.0.2.12', {}).status,
      'impersonation',
      'a Google Cloud customer VM must not pass as Googlebot',
    );
  });

  test('accepts the Cloudflare verified bot signal only through the edge', () => {
    const verifier = new CrawlerVerifier({ intel: new NetworkIntel(), reverseDns: false });
    assert.equal(verifier.verify(undefined, parseIp('192.0.2.1'), '192.0.2.1', { verifiedBot: true }).status, 'verified');
    assert.equal(verifier.verify(parseUserAgent(googlebot).crawler, parseIp('192.0.2.1'), '192.0.2.1', { verifiedBot: false }).status, 'impersonation');
  });
});

describe('network classification', () => {
  test('classifies hosting, relay and tor networks and keeps the rest unclassified', () => {
    const intel = new NetworkIntel({ dataset: dataset() });
    const profile = (ip: string, edge = {}) =>
      intel.profile({ ip: parseIp(ip), text: ip, via: 'direct', viaEdge: false, edgeVerified: Object.keys(edge).length > 0, edge });
    assert.equal(profile('3.5.1.1').category, 'hosting');
    assert.equal(profile('3.5.1.1').provider, 'amazon');
    assert.equal(profile('172.224.226.9').category, 'privacy_relay');
    assert.equal(profile('185.220.101.1').category, 'tor');
    assert.equal(profile('198.51.100.1').category, 'unclassified');
    assert.equal(profile('198.51.100.1', { asn: 14061 }).category, 'hosting');
    assert.equal(profile('198.51.100.1', { country: 'T1' }).category, 'tor');
  });
});
