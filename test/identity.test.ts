import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { parseAttribution } from '../src/attribution/attribution.ts';
import { googleNormalizedEmail, toE164 } from '../src/conversion/lead.ts';
import { Keyring } from '../src/crypto/keyring.ts';
import { cookieNames, readCookies, serializeCookie } from '../src/identity/cookies.ts';
import { IdentityService } from '../src/identity/visitor.ts';
import { parseUserAgent } from '../src/request/user-agent.ts';
import { TEST_SECRET } from './helpers/harness.ts';

const NOW = 1_790_000_000;

describe('keyring', () => {
  test('seals tokens that cannot be altered or reused across purposes', () => {
    const keyring = new Keyring(TEST_SECRET);
    const token = keyring.seal('visitor', ['abc', 'def']);
    assert.deepEqual(keyring.open('visitor', token, 2), ['abc', 'def']);
    assert.equal(keyring.open('session', token, 2), null);
    assert.equal(keyring.open('visitor', token.replace('abc', 'abd'), 2), null);
    assert.equal(keyring.open('visitor', `${token}x`, 2), null);
    assert.equal(keyring.open('visitor', token, 3), null);
  });

  test('keeps accepting tokens signed with the previous secret during rotation', () => {
    const old = new Keyring(TEST_SECRET);
    const rotated = new Keyring('a-brand-new-secret-value-that-is-also-long', TEST_SECRET);
    const token = old.seal('form', ['nonce']);
    assert.deepEqual(rotated.open('form', token, 1), ['nonce']);
    assert.equal(new Keyring('a-brand-new-secret-value-that-is-also-long').open('form', token, 1), null);
  });
});

describe('visitor identity', () => {
  const keyring = new Keyring(TEST_SECRET);
  const names = cookieNames(true);
  const identities = new IdentityService(keyring, names, 180);

  test('issues secure host-only cookies for a first visit', () => {
    const first = identities.resolve({ visitorCookie: undefined, sessionCookie: undefined }, NOW);
    assert.equal(first.identity.origin, 'new');
    assert.equal(first.cookies.length, 2);
    const header = serializeCookie(first.cookies[0]!, true);
    assert.match(header, /^__Host-vid=/);
    assert.match(header, /Path=\//);
    assert.match(header, /HttpOnly/);
    assert.match(header, /Secure/);
    assert.match(header, /SameSite=Lax/);
    assert.match(header, /Max-Age=15552000/);
  });

  test('recognizes a returning visitor and renews the cookie weekly without changing identity', () => {
    const first = identities.resolve({ visitorCookie: undefined, sessionCookie: undefined }, NOW);
    const visitorCookie = first.cookies.find((c) => c.name === names.visitor)!.value;
    const sessionCookie = first.cookies.find((c) => c.name === names.session)!.value;

    const next = identities.resolve({ visitorCookie, sessionCookie }, NOW + 3600);
    assert.equal(next.identity.origin, 'returning');
    assert.equal(next.identity.visitorId, first.identity.visitorId);
    assert.equal(next.identity.sessionId, first.identity.sessionId);
    assert.equal(next.identity.issuedAt, NOW);
    assert.equal(next.cookies.length, 0);

    const later = identities.resolve({ visitorCookie, sessionCookie }, NOW + 8 * 86_400);
    assert.equal(later.identity.visitorId, first.identity.visitorId);
    assert.equal(later.cookies.length, 1);
  });

  test('treats a forged or tampered visitor cookie as a new identity', () => {
    const forged = identities.resolve({ visitorCookie: 'AAAAAAAAAAAAAAAAAAAAAA.1.1.AAAAAAAAAAAAAAAAAAAAAA', sessionCookie: undefined }, NOW);
    assert.equal(forged.identity.origin, 'forged');
    const genuine = identities.resolve({ visitorCookie: undefined, sessionCookie: undefined }, NOW).cookies[0]!.value;
    const backdated = genuine.replace(/^([^.]+)\.[^.]+/, '$1.1');
    assert.equal(identities.resolve({ visitorCookie: backdated, sessionCookie: undefined }, NOW).identity.origin, 'forged');
  });

  test('parses only the cookies it owns and keeps the first occurrence', () => {
    const jar = readCookies('a=1; __Host-vid=first; __Host-vid=second; "x"=y; __Host-sid="quoted"', ['__Host-vid', '__Host-sid']);
    assert.equal(jar.get('__Host-vid'), 'first');
    assert.equal(jar.get('__Host-sid'), 'quoted');
    assert.equal(jar.size, 2);
  });
});

describe('paid attribution', () => {
  test('captures Google click identifiers, aggregate parameters and UTM values', () => {
    const result = parseAttribution(
      new URLSearchParams('gclid=Cj0KCQjwvalidclick_BwE&gbraid=0AAAAADkfrValid&gad_source=1&gad_campaignid=21987654321&utm_source=google&utm_campaign=Spring%20Sale&utm_term=roof%0Arepair'),
    );
    assert.equal(result.attribution?.primary?.type, 'gclid');
    assert.equal(result.attribution?.clickIds.gbraid, '0AAAAADkfrValid');
    assert.equal(result.attribution?.gadCampaignId, '21987654321');
    assert.equal(result.attribution?.utm.utm_campaign, 'Spring Sale');
    assert.equal(result.attribution?.utm.utm_term, 'roof repair');
    assert.deepEqual(result.malformed, []);
  });

  test('ignores malformed and conflicting attribution values instead of trusting them', () => {
    const result = parseAttribution(new URLSearchParams('gclid=<script>alert(1)</script>&gclid=other&wbraid=short&gad_campaignid=12ab'));
    assert.equal(result.attribution, undefined);
    assert.deepEqual([...result.malformed].sort(), ['gad_campaignid', 'gclid', 'wbraid']);
    const repeated = parseAttribution(new URLSearchParams('gclid=Cj0KCQjwsameclick&gclid=Cj0KCQjwsameclick'));
    assert.equal(repeated.attribution?.clickIds.gclid, 'Cj0KCQjwsameclick');
  });

  test('treats UTM-only traffic as non-paid', () => {
    assert.equal(parseAttribution(new URLSearchParams('utm_source=newsletter')).attribution, undefined);
  });
});

describe('user agent parsing', () => {
  test('identifies browsers, automation tools, crawlers and link previews', () => {
    const chrome = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36');
    assert.deepEqual([chrome.family, chrome.engine, chrome.os, chrome.device, chrome.major], ['chrome', 'blink', 'windows', 'desktop', 141]);
    const criOS = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1');
    assert.deepEqual([criOS.family, criOS.engine, criOS.os, criOS.device], ['chrome', 'webkit', 'ios', 'mobile']);
    assert.equal(parseUserAgent('python-requests/2.32.3').automation, 'python');
    assert.equal(parseUserAgent('curl/8.9.1').automation, 'curl');
    assert.equal(parseUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36').automation, 'headless-chrome');
    assert.equal(parseUserAgent('AdsBot-Google (+http://www.google.com/adsbot.html)').crawler?.operator, 'google');
    assert.equal(parseUserAgent('WhatsApp/2.24.20.79 A').preview, 'whatsapp');
    assert.equal(parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22G86 [FBAN/FBIOS;FBAV/500.0]').preview, undefined);
    assert.equal(parseUserAgent(undefined).present, false);
  });
});

describe('enhanced conversion normalization', () => {
  test('applies Google gmail normalization and E.164 phone formatting', () => {
    assert.equal(googleNormalizedEmail(' Jane.Doe+Shopping@GoogleMail.com '), 'janedoe@googlemail.com');
    assert.equal(googleNormalizedEmail('user.name+NYC@Example.com'), 'user.name+nyc@example.com');
    assert.equal(toE164('+1 (800) 555-0102', undefined), '+18005550102');
    assert.equal(toE164('054-123-4567', '972'), '+972541234567');
    assert.equal(toE164('0044 20 7946 0958', undefined), '+442079460958');
    assert.equal(toE164('054-123-4567', undefined), undefined);
  });
});
