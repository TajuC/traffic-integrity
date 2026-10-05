import { parseIp } from '../net/ip.ts';
import { parseUserAgent } from '../request/user-agent.ts';
import type { RiskContext } from '../risk/context.ts';
import type { AddressObservation, NetworkObservation, Observation, VisitorObservation } from '../store/types.ts';
import type { AttackerClass } from './dataset.ts';

const START = Date.parse('2026-10-05T12:00:00.000Z');
const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const CHROME_HINTS = '"Google Chrome";v="141", "Chromium";v="141", "Not=A?Brand";v="24"';

function visitorObservation(overrides: Partial<VisitorObservation> = {}): VisitorObservation {
  return {
    requestRate: 3,
    actionRate: 0,
    conversionRate: 0,
    timing: { samples: 3, meanMs: 9000, cv: 0.8 },
    sessionStartedAt: START - 120_000,
    sessionDepth: 2,
    sessionCount: 1,
    scriptVerifiedAt: undefined,
    interactionAt: undefined,
    automationFlags: 0,
    clearanceUntil: undefined,
    restrictedUntil: undefined,
    strikes: 0,
    acceptedConversions: 0,
    paidClicks5m: 0,
    paidClicks1h: 0,
    attribution: undefined,
    ...overrides,
  };
}

function observation(
  parts: {
    visitor?: Partial<VisitorObservation> | null;
    address?: Partial<AddressObservation>;
    network?: Partial<NetworkObservation>;
    clickVisitors?: number;
  } = {},
): Observation {
  return {
    source: 'redis',
    visitor: parts.visitor === null ? undefined : visitorObservation(parts.visitor ?? {}),
    address: { requestRate: 3, population: 0, restrictedUntil: undefined, strikes: 0, ...parts.address },
    network: { requestRate: 5, conversionRate: 0, paidClicks5m: 0, paidClicks1h: 0, freshIdentities: 1, population: 0, ...parts.network },
    asnPaidClicks5m: undefined,
    clickVisitors: parts.clickVisitors,
  };
}

export interface SyntheticCase {
  readonly id: string;
  readonly clazz: AttackerClass;
  readonly label: 0 | 1;
  readonly context: RiskContext;
  readonly expectedFailure?: string;
}

const CURL = 'curl/8.5.0';
const PYTHON = 'python-requests/2.32.3';
const GO = 'Go-http-client/2.0';
const HEADLESS = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36';
const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

function base(overrides: Partial<RiskContext> = {}): RiskContext {
  return {
    now: START,
    routeClass: 'page',
    secure: true,
    headers: {
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      acceptLanguage: 'en-US,en;q=0.9',
      secFetchMode: 'navigate',
      secFetchSite: 'cross-site',
      secChUa: CHROME_HINTS,
      secChUaPlatform: '"Windows"',
      secChUaMobile: '?0',
      secChUaArch: undefined,
      secChUaBitness: undefined,
      origin: undefined,
    },
    ua: parseUserAgent(CHROME_UA),
    crawler: { status: 'none' },
    address: { ip: parseIp('198.51.100.10'), text: '198.51.100.10', via: 'proxy', viaEdge: false, edgeVerified: false, edge: {} },
    network: { asn: 64500, asOrg: 'Example Broadband', country: 'US', category: 'unclassified', provider: undefined, asnSource: 'database', confidence: 0.3 },
    edgeRequired: false,
    identity: { origin: 'new', cookieAgeSeconds: 0 },
    paidArrival: false,
    malformedAttribution: [],
    observation: observation(),
    clearanceValid: false,
    authenticated: false,
    action: undefined,
    degraded: [],
    ...overrides,
  };
}

const HOSTING = { asn: 16509, asOrg: 'AMAZON-02', country: 'US', category: 'hosting' as const, provider: 'amazon', asnSource: 'database' as const, confidence: 0.8 };

export function syntheticCases(): SyntheticCase[] {
  const cases: SyntheticCase[] = [];
  let n = 0;
  const add = (clazz: AttackerClass, label: 0 | 1, context: RiskContext, expectedFailure?: string): void => {
    n += 1;
    cases.push({ id: `${clazz}-${n}`, clazz, label, context, expectedFailure });
  };

  for (let i = 0; i < 40; i += 1) {
    add('legitimate', 0, base({ identity: { origin: 'returning', cookieAgeSeconds: 200_000 }, observation: observation({ visitor: { sessionCount: 4, sessionDepth: 3, scriptVerifiedAt: START - 1000, interactionAt: START - 400 } }) }));
  }
  for (let i = 0; i < 12; i += 1) {
    add('legitimate', 0, base({ observation: observation({ address: { requestRate: 80, population: 40 }, network: { population: 40, requestRate: 120 } }) }));
  }
  for (let i = 0; i < 8; i += 1) {
    add('crawler', 0, base({ ua: parseUserAgent(GOOGLEBOT), crawler: { status: 'verified', operator: 'google', via: 'ranges' }, identity: undefined, observation: observation({ visitor: null }) }));
  }

  for (let i = 0; i < 20; i += 1) add('scripted_http', 1, base({ ua: parseUserAgent(CURL), headers: { ...base().headers, secChUa: undefined, secFetchMode: undefined, accept: '*/*' } }));
  for (let i = 0; i < 12; i += 1) add('scripted_http', 1, base({ ua: parseUserAgent(PYTHON), headers: { ...base().headers, secChUa: undefined, secFetchMode: undefined, acceptLanguage: undefined, accept: '*/*' } }));
  for (let i = 0; i < 8; i += 1) add('scripted_http', 1, base({ ua: parseUserAgent(GO), headers: { ...base().headers, secChUa: undefined, secFetchMode: undefined, accept: '*/*' } }));

  for (let i = 0; i < 20; i += 1) add('obvious_bot', 1, base({ ua: parseUserAgent(HEADLESS), network: HOSTING }));
  for (let i = 0; i < 12; i += 1) add('obvious_bot', 1, base({ observation: observation({ visitor: { automationFlags: 1 + 2 + 32 } }) }));

  for (let i = 0; i < 16; i += 1) {
    add('datacenter_browser', 1, base({ network: HOSTING, ua: parseUserAgent(CHROME_UA), observation: observation({ visitor: { requestRate: 140, timing: { samples: 12, meanMs: 800, cv: 0.04 } } }) }));
  }

  for (let i = 0; i < 16; i += 1) {
    add(
      'repeated_click',
      1,
      base({
        paidArrival: true,
        observation: observation({ visitor: { paidClicks5m: 8, paidClicks1h: 12 }, clickVisitors: 7 }),
      }),
    );
  }

  for (let i = 0; i < 12; i += 1) {
    add(
      'conversion_spam',
      1,
      base({
        routeClass: 'conversion',
        ua: parseUserAgent(PYTHON),
        headers: { ...base().headers, origin: undefined, secChUa: undefined, secFetchMode: undefined, acceptLanguage: undefined, accept: '*/*' },
        action: { honeypot: false, formToken: 'missing', formAgeMs: undefined, originPresent: false, repeatedMessageContacts: 0 },
        observation: observation({ visitor: { sessionDepth: 0 } }),
      }),
    );
  }

  for (let i = 0; i < 20; i += 1) {
    add(
      'stealth_automation',
      1,
      base({
        network: { ...HOSTING, category: 'unclassified', provider: undefined, confidence: 0.2 },
        observation: observation({ visitor: { requestRate: 8, timing: { samples: 10, meanMs: 11_000, cv: 0.09 }, scriptVerifiedAt: START - 500, interactionAt: START - 200 } }),
      }),
      'slow real-browser automation with a residential-looking address is often allowed',
    );
  }

  for (let i = 0; i < 20; i += 1) {
    add(
      'residential_proxy',
      1,
      base({
        paidArrival: true,
        identity: { origin: 'new', cookieAgeSeconds: 0 },
        observation: observation({ visitor: { paidClicks5m: 1, paidClicks1h: 1, scriptVerifiedAt: START - 200, interactionAt: START - 100 } }),
      }),
      'one request per unique residential address carries little origin-side evidence',
    );
  }

  for (let i = 0; i < 10; i += 1) {
    add('ambiguous', 0, base({ ua: parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0'), headers: { ...base().headers, secChUa: undefined } }));
  }

  return cases;
}
