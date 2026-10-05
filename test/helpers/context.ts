import { parseIp } from '../../src/net/ip.ts';
import { parseUserAgent } from '../../src/request/user-agent.ts';
import type { RiskContext } from '../../src/risk/context.ts';
import type { AddressObservation, NetworkObservation, Observation, VisitorObservation } from '../../src/store/types.ts';
import { CHROME, START } from './harness.ts';

export function visitorObservation(overrides: Partial<VisitorObservation> = {}): VisitorObservation {
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

export function observation(
  parts: {
    visitor?: Partial<VisitorObservation> | null;
    address?: Partial<AddressObservation>;
    network?: Partial<NetworkObservation>;
    asnPaidClicks5m?: number;
    clickVisitors?: number;
    source?: 'redis' | 'memory';
  } = {},
): Observation {
  return {
    source: parts.source ?? 'redis',
    visitor: parts.visitor === null ? undefined : visitorObservation(parts.visitor ?? {}),
    address: { requestRate: 3, population: 0, restrictedUntil: undefined, strikes: 0, ...parts.address },
    network: { requestRate: 5, conversionRate: 0, paidClicks5m: 0, paidClicks1h: 0, freshIdentities: 1, population: 0, ...parts.network },
    asnPaidClicks5m: parts.asnPaidClicks5m,
    clickVisitors: parts.clickVisitors,
  };
}

export function riskContext(overrides: Partial<RiskContext> = {}): RiskContext {
  return {
    now: START,
    routeClass: 'page',
    secure: true,
    headers: {
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      acceptLanguage: 'en-US,en;q=0.9',
      secFetchMode: 'navigate',
      secFetchSite: 'cross-site',
      secChUa: CHROME['sec-ch-ua'],
      secChUaPlatform: CHROME['sec-ch-ua-platform'],
      secChUaMobile: '?0',
      secChUaArch: undefined,
      secChUaBitness: undefined,
      origin: undefined,
    },
    ua: parseUserAgent(CHROME['user-agent']),
    crawler: { status: 'none' },
    address: { ip: parseIp('198.51.100.10'), text: '198.51.100.10', via: 'proxy', viaEdge: false, edgeVerified: false, edge: {} },
    network: { asn: 64500, asOrg: 'Example Broadband', country: 'US', category: 'unclassified', provider: undefined, asnSource: 'database' },
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

export const ESTABLISHED = { origin: 'returning', cookieAgeSeconds: 3 * 86_400 } as const;
