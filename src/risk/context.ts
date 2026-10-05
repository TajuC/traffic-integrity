import type { IdentityOrigin } from '../identity/visitor.ts';
import type { ClientAddress } from '../net/client-address.ts';
import type { CrawlerVerdict } from '../net/crawler.ts';
import type { NetworkProfile } from '../net/network-intel.ts';
import type { RouteClass } from '../request/classify.ts';
import type { UserAgentInfo } from '../request/user-agent.ts';
import type { Observation } from '../store/types.ts';

export interface HeaderFacts {
  readonly accept: string | undefined;
  readonly acceptLanguage: string | undefined;
  readonly secFetchMode: string | undefined;
  readonly secFetchSite: string | undefined;
  readonly secChUa: string | undefined;
  readonly secChUaPlatform: string | undefined;
  readonly origin: string | undefined;
}

export type FormTokenState = 'valid' | 'missing' | 'invalid' | 'expired' | 'replayed';

export interface ActionFacts {
  readonly honeypot: boolean;
  readonly formToken: FormTokenState;
  readonly formAgeMs: number | undefined;
  readonly originPresent: boolean;
  readonly repeatedMessageContacts: number;
}

export interface IdentityFacts {
  readonly origin: IdentityOrigin;
  readonly cookieAgeSeconds: number;
}

export interface RiskContext {
  readonly now: number;
  readonly routeClass: RouteClass;
  readonly secure: boolean;
  readonly headers: HeaderFacts;
  readonly ua: UserAgentInfo;
  readonly crawler: CrawlerVerdict;
  readonly address: ClientAddress;
  readonly network: NetworkProfile;
  readonly edgeRequired: boolean;
  readonly identity: IdentityFacts | undefined;
  readonly paidArrival: boolean;
  readonly malformedAttribution: readonly string[];
  readonly observation: Observation | undefined;
  readonly clearanceValid: boolean;
  readonly authenticated: boolean;
  readonly action: ActionFacts | undefined;
  readonly degraded: readonly string[];
}

export const AUTOMATION_FLAGS = {
  webdriver: 1,
  headless: 2,
  noLanguages: 4,
  phantom: 8,
  selenium: 16,
  playwright: 32,
  zeroViewport: 64,
} as const;
