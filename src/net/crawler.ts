import { promises as dns } from 'node:dns';
import type { EdgeSignals } from './client-address.ts';
import { formatIp, parseIp, type ParsedIp } from './ip.ts';
import type { CrawlerRangeKind, NetworkIntel } from './network-intel.ts';

export type CrawlerOperator = 'google' | 'bing' | 'apple' | 'yandex';

export interface CrawlerClaim {
  readonly operator: CrawlerOperator;
  readonly token: string;
}

export type CrawlerVerdict =
  | { readonly status: 'none' }
  | { readonly status: 'verified'; readonly operator: CrawlerOperator | 'edge'; readonly via: 'ranges' | 'dns' | 'edge' }
  | { readonly status: 'unverified'; readonly operator: CrawlerOperator }
  | { readonly status: 'impersonation'; readonly operator: CrawlerOperator; readonly via: 'ranges' | 'dns' | 'edge' };

export interface DnsResolver {
  reverse(ip: string): Promise<string[]>;
  lookup(hostname: string): Promise<string[]>;
}

const RANGE_OWNERS: Partial<Record<CrawlerOperator, (kind: CrawlerRangeKind) => boolean>> = {
  google: (kind) => kind.startsWith('google-'),
  bing: (kind) => kind === 'bing',
};

const DNS_SUFFIXES: Readonly<Record<CrawlerOperator, readonly string[]>> = {
  google: ['.googlebot.com', '.google.com'],
  bing: ['.search.msn.com'],
  apple: ['.applebot.apple.com'],
  yandex: ['.yandex.ru', '.yandex.net', '.yandex.com'],
};

const DEFINITIVE_DNS_ERRORS = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN']);
const MAX_CONCURRENT_CHECKS = 64;

const NONE: CrawlerVerdict = Object.freeze({ status: 'none' });

const systemResolver: DnsResolver = {
  reverse: (ip) => dns.reverse(ip),
  lookup: async (hostname) => (await dns.lookup(hostname, { all: true, verbatim: true })).map((entry) => entry.address),
};

interface CachedVerdict {
  readonly verified: boolean;
  readonly expiresAt: number;
}

export interface CrawlerVerifierOptions {
  readonly intel: NetworkIntel;
  readonly reverseDns: boolean;
  readonly resolver?: DnsResolver;
  readonly now?: () => number;
  readonly timeoutMs?: number;
  readonly cacheSize?: number;
}

export class CrawlerVerifier {
  private readonly intel: NetworkIntel;
  private readonly reverseDns: boolean;
  private readonly resolver: DnsResolver;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  private readonly cacheSize: number;
  private readonly cache = new Map<string, CachedVerdict>();
  private readonly inflight = new Set<string>();

  constructor(options: CrawlerVerifierOptions) {
    this.intel = options.intel;
    this.reverseDns = options.reverseDns;
    this.resolver = options.resolver ?? systemResolver;
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? 2000;
    this.cacheSize = options.cacheSize ?? 10_000;
  }

  verify(claim: CrawlerClaim | undefined, ip: ParsedIp | null, ipText: string, edge: EdgeSignals): CrawlerVerdict {
    if (edge.verifiedBot === true) return { status: 'verified', operator: claim?.operator ?? 'edge', via: 'edge' };
    if (!claim) return NONE;
    if (!ip) return { status: 'unverified', operator: claim.operator };

    const owns = RANGE_OWNERS[claim.operator];
    if (owns) {
      const kind = this.intel.crawlerRange(ip);
      if (kind && owns(kind)) return { status: 'verified', operator: claim.operator, via: 'ranges' };
      if (edge.verifiedBot === false) return { status: 'impersonation', operator: claim.operator, via: 'edge' };
      if (this.intel.crawlerRangesFresh(this.now())) return { status: 'impersonation', operator: claim.operator, via: 'ranges' };
    }

    if (!this.reverseDns) return { status: 'unverified', operator: claim.operator };
    const cached = this.cache.get(ipText);
    if (cached && cached.expiresAt > this.now()) {
      return cached.verified
        ? { status: 'verified', operator: claim.operator, via: 'dns' }
        : { status: 'impersonation', operator: claim.operator, via: 'dns' };
    }
    this.startCheck(claim.operator, ipText);
    return { status: 'unverified', operator: claim.operator };
  }

  private startCheck(operator: CrawlerOperator, ipText: string): void {
    if (this.inflight.has(ipText) || this.inflight.size >= MAX_CONCURRENT_CHECKS) return;
    this.inflight.add(ipText);
    void this.confirm(operator, ipText)
      .then((verified) => {
        if (verified !== undefined) this.remember(ipText, verified);
      })
      .finally(() => this.inflight.delete(ipText));
  }

  private async confirm(operator: CrawlerOperator, ipText: string): Promise<boolean | undefined> {
    const timeout = new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), this.timeoutMs).unref());
    const check = (async (): Promise<boolean | undefined> => {
      try {
        const hostnames = await this.resolver.reverse(ipText);
        const host = hostnames
          .map((name) => name.toLowerCase().replace(/\.$/, ''))
          .find((name) => DNS_SUFFIXES[operator].some((suffix) => name.endsWith(suffix)));
        if (!host) return false;
        const addresses = await this.resolver.lookup(host);
        return addresses.some((address) => {
          const parsed = parseIp(address);
          return parsed !== null && formatIp(parsed) === ipText;
        });
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        return code && DEFINITIVE_DNS_ERRORS.has(code) ? false : undefined;
      }
    })();
    return Promise.race([check, timeout]);
  }

  private remember(ipText: string, verified: boolean): void {
    const ttl = verified ? 24 * 60 * 60 * 1000 : 6 * 60 * 60 * 1000;
    this.cache.delete(ipText);
    this.cache.set(ipText, { verified, expiresAt: this.now() + ttl });
    if (this.cache.size > this.cacheSize) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
  }
}
