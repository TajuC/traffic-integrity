import type { Logger } from 'pino';
import { ClearanceService } from './challenge/clearance.ts';
import { CloudflareTurnstile, type TurnstileVerifier } from './challenge/turnstile.ts';
import type { Config } from './config/env.ts';
import { FormTokens } from './conversion/form-token.ts';
import { Keyring } from './crypto/keyring.ts';
import { openDatabase, type SqlClient } from './db/sql.ts';
import { RestrictionCache } from './guard/restrictions.ts';
import { cookieNames, type CookieNames } from './identity/cookies.ts';
import { IdentityService } from './identity/visitor.ts';
import { ClientAddressResolver } from './net/client-address.ts';
import { CrawlerVerifier, type DnsResolver } from './net/crawler.ts';
import { NetworkIntel } from './net/network-intel.ts';
import type { RouteRules } from './request/classify.ts';
import type { RiskPolicy } from './risk/policy.ts';
import { MemoryStore } from './store/memory-store.ts';
import { RedisStore } from './store/redis-store.ts';
import { CircuitBreaker, ResilientStore } from './store/resilient-store.ts';
import type { IntegrityStore } from './store/types.ts';
import { SecurityEvents } from './telemetry/events.ts';
import { createLogger } from './telemetry/logger.ts';
import { IntegrityMetrics } from './telemetry/metrics.ts';
import { PaidVisitRecorder } from './telemetry/paid-visits.ts';

export interface Runtime {
  readonly config: Config;
  readonly policy: RiskPolicy;
  readonly logger: Logger;
  readonly events: SecurityEvents;
  readonly metrics: IntegrityMetrics;
  readonly keyring: Keyring;
  readonly cookieNames: CookieNames;
  readonly identities: IdentityService;
  readonly clearance: ClearanceService;
  readonly formTokens: FormTokens;
  readonly addresses: ClientAddressResolver;
  readonly intel: NetworkIntel;
  readonly crawlers: CrawlerVerifier;
  readonly store: ResilientStore;
  readonly turnstile: TurnstileVerifier | undefined;
  readonly db: SqlClient | undefined;
  readonly paidVisits: PaidVisitRecorder;
  readonly restrictions: RestrictionCache;
  readonly routes: RouteRules;
  readonly clock: () => number;
  close(): Promise<void>;
}

export interface RuntimeOverrides {
  readonly clock?: () => number;
  readonly logger?: Logger;
  readonly primaryStore?: IntegrityStore | null;
  readonly intel?: NetworkIntel;
  readonly db?: SqlClient | null;
  readonly turnstile?: TurnstileVerifier | null;
  readonly dnsResolver?: DnsResolver;
  readonly background?: boolean;
}

const INTEL_REFRESH_MS = 10 * 60 * 1000;
const MEMORY_SWEEP_MS = 60 * 1000;

export async function createRuntime(config: Config, overrides: RuntimeOverrides = {}): Promise<Runtime> {
  const clock = overrides.clock ?? Date.now;
  const logger = overrides.logger ?? createLogger({ level: config.logging.level });
  const events = new SecurityEvents(logger, clock);
  const metrics = new IntegrityMetrics();
  const keyring = new Keyring(config.secrets.current, config.secrets.previous);
  const names = cookieNames(config.origin.secure);
  const policy = config.policy;

  const degraded = (component: string, error: unknown, operation?: string): void => {
    events.emitOnce(
      `degraded:${component}:${operation ?? ''}`,
      30_000,
      'security_degraded',
      { component, operation, error: error instanceof Error ? error.message : String(error) },
      'warn',
    );
  };

  const intel = overrides.intel ?? (await NetworkIntel.open({ path: config.intel.path, asnDatabasePath: config.intel.asnDatabasePath }));
  const addresses = new ClientAddressResolver({
    trusted: config.proxy.trusted,
    edgeMode: config.edge.mode,
    edgeSecrets: config.edge.secrets,
    cloudflareRanges: intel.cloudflareRanges,
  });
  const crawlers = new CrawlerVerifier({
    intel,
    reverseDns: config.intel.reverseDns,
    now: clock,
    ...(overrides.dnsResolver ? { resolver: overrides.dnsResolver } : {}),
  });

  let primary: IntegrityStore | undefined;
  if (overrides.primaryStore !== undefined) {
    primary = overrides.primaryStore ?? undefined;
  } else if (config.redis) {
    const redis = new RedisStore({ ...config.redis, onError: (error) => degraded('redis', error) });
    await redis.ready().catch((error: unknown) => degraded('redis', error, 'startup'));
    primary = redis;
  }
  const fallback = new MemoryStore();
  const store = new ResilientStore({
    primary,
    fallback,
    breaker: new CircuitBreaker({ now: clock }),
    onFallback: (operation, error) => {
      metrics.storeFallbacks.inc({ operation });
      degraded('store', error, operation);
    },
  });

  const db =
    overrides.db !== undefined
      ? (overrides.db ?? undefined)
      : config.database
        ? await openDatabase({ ...config.database, onError: (error) => degraded('database', error) })
        : undefined;

  const turnstile =
    overrides.turnstile !== undefined
      ? (overrides.turnstile ?? undefined)
      : config.turnstile
        ? new CloudflareTurnstile({
            secretKey: config.turnstile.secretKey,
            hostnames: config.origin.hostnames,
            timeoutMs: config.turnstile.timeoutMs,
            maxAgeSeconds: config.turnstile.maxAgeSeconds,
            store,
            allowTestKeys: config.env !== 'production',
            onUnavailable: (reason) =>
              events.emitOnce(
                `turnstile:${reason}`,
                60_000,
                'security_degraded',
                { component: 'turnstile', reason },
                reason === 'misconfigured' || reason === 'testing_key' ? 'error' : 'warn',
              ),
            now: clock,
          })
        : undefined;

  const paidVisits = new PaidVisitRecorder(db, {
    onResult: (result, count, error) => {
      metrics.paidVisitWrites.inc({ result }, count);
      if (result !== 'written') degraded('paid_visits', error ?? result);
    },
  });

  const timers: NodeJS.Timeout[] = [];
  if (overrides.background !== false) {
    paidVisits.start();
    timers.push(setInterval(() => fallback.sweep(clock()), MEMORY_SWEEP_MS));
    timers.push(
      setInterval(() => {
        intel
          .refresh()
          .then((result) => {
            if (result !== 'reloaded') return;
            addresses.updateCloudflareRanges(intel.cloudflareRanges);
            logger.info({ event: 'network_intel_reloaded', generatedAt: intel.generatedAt }, 'network intelligence reloaded');
          })
          .catch((error: unknown) => degraded('network_intel', error));
      }, INTEL_REFRESH_MS),
    );
    for (const timer of timers) timer.unref();
  }

  return {
    config,
    policy,
    logger,
    events,
    metrics,
    keyring,
    cookieNames: names,
    identities: new IdentityService(keyring, names, config.cookies.visitorDays),
    clearance: new ClearanceService(keyring, names, policy.clearanceTtlSeconds),
    formTokens: new FormTokens(keyring, policy.limits.form.maxAgeMs),
    addresses,
    intel,
    crawlers,
    store,
    turnstile,
    db,
    paidVisits,
    restrictions: new RestrictionCache(),
    routes: {
      internalPrefix: config.routes.internalPrefix,
      conversionPath: config.conversion.path,
      actionPaths: new Set(config.routes.actionPaths),
      apiPrefixes: config.routes.apiPrefixes,
      bypassPaths: new Set(config.routes.bypassPaths),
    },
    clock,
    async close(): Promise<void> {
      for (const timer of timers) clearInterval(timer);
      await paidVisits.stop();
      await store.close();
      await db?.close();
    },
  };
}
