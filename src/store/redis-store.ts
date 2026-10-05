import { Redis, type Result } from 'ioredis';
import { COUNTER, OBSERVE_ADDRESS, OBSERVE_DISTINCT, OBSERVE_NETWORK, OBSERVE_VISITOR, PATCH, RESTRICT } from './scripts.ts';
import {
  bucket,
  coefficientOfVariation,
  TTLS,
  WINDOWS,
  type AddressObservation,
  type IntegrityStore,
  type NetworkObservation,
  type Observation,
  type ObservationPlan,
  type RestrictionTarget,
  type VisitorObservation,
  type VisitorPatch,
} from './types.ts';

type Arg = string | number;

declare module 'ioredis' {
  interface RedisCommander<Context> {
    tiVisitor(...args: Arg[]): Result<string[], Context>;
    tiAddress(...args: Arg[]): Result<string[], Context>;
    tiNetwork(...args: Arg[]): Result<string[], Context>;
    tiDistinct(...args: Arg[]): Result<number, Context>;
    tiRestrict(...args: Arg[]): Result<string, Context>;
    tiPatch(...args: Arg[]): Result<number, Context>;
    tiCounter(...args: Arg[]): Result<string, Context>;
  }
}

export interface RedisStoreOptions {
  readonly url: string;
  readonly keyPrefix: string;
  readonly commandTimeoutMs: number;
  readonly onError?: (error: Error) => void;
}

export class RedisStore implements IntegrityStore {
  readonly client: Redis;
  private readonly prefix: string;

  constructor(options: RedisStoreOptions) {
    this.prefix = options.keyPrefix;
    this.client = new Redis(options.url, {
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      commandTimeout: options.commandTimeoutMs,
      connectTimeout: 2000,
      retryStrategy: (attempt) => Math.min(attempt * 250, 3000),
    });
    this.client.on('error', (error: Error) => options.onError?.(error));
    this.client.defineCommand('tiVisitor', { numberOfKeys: 5, lua: OBSERVE_VISITOR });
    this.client.defineCommand('tiAddress', { numberOfKeys: 3, lua: OBSERVE_ADDRESS });
    this.client.defineCommand('tiNetwork', { numberOfKeys: 9, lua: OBSERVE_NETWORK });
    this.client.defineCommand('tiDistinct', { numberOfKeys: 2, lua: OBSERVE_DISTINCT });
    this.client.defineCommand('tiRestrict', { numberOfKeys: 1, lua: RESTRICT });
    this.client.defineCommand('tiPatch', { numberOfKeys: 1, lua: PATCH });
    this.client.defineCommand('tiCounter', { numberOfKeys: 1, lua: COUNTER });
  }

  ready(timeoutMs = 2000): Promise<void> {
    if (this.client.status === 'ready') return Promise.resolve();
    return new Promise((resolve, reject) => {
      const onReady = (): void => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        this.client.off('ready', onReady);
        reject(new Error(`redis was not ready within ${timeoutMs}ms`));
      }, timeoutMs);
      this.client.once('ready', onReady);
    });
  }

  async observe(plan: ObservationPlan): Promise<Observation> {
    const pipeline = this.client.pipeline();
    const { now, visitor } = plan;
    const short = bucket(now, WINDOWS.paidShortMs);
    const long = bucket(now, WINDOWS.paidLongMs);
    const population = bucket(now, WINDOWS.populationMs);

    if (visitor) {
      const base = this.slot('v', visitor.id);
      pipeline.tiVisitor(
        `${base}:s`,
        `${base}:p5:${short}`,
        `${base}:p5:${short - 1}`,
        `${base}:p60:${long}`,
        `${base}:p60:${long - 1}`,
        now,
        visitor.fresh ? TTLS.provisionalVisitorMs : TTLS.visitorMs,
        plan.kind,
        visitor.sessionId,
        plan.sessionIdleMs,
        plan.paidClick ?? '',
        plan.attribution ?? '',
        WINDOWS.requestTauMs,
        WINDOWS.actionTauMs,
        WINDOWS.visitorConversionTauMs,
        WINDOWS.strikeTauMs,
        WINDOWS.paidShortMs * 2,
        WINDOWS.paidLongMs * 2,
        WINDOWS.timingMaxGapMs,
        WINDOWS.timingAlpha,
      );
    }

    const address = this.slot('i', plan.addressKey);
    pipeline.tiAddress(
      `${address}:s`,
      `${address}:e:${population}`,
      `${address}:e:${population - 1}`,
      now,
      WINDOWS.requestTauMs,
      TTLS.addressMs,
      visitor?.established ? visitor.id : '',
      WINDOWS.populationMs * 2,
      WINDOWS.strikeTauMs,
    );

    const network = this.slot('n', plan.networkKey);
    const fresh = bucket(now, WINDOWS.freshMs);
    pipeline.tiNetwork(
      `${network}:s`,
      `${network}:p5:${short}`,
      `${network}:p5:${short - 1}`,
      `${network}:p60:${long}`,
      `${network}:p60:${long - 1}`,
      `${network}:f:${fresh}`,
      `${network}:f:${fresh - 1}`,
      `${network}:e:${population}`,
      `${network}:e:${population - 1}`,
      now,
      WINDOWS.requestTauMs,
      WINDOWS.networkConversionTauMs,
      TTLS.networkMs,
      plan.kind,
      plan.paidClick ?? '',
      visitor?.fresh ? visitor.id : '',
      visitor?.established ? visitor.id : '',
      WINDOWS.paidShortMs * 2,
      WINDOWS.paidLongMs * 2,
      WINDOWS.freshMs * 2,
      WINDOWS.populationMs * 2,
    );

    const trackAsn = plan.paidClick !== undefined && plan.asn !== undefined;
    if (trackAsn) {
      const asn = this.slot('a', String(plan.asn));
      pipeline.tiDistinct(`${asn}:p5:${short}`, `${asn}:p5:${short - 1}`, plan.paidClick, WINDOWS.paidShortMs * 2);
    }
    const trackClick = plan.paidClick !== undefined && visitor !== undefined;
    if (trackClick) {
      const click = this.slot('c', plan.paidClick);
      const reuse = bucket(now, WINDOWS.clickReuseMs);
      pipeline.tiDistinct(`${click}:v:${reuse}`, `${click}:v:${reuse - 1}`, visitor.id, WINDOWS.clickReuseMs * 2);
    }

    const results = await pipeline.exec();
    if (!results) throw new Error('redis pipeline was aborted');
    const values = results.map(([error, value]) => {
      if (error) throw error;
      return value;
    });

    let index = 0;
    const next = (): unknown => values[index++];
    return {
      source: 'redis',
      visitor: visitor ? parseVisitor(next() as string[]) : undefined,
      address: parseAddress(next() as string[]),
      network: parseNetwork(next() as string[]),
      asnPaidClicks5m: trackAsn ? Number(next()) : undefined,
      clickVisitors: trackClick ? Number(next()) : undefined,
    };
  }

  async patchVisitor(visitorId: string, patch: VisitorPatch, now: number): Promise<void> {
    const fields: Arg[] = [];
    if (patch.scriptVerifiedAt !== undefined) fields.push('js', patch.scriptVerifiedAt);
    if (patch.interactionAt !== undefined) fields.push('ix', patch.interactionAt);
    if (patch.automationFlags !== undefined) fields.push('af', patch.automationFlags);
    if (patch.clearanceUntil !== undefined) fields.push('cl', patch.clearanceUntil);
    const ttl = Math.max(TTLS.visitorMs, (patch.clearanceUntil ?? 0) - now);
    await this.client.tiPatch(`${this.slot('v', visitorId)}:s`, ttl, patch.acceptedConversion ? 'co' : '', ...fields);
  }

  async restrict(target: RestrictionTarget, until: number, now: number): Promise<void> {
    const pipeline = this.client.pipeline();
    if (target.visitorId) pipeline.tiRestrict(`${this.slot('v', target.visitorId)}:s`, until, now, TTLS.visitorMs, WINDOWS.strikeTauMs);
    if (target.addressKey) pipeline.tiRestrict(`${this.slot('i', target.addressKey)}:s`, until, now, TTLS.addressMs, WINDOWS.strikeTauMs);
    const results = await pipeline.exec();
    for (const [error] of results ?? []) if (error) throw error;
  }

  async claimOnce(key: string, ttlMs: number): Promise<boolean> {
    return (await this.client.set(`${this.prefix}{o:${key}}`, '1', 'PX', ttlMs, 'NX')) === 'OK';
  }

  async countGlobalConversion(now: number): Promise<number> {
    return Number(await this.client.tiCounter(`${this.prefix}{g}:conversions`, now, WINDOWS.globalConversionTauMs, TTLS.globalMs));
  }

  async ping(): Promise<boolean> {
    return (await this.client.ping()) === 'PONG';
  }

  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }

  private slot(kind: string, id: string): string {
    return `${this.prefix}{${kind}:${id}}`;
  }
}

function optional(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseVisitor(raw: string[]): VisitorObservation {
  const n = (i: number): number => Number(raw[i] ?? 0) || 0;
  const mean = n(4);
  return {
    requestRate: n(0),
    actionRate: n(1),
    conversionRate: n(2),
    timing: { samples: n(3), meanMs: mean, cv: coefficientOfVariation(mean, n(5)) },
    sessionStartedAt: n(6),
    sessionDepth: n(7),
    sessionCount: n(8),
    scriptVerifiedAt: optional(raw[9]),
    interactionAt: optional(raw[10]),
    automationFlags: optional(raw[11]) ?? 0,
    clearanceUntil: optional(raw[12]),
    restrictedUntil: optional(raw[13]),
    strikes: n(14),
    acceptedConversions: optional(raw[15]) ?? 0,
    paidClicks5m: n(16),
    paidClicks1h: n(17),
    attribution: raw[18] ? raw[18] : undefined,
  };
}

function parseAddress(raw: string[]): AddressObservation {
  return {
    requestRate: Number(raw[0] ?? 0) || 0,
    population: Number(raw[1] ?? 0) || 0,
    restrictedUntil: optional(raw[2]),
    strikes: Number(raw[3] ?? 0) || 0,
  };
}

function parseNetwork(raw: string[]): NetworkObservation {
  const n = (i: number): number => Number(raw[i] ?? 0) || 0;
  return {
    requestRate: n(0),
    conversionRate: n(1),
    paidClicks5m: n(2),
    paidClicks1h: n(3),
    freshIdentities: n(4),
    population: n(5),
  };
}
