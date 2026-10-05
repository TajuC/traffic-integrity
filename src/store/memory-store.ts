import {
  bucket,
  coefficientOfVariation,
  decay,
  TTLS,
  WINDOWS,
  type IntegrityStore,
  type Observation,
  type ObservationPlan,
  type RestrictionTarget,
  type VisitorObservation,
  type VisitorPatch,
} from './types.ts';

interface Entry {
  expiresAt: number;
  readonly fields: Map<string, number | string>;
  readonly members: Set<string>;
}

export interface MemoryStoreOptions {
  readonly maxEntries?: number;
  readonly maxMembers?: number;
}

export class MemoryStore implements IntegrityStore {
  private readonly entries = new Map<string, Entry>();
  private readonly maxEntries: number;
  private readonly maxMembers: number;

  constructor(options: MemoryStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? 100_000;
    this.maxMembers = options.maxMembers ?? 5_000;
  }

  get size(): number {
    return this.entries.size;
  }

  observe(plan: ObservationPlan): Promise<Observation> {
    const { now, visitor } = plan;
    const short = bucket(now, WINDOWS.paidShortMs);
    const long = bucket(now, WINDOWS.paidLongMs);
    const population = bucket(now, WINDOWS.populationMs);

    let visitorObservation: VisitorObservation | undefined;
    if (visitor) {
      const base = `v:${visitor.id}`;
      const state = this.entry(`${base}:s`, now);
      const f = state.fields;
      const counted = plan.kind !== 'internal';
      const requestRate = decay(num(f.get('rv')), opt(f.get('rt')), now, WINDOWS.requestTauMs) + (counted ? 1 : 0);
      const actionRate = decay(num(f.get('av')), opt(f.get('at')), now, WINDOWS.actionTauMs) + (plan.kind === 'action' ? 1 : 0);
      const conversionRate =
        decay(num(f.get('cv')), opt(f.get('ct')), now, WINDOWS.visitorConversionTauMs) + (plan.kind === 'conversion' ? 1 : 0);

      let samples = num(f.get('gn'));
      let mean = num(f.get('gm'));
      let variance = num(f.get('gs'));
      const lastGap = opt(f.get('gl'));
      if (plan.kind === 'page') {
        if (lastGap !== undefined) {
          const gap = now - lastGap;
          if (gap > 0 && gap < WINDOWS.timingMaxGapMs) {
            if (samples === 0) {
              mean = gap;
              variance = 0;
            } else {
              const delta = gap - mean;
              mean += WINDOWS.timingAlpha * delta;
              variance = (1 - WINDOWS.timingAlpha) * (variance + WINDOWS.timingAlpha * delta * delta);
            }
            samples = Math.min(samples + 1, 1000);
          }
        }
        f.set('gl', now);
      }

      let sessionStartedAt = opt(f.get('ss'));
      let sessionDepth = num(f.get('sd'));
      let sessionCount = num(f.get('sn'));
      const sessionLast = opt(f.get('sl'));
      if (f.get('sid') !== visitor.sessionId || sessionLast === undefined || sessionStartedAt === undefined || now - sessionLast > plan.sessionIdleMs) {
        sessionStartedAt = now;
        sessionDepth = 0;
        sessionCount += 1;
      }
      if (plan.kind === 'page') sessionDepth += 1;

      let paidClicks5m = 0;
      let paidClicks1h = 0;
      if (plan.paidClick) {
        paidClicks5m = this.distinct(`${base}:p5:${short}`, `${base}:p5:${short - 1}`, plan.paidClick, now, WINDOWS.paidShortMs * 2);
        paidClicks1h = this.distinct(`${base}:p60:${long}`, `${base}:p60:${long - 1}`, plan.paidClick, now, WINDOWS.paidLongMs * 2);
      }
      if (plan.attribution) f.set('pa', plan.attribution);

      for (const [key, value] of [
        ['rv', requestRate], ['rt', now], ['av', actionRate], ['at', now], ['cv', conversionRate], ['ct', now],
        ['gn', samples], ['gm', mean], ['gs', variance], ['sid', visitor.sessionId], ['ss', sessionStartedAt],
        ['sl', now], ['sd', sessionDepth], ['sn', sessionCount],
      ] as const) {
        f.set(key, value);
      }

      const clearanceUntil = opt(f.get('cl'));
      const restrictedUntil = opt(f.get('ru'));
      const ttl = visitor.fresh ? TTLS.provisionalVisitorMs : TTLS.visitorMs;
      this.keepAlive(state, now, Math.max(ttl, (restrictedUntil ?? 0) - now, (clearanceUntil ?? 0) - now));

      const pa = f.get('pa');
      visitorObservation = {
        requestRate,
        actionRate,
        conversionRate,
        timing: { samples, meanMs: mean, cv: coefficientOfVariation(mean, variance) },
        sessionStartedAt,
        sessionDepth,
        sessionCount,
        scriptVerifiedAt: opt(f.get('js')),
        interactionAt: opt(f.get('ix')),
        automationFlags: num(f.get('af')),
        clearanceUntil,
        restrictedUntil,
        strikes: decay(num(f.get('kv')), opt(f.get('kt')), now, WINDOWS.strikeTauMs),
        acceptedConversions: num(f.get('co')),
        paidClicks5m,
        paidClicks1h,
        attribution: typeof pa === 'string' ? pa : undefined,
      };
    }

    const addressBase = `i:${plan.addressKey}`;
    const address = this.entry(`${addressBase}:s`, now);
    const addressRate = decay(num(address.fields.get('rv')), opt(address.fields.get('rt')), now, WINDOWS.requestTauMs) + 1;
    address.fields.set('rv', addressRate);
    address.fields.set('rt', now);
    const addressRestricted = opt(address.fields.get('ru'));
    this.keepAlive(address, now, Math.max(TTLS.addressMs, (addressRestricted ?? 0) - now));
    if (visitor?.established) this.add(`${addressBase}:e:${population}`, visitor.id, now, WINDOWS.populationMs * 2);
    const addressPopulation = this.union(`${addressBase}:e:${population}`, `${addressBase}:e:${population - 1}`, now);

    const networkBase = `n:${plan.networkKey}`;
    const network = this.entry(`${networkBase}:s`, now);
    const networkRate = decay(num(network.fields.get('rv')), opt(network.fields.get('rt')), now, WINDOWS.requestTauMs) + 1;
    const networkConversions =
      decay(num(network.fields.get('cv')), opt(network.fields.get('ct')), now, WINDOWS.networkConversionTauMs) +
      (plan.kind === 'conversion' ? 1 : 0);
    network.fields.set('rv', networkRate);
    network.fields.set('rt', now);
    network.fields.set('cv', networkConversions);
    network.fields.set('ct', now);
    network.expiresAt = now + TTLS.networkMs;
    const fresh = bucket(now, WINDOWS.freshMs);
    if (plan.paidClick) {
      this.add(`${networkBase}:p5:${short}`, plan.paidClick, now, WINDOWS.paidShortMs * 2);
      this.add(`${networkBase}:p60:${long}`, plan.paidClick, now, WINDOWS.paidLongMs * 2);
    }
    if (visitor?.fresh) this.add(`${networkBase}:f:${fresh}`, visitor.id, now, WINDOWS.freshMs * 2);
    if (visitor?.established) this.add(`${networkBase}:e:${population}`, visitor.id, now, WINDOWS.populationMs * 2);

    let asnPaidClicks5m: number | undefined;
    if (plan.paidClick && plan.asn !== undefined) {
      asnPaidClicks5m = this.distinct(`a:${plan.asn}:p5:${short}`, `a:${plan.asn}:p5:${short - 1}`, plan.paidClick, now, WINDOWS.paidShortMs * 2);
    }
    let clickVisitors: number | undefined;
    if (plan.paidClick && visitor) {
      const reuse = bucket(now, WINDOWS.clickReuseMs);
      clickVisitors = this.distinct(`c:${plan.paidClick}:v:${reuse}`, `c:${plan.paidClick}:v:${reuse - 1}`, visitor.id, now, WINDOWS.clickReuseMs * 2);
    }

    return Promise.resolve({
      source: 'memory',
      visitor: visitorObservation,
      address: {
        requestRate: addressRate,
        population: addressPopulation,
        restrictedUntil: addressRestricted,
        strikes: decay(num(address.fields.get('kv')), opt(address.fields.get('kt')), now, WINDOWS.strikeTauMs),
      },
      network: {
        requestRate: networkRate,
        conversionRate: networkConversions,
        paidClicks5m: this.union(`${networkBase}:p5:${short}`, `${networkBase}:p5:${short - 1}`, now),
        paidClicks1h: this.union(`${networkBase}:p60:${long}`, `${networkBase}:p60:${long - 1}`, now),
        freshIdentities: this.union(`${networkBase}:f:${fresh}`, `${networkBase}:f:${fresh - 1}`, now),
        population: this.union(`${networkBase}:e:${population}`, `${networkBase}:e:${population - 1}`, now),
      },
      asnPaidClicks5m,
      clickVisitors,
    });
  }

  patchVisitor(visitorId: string, patch: VisitorPatch, now: number): Promise<void> {
    const state = this.entry(`v:${visitorId}:s`, now);
    if (patch.scriptVerifiedAt !== undefined) state.fields.set('js', patch.scriptVerifiedAt);
    if (patch.interactionAt !== undefined) state.fields.set('ix', patch.interactionAt);
    if (patch.automationFlags !== undefined) state.fields.set('af', patch.automationFlags);
    if (patch.clearanceUntil !== undefined) state.fields.set('cl', patch.clearanceUntil);
    if (patch.acceptedConversion) state.fields.set('co', num(state.fields.get('co')) + 1);
    this.keepAlive(state, now, Math.max(TTLS.visitorMs, (patch.clearanceUntil ?? 0) - now));
    return Promise.resolve();
  }

  restrict(target: RestrictionTarget, until: number, now: number): Promise<void> {
    const apply = (key: string, ttl: number): void => {
      const state = this.entry(key, now);
      state.fields.set('ru', Math.max(num(state.fields.get('ru')), until));
      state.fields.set('kv', decay(num(state.fields.get('kv')), opt(state.fields.get('kt')), now, WINDOWS.strikeTauMs) + 1);
      state.fields.set('kt', now);
      this.keepAlive(state, now, Math.max(ttl, until - now));
    };
    if (target.visitorId) apply(`v:${target.visitorId}:s`, TTLS.visitorMs);
    if (target.addressKey) apply(`i:${target.addressKey}:s`, TTLS.addressMs);
    return Promise.resolve();
  }

  claimOnce(key: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    const existing = this.live(`o:${key}`, now);
    if (existing) return Promise.resolve(false);
    const entry = this.entry(`o:${key}`, now);
    entry.expiresAt = now + ttlMs;
    return Promise.resolve(true);
  }

  countGlobalConversion(now: number): Promise<number> {
    const state = this.entry('g:conversions', now);
    const value = decay(num(state.fields.get('v')), opt(state.fields.get('t')), now, WINDOWS.globalConversionTauMs) + 1;
    state.fields.set('v', value);
    state.fields.set('t', now);
    state.expiresAt = now + TTLS.globalMs;
    return Promise.resolve(value);
  }

  ping(): Promise<boolean> {
    return Promise.resolve(true);
  }

  close(): Promise<void> {
    this.entries.clear();
    return Promise.resolve();
  }

  sweep(now: number): number {
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  private live(key: string, now: number): Entry | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= now) {
      this.entries.delete(key);
      return undefined;
    }
    return entry;
  }

  private entry(key: string, now: number): Entry {
    const existing = this.live(key, now);
    if (existing) {
      this.entries.delete(key);
      this.entries.set(key, existing);
      return existing;
    }
    const created: Entry = { expiresAt: now + TTLS.addressMs, fields: new Map(), members: new Set() };
    this.entries.set(key, created);
    if (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    return created;
  }

  private keepAlive(entry: Entry, now: number, ttl: number): void {
    entry.expiresAt = Math.max(entry.expiresAt, now + ttl);
  }

  private add(key: string, member: string, now: number, ttl: number): void {
    const entry = this.entry(key, now);
    if (entry.members.size < this.maxMembers) entry.members.add(member);
    entry.expiresAt = now + ttl;
  }

  private union(current: string, previous: string, now: number): number {
    const a = this.live(current, now)?.members;
    const b = this.live(previous, now)?.members;
    if (!a || a.size === 0) return b?.size ?? 0;
    if (!b || b.size === 0) return a.size;
    const [small, large] = a.size < b.size ? [a, b] : [b, a];
    let count = large.size;
    for (const member of small) if (!large.has(member)) count += 1;
    return count;
  }

  private distinct(current: string, previous: string, member: string, now: number, ttl: number): number {
    this.add(current, member, now, ttl);
    return this.union(current, previous, now);
  }
}

function num(value: number | string | undefined): number {
  const parsed = typeof value === 'number' ? value : Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function opt(value: number | string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}
