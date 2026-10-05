import type { IntegrityStore, Observation, ObservationPlan, RestrictionTarget, VisitorPatch } from './types.ts';

export class CircuitBreaker {
  private failures = 0;
  private openedAt: number | undefined;
  private probing = false;
  private readonly threshold: number;
  private readonly cooldownMs: number;
  private readonly now: () => number;

  constructor(options: { threshold?: number; cooldownMs?: number; now?: () => number } = {}) {
    this.threshold = options.threshold ?? 3;
    this.cooldownMs = options.cooldownMs ?? 5000;
    this.now = options.now ?? Date.now;
  }

  get open(): boolean {
    return this.openedAt !== undefined;
  }

  allow(): boolean {
    if (this.openedAt === undefined) return true;
    if (this.probing || this.now() - this.openedAt < this.cooldownMs) return false;
    this.probing = true;
    return true;
  }

  success(): void {
    this.failures = 0;
    this.openedAt = undefined;
    this.probing = false;
  }

  failure(): void {
    this.probing = false;
    this.failures += 1;
    if (this.failures >= this.threshold) this.openedAt = this.now();
  }
}

export type StoreOperation = 'observe' | 'patchVisitor' | 'restrict' | 'claimOnce' | 'countGlobalConversion';

export class ResilientStore implements IntegrityStore {
  private readonly primary: IntegrityStore | undefined;
  private readonly fallback: IntegrityStore;
  private readonly breaker: CircuitBreaker;
  private readonly onFallback: (operation: StoreOperation, error: unknown) => void;

  constructor(options: {
    primary: IntegrityStore | undefined;
    fallback: IntegrityStore;
    breaker?: CircuitBreaker;
    onFallback?: (operation: StoreOperation, error: unknown) => void;
  }) {
    this.primary = options.primary;
    this.fallback = options.fallback;
    this.breaker = options.breaker ?? new CircuitBreaker();
    this.onFallback = options.onFallback ?? (() => undefined);
  }

  async health(): Promise<'shared' | 'local'> {
    if (!this.primary) return 'local';
    try {
      return (await this.primary.ping()) ? 'shared' : 'local';
    } catch {
      return 'local';
    }
  }

  ping(): Promise<boolean> {
    return this.health().then((state) => state === 'shared');
  }

  observe(plan: ObservationPlan): Promise<Observation> {
    return this.run('observe', (store) => store.observe(plan));
  }

  patchVisitor(visitorId: string, patch: VisitorPatch, now: number): Promise<void> {
    return this.run('patchVisitor', (store) => store.patchVisitor(visitorId, patch, now));
  }

  restrict(target: RestrictionTarget, until: number, now: number): Promise<void> {
    return this.run('restrict', (store) => store.restrict(target, until, now));
  }

  claimOnce(key: string, ttlMs: number): Promise<boolean> {
    return this.run('claimOnce', (store) => store.claimOnce(key, ttlMs));
  }

  countGlobalConversion(now: number): Promise<number> {
    return this.run('countGlobalConversion', (store) => store.countGlobalConversion(now));
  }

  async close(): Promise<void> {
    await Promise.allSettled([this.primary?.close(), this.fallback.close()]);
  }

  private async run<T>(operation: StoreOperation, action: (store: IntegrityStore) => Promise<T>): Promise<T> {
    if (this.primary && this.breaker.allow()) {
      try {
        const result = await action(this.primary);
        this.breaker.success();
        return result;
      } catch (error) {
        this.breaker.failure();
        this.onFallback(operation, error);
      }
    }
    return action(this.fallback);
  }
}
