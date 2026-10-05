import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { MemoryStore } from '../src/store/memory-store.ts';
import { RedisStore } from '../src/store/redis-store.ts';
import { CircuitBreaker, ResilientStore } from '../src/store/resilient-store.ts';
import type { IntegrityStore, ObservationPlan } from '../src/store/types.ts';
import { FailingStore, START } from './helpers/harness.ts';

const REDIS_URL = process.env.TEST_REDIS_URL;

function plan(overrides: Partial<ObservationPlan> & { visitorId?: string; fresh?: boolean; established?: boolean } = {}): ObservationPlan {
  const { visitorId, fresh, established, ...rest } = overrides;
  return {
    now: START,
    kind: 'page',
    sessionIdleMs: 30 * 60_000,
    visitor: visitorId === undefined ? undefined : { id: visitorId, sessionId: 'session-1', fresh: fresh ?? false, established: established ?? false },
    addressKey: `addr-${randomUUID()}`,
    networkKey: `net-${randomUUID()}`,
    asn: undefined,
    paidClick: undefined,
    attribution: undefined,
    ...rest,
  };
}

function contract(name: string, create: () => Promise<IntegrityStore>, options: { skip?: string } = {}): void {
  describe(`${name} store contract`, { skip: options.skip }, () => {
    let store: IntegrityStore;
    before(async () => {
      store = await create();
    });
    after(async () => {
      await store.close();
    });

    test('counts requests with decay, tracks sessions and depth', async () => {
      const visitorId = randomUUID();
      const base = plan({ visitorId });
      let last;
      for (let i = 0; i < 5; i += 1) last = await store.observe({ ...base, now: START + i * 1000 });
      assert.ok(last?.visitor);
      assert.ok(last.visitor.requestRate > 4.8 && last.visitor.requestRate <= 5, `rate ${last.visitor.requestRate}`);
      assert.equal(last.visitor.sessionDepth, 5);
      assert.equal(last.visitor.sessionCount, 1);
      assert.equal(last.visitor.timing.samples, 4);
      assert.ok(last.visitor.timing.cv < 0.01, 'evenly spaced requests have near-zero variation');

      const later = await store.observe({ ...base, now: START + 45 * 60_000 });
      assert.equal(later.visitor?.sessionCount, 2, 'idle session rolls over');
      assert.equal(later.visitor?.sessionDepth, 1);
      assert.ok((later.visitor?.requestRate ?? 99) < 1.1, 'request rate decays after inactivity');
    });

    test('counts distinct paid clicks per visitor, network and click reuse', async () => {
      const visitorId = randomUUID();
      const base = plan({ visitorId, asn: 64500 });
      await store.observe({ ...base, paidClick: 'click-a' });
      await store.observe({ ...base, paidClick: 'click-a', now: START + 1000 });
      const third = await store.observe({ ...base, paidClick: 'click-b', now: START + 2000 });
      assert.equal(third.visitor?.paidClicks5m, 2);
      assert.equal(third.visitor?.paidClicks1h, 2);
      assert.equal(third.network.paidClicks5m, 2);
      assert.equal(third.asnPaidClicks5m, 2);

      const other = await store.observe({ ...plan({ visitorId: randomUUID(), networkKey: base.networkKey }), paidClick: 'click-b', now: START + 3000 });
      assert.equal(other.clickVisitors, 2, 'the same click id seen from two identities');
    });

    test('tracks fresh identities and the established population of a network', async () => {
      const networkKey = `net-${randomUUID()}`;
      for (let i = 0; i < 6; i += 1) await store.observe(plan({ visitorId: randomUUID(), fresh: true, networkKey, now: START + i }));
      const established = await store.observe(plan({ visitorId: randomUUID(), established: true, networkKey, now: START + 10 }));
      assert.equal(established.network.freshIdentities, 6);
      assert.equal(established.network.population, 1);
    });

    test('applies restrictions with strikes and lets them expire', async () => {
      const visitorId = randomUUID();
      const addressKey = `addr-${randomUUID()}`;
      await store.restrict({ visitorId, addressKey }, START + 60_000, START);
      const restricted = await store.observe(plan({ visitorId, addressKey, now: START + 1000 }));
      assert.equal(restricted.visitor?.restrictedUntil, START + 60_000);
      assert.equal(restricted.address.restrictedUntil, START + 60_000);
      assert.ok((restricted.visitor?.strikes ?? 0) > 0.99);
      const expired = await store.observe(plan({ visitorId, addressKey, now: START + 61_000 }));
      assert.ok((expired.visitor?.restrictedUntil ?? 0) <= START + 61_000);
    });

    test('patches visitor state used by trust signals', async () => {
      const visitorId = randomUUID();
      await store.observe(plan({ visitorId }));
      await store.patchVisitor(visitorId, { scriptVerifiedAt: START + 5, interactionAt: START + 6, automationFlags: 1, clearanceUntil: START + 600_000, acceptedConversion: true }, START);
      const seen = await store.observe(plan({ visitorId, now: START + 10 }));
      assert.equal(seen.visitor?.scriptVerifiedAt, START + 5);
      assert.equal(seen.visitor?.interactionAt, START + 6);
      assert.equal(seen.visitor?.automationFlags, 1);
      assert.equal(seen.visitor?.clearanceUntil, START + 600_000);
      assert.equal(seen.visitor?.acceptedConversions, 1);
    });

    test('claims one-time keys exactly once', async () => {
      const key = randomUUID();
      const results = await Promise.all(Array.from({ length: 20 }, () => store.claimOnce(key, 60_000)));
      assert.equal(results.filter(Boolean).length, 1);
    });

    test('keeps counters exact under concurrent requests', async () => {
      const visitorId = randomUUID();
      const base = plan({ visitorId });
      await Promise.all(Array.from({ length: 200 }, () => store.observe(base)));
      const final = await store.observe({ ...base, kind: 'internal' });
      assert.ok(Math.abs((final.visitor?.requestRate ?? 0) - 200) < 1e-6, `rate ${final.visitor?.requestRate}`);
      assert.equal(final.visitor?.sessionDepth, 200);
      assert.equal(final.address.requestRate, 201);
    });

    test('decays the global conversion counter', async () => {
      const first = await store.countGlobalConversion(START);
      const second = await store.countGlobalConversion(START + 1);
      assert.ok(second > first);
    });
  });
}

contract('memory', () => Promise.resolve(new MemoryStore()));
contract(
  'redis',
  async () => {
    const store = new RedisStore({ url: REDIS_URL ?? 'redis://127.0.0.1:1', keyPrefix: `test:${randomUUID().slice(0, 8)}:`, commandTimeoutMs: 1000 });
    await store.ready(5000);
    return store;
  },
  REDIS_URL ? {} : { skip: 'TEST_REDIS_URL is not set' },
);

describe('resilient store', () => {
  test('falls back to the local store when the shared store fails and opens the circuit', async () => {
    const failing = new FailingStore();
    let now = START;
    const fallbacks: string[] = [];
    const store = new ResilientStore({
      primary: failing,
      fallback: new MemoryStore(),
      breaker: new CircuitBreaker({ threshold: 2, cooldownMs: 5000, now: () => now }),
      onFallback: (operation) => fallbacks.push(operation),
    });
    const visitorId = randomUUID();
    for (let i = 0; i < 5; i += 1) {
      const result = await store.observe(plan({ visitorId }));
      assert.equal(result.source, 'memory');
    }
    assert.equal(failing.calls, 2, 'circuit opens after the threshold and stops hitting the failing store');
    now += 6000;
    await store.observe(plan({ visitorId }));
    assert.equal(failing.calls, 3, 'a single probe is attempted after the cooldown');
    assert.equal(await store.health(), 'local');
    assert.deepEqual(new Set(fallbacks), new Set(['observe']));
  });
});
