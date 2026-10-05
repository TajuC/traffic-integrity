import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { describe, test } from 'node:test';
import { RedisStore } from '../src/store/redis-store.ts';
import { Clock, gclid, startHarness, type Harness, type HttpResponse } from './helpers/harness.ts';

const REDIS_URL = process.env.TEST_REDIS_URL;

async function redisStore(prefix: string): Promise<RedisStore> {
  const store = new RedisStore({ url: REDIS_URL ?? 'redis://127.0.0.1:1', keyPrefix: prefix, commandTimeoutMs: 1000 });
  await store.ready(5000);
  return store;
}

async function instances(count: number): Promise<{ apps: Harness[]; close: () => Promise<void> }> {
  const prefix = `e2e:${randomUUID().slice(0, 8)}:`;
  const clock = new Clock();
  const apps: Harness[] = [];
  for (let i = 0; i < count; i += 1) apps.push(await startHarness({ store: await redisStore(prefix), clock }));
  return { apps, close: async () => void (await Promise.all(apps.map((app) => app.close()))) };
}

describe('distributed protection with Redis', { skip: REDIS_URL ? undefined : 'TEST_REDIS_URL is not set' }, () => {
  test('a restriction applied by one instance is enforced by another and expires on schedule', async () => {
    const { apps, close } = await instances(2);
    try {
      const [first, second] = apps as [Harness, Harness];
      const onFirst = first.browser('198.51.100.60');
      const statuses: number[] = [];
      for (let i = 0; i < 330; i += 1) statuses.push((await onFirst.visit('/')).status);
      assert.equal(statuses.at(-1), 429);

      const onSecond = second.browser('198.51.100.60');
      for (const [name, value] of onFirst.jar) onSecond.jar.set(name, value);
      assert.equal((await onSecond.visit('/')).status, 429, 'the second instance reads the shared restriction');

      first.clock.advance(11 * 60_000);
      assert.equal((await onSecond.visit('/')).status, 200);
    } finally {
      await close();
    }
  });

  test('requests spread across instances share exact counters', async () => {
    const { apps, close } = await instances(3);
    try {
      const browsers = apps.map((app) => app.browser('198.51.100.61'));
      await browsers[0]!.visit('/');
      for (const browser of browsers.slice(1)) for (const [name, value] of browsers[0]!.jar) browser.jar.set(name, value);
      const results: HttpResponse[] = await Promise.all(Array.from({ length: 240 }, (_, i) => browsers[i % 3]!.visit('/')));
      assert.ok(results.every((response) => response.status === 200 || response.status === 429));
      const statuses = [];
      for (let i = 0; i < 70; i += 1) statuses.push((await browsers[i % 3]!.visit('/')).status);
      assert.equal(statuses.at(-1), 429, 'the combined rate across instances crosses the extreme threshold');
    } finally {
      await close();
    }
  });

  test('a paid-click flood spread across instances is detected on the shared network counters', async () => {
    const { apps, close } = await instances(2);
    try {
      let last: HttpResponse | undefined;
      for (let i = 1; i <= 50; i += 1) last = await apps[i % 2]!.browser(`203.0.113.${i}`).visit(`/?gclid=${gclid(`redis${i}`)}`);
      assert.equal(last?.status, 403);
    } finally {
      await close();
    }
  });
});
