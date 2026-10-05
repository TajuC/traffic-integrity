import { loadConfig } from '../src/config/env.ts';
import { inspectRequest } from '../src/guard/inspect.ts';
import { NetworkIntel } from '../src/net/network-intel.ts';
import { createRuntime } from '../src/runtime.ts';
import { RedisStore } from '../src/store/redis-store.ts';
import { createLogger } from '../src/telemetry/logger.ts';
import { BASE_ENV, CHROME, dataset, NAVIGATE } from './helpers/harness.ts';

async function run(label: string, primary: RedisStore | null): Promise<void> {
  const runtime = await createRuntime(loadConfig({ ...BASE_ENV, ASSESSMENT_LOG_SAMPLE_RATE: '0' }), {
    logger: createLogger({ level: 'silent' }),
    primaryStore: primary,
    intel: new NetworkIntel({ dataset: dataset() }),
    db: null,
    turnstile: null,
    background: false,
  });
  const samples: number[] = [];
  for (let i = 0; i < 6000; i += 1) {
    const ip = `198.51.${(i >> 8) & 255}.${i & 255}`;
    const started = performance.now();
    await inspectRequest(runtime, {
      method: 'GET',
      path: '/',
      url: i % 5 === 0 ? `/?gclid=Cj0KCQjwBench${i}Click_BwE` : '/',
      headers: { ...CHROME, ...NAVIGATE, 'x-forwarded-for': ip },
      socketAddress: '127.0.0.1',
      authenticated: false,
    });
    if (i >= 1000) samples.push(performance.now() - started);
  }
  samples.sort((a, b) => a - b);
  const at = (q: number) => samples[Math.floor(q * (samples.length - 1))]!.toFixed(3);
  process.stdout.write(`${label}: p50 ${at(0.5)} ms, p95 ${at(0.95)} ms, p99 ${at(0.99)} ms over ${samples.length} requests\n`);
  await runtime.close();
}

await run('memory store', null);
if (process.env.TEST_REDIS_URL) {
  const store = new RedisStore({ url: process.env.TEST_REDIS_URL, keyPrefix: 'bench:', commandTimeoutMs: 1000 });
  await store.ready(5000);
  await run('redis store ', store);
}
