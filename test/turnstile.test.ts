import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { CloudflareTurnstile } from '../src/challenge/turnstile.ts';
import { MemoryStore } from '../src/store/memory-store.ts';
import { START } from './helpers/harness.ts';

interface Call {
  readonly body: Record<string, unknown>;
  readonly signal: AbortSignal | undefined;
}

function hang(signal: AbortSignal | undefined): Promise<Response> {
  return new Promise((_resolve, reject) => {
    const fail = () => {
      const reason = signal?.reason;
      reject(reason instanceof Error ? reason : Object.assign(new Error('timed out'), { name: 'TimeoutError' }));
    };
    const timer = setTimeout(fail, 80);
    if (!signal) return;
    if (signal.aborted) {
      clearTimeout(timer);
      fail();
      return;
    }
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        fail();
      },
      { once: true },
    );
  });
}

function verifier(responder: (call: Call, attempt: number) => Response | Promise<Response>, now = START, allowTestKeys = false) {
  const calls: Call[] = [];
  const fetchStub = ((_url: string | URL | Request, init?: RequestInit) => {
    const call = { body: JSON.parse(typeof init?.body === 'string' ? init.body : '{}') as Record<string, unknown>, signal: init?.signal ?? undefined };
    calls.push(call);
    return Promise.resolve(responder(call, calls.length));
  }) as typeof fetch;
  const turnstile = new CloudflareTurnstile({
    secretKey: 'secret',
    hostnames: new Set(['www.example.com']),
    timeoutMs: 50,
    maxAgeSeconds: 300,
    store: new MemoryStore(),
    allowTestKeys,
    fetch: fetchStub,
    now: () => now,
  });
  return { turnstile, calls };
}

const testingKeyResult = (): Response =>
  Response.json({ success: true, challenge_ts: new Date(START).toISOString(), hostname: 'example.com', 'error-codes': [], metadata: { result_with_testing_key: true } });

const ok = (overrides: Record<string, unknown> = {}): Response =>
  Response.json({ success: true, challenge_ts: new Date(START - 10_000).toISOString(), hostname: 'www.example.com', action: 'lead_quote', cdata: 'bound', 'error-codes': [], ...overrides });

const check = { token: 'token-value-1', remoteIp: '203.0.113.5', action: 'lead_quote', cdata: 'bound' };

describe('turnstile verification', () => {
  test('passes a valid token and sends the remote ip and an idempotency key', async () => {
    const { turnstile, calls } = verifier(() => ok());
    assert.deepEqual(await turnstile.verify(check), { status: 'passed', challengeTs: START - 10_000, hostname: 'www.example.com' });
    assert.equal(calls[0]?.body.remoteip, '203.0.113.5');
    assert.match(String(calls[0]?.body.idempotency_key), /^[0-9a-f-]{36}$/);
  });

  test('rejects hostname, action and cdata mismatches', async () => {
    assert.deepEqual(await verifier(() => ok({ hostname: 'evil.example' })).turnstile.verify(check), { status: 'failed', reason: 'hostname_mismatch' });
    assert.deepEqual(await verifier(() => ok({ action: 'login' })).turnstile.verify(check), { status: 'failed', reason: 'action_mismatch' });
    assert.deepEqual(await verifier(() => ok({ cdata: 'other' })).turnstile.verify(check), { status: 'failed', reason: 'cdata_mismatch' });
  });

  test('rejects an expired challenge even when Cloudflare reports success', async () => {
    const stale = verifier(() => ok({ challenge_ts: new Date(START - 301_000).toISOString() }));
    assert.deepEqual(await stale.turnstile.verify(check), { status: 'failed', reason: 'expired' });
    const duplicate = verifier(() => Response.json({ success: false, 'error-codes': ['timeout-or-duplicate'] }));
    assert.deepEqual(await duplicate.turnstile.verify(check), { status: 'failed', reason: 'expired' });
  });

  test('blocks replayed tokens locally before calling Cloudflare again', async () => {
    const { turnstile, calls } = verifier(() => ok());
    await turnstile.verify(check);
    assert.deepEqual(await turnstile.verify(check), { status: 'failed', reason: 'replayed' });
    assert.equal(calls.length, 1);
  });

  test('reports the service as unavailable on timeouts and internal errors', async () => {
    const slow = verifier((call) => hang(call.signal));
    assert.deepEqual(await slow.turnstile.verify(check), { status: 'unavailable', reason: 'timeout' });
    const internal = verifier(() => Response.json({ success: false, 'error-codes': ['internal-error'] }));
    assert.deepEqual(await internal.turnstile.verify(check), { status: 'unavailable', reason: 'internal-error' });
    const misconfigured = verifier(() => Response.json({ success: false, 'error-codes': ['invalid-input-secret'] }));
    assert.deepEqual(await misconfigured.turnstile.verify(check), { status: 'unavailable', reason: 'misconfigured' });
  });

  test('retries a server error once with the same idempotency key', async () => {
    const { turnstile, calls } = verifier((_call, attempt) => (attempt === 1 ? new Response('busy', { status: 503 }) : ok()));
    assert.equal((await turnstile.verify(check)).status, 'passed');
    assert.equal(calls.length, 2);
    assert.equal(calls[0]?.body.idempotency_key, calls[1]?.body.idempotency_key);
  });

  test('accepts Cloudflare testing keys only outside production', async () => {
    const development = verifier(() => testingKeyResult(), START, true);
    assert.equal((await development.turnstile.verify(check)).status, 'passed');
    const production = verifier(() => testingKeyResult(), START, false);
    assert.deepEqual(await production.turnstile.verify(check), { status: 'unavailable', reason: 'testing_key' });
  });

  test('rejects missing and malformed tokens without a network call', async () => {
    const { turnstile, calls } = verifier(() => ok());
    assert.deepEqual(await turnstile.verify({ ...check, token: undefined }), { status: 'failed', reason: 'missing' });
    assert.deepEqual(await turnstile.verify({ ...check, token: 'has spaces in it' }), { status: 'failed', reason: 'malformed' });
    assert.equal(calls.length, 0);
  });
});
