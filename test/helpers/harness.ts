import { randomBytes } from 'node:crypto';
import { request as httpRequest, type IncomingHttpHeaders, type OutgoingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Writable } from 'node:stream';
import { createApp } from '../../src/app.ts';
import type { TurnstileCheck, TurnstileOutcome, TurnstileVerifier } from '../../src/challenge/turnstile.ts';
import { loadConfig } from '../../src/config/env.ts';
import { migrate } from '../../src/db/migrate.ts';
import { openDatabase, type SqlClient } from '../../src/db/sql.ts';
import { createIntegrityGuard, type IntegrityGuard } from '../../src/http/guard.ts';
import type { AcceptedLead } from '../../src/conversion/pipeline.ts';
import type { DnsResolver } from '../../src/net/crawler.ts';
import { NetworkIntel, type NetworkDataset } from '../../src/net/network-intel.ts';
import { createRuntime, type Runtime } from '../../src/runtime.ts';
import type { IntegrityStore } from '../../src/store/types.ts';
import { createLogger } from '../../src/telemetry/logger.ts';

export const START = Date.parse('2026-10-05T12:00:00.000Z');

export class Clock {
  now: number;

  constructor(start = START) {
    this.now = start;
  }

  readonly read = (): number => this.now;

  advance(ms: number): void {
    this.now += ms;
  }
}

export const TEST_SECRET = 'test-secret-value-that-is-long-enough-1234567890';

export const BASE_ENV: Readonly<Record<string, string>> = {
  NODE_ENV: 'test',
  PUBLIC_ORIGIN: 'http://localhost',
  INTEGRITY_SECRET: TEST_SECRET,
  ENFORCEMENT_MODE: 'enforce',
  LOG_LEVEL: 'silent',
  TRUSTED_PROXIES: 'loopback',
  CRAWLER_REVERSE_DNS: 'false',
  TURNSTILE_SITE_KEY: '1x00000000000000000000AA',
  TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA',
  CONVERSION_HOLD_MINUTES: '60',
  ADMIN_TOKEN: 'admin-token-for-tests-0123456789abcdef',
  EXPORT_USERNAME: 'google-ads',
  EXPORT_PASSWORD: 'export-password-0123456789',
};

export function dataset(generatedAt = new Date(START).toISOString()): NetworkDataset {
  return {
    version: 1,
    generatedAt,
    cloudflare: [],
    crawlers: [
      ['66.249.64.0/27', 'google-common'],
      ['66.249.79.0/27', 'google-special'],
      ['2001:4860:4801:10::/64', 'google-common'],
      ['157.55.39.0/24', 'bing'],
    ],
    hosting: [
      ['3.0.0.0/9', 'amazon'],
      ['34.64.0.0/10', 'google-cloud'],
    ],
    relays: [['172.224.226.0/27', 'apple-private-relay']],
    tor: ['185.220.101.1/32'],
  };
}

export class FakeTurnstile implements TurnstileVerifier {
  mode: 'pass' | 'fail' | 'expired' | 'unavailable' = 'pass';
  readonly calls: TurnstileCheck[] = [];
  private readonly used = new Set<string>();

  verify(check: TurnstileCheck): Promise<TurnstileOutcome> {
    this.calls.push(check);
    if (!check.token) return Promise.resolve({ status: 'failed', reason: 'missing' });
    if (this.used.has(check.token)) return Promise.resolve({ status: 'failed', reason: 'replayed' });
    this.used.add(check.token);
    switch (this.mode) {
      case 'pass':
        return Promise.resolve({ status: 'passed', challengeTs: Date.now(), hostname: 'localhost' });
      case 'fail':
        return Promise.resolve({ status: 'failed', reason: 'rejected' });
      case 'expired':
        return Promise.resolve({ status: 'failed', reason: 'expired' });
      case 'unavailable':
        return Promise.resolve({ status: 'unavailable', reason: 'timeout' });
    }
  }
}

export class FailingStore implements IntegrityStore {
  calls = 0;

  private fail(): Promise<never> {
    this.calls += 1;
    return Promise.reject(new Error('connection refused'));
  }

  observe(): Promise<never> {
    return this.fail();
  }

  patchVisitor(): Promise<never> {
    return this.fail();
  }

  restrict(): Promise<never> {
    return this.fail();
  }

  claimOnce(): Promise<never> {
    return this.fail();
  }

  countGlobalConversion(): Promise<never> {
    return this.fail();
  }

  ping(): Promise<never> {
    return this.fail();
  }

  close(): Promise<void> {
    return Promise.resolve();
  }
}

export interface HarnessOptions {
  readonly env?: Readonly<Record<string, string>>;
  readonly turnstile?: TurnstileVerifier | null;
  readonly store?: IntegrityStore | null;
  readonly db?: SqlClient | null;
  readonly intel?: NetworkIntel;
  readonly dns?: DnsResolver;
  readonly clock?: Clock;
}

export type LoggedEvent = Record<string, unknown> & { readonly event?: string };

export interface Harness {
  readonly runtime: Runtime;
  readonly guard: IntegrityGuard;
  readonly clock: Clock;
  readonly turnstile: FakeTurnstile;
  readonly leads: AcceptedLead[];
  readonly events: LoggedEvent[];
  readonly port: number;
  eventsNamed(name: string): LoggedEvent[];
  browser(ip: string, profile?: Readonly<Record<string, string>>): Browser;
  raw(method: string, path: string, headers: OutgoingHttpHeaders, body?: string): Promise<HttpResponse>;
  close(): Promise<void>;
}

export async function emptyTestDatabase(): Promise<SqlClient> {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) return openDatabase({ url: 'pglite://memory', ssl: 'disable', poolMax: 1 });
  const schema = `ti_test_${randomBytes(4).toString('hex')}`;
  const admin = await openDatabase({ url, ssl: 'disable', poolMax: 1 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  await admin.close();
  return openDatabase({ url, ssl: 'disable', poolMax: 2, searchPath: schema });
}

export async function sharedDatabase(): Promise<SqlClient> {
  const db = await emptyTestDatabase();
  await migrate(db);
  return db;
}

export async function startHarness(options: HarnessOptions = {}): Promise<Harness> {
  const clock = options.clock ?? new Clock();
  const turnstile = options.turnstile instanceof FakeTurnstile ? options.turnstile : new FakeTurnstile();
  const config = loadConfig({ ...BASE_ENV, ...options.env });
  const events: LoggedEvent[] = [];
  const capture = new Writable({
    write(chunk: Buffer, _encoding, done) {
      for (const line of chunk.toString('utf8').split('\n')) if (line.trim()) events.push(JSON.parse(line) as LoggedEvent);
      done();
    },
  });
  const runtime = await createRuntime(config, {
    clock: clock.read,
    logger: createLogger({ level: 'info', destination: capture }),
    primaryStore: options.store ?? null,
    intel: options.intel ?? new NetworkIntel({ dataset: dataset() }),
    db: options.db ?? null,
    turnstile: options.turnstile === null ? null : (options.turnstile ?? turnstile),
    background: false,
    ...(options.dns ? { dnsResolver: options.dns } : {}),
  });
  const leads: AcceptedLead[] = [];
  const guard = createIntegrityGuard(runtime, {
    onLeadAccepted: (lead) => {
      leads.push(lead);
      return Promise.resolve();
    },
  });
  const server: Server = await new Promise((resolve) => {
    const listening = createApp(runtime, guard).listen(0, '127.0.0.1', () => resolve(listening));
  });
  const port = (server.address() as AddressInfo).port;

  const raw = (method: string, path: string, headers: OutgoingHttpHeaders, body?: string): Promise<HttpResponse> =>
    send(port, method, path, headers, body);

  return {
    runtime,
    guard,
    clock,
    turnstile,
    leads,
    events,
    port,
    eventsNamed: (name) => events.filter((entry) => entry.event === name),
    browser: (ip, profile = CHROME) => new Browser(raw, ip, profile),
    raw,
    async close(): Promise<void> {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await runtime.paidVisits.flush();
      await runtime.store.close();
    },
  };
}

export const CHROME = {
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
  'sec-ch-ua': '"Google Chrome";v="141", "Chromium";v="141", "Not=A?Brand";v="24"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
  'accept-language': 'en-US,en;q=0.9',
} as const;

export const SAFARI_IPHONE: Readonly<Record<string, string>> = {
  'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1',
  'accept-language': 'en-GB,en;q=0.9',
};

export const NAVIGATE: Readonly<Record<string, string>> = {
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-site': 'cross-site',
  'sec-fetch-dest': 'document',
  'sec-fetch-user': '?1',
};

export interface HttpResponse {
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly text: string;
  json<T = Record<string, unknown>>(): T;
}

export class Browser {
  readonly jar = new Map<string, string>();
  ip: string;
  private readonly raw: Harness['raw'];
  private readonly profile: Readonly<Record<string, string>>;

  constructor(raw: Harness['raw'], ip: string, profile: Readonly<Record<string, string>>) {
    this.raw = raw;
    this.ip = ip;
    this.profile = profile;
  }

  forgetCookies(): void {
    this.jar.clear();
  }

  visit(path: string, extra: Readonly<Record<string, string>> = {}): Promise<HttpResponse> {
    return this.request('GET', path, { ...NAVIGATE, ...extra });
  }

  fetchJson(path: string, extra: Readonly<Record<string, string>> = {}): Promise<HttpResponse> {
    return this.request('GET', path, { accept: 'application/json', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', ...extra });
  }

  postJson(path: string, payload: unknown, extra: Readonly<Record<string, string>> = {}): Promise<HttpResponse> {
    return this.request(
      'POST',
      path,
      { 'content-type': 'application/json', accept: 'application/json', origin: 'http://localhost', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', ...extra },
      JSON.stringify(payload),
    );
  }

  async request(method: string, path: string, extra: Readonly<Record<string, string>>, body?: string): Promise<HttpResponse> {
    const cookie = [...this.jar].map(([name, value]) => `${name}=${value}`).join('; ');
    const headers: OutgoingHttpHeaders = { ...this.profile, ...extra, 'x-forwarded-for': this.ip, ...(cookie ? { cookie } : {}) };
    for (const [name, value] of Object.entries(headers)) if (value === '') delete headers[name];
    const response = await this.raw(method, path, headers, body);
    const setCookie = response.headers['set-cookie'] ?? [];
    for (const line of setCookie) {
      const [pair] = line.split(';');
      const eq = pair?.indexOf('=') ?? -1;
      if (pair && eq > 0) this.jar.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
    return response;
  }
}

function send(port: number, method: string, path: string, headers: OutgoingHttpHeaders, body?: string): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, method, path, headers: { ...headers, ...(body !== undefined ? { 'content-length': Buffer.byteLength(body) } : {}) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json: <T>() => JSON.parse(text) as T });
        });
      },
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export function gclid(seed: number | string): string {
  return `Cj0KCQjw${String(seed).padStart(6, '0')}TestClickIdentifierValue_BwE`;
}
