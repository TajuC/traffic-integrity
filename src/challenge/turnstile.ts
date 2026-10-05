import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { sha256Hex } from '../crypto/keyring.ts';
import type { IntegrityStore } from '../store/types.ts';

export type TurnstileFailure =
  | 'missing'
  | 'malformed'
  | 'replayed'
  | 'rejected'
  | 'expired'
  | 'hostname_mismatch'
  | 'action_mismatch'
  | 'cdata_mismatch';

export type TurnstileOutcome =
  | { readonly status: 'passed'; readonly challengeTs: number; readonly hostname: string }
  | { readonly status: 'failed'; readonly reason: TurnstileFailure }
  | { readonly status: 'unavailable'; readonly reason: string };

export interface TurnstileCheck {
  readonly token: string | undefined;
  readonly remoteIp: string | undefined;
  readonly action: string;
  readonly cdata?: string;
}

export interface TurnstileVerifier {
  verify(check: TurnstileCheck): Promise<TurnstileOutcome>;
}

export interface TurnstileOptions {
  readonly secretKey: string;
  readonly hostnames: ReadonlySet<string>;
  readonly timeoutMs: number;
  readonly maxAgeSeconds: number;
  readonly store: IntegrityStore;
  readonly allowTestKeys: boolean;
  readonly onUnavailable?: (reason: string) => void;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly endpoint?: string;
}

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TOKEN = /^[\x21-\x7e]{1,2048}$/;
const ATTEMPTS = 2;

const responseSchema = z.object({
  success: z.boolean(),
  challenge_ts: z.string().optional(),
  hostname: z.string().optional(),
  'error-codes': z.array(z.string()).default([]),
  action: z.string().optional(),
  cdata: z.string().optional(),
  metadata: z.object({ result_with_testing_key: z.boolean().optional() }).optional(),
});

export class CloudflareTurnstile implements TurnstileVerifier {
  private readonly options: TurnstileOptions;
  private readonly fetch: typeof fetch;
  private readonly now: () => number;

  constructor(options: TurnstileOptions) {
    this.options = options;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.now = options.now ?? Date.now;
  }

  async verify(check: TurnstileCheck): Promise<TurnstileOutcome> {
    const outcome = await this.siteverify(check);
    if (outcome.status === 'unavailable') this.options.onUnavailable?.(outcome.reason);
    return outcome;
  }

  private async siteverify(check: TurnstileCheck): Promise<TurnstileOutcome> {
    const token = check.token?.trim();
    if (!token) return { status: 'failed', reason: 'missing' };
    if (!TOKEN.test(token)) return { status: 'failed', reason: 'malformed' };
    const fresh = await this.options.store.claimOnce(`ts:${sha256Hex(token).slice(0, 40)}`, (this.options.maxAgeSeconds + 60) * 1000);
    if (!fresh) return { status: 'failed', reason: 'replayed' };

    const body = JSON.stringify({
      secret: this.options.secretKey,
      response: token,
      remoteip: check.remoteIp,
      idempotency_key: randomUUID(),
    });

    let payload: unknown;
    let lastError = 'no_response';
    for (let attempt = 0; attempt < ATTEMPTS && payload === undefined; attempt += 1) {
      try {
        const response = await this.fetch(this.options.endpoint ?? SITEVERIFY, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
          signal: AbortSignal.timeout(this.options.timeoutMs),
        });
        if (response.status >= 500) {
          lastError = `http_${response.status}`;
          continue;
        }
        payload = await response.json();
      } catch (error) {
        lastError = error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError') ? 'timeout' : 'network_error';
      }
    }
    if (payload === undefined) return { status: 'unavailable', reason: lastError };

    const parsed = responseSchema.safeParse(payload);
    if (!parsed.success) return { status: 'unavailable', reason: 'invalid_response' };
    const result = parsed.data;
    const codes = result['error-codes'];

    if (!result.success) {
      if (codes.includes('internal-error')) return { status: 'unavailable', reason: 'internal-error' };
      if (codes.some((code) => code.includes('input-secret'))) return { status: 'unavailable', reason: 'misconfigured' };
      if (codes.includes('timeout-or-duplicate')) return { status: 'failed', reason: 'expired' };
      return { status: 'failed', reason: 'rejected' };
    }

    const hostname = result.hostname ?? '';
    if (result.metadata?.result_with_testing_key) {
      if (!this.options.allowTestKeys) return { status: 'unavailable', reason: 'testing_key' };
      return { status: 'passed', challengeTs: this.now(), hostname };
    }
    if (!this.options.hostnames.has(hostname)) return { status: 'failed', reason: 'hostname_mismatch' };
    if (result.action !== check.action) return { status: 'failed', reason: 'action_mismatch' };
    if (check.cdata !== undefined && result.cdata !== check.cdata) return { status: 'failed', reason: 'cdata_mismatch' };

    const challengeTs = result.challenge_ts ? Date.parse(result.challenge_ts) : Number.NaN;
    if (!Number.isFinite(challengeTs) || this.now() - challengeTs > this.options.maxAgeSeconds * 1000) {
      return { status: 'failed', reason: 'expired' };
    }
    return { status: 'passed', challengeTs, hostname };
  }
}
