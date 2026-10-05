import { randomId, type Keyring } from '../crypto/keyring.ts';
import type { CookieNames, CookieSpec } from '../identity/cookies.ts';

const CHALLENGE_NONCE_TTL_SECONDS = 900;

export class ClearanceService {
  private readonly keyring: Keyring;
  private readonly names: CookieNames;
  private readonly ttlSeconds: number;

  constructor(keyring: Keyring, names: CookieNames, ttlSeconds: number) {
    this.keyring = keyring;
    this.names = names;
    this.ttlSeconds = ttlSeconds;
  }

  issue(visitorId: string, nowSeconds: number, ttlSeconds: number = this.ttlSeconds): { cookie: CookieSpec; untilMs: number } {
    const until = nowSeconds + ttlSeconds;
    return {
      cookie: { name: this.names.clearance, value: this.keyring.seal('clearance', [visitorId, until.toString(36)]), maxAgeSeconds: ttlSeconds },
      untilMs: until * 1000,
    };
  }

  isValid(token: string | undefined, visitorId: string, nowSeconds: number): boolean {
    const fields = this.keyring.open('clearance', token, 2);
    if (!fields) return false;
    const [boundTo, until] = fields as [string, string];
    return boundTo === visitorId && parseInt(until, 36) > nowSeconds;
  }

  challengeNonce(visitorId: string, nowSeconds: number): { nonce: string; cdata: string } {
    const nonce = this.keyring.seal('challenge', [randomId(12), visitorId, nowSeconds.toString(36)]);
    return { nonce, cdata: this.keyring.digest('subject', `challenge:${nonce}`, 16) };
  }

  openChallengeNonce(nonce: string | undefined, visitorId: string, nowSeconds: number): { id: string; cdata: string } | null {
    const fields = this.keyring.open('challenge', nonce, 3);
    if (!fields || !nonce) return null;
    const [id, boundTo, issued] = fields as [string, string, string];
    const issuedAt = parseInt(issued, 36);
    if (boundTo !== visitorId || nowSeconds - issuedAt > CHALLENGE_NONCE_TTL_SECONDS || issuedAt > nowSeconds + 60) return null;
    return { id, cdata: this.keyring.digest('subject', `challenge:${nonce}`, 16) };
  }
}
