import { randomId, type Keyring } from '../crypto/keyring.ts';
import type { CookieNames, CookieSpec } from './cookies.ts';

export type IdentityOrigin = 'returning' | 'new' | 'forged';

export interface VisitorIdentity {
  readonly visitorId: string;
  readonly issuedAt: number;
  readonly origin: IdentityOrigin;
  readonly sessionId: string;
}

export interface IdentityResolution {
  readonly identity: VisitorIdentity;
  readonly cookies: readonly CookieSpec[];
}

export interface IdentityInput {
  readonly visitorCookie: string | undefined;
  readonly sessionCookie: string | undefined;
}

const RENEW_AFTER_SECONDS = 7 * 86_400;
const CLOCK_SKEW_SECONDS = 300;

export class IdentityService {
  private readonly keyring: Keyring;
  private readonly names: CookieNames;
  private readonly maxAgeSeconds: number;

  constructor(keyring: Keyring, names: CookieNames, visitorDays: number) {
    this.keyring = keyring;
    this.names = names;
    this.maxAgeSeconds = visitorDays * 86_400;
  }

  resolve(input: IdentityInput, nowSeconds: number): IdentityResolution {
    const cookies: CookieSpec[] = [];
    const visitor = this.readVisitor(input.visitorCookie, nowSeconds);

    let visitorId: string;
    let issuedAt: number;
    let origin: IdentityOrigin;
    if (visitor) {
      visitorId = visitor.id;
      issuedAt = visitor.issuedAt;
      origin = 'returning';
      if (nowSeconds - visitor.renewedAt > RENEW_AFTER_SECONDS) cookies.push(this.visitorCookie(visitorId, issuedAt, nowSeconds));
    } else {
      visitorId = randomId(16);
      issuedAt = nowSeconds;
      origin = input.visitorCookie ? 'forged' : 'new';
      cookies.push(this.visitorCookie(visitorId, issuedAt, nowSeconds));
    }

    let sessionId = origin === 'returning' ? this.keyring.open('session', input.sessionCookie, 1)?.[0] : undefined;
    if (!sessionId) {
      sessionId = randomId(12);
      cookies.push({ name: this.names.session, value: this.keyring.seal('session', [sessionId]) });
    }

    return { identity: { visitorId, issuedAt, origin, sessionId }, cookies };
  }

  private readVisitor(token: string | undefined, nowSeconds: number): { id: string; issuedAt: number; renewedAt: number } | null {
    const fields = this.keyring.open('visitor', token, 3);
    if (!fields) return null;
    const [id, issued, renewed] = fields as [string, string, string];
    const issuedAt = parseInt(issued, 36);
    const renewedAt = parseInt(renewed, 36);
    if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(renewedAt)) return null;
    if (issuedAt > nowSeconds + CLOCK_SKEW_SECONDS || renewedAt < issuedAt) return null;
    if (nowSeconds - renewedAt > this.maxAgeSeconds) return null;
    return { id, issuedAt, renewedAt };
  }

  private visitorCookie(visitorId: string, issuedAt: number, nowSeconds: number): CookieSpec {
    return {
      name: this.names.visitor,
      value: this.keyring.seal('visitor', [visitorId, issuedAt.toString(36), nowSeconds.toString(36)]),
      maxAgeSeconds: this.maxAgeSeconds,
    };
  }
}
