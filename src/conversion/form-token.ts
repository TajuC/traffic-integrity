import { randomId, type Keyring } from '../crypto/keyring.ts';
import type { FormTokenState } from '../risk/context.ts';

export interface IssuedFormToken {
  readonly token: string;
  readonly cdata: string;
}

export interface FormTokenCheck {
  readonly state: FormTokenState;
  readonly nonce: string | undefined;
  readonly ageMs: number | undefined;
  readonly cdata: string | undefined;
}

const CLOCK_SKEW_MS = 60_000;

export class FormTokens {
  private readonly keyring: Keyring;
  private readonly maxAgeMs: number;

  constructor(keyring: Keyring, maxAgeMs: number) {
    this.keyring = keyring;
    this.maxAgeMs = maxAgeMs;
  }

  issue(visitorId: string, formId: string, now: number): IssuedFormToken {
    const token = this.keyring.seal('form', [randomId(16), visitorId, formId, now.toString(36)]);
    return { token, cdata: this.cdata(token) };
  }

  check(token: string | undefined, visitorId: string, formId: string, now: number): FormTokenCheck {
    if (!token) return { state: 'missing', nonce: undefined, ageMs: undefined, cdata: undefined };
    const fields = this.keyring.open('form', token, 4);
    if (!fields) return { state: 'invalid', nonce: undefined, ageMs: undefined, cdata: undefined };
    const [nonce, boundVisitor, boundForm, issued] = fields as [string, string, string, string];
    const ageMs = now - parseInt(issued, 36);
    if (boundVisitor !== visitorId || boundForm !== formId || ageMs < -CLOCK_SKEW_MS) {
      return { state: 'invalid', nonce, ageMs: undefined, cdata: undefined };
    }
    return { state: ageMs > this.maxAgeMs ? 'expired' : 'valid', nonce, ageMs: Math.max(ageMs, 0), cdata: this.cdata(token) };
  }

  private cdata(token: string): string {
    return this.keyring.digest('subject', `form:${token}`, 16);
  }
}
