import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

export type KeyPurpose =
  | 'visitor'
  | 'session'
  | 'clearance'
  | 'challenge'
  | 'form'
  | 'beacon'
  | 'subject'
  | 'fingerprint';

const PURPOSES: readonly KeyPurpose[] = [
  'visitor',
  'session',
  'clearance',
  'challenge',
  'form',
  'beacon',
  'subject',
  'fingerprint',
];

const FIELD = /^[A-Za-z0-9_-]{1,128}$/;
const MAC_BYTES = 16;
const MAX_TOKEN_LENGTH = 640;
const SALT = Buffer.from('traffic-integrity/keyring/v1');

type KeySet = ReadonlyMap<KeyPurpose, Buffer>;

export class Keyring {
  private readonly current: KeySet;
  private readonly verifiers: readonly KeySet[];

  constructor(secret: string, previousSecret?: string) {
    this.current = derive(secret);
    this.verifiers = previousSecret ? [this.current, derive(previousSecret)] : [this.current];
  }

  seal(purpose: KeyPurpose, fields: readonly string[]): string {
    for (const field of fields) {
      if (!FIELD.test(field)) throw new Error(`token field for ${purpose} is not url-safe`);
    }
    const payload = fields.join('.');
    return `${payload}.${mac(this.key(this.current, purpose), purpose, payload).toString('base64url')}`;
  }

  open(purpose: KeyPurpose, token: string | undefined, fieldCount: number): string[] | null {
    if (!token || token.length > MAX_TOKEN_LENGTH) return null;
    const parts = token.split('.');
    if (parts.length !== fieldCount + 1) return null;
    const presented = Buffer.from(parts.pop() as string, 'base64url');
    if (presented.length !== MAC_BYTES) return null;
    if (!parts.every((part) => FIELD.test(part))) return null;
    const payload = parts.join('.');
    for (const keys of this.verifiers) {
      if (timingSafeEqual(presented, mac(this.key(keys, purpose), purpose, payload))) return parts;
    }
    return null;
  }

  digest(purpose: 'subject' | 'fingerprint', value: string, bytes = 12): string {
    return createHmac('sha256', this.key(this.current, purpose)).update(value).digest().subarray(0, bytes).toString('base64url');
  }

  private key(keys: KeySet, purpose: KeyPurpose): Buffer {
    const key = keys.get(purpose);
    if (!key) throw new Error(`no key derived for ${purpose}`);
    return key;
  }
}

export function randomId(bytes = 16): string {
  return randomBytes(bytes).toString('base64url');
}

export function safeEqual(presented: string | undefined, expected: string): boolean {
  if (presented === undefined) return false;
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function derive(secret: string): KeySet {
  const ikm = Buffer.from(secret, 'utf8');
  return new Map(
    PURPOSES.map((purpose) => [purpose, Buffer.from(hkdfSync('sha256', ikm, SALT, `purpose:${purpose}`, 32))]),
  );
}

function mac(key: Buffer, purpose: KeyPurpose, payload: string): Buffer {
  return createHmac('sha256', key).update(`${purpose}\n${payload}`).digest().subarray(0, MAC_BYTES);
}
