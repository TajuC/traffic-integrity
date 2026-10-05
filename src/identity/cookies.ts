export interface CookieNames {
  readonly visitor: string;
  readonly session: string;
  readonly clearance: string;
}

export interface CookieSpec {
  readonly name: string;
  readonly value: string;
  readonly maxAgeSeconds?: number;
}

const MAX_COOKIE_HEADER = 8192;

export function cookieNames(secure: boolean): CookieNames {
  const prefix = secure ? '__Host-' : '';
  return { visitor: `${prefix}vid`, session: `${prefix}sid`, clearance: `${prefix}clr` };
}

export function readCookies(header: string | undefined, wanted: readonly string[]): Map<string, string> {
  const found = new Map<string, string>();
  if (!header) return found;
  for (const part of header.slice(0, MAX_COOKIE_HEADER).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (!wanted.includes(name) || found.has(name)) continue;
    let value = part.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    found.set(name, value);
  }
  return found;
}

export function serializeCookie(spec: CookieSpec, secure: boolean): string {
  const parts = [`${spec.name}=${spec.value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (spec.maxAgeSeconds !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(spec.maxAgeSeconds))}`);
  if (secure) parts.push('Secure');
  return parts.join('; ');
}
