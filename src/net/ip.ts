import { isIP } from 'node:net';

export type ParsedIp =
  | { readonly version: 4; readonly value: number }
  | { readonly version: 6; readonly value: bigint };

export type IpRange =
  | { readonly version: 4; readonly start: number; readonly end: number; readonly bits: number }
  | { readonly version: 6; readonly start: bigint; readonly end: bigint; readonly bits: number };

const V6_ALL = (1n << 128n) - 1n;
const MAPPED_V4_HIGH = 0xffffn;

export function parseIp(input: string | null | undefined): ParsedIp | null {
  if (!input) return null;
  let text = input.trim();
  if (text.length === 0 || text.length > 64) return null;

  if (text.startsWith('[')) {
    const close = text.indexOf(']');
    if (close < 0) return null;
    text = text.slice(1, close);
  } else if (text.includes('.') && text.indexOf(':') !== -1 && text.indexOf(':') === text.lastIndexOf(':')) {
    text = text.slice(0, text.indexOf(':'));
  }

  const zone = text.indexOf('%');
  if (zone >= 0) text = text.slice(0, zone);

  const kind = isIP(text);
  if (kind === 4) return { version: 4, value: ipv4ToNumber(text) };
  if (kind !== 6) return null;

  const value = ipv6ToBigInt(text);
  if (value >> 32n === MAPPED_V4_HIGH) return { version: 4, value: Number(value & 0xffffffffn) };
  return { version: 6, value };
}

export function formatIp(ip: ParsedIp): string {
  if (ip.version === 4) {
    const v = ip.value;
    return `${Math.floor(v / 16777216) % 256}.${Math.floor(v / 65536) % 256}.${Math.floor(v / 256) % 256}.${v % 256}`;
  }
  return formatIpv6(ip.value);
}

export function maskIp(ip: ParsedIp, bits: number): ParsedIp {
  if (ip.version === 4) {
    const hostSize = 2 ** (32 - clampBits(bits, 32));
    return { version: 4, value: ip.value - (ip.value % hostSize) };
  }
  return { version: 6, value: ip.value & v6Mask(clampBits(bits, 128)) };
}

export function formatPrefix(ip: ParsedIp, bits: number): string {
  return `${formatIp(maskIp(ip, bits))}/${bits}`;
}

export function parseCidr(text: string): IpRange | null {
  const slash = text.indexOf('/');
  const address = parseIp(slash < 0 ? text : text.slice(0, slash));
  if (!address) return null;
  const maxBits = address.version === 4 ? 32 : 128;
  let bits = maxBits;
  if (slash >= 0) {
    const raw = text.slice(slash + 1).trim();
    if (!/^\d{1,3}$/.test(raw)) return null;
    bits = Number(raw);
    if (bits > maxBits) return null;
  }
  if (address.version === 4) {
    const size = 2 ** (32 - bits);
    const start = address.value - (address.value % size);
    return { version: 4, start, end: start + size - 1, bits };
  }
  const mask = v6Mask(bits);
  const start = address.value & mask;
  return { version: 6, start, end: start | (~mask & V6_ALL), bits };
}

export function addressBucket(ip: ParsedIp): string {
  return ip.version === 4 ? formatIp(ip) : formatPrefix(ip, 64);
}

export function networkBucket(ip: ParsedIp): string {
  return ip.version === 4 ? formatPrefix(ip, 24) : formatPrefix(ip, 48);
}

function clampBits(bits: number, max: number): number {
  return Math.min(Math.max(Math.trunc(bits), 0), max);
}

function v6Mask(bits: number): bigint {
  if (bits === 0) return 0n;
  return ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
}

function ipv4ToNumber(text: string): number {
  let value = 0;
  for (const part of text.split('.')) value = value * 256 + Number(part);
  return value;
}

function ipv6ToBigInt(text: string): bigint {
  const compressed = text.indexOf('::');
  const head = compressed >= 0 ? text.slice(0, compressed) : text;
  const tail = compressed >= 0 ? text.slice(compressed + 2) : '';
  const left = toGroups(head);
  const right = toGroups(tail);
  const zeros = compressed >= 0 ? 8 - left.length - right.length : 0;
  let value = 0n;
  for (const group of [...left, ...new Array<number>(zeros).fill(0), ...right]) {
    value = (value << 16n) | BigInt(group);
  }
  return value;
}

function toGroups(segment: string): number[] {
  if (segment === '') return [];
  const groups: number[] = [];
  for (const part of segment.split(':')) {
    if (part.includes('.')) {
      const v4 = ipv4ToNumber(part);
      groups.push(Math.floor(v4 / 65536), v4 % 65536);
    } else {
      groups.push(parseInt(part, 16));
    }
  }
  return groups;
}

function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push(Number((value >> shift) & 0xffffn));

  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < groups.length; ) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < groups.length && groups[j] === 0) j += 1;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }

  const hex = groups.map((g) => g.toString(16));
  if (bestLength < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}
