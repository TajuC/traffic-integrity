import type { IncomingHttpHeaders } from 'node:http';
import type { EdgeMode } from '../config/env.ts';
import { safeEqual } from '../crypto/keyring.ts';
import { formatIp, parseIp, type ParsedIp } from './ip.ts';
import { IpRangeTable } from './range-table.ts';

export const EDGE_HEADERS = {
  auth: 'x-edge-auth',
  asn: 'x-edge-asn',
  botScore: 'x-edge-bot-score',
  verifiedBot: 'x-edge-verified-bot',
  country: 'cf-ipcountry',
  connectingIp: 'cf-connecting-ip',
} as const;

export const CLOUDFLARE_RANGES: readonly string[] = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

const PROXY_KEYWORDS: Readonly<Record<string, readonly string[]>> = {
  loopback: ['127.0.0.0/8', '::1/128'],
  private: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'],
};

const MAX_FORWARDED_HOPS = 20;

export interface EdgeSignals {
  readonly asn?: number;
  readonly country?: string;
  readonly botScore?: number;
  readonly verifiedBot?: boolean;
}

export interface ClientAddress {
  readonly ip: ParsedIp | null;
  readonly text: string;
  readonly via: 'direct' | 'proxy' | 'cloudflare';
  readonly viaEdge: boolean;
  readonly edgeVerified: boolean;
  readonly edge: EdgeSignals;
  readonly ray?: string;
}

const NO_EDGE: EdgeSignals = Object.freeze({});
const RAY = /^[0-9a-f]{16}(-[A-Z]{3})?$/i;
const UNKNOWN: ClientAddress = Object.freeze({ ip: null, text: 'unknown', via: 'direct', viaEdge: false, edgeVerified: false, edge: NO_EDGE });

export interface ClientAddressOptions {
  readonly trusted: readonly string[];
  readonly edgeMode: EdgeMode;
  readonly edgeSecrets: readonly string[];
  readonly cloudflareRanges?: readonly string[];
}

export class ClientAddressResolver {
  private readonly trusted: IpRangeTable<true>;
  private readonly edgeMode: EdgeMode;
  private readonly edgeSecrets: readonly string[];
  private cloudflare: IpRangeTable<true>;

  constructor(options: ClientAddressOptions) {
    const cidrs = options.trusted.flatMap((token) => PROXY_KEYWORDS[token] ?? [token]);
    this.trusted = new IpRangeTable(cidrs.map((cidr) => ({ cidr, label: true as const })));
    this.edgeMode = options.edgeMode;
    this.edgeSecrets = options.edgeSecrets;
    this.cloudflare = cloudflareTable(options.cloudflareRanges ?? []);
  }

  updateCloudflareRanges(extra: readonly string[]): void {
    this.cloudflare = cloudflareTable(extra);
  }

  get edgeEnabled(): boolean {
    return this.edgeMode !== 'off';
  }

  resolve(socketAddress: string | undefined, headers: IncomingHttpHeaders): ClientAddress {
    const peer = parseIp(socketAddress);
    if (!peer) return UNKNOWN;

    let client = peer;
    let via: ClientAddress['via'] = 'direct';
    if (this.trusted.has(peer)) {
      const hops = forwardedHops(headers['x-forwarded-for']);
      for (let i = hops.length - 1; i >= 0; i -= 1) {
        const hop = parseIp(hops[i]);
        if (!hop) break;
        client = hop;
        via = 'proxy';
        if (!this.trusted.has(hop)) break;
      }
    }

    if (this.edgeMode !== 'off' && this.cloudflare.has(client)) {
      const connecting = parseIp(single(headers[EDGE_HEADERS.connectingIp]));
      const resolved = connecting ?? client;
      const presented = single(headers[EDGE_HEADERS.auth]);
      const secretMatches = this.edgeSecrets.some((secret) => safeEqual(presented, secret));
      const verified = connecting !== null && secretMatches;
      const ray = single(headers['cf-ray']);
      return {
        ip: resolved,
        text: formatIp(resolved),
        via: 'cloudflare',
        viaEdge: connecting !== null && (this.edgeSecrets.length === 0 || secretMatches),
        edgeVerified: verified,
        edge: verified ? readEdgeSignals(headers) : NO_EDGE,
        ...(ray && RAY.test(ray) ? { ray } : {}),
      };
    }

    return { ip: client, text: formatIp(client), via, viaEdge: false, edgeVerified: false, edge: NO_EDGE };
  }
}

function cloudflareTable(extra: readonly string[]): IpRangeTable<true> {
  return new IpRangeTable([...CLOUDFLARE_RANGES, ...extra].map((cidr) => ({ cidr, label: true as const })));
}

function forwardedHops(value: string | string[] | undefined): string[] {
  if (!value) return [];
  const joined = Array.isArray(value) ? value.join(',') : value;
  const hops = joined.split(',').map((hop) => hop.trim()).filter(Boolean);
  return hops.length > MAX_FORWARDED_HOPS ? hops.slice(-MAX_FORWARDED_HOPS) : hops;
}

function single(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function readEdgeSignals(headers: IncomingHttpHeaders): EdgeSignals {
  const signals: { asn?: number; country?: string; botScore?: number; verifiedBot?: boolean } = {};
  const asn = integer(single(headers[EDGE_HEADERS.asn]), 1, 4_294_967_295);
  if (asn !== undefined) signals.asn = asn;
  const country = single(headers[EDGE_HEADERS.country])?.trim().toUpperCase();
  if (country && /^[A-Z][A-Z0-9]$/.test(country)) signals.country = country;
  const score = integer(single(headers[EDGE_HEADERS.botScore]), 1, 99);
  if (score !== undefined) signals.botScore = score;
  const verified = single(headers[EDGE_HEADERS.verifiedBot])?.trim().toLowerCase();
  if (verified === 'true' || verified === 'false') signals.verifiedBot = verified === 'true';
  return signals;
}

function integer(value: string | undefined, min: number, max: number): number | undefined {
  if (!value || !/^\d{1,10}$/.test(value.trim())) return undefined;
  const parsed = Number(value.trim());
  return parsed >= min && parsed <= max ? parsed : undefined;
}
