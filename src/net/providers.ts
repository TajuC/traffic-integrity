export type NetworkCategory =
  | 'residential_isp'
  | 'mobile_carrier'
  | 'enterprise'
  | 'university'
  | 'cloud'
  | 'hosting'
  | 'cdn'
  | 'vpn'
  | 'tor'
  | 'privacy_relay'
  | 'public_proxy'
  | 'residential_proxy'
  | 'unclassified';

export interface NetworkClassification {
  readonly category: NetworkCategory;
  readonly confidence: number;
  readonly source: string;
  readonly provider?: string;
}

export interface AsnRecord {
  readonly asn: number;
  readonly org?: string;
  readonly country?: string;
  readonly type?: NetworkCategory;
}

export interface ReputationRecord {
  readonly proxy?: boolean;
  readonly vpn?: boolean;
  readonly tor?: boolean;
  readonly hosting?: boolean;
  readonly residentialProxy?: boolean;
  readonly abuseScore?: number;
  readonly confidence: number;
  readonly source: string;
}

export interface IntelLookup {
  readonly ip: string;
  readonly asn?: AsnRecord;
  readonly reputation?: ReputationRecord;
}

export interface NetworkIntelProvider {
  readonly id: string;
  lookup(ip: string): Promise<IntelLookup | undefined>;
}

export class StaticProvider implements NetworkIntelProvider {
  readonly id = 'static';
  lookup(): Promise<undefined> {
    return Promise.resolve(undefined);
  }
}

export function mergeClassifications(parts: readonly NetworkClassification[]): NetworkClassification {
  if (parts.length === 0) return { category: 'unclassified', confidence: 0.2, source: 'none' };
  return [...parts].sort((a, b) => b.confidence - a.confidence)[0] ?? { category: 'unclassified', confidence: 0.2, source: 'none' };
}

export function classifyFromOrg(org: string | undefined): NetworkCategory | undefined {
  if (!org) return undefined;
  const value = org.toLowerCase();
  if (/\b(vpn|mullvad|nordvpn|expressvpn|surfshark|proton)\b/.test(value)) return 'vpn';
  if (/\b(cloudflare|akamai|fastly|cloudfront|cdn)\b/.test(value)) return 'cdn';
  if (/\b(university|universidad|college|campus)\b/.test(value)) return 'university';
  if (/\b(mobile|wireless|cellular|lte|vodafone|t-mobile)\b/.test(value)) return 'mobile_carrier';
  if (/\b(amazon|google cloud|microsoft|digitalocean|linode|ovh|hetzner|vultr)\b/.test(value)) return 'cloud';
  if (/\b(hosting|vps|server|colo|dedicated)\b/.test(value)) return 'hosting';
  if (/\b(telecom|broadband|cable|fiber|isp|communications)\b/.test(value)) return 'residential_isp';
  return undefined;
}
