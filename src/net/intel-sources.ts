import { parseCidr } from './ip.ts';
import type { CrawlerRangeKind, NetworkDataset } from './network-intel.ts';
import { IpRangeTable, type RangeEntry } from './range-table.ts';

type Section = 'cloudflare' | 'crawlers' | 'hosting' | 'relays' | 'tor';

export interface SourceSpec {
  readonly id: string;
  readonly section: Section;
  readonly label: string;
  readonly urls: readonly string[];
  readonly parse: (body: string) => string[];
  readonly optional?: boolean;
}

export interface SourceReport {
  readonly id: string;
  readonly status: 'fetched' | 'reused' | 'failed' | 'skipped';
  readonly entries: number;
  readonly error?: string;
}

const GOOGLE = 'https://developers.google.com/static/crawling/ipranges';

export const SOURCES: readonly SourceSpec[] = [
  { id: 'cloudflare', section: 'cloudflare', label: 'cloudflare', urls: ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6'], parse: lines },
  { id: 'google-common', section: 'crawlers', label: 'google-common', urls: [`${GOOGLE}/common-crawlers.json`], parse: googlePrefixes },
  { id: 'google-special', section: 'crawlers', label: 'google-special', urls: [`${GOOGLE}/special-crawlers.json`], parse: googlePrefixes },
  { id: 'google-fetcher', section: 'crawlers', label: 'google-fetcher', urls: [`${GOOGLE}/user-triggered-fetchers-google.json`], parse: googlePrefixes },
  { id: 'google-agent', section: 'crawlers', label: 'google-agent', urls: [`${GOOGLE}/user-triggered-agents.json`], parse: googlePrefixes },
  { id: 'bing', section: 'crawlers', label: 'bing', urls: ['https://www.bing.com/toolbox/bingbot.json'], parse: googlePrefixes },
  { id: 'aws', section: 'hosting', label: 'amazon', urls: ['https://ip-ranges.amazonaws.com/ip-ranges.json'], parse: awsPrefixes },
  { id: 'gcp', section: 'hosting', label: 'google-cloud', urls: ['https://www.gstatic.com/ipranges/cloud.json'], parse: googlePrefixes },
  { id: 'oracle', section: 'hosting', label: 'oracle', urls: ['https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json'], parse: oraclePrefixes },
  { id: 'digitalocean', section: 'hosting', label: 'digitalocean', urls: ['https://digitalocean.com/geo/google.csv'], parse: firstCsvColumn },
  { id: 'tor', section: 'tor', label: 'tor', urls: ['https://check.torproject.org/torbulkexitlist'], parse: lines },
  {
    id: 'apple-private-relay',
    section: 'relays',
    label: 'apple-private-relay',
    urls: ['https://mask-api.icloud.com/egress-ip-ranges.csv'],
    parse: firstCsvColumn,
    optional: true,
  },
];

export type TextFetcher = (url: string) => Promise<string>;

export async function buildDataset(
  fetchText: TextFetcher,
  previous: NetworkDataset | undefined,
  options: { readonly includeOptional: boolean; readonly now: Date },
): Promise<{ dataset: NetworkDataset; reports: SourceReport[] }> {
  const collected = new Map<string, string[]>();
  const reports: SourceReport[] = [];

  for (const source of SOURCES) {
    if (source.optional && !options.includeOptional) {
      const reused = previousEntries(previous, source);
      if (reused.length > 0) collected.set(source.id, reused);
      reports.push({ id: source.id, status: reused.length > 0 ? 'reused' : 'skipped', entries: reused.length });
      continue;
    }
    try {
      const entries = new Set<string>();
      for (const url of source.urls) for (const cidr of source.parse(await fetchText(url))) if (parseCidr(cidr)) entries.add(cidr);
      if (entries.size === 0) throw new Error('source returned no valid ranges');
      collected.set(source.id, [...entries]);
      reports.push({ id: source.id, status: 'fetched', entries: entries.size });
    } catch (error) {
      const reused = previousEntries(previous, source);
      if (reused.length > 0) collected.set(source.id, reused);
      reports.push({ id: source.id, status: reused.length > 0 ? 'reused' : 'failed', entries: reused.length, error: error instanceof Error ? error.message : String(error) });
    }
  }

  const sections = new Map<Section, RangeEntry<string>[]>();
  for (const source of SOURCES) {
    const target = sections.get(source.section) ?? [];
    for (const cidr of collected.get(source.id) ?? []) target.push({ cidr, label: source.label });
    sections.set(source.section, target);
  }
  const compact = (section: Section): RangeEntry<string>[] => new IpRangeTable(sections.get(section) ?? []).minimalEntries();

  return {
    dataset: {
      version: 1,
      generatedAt: options.now.toISOString(),
      cloudflare: (sections.get('cloudflare') ?? []).map((entry) => entry.cidr),
      crawlers: compact('crawlers').map((entry): [string, CrawlerRangeKind] => [entry.cidr, entry.label as CrawlerRangeKind]),
      hosting: compact('hosting').map((entry): [string, string] => [entry.cidr, entry.label]),
      relays: compact('relays').map((entry): [string, string] => [entry.cidr, entry.label]),
      tor: compact('tor').map((entry) => entry.cidr),
    },
    reports,
  };
}

function previousEntries(previous: NetworkDataset | undefined, source: SourceSpec): string[] {
  if (!previous) return [];
  switch (source.section) {
    case 'cloudflare':
      return previous.cloudflare;
    case 'tor':
      return previous.tor;
    case 'crawlers':
      return previous.crawlers.filter(([, label]) => label === source.label).map(([cidr]) => cidr);
    case 'hosting':
      return previous.hosting.filter(([, label]) => label === source.label).map(([cidr]) => cidr);
    case 'relays':
      return previous.relays.filter(([, label]) => label === source.label).map(([cidr]) => cidr);
  }
}

export function lines(body: string): string[] {
  return body
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));
}

export function firstCsvColumn(body: string): string[] {
  return lines(body).map((line) => line.split(',')[0]?.trim() ?? '');
}

export function googlePrefixes(body: string): string[] {
  const parsed = JSON.parse(body) as { prefixes?: Array<{ ipv4Prefix?: string; ipv6Prefix?: string }> };
  return (parsed.prefixes ?? []).map((prefix) => prefix.ipv4Prefix ?? prefix.ipv6Prefix ?? '');
}

export function awsPrefixes(body: string): string[] {
  const parsed = JSON.parse(body) as { prefixes?: Array<{ ip_prefix?: string }>; ipv6_prefixes?: Array<{ ipv6_prefix?: string }> };
  return [...(parsed.prefixes ?? []).map((p) => p.ip_prefix ?? ''), ...(parsed.ipv6_prefixes ?? []).map((p) => p.ipv6_prefix ?? '')];
}

export function oraclePrefixes(body: string): string[] {
  const parsed = JSON.parse(body) as { regions?: Array<{ cidrs?: Array<{ cidr?: string }> }> };
  return (parsed.regions ?? []).flatMap((region) => (region.cidrs ?? []).map((entry) => entry.cidr ?? ''));
}
