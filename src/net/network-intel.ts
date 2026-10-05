import { readFile, stat } from 'node:fs/promises';
import type { AsnResponse } from 'maxmind';
import { z } from 'zod';
import type { ClientAddress } from './client-address.ts';
import { HOSTING_ASNS } from './hosting-asns.ts';
import type { ParsedIp } from './ip.ts';
import { IpRangeTable } from './range-table.ts';

export type NetworkCategory = 'hosting' | 'privacy_relay' | 'tor' | 'unclassified';

export const CRAWLER_RANGE_KINDS = ['google-common', 'google-special', 'google-fetcher', 'google-agent', 'bing'] as const;
export type CrawlerRangeKind = (typeof CRAWLER_RANGE_KINDS)[number];

export interface NetworkProfile {
  readonly asn: number | undefined;
  readonly asOrg: string | undefined;
  readonly country: string | undefined;
  readonly category: NetworkCategory;
  readonly provider: string | undefined;
  readonly asnSource: 'edge' | 'database' | 'none';
}

export const datasetSchema = z.object({
  version: z.literal(1),
  generatedAt: z.iso.datetime(),
  cloudflare: z.array(z.string()).default([]),
  crawlers: z.array(z.tuple([z.string(), z.enum(CRAWLER_RANGE_KINDS)])).default([]),
  hosting: z.array(z.tuple([z.string(), z.string().max(48)])).default([]),
  relays: z.array(z.tuple([z.string(), z.string().max(48)])).default([]),
  tor: z.array(z.string()).default([]),
});

export type NetworkDataset = z.infer<typeof datasetSchema>;

export interface AsnRecord {
  readonly asn: number;
  readonly org: string | undefined;
  readonly country: string | undefined;
}

export interface AsnLookup {
  lookup(ipText: string): AsnRecord | undefined;
}

interface Tables {
  readonly generatedAt: number | undefined;
  readonly cloudflare: readonly string[];
  readonly crawlers: IpRangeTable<CrawlerRangeKind>;
  readonly hosting: IpRangeTable<string>;
  readonly relays: IpRangeTable<string>;
  readonly tor: IpRangeTable<true>;
}

const STALE_AFTER_MS = 14 * 24 * 60 * 60 * 1000;

export class NetworkIntel {
  private tables: Tables;
  private mtimeMs: number | undefined;
  private readonly path: string | undefined;
  private readonly asn: AsnLookup | undefined;

  constructor(options: { dataset?: NetworkDataset; path?: string; asn?: AsnLookup } = {}) {
    this.tables = buildTables(options.dataset);
    this.path = options.path;
    this.asn = options.asn;
  }

  static async open(options: { path: string; asnDatabasePath: string | undefined }): Promise<NetworkIntel> {
    const asn = options.asnDatabasePath ? await openAsnDatabase(options.asnDatabasePath) : undefined;
    const intel = new NetworkIntel({ path: options.path, ...(asn ? { asn } : {}) });
    await intel.refresh();
    return intel;
  }

  async refresh(): Promise<'reloaded' | 'unchanged' | 'missing'> {
    if (!this.path) return 'missing';
    let mtimeMs: number;
    try {
      mtimeMs = (await stat(this.path)).mtimeMs;
    } catch {
      return 'missing';
    }
    if (mtimeMs === this.mtimeMs) return 'unchanged';
    const dataset = datasetSchema.parse(JSON.parse(await readFile(this.path, 'utf8')));
    this.tables = buildTables(dataset);
    this.mtimeMs = mtimeMs;
    return 'reloaded';
  }

  get cloudflareRanges(): readonly string[] {
    return this.tables.cloudflare;
  }

  get generatedAt(): number | undefined {
    return this.tables.generatedAt;
  }

  crawlerRangesFresh(now: number): boolean {
    const generated = this.tables.generatedAt;
    return generated !== undefined && now - generated < STALE_AFTER_MS && this.tables.crawlers.size > 0;
  }

  crawlerRange(ip: ParsedIp | null): CrawlerRangeKind | undefined {
    return this.tables.crawlers.lookup(ip);
  }

  profile(address: ClientAddress): NetworkProfile {
    let asn = address.edge.asn;
    let country = address.edge.country;
    let asOrg: string | undefined;
    let asnSource: NetworkProfile['asnSource'] = asn === undefined ? 'none' : 'edge';

    if (this.asn && address.ip && (asn === undefined || country === undefined)) {
      const record = this.asn.lookup(address.text);
      if (record) {
        if (asn === undefined) {
          asn = record.asn;
          asnSource = 'database';
        }
        asOrg = record.org;
        country ??= record.country;
      }
    }

    const ip = address.ip;
    let category: NetworkCategory = 'unclassified';
    let provider: string | undefined;
    const relay = this.tables.relays.lookup(ip);
    const hosting = this.tables.hosting.lookup(ip) ?? (asn === undefined ? undefined : HOSTING_ASNS.get(asn));
    if (country === 'T1' || this.tables.tor.has(ip)) {
      category = 'tor';
    } else if (relay) {
      category = 'privacy_relay';
      provider = relay;
    } else if (hosting) {
      category = 'hosting';
      provider = hosting;
    }

    return {
      asn,
      asOrg,
      country: country === 'T1' || country === 'XX' ? undefined : country,
      category,
      provider,
      asnSource,
    };
  }
}

function buildTables(dataset: NetworkDataset | undefined): Tables {
  if (!dataset) {
    return {
      generatedAt: undefined,
      cloudflare: [],
      crawlers: IpRangeTable.empty(),
      hosting: IpRangeTable.empty(),
      relays: IpRangeTable.empty(),
      tor: IpRangeTable.empty(),
    };
  }
  return {
    generatedAt: Date.parse(dataset.generatedAt),
    cloudflare: dataset.cloudflare,
    crawlers: new IpRangeTable(dataset.crawlers.map(([cidr, label]) => ({ cidr, label }))),
    hosting: new IpRangeTable(dataset.hosting.map(([cidr, label]) => ({ cidr, label }))),
    relays: new IpRangeTable(dataset.relays.map(([cidr, label]) => ({ cidr, label }))),
    tor: new IpRangeTable(dataset.tor.map((cidr) => ({ cidr, label: true as const }))),
  };
}

interface MmdbAsnRecord {
  readonly autonomous_system_number?: number;
  readonly autonomous_system_organization?: string;
  readonly asn?: string;
  readonly as_name?: string;
  readonly country_code?: string;
}

async function openAsnDatabase(path: string): Promise<AsnLookup> {
  const { open } = await import('maxmind');
  const reader = await open<AsnResponse>(path, { cache: { max: 20_000 } });
  return {
    lookup(ipText: string): AsnRecord | undefined {
      const record = reader.get(ipText) as MmdbAsnRecord | null;
      if (!record) return undefined;
      const asn = record.autonomous_system_number ?? (record.asn ? Number(record.asn.replace(/^AS/i, '')) : undefined);
      if (!asn || !Number.isInteger(asn)) return undefined;
      return {
        asn,
        org: record.autonomous_system_organization ?? record.as_name,
        country: record.country_code?.toUpperCase(),
      };
    },
  };
}
