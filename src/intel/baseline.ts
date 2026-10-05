import { median, mad, robustZ, ewma } from './stats.ts';

export interface BaselineSample {
  readonly key: string;
  readonly value: number;
  readonly now: number;
}

export interface BaselineSnapshot {
  readonly key: string;
  readonly samples: number;
  readonly ewma: number;
  readonly ewad: number;
  readonly last: number;
  readonly robustZ: number;
  readonly spike: boolean;
}

interface Series {
  samples: number;
  ewma: number;
  ewad: number;
  last: number;
  updatedAt: number;
  recent: number[];
}

const MAX_RECENT = 48;
const MAX_KEYS = 20_000;
const ALPHA = 0.2;

export class BaselineTracker {
  private readonly series = new Map<string, Series>();

  sample(key: string, value: number, now: number, spikeZ = 4): BaselineSnapshot {
    const existing = this.series.get(key);
    if (!existing) {
      const created: Series = { samples: 1, ewma: value, ewad: 0, last: value, updatedAt: now, recent: [value] };
      this.series.set(key, created);
      this.trim();
      return { key, samples: 1, ewma: value, ewad: 0, last: value, robustZ: 0, spike: false };
    }
    const nextEwma = ewma(existing.ewma, value, ALPHA);
    const deviation = Math.abs(value - existing.ewma);
    const nextEwad = ewma(existing.ewad, deviation, ALPHA);
    existing.samples += 1;
    existing.ewma = nextEwma;
    existing.ewad = nextEwad;
    existing.last = value;
    existing.updatedAt = now;
    existing.recent.push(value);
    if (existing.recent.length > MAX_RECENT) existing.recent.shift();
    this.series.delete(key);
    this.series.set(key, existing);
    const z = existing.samples >= 8 ? robustZ(value, median(existing.recent), mad(existing.recent)) : 0;
    return {
      key,
      samples: existing.samples,
      ewma: nextEwma,
      ewad: nextEwad,
      last: value,
      robustZ: z,
      spike: existing.samples >= 8 && z >= spikeZ && value > existing.ewma,
    };
  }

  snapshot(key: string): BaselineSnapshot | undefined {
    const existing = this.series.get(key);
    if (!existing) return undefined;
    return {
      key,
      samples: existing.samples,
      ewma: existing.ewma,
      ewad: existing.ewad,
      last: existing.last,
      robustZ: 0,
      spike: false,
    };
  }

  private trim(): void {
    while (this.series.size > MAX_KEYS) {
      const oldest = this.series.keys().next().value;
      if (oldest === undefined) break;
      this.series.delete(oldest);
    }
  }
}

export function campaignKey(campaign: string, hour: number): string {
  return `campaign:${campaign}:h${hour}`;
}

export function campaignAsnKey(campaign: string, asn: number): string {
  return `campaign:${campaign}:asn:${asn}`;
}

export function landingKey(path: string, hour: number): string {
  return `landing:${path}:h${hour}`;
}

export function countryKey(country: string, hour: number): string {
  return `country:${country}:h${hour}`;
}

export function browserKey(family: string, hour: number): string {
  return `browser:${family}:h${hour}`;
}
