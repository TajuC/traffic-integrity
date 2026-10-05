import type { ClientSnapshot } from './consistency.ts';

const MAX = 50_000;
const TTL_MS = 30 * 60_000;

export class SnapshotCache {
  private readonly items = new Map<string, { snapshot: ClientSnapshot; expiresAt: number }>();

  set(visitorId: string, snapshot: ClientSnapshot, now: number): void {
    this.items.delete(visitorId);
    this.items.set(visitorId, { snapshot, expiresAt: now + TTL_MS });
    while (this.items.size > MAX) {
      const oldest = this.items.keys().next().value;
      if (oldest === undefined) break;
      this.items.delete(oldest);
    }
  }

  get(visitorId: string | undefined, now: number): ClientSnapshot | undefined {
    if (!visitorId) return undefined;
    const item = this.items.get(visitorId);
    if (!item) return undefined;
    if (item.expiresAt <= now) {
      this.items.delete(visitorId);
      return undefined;
    }
    return item.snapshot;
  }
}
