export class RestrictionCache {
  private readonly entries = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(maxEntries = 50_000) {
    this.maxEntries = maxEntries;
  }

  set(key: string, until: number): void {
    const current = this.entries.get(key) ?? 0;
    this.entries.delete(key);
    this.entries.set(key, Math.max(current, until));
    if (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
  }

  until(key: string, now: number): number | undefined {
    const until = this.entries.get(key);
    if (until === undefined) return undefined;
    if (until <= now) {
      this.entries.delete(key);
      return undefined;
    }
    return until;
  }
}
