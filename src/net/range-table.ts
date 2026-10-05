import { formatIp, parseCidr, type ParsedIp } from './ip.ts';

export interface RangeEntry<L> {
  readonly cidr: string;
  readonly label: L;
}

interface Ordering<T> {
  less(a: T, b: T): boolean;
  next(value: T): T;
  previous(value: T): T;
}

interface Span<T, L> {
  readonly start: T;
  readonly end: T;
  readonly label: L;
}

interface Segments<T, L> {
  readonly starts: T[];
  readonly ends: T[];
  readonly labels: L[];
}

const V4: Ordering<number> = {
  less: (a, b) => a < b,
  next: (v) => v + 1,
  previous: (v) => v - 1,
};

const V6: Ordering<bigint> = {
  less: (a, b) => a < b,
  next: (v) => v + 1n,
  previous: (v) => v - 1n,
};

export class IpRangeTable<L> {
  readonly size: number;
  readonly rejected: number;
  private readonly v4: Segments<number, L>;
  private readonly v6: Segments<bigint, L>;

  constructor(entries: Iterable<RangeEntry<L>>) {
    const v4: Span<number, L>[] = [];
    const v6: Span<bigint, L>[] = [];
    let rejected = 0;
    for (const entry of entries) {
      const range = parseCidr(entry.cidr);
      if (!range) {
        rejected += 1;
      } else if (range.version === 4) {
        v4.push({ start: range.start, end: range.end, label: entry.label });
      } else {
        v6.push({ start: range.start, end: range.end, label: entry.label });
      }
    }
    this.v4 = flatten(v4, V4);
    this.v6 = flatten(v6, V6);
    this.size = v4.length + v6.length;
    this.rejected = rejected;
  }

  static empty<L>(): IpRangeTable<L> {
    return new IpRangeTable<L>([]);
  }

  lookup(ip: ParsedIp | null): L | undefined {
    if (!ip) return undefined;
    return ip.version === 4 ? search(this.v4, ip.value, V4) : search(this.v6, ip.value, V6);
  }

  has(ip: ParsedIp | null): boolean {
    return this.lookup(ip) !== undefined;
  }

  minimalEntries(): RangeEntry<L>[] {
    const entries: RangeEntry<L>[] = [];
    this.v4.starts.forEach((start, i) => {
      for (const cidr of cover(BigInt(start), BigInt(this.v4.ends[i] as number), 32)) entries.push({ cidr, label: this.v4.labels[i] as L });
    });
    this.v6.starts.forEach((start, i) => {
      for (const cidr of cover(start, this.v6.ends[i] as bigint, 128)) entries.push({ cidr, label: this.v6.labels[i] as L });
    });
    return entries;
  }
}

function cover(start: bigint, end: bigint, width: 32 | 128): string[] {
  const cidrs: string[] = [];
  for (let block = start; block <= end; ) {
    let bits = width;
    while (bits > 0) {
      const size = 1n << BigInt(width - bits + 1);
      if (block % size !== 0n || block + size - 1n > end) break;
      bits -= 1;
    }
    const address = width === 32 ? formatIp({ version: 4, value: Number(block) }) : formatIp({ version: 6, value: block });
    cidrs.push(`${address}/${bits}`);
    block += 1n << BigInt(width - bits);
  }
  return cidrs;
}

function flatten<T, L>(spans: Span<T, L>[], order: Ordering<T>): Segments<T, L> {
  spans.sort((a, b) => {
    if (order.less(a.start, b.start)) return -1;
    if (order.less(b.start, a.start)) return 1;
    if (order.less(b.end, a.end)) return -1;
    if (order.less(a.end, b.end)) return 1;
    return 0;
  });

  const out: Segments<T, L> = { starts: [], ends: [], labels: [] };
  const emit = (start: T, end: T, label: L): void => {
    if (order.less(end, start)) return;
    const last = out.starts.length - 1;
    if (last >= 0 && out.labels[last] === label && order.next(out.ends[last] as T) === start) {
      out.ends[last] = end;
      return;
    }
    out.starts.push(start);
    out.ends.push(end);
    out.labels.push(label);
  };

  const stack: Span<T, L>[] = [];
  let uncovered: T | undefined;
  for (const span of spans) {
    let top = stack.at(-1);
    while (top && order.less(top.end, span.start)) {
      stack.pop();
      emit(uncovered ?? top.start, top.end, top.label);
      uncovered = order.next(top.end);
      top = stack.at(-1);
    }
    if (top) {
      if (top.start === span.start && top.end === span.end) continue;
      if (uncovered !== undefined && order.less(uncovered, span.start)) emit(uncovered, order.previous(span.start), top.label);
    }
    uncovered = span.start;
    stack.push(span);
  }
  for (let top = stack.pop(); top; top = stack.pop()) {
    emit(uncovered ?? top.start, top.end, top.label);
    uncovered = order.next(top.end);
  }
  return out;
}

function search<T, L>(segments: Segments<T, L>, value: T, order: Ordering<T>): L | undefined {
  let low = 0;
  let high = segments.starts.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    if (order.less(value, segments.starts[mid] as T)) high = mid - 1;
    else if (order.less(segments.ends[mid] as T, value)) low = mid + 1;
    else return segments.labels[mid];
  }
  return undefined;
}
