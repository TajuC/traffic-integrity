export interface GraphSubject {
  readonly now: number;
  readonly visitorId?: string;
  readonly addressKey: string;
  readonly networkKey: string;
  readonly asn?: number;
  readonly clickHash?: string;
  readonly campaign?: string;
  readonly landing?: string;
  readonly behaviorSig?: string;
  readonly deviceSig?: string;
  readonly timingSig?: string;
  readonly emailFingerprint?: string;
  readonly phoneFingerprint?: string;
  readonly messageFingerprint?: string;
}

export type ClusterKind = 'behavior' | 'device' | 'timing' | 'click' | 'campaign_asn' | 'lead';

export interface ClusterHit {
  readonly kind: ClusterKind;
  readonly key: string;
  readonly members: number;
  readonly threshold: number;
}

interface Bucket {
  readonly members: Set<string>;
  expiresAt: number;
}

const TTL_MS = 6 * 60 * 60 * 1000;
const MAX_BUCKETS = 30_000;
const MAX_MEMBERS = 4_000;

const THRESHOLDS: Readonly<Record<ClusterKind, number>> = {
  behavior: 8,
  device: 12,
  timing: 10,
  click: 4,
  campaign_asn: 25,
  lead: 5,
};

export class CorrelationEngine {
  private readonly buckets = new Map<string, Bucket>();

  observe(subject: GraphSubject): ClusterHit[] {
    const hits: ClusterHit[] = [];
    const member = subject.visitorId ?? subject.addressKey;
    const now = subject.now;
    if (subject.behaviorSig) this.collect(hits, 'behavior', subject.behaviorSig, member, now);
    if (subject.deviceSig) this.collect(hits, 'device', subject.deviceSig, member, now);
    if (subject.timingSig) this.collect(hits, 'timing', subject.timingSig, member, now);
    if (subject.clickHash && subject.visitorId) this.collect(hits, 'click', subject.clickHash, subject.visitorId, now);
    if (subject.campaign && subject.asn !== undefined) {
      this.collect(hits, 'campaign_asn', `${subject.campaign}:${subject.asn}`, member, now);
    }
    const leadKey = subject.emailFingerprint ?? subject.phoneFingerprint ?? subject.messageFingerprint;
    if (leadKey) this.collect(hits, 'lead', leadKey, member, now);
    return hits;
  }

  private collect(hits: ClusterHit[], kind: ClusterKind, key: string, member: string, now: number): void {
    const size = this.add(`${kind}:${key}`, member, now);
    const threshold = THRESHOLDS[kind];
    if (size >= threshold) hits.push({ kind, key, members: size, threshold });
  }

  private add(key: string, member: string, now: number): number {
    let bucket = this.buckets.get(key);
    if (!bucket || bucket.expiresAt <= now) {
      bucket = { members: new Set(), expiresAt: now + TTL_MS };
      this.buckets.set(key, bucket);
    }
    if (bucket.members.size < MAX_MEMBERS) bucket.members.add(member);
    bucket.expiresAt = now + TTL_MS;
    this.buckets.delete(key);
    this.buckets.set(key, bucket);
    while (this.buckets.size > MAX_BUCKETS) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
    return bucket.members.size;
  }
}
