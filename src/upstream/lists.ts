export interface EdgeListEntry {
  readonly action: 'challenge' | 'block';
  readonly subjectType: 'ip' | 'network' | 'asn' | 'visitor';
  readonly subjectKey: string;
  readonly reason: string;
  readonly confidence: number;
  readonly ttlSeconds: number;
  readonly clusterId?: string;
}

const MAX_TTL_SECONDS = 30 * 60;
const MIN_BLOCK_CONFIDENCE = 0.92;
const MIN_CHALLENGE_CONFIDENCE = 0.8;

export function proposeEdgeAction(input: {
  readonly decision: string;
  readonly numericConfidence: number;
  readonly clusterSize: number;
  readonly personalAddress: boolean;
  readonly ipHash: string;
  readonly visitorId?: string;
  readonly reasons: readonly string[];
}): EdgeListEntry | undefined {
  if (input.decision !== 'BLOCK' && input.decision !== 'TEMPORARILY_RESTRICT') return undefined;
  const clustered = input.clusterSize >= 8;
  if (!clustered && input.numericConfidence < MIN_BLOCK_CONFIDENCE) return undefined;
  const action: EdgeListEntry['action'] = input.decision === 'BLOCK' && input.numericConfidence >= MIN_BLOCK_CONFIDENCE ? 'block' : 'challenge';
  if (action === 'challenge' && input.numericConfidence < MIN_CHALLENGE_CONFIDENCE && !clustered) return undefined;
  const ttlSeconds = Math.min(MAX_TTL_SECONDS, action === 'block' ? 600 : 300);
  const subjectType = input.personalAddress ? 'ip' : input.visitorId ? 'visitor' : 'network';
  const subjectKey = subjectType === 'visitor' ? (input.visitorId ?? input.ipHash) : input.ipHash;
  return {
    action,
    subjectType,
    subjectKey,
    reason: input.reasons.slice(0, 8).join(','),
    confidence: input.numericConfidence,
    ttlSeconds,
  };
}

export function cloudflareExpression(entries: readonly EdgeListEntry[]): string {
  const ips = entries.filter((entry) => entry.subjectType === 'ip').map((entry) => entry.subjectKey);
  if (ips.length === 0) return '';
  return `(ip.src in {${ips.join(' ')}})`;
}

export interface CloudflareListPayload {
  readonly kind: 'cloudflare_custom_list';
  readonly action: 'challenge' | 'block';
  readonly ttlSeconds: number;
  readonly items: readonly string[];
  readonly note: string;
}

export function cloudflareListPayload(entries: readonly EdgeListEntry[]): CloudflareListPayload[] {
  const groups: Record<string, EdgeListEntry[]> = { challenge: [], block: [] };
  for (const entry of entries) (groups[entry.action] ?? []).push(entry);
  return (['challenge', 'block'] as const)
    .filter((action) => (groups[action] ?? []).length > 0)
    .map((action) => ({
      kind: 'cloudflare_custom_list' as const,
      action,
      ttlSeconds: Math.min(...(groups[action] ?? []).map((entry) => entry.ttlSeconds)),
      items: (groups[action] ?? []).map((entry) => entry.subjectKey),
      note: 'Short-lived origin-proposed edge restriction. Review before applying. Origin-side software cannot prevent Google Ads from billing a click that already happened.',
    }));
}
