export interface ExclusionRecommendation {
  readonly kind: 'ip' | 'network' | 'asn';
  readonly target: string;
  readonly visits: number;
  readonly visitors: number;
  readonly campaigns: readonly string[];
  readonly lastSeen: string;
  readonly applyAutomatically: false;
  readonly note: string;
}

export interface CampaignRecommendation {
  readonly campaign: string;
  readonly kind: 'investigate' | 'throttle' | 'pause_review';
  readonly suspiciousVisits: number;
  readonly totalVisits: number;
  readonly spendAtRiskUsd: number | undefined;
  readonly note: string;
  readonly applyAutomatically: false;
}

export function spendAtRisk(suspiciousVisits: number, cpcUsd: number | undefined): number | undefined {
  if (cpcUsd === undefined || cpcUsd < 0) return undefined;
  return Math.round(suspiciousVisits * cpcUsd * 100) / 100;
}

export function campaignRecommendation(input: {
  readonly campaign: string;
  readonly visits: number;
  readonly suspicious: number;
  readonly cpcUsd?: number;
}): CampaignRecommendation {
  const ratio = input.visits === 0 ? 0 : input.suspicious / input.visits;
  const kind = ratio >= 0.6 && input.suspicious >= 40 ? 'pause_review' : ratio >= 0.35 && input.suspicious >= 15 ? 'throttle' : 'investigate';
  return {
    campaign: input.campaign,
    kind,
    suspiciousVisits: input.suspicious,
    totalVisits: input.visits,
    spendAtRiskUsd: spendAtRisk(input.suspicious, input.cpcUsd),
    applyAutomatically: false,
    note:
      kind === 'pause_review'
        ? 'Severe campaign anomaly. Review before any pause. Origin-side detection cannot stop Google from billing clicks that already occurred.'
        : 'Investigate invalid traffic and consider IP exclusions. Do not apply campaign changes without an explicit approval step.',
  };
}

export interface AdsControlPlane {
  readonly enabled: boolean;
  listCampaigns(): Promise<ReadonlyArray<{ id: string; name: string; status: string }>>;
  applyIpExclusions(ips: readonly string[]): Promise<{ applied: number; skipped: number }>;
}

export function disabledAdsControlPlane(): AdsControlPlane {
  return {
    enabled: false,
    listCampaigns: () => Promise.resolve([]),
    applyIpExclusions: () => Promise.resolve({ applied: 0, skipped: 0 }),
  };
}
