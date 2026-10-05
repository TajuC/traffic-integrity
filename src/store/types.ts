export type ObservedKind = 'page' | 'api' | 'action' | 'conversion' | 'internal';

export const WINDOWS = {
  requestTauMs: 60_000,
  actionTauMs: 600_000,
  visitorConversionTauMs: 86_400_000,
  networkConversionTauMs: 3_600_000,
  globalConversionTauMs: 3_600_000,
  strikeTauMs: 86_400_000,
  paidShortMs: 300_000,
  paidLongMs: 3_600_000,
  freshMs: 3_600_000,
  populationMs: 43_200_000,
  clickReuseMs: 43_200_000,
  timingMaxGapMs: 600_000,
  timingAlpha: 0.2,
} as const;

export const TTLS = {
  visitorMs: 7 * 86_400_000,
  provisionalVisitorMs: 600_000,
  addressMs: 600_000,
  networkMs: 7_200_000,
  globalMs: 7_200_000,
} as const;

export interface ObservedVisitor {
  readonly id: string;
  readonly sessionId: string;
  readonly fresh: boolean;
  readonly established: boolean;
}

export interface ObservationPlan {
  readonly now: number;
  readonly kind: ObservedKind;
  readonly sessionIdleMs: number;
  readonly visitor: ObservedVisitor | undefined;
  readonly addressKey: string;
  readonly networkKey: string;
  readonly asn: number | undefined;
  readonly paidClick: string | undefined;
  readonly attribution: string | undefined;
}

export interface TimingStats {
  readonly samples: number;
  readonly meanMs: number;
  readonly cv: number;
}

export interface VisitorObservation {
  readonly requestRate: number;
  readonly actionRate: number;
  readonly conversionRate: number;
  readonly timing: TimingStats;
  readonly sessionStartedAt: number;
  readonly sessionDepth: number;
  readonly sessionCount: number;
  readonly scriptVerifiedAt: number | undefined;
  readonly interactionAt: number | undefined;
  readonly automationFlags: number;
  readonly clearanceUntil: number | undefined;
  readonly restrictedUntil: number | undefined;
  readonly strikes: number;
  readonly acceptedConversions: number;
  readonly paidClicks5m: number;
  readonly paidClicks1h: number;
  readonly attribution: string | undefined;
}

export interface AddressObservation {
  readonly requestRate: number;
  readonly population: number;
  readonly restrictedUntil: number | undefined;
  readonly strikes: number;
}

export interface NetworkObservation {
  readonly requestRate: number;
  readonly conversionRate: number;
  readonly paidClicks5m: number;
  readonly paidClicks1h: number;
  readonly freshIdentities: number;
  readonly population: number;
}

export interface Observation {
  readonly source: 'redis' | 'memory';
  readonly visitor: VisitorObservation | undefined;
  readonly address: AddressObservation;
  readonly network: NetworkObservation;
  readonly asnPaidClicks5m: number | undefined;
  readonly clickVisitors: number | undefined;
}

export interface VisitorPatch {
  readonly scriptVerifiedAt?: number;
  readonly interactionAt?: number;
  readonly automationFlags?: number;
  readonly clearanceUntil?: number;
  readonly acceptedConversion?: boolean;
}

export interface RestrictionTarget {
  readonly visitorId?: string;
  readonly addressKey?: string;
}

export interface IntegrityStore {
  observe(plan: ObservationPlan): Promise<Observation>;
  patchVisitor(visitorId: string, patch: VisitorPatch, now: number): Promise<void>;
  restrict(target: RestrictionTarget, until: number, now: number): Promise<void>;
  claimOnce(key: string, ttlMs: number): Promise<boolean>;
  countGlobalConversion(now: number): Promise<number>;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}

export function bucket(now: number, width: number): number {
  return Math.floor(now / width);
}

export function decay(value: number, last: number | undefined, now: number, tauMs: number): number {
  if (last === undefined || !Number.isFinite(value)) return 0;
  const elapsed = now - last;
  return elapsed <= 0 ? value : value * Math.exp(-elapsed / tauMs);
}

export function coefficientOfVariation(mean: number, variance: number): number {
  return mean > 0 ? Math.sqrt(Math.max(variance, 0)) / mean : 0;
}
