import { z } from 'zod';
import { ALL_REASONS, type RiskFamily, type RiskReason } from './types.ts';

export interface Thresholds {
  readonly monitor: number;
  readonly challenge: number;
  readonly restrict: number;
  readonly block: number;
}

export type ScoredFamily = Exclude<RiskFamily, 'trust'>;

export interface RiskPolicy {
  readonly version: string;
  readonly thresholds: Thresholds;
  readonly conversionThresholds: Thresholds;
  readonly familyCaps: Readonly<Record<ScoredFamily, number>>;
  readonly familyDecay: number;
  readonly trust: {
    readonly maxCredit: number;
    readonly highSeverityFactor: number;
    readonly criticalSeverityFactor: number;
  };
  readonly blockMinHighFamilies: number;
  readonly points: Readonly<Record<RiskReason, number>>;
  readonly limits: {
    readonly visitorRequestsPerMinute: { readonly elevated: number; readonly extreme: number };
    readonly addressRequestsPerMinute: { readonly base: number; readonly perMember: number; readonly extremeFactor: number };
    readonly visitorPaidClicks: { readonly per5m: number; readonly per1h: number; readonly extremeFactor: number };
    readonly networkPaidClicks: {
      readonly per5m: number;
      readonly per1h: number;
      readonly perMember: number;
      readonly extremeFactor: number;
    };
    readonly asnPaidClicksPer5m: number;
    readonly clickReuseVisitors: { readonly elevated: number; readonly extreme: number };
    readonly networkFreshIdentities: { readonly perHour: number; readonly perMember: number; readonly extremeFactor: number };
    readonly visitorActionsPer10m: number;
    readonly visitorConversionsPerDay: number;
    readonly networkConversionsPerHour: { readonly base: number; readonly perMember: number };
    readonly mechanicalTiming: { readonly minSamples: number; readonly maxCv: number; readonly maxMeanMs: number };
    readonly burstiness: { readonly minSamples: number; readonly minBurst: number };
    readonly pathEntropy: { readonly minDepth: number; readonly maxEntropy: number };
    readonly pointerMechanicalCv: number;
    readonly conversionTimingMs: number;
    readonly form: { readonly minFillMs: number; readonly maxAgeMs: number };
    readonly repeatedMessageContacts: number;
    readonly repeatOffender: { readonly elevated: number; readonly extreme: number };
    readonly graph: {
      readonly behavior: number;
      readonly device: number;
      readonly timing: number;
      readonly click: number;
      readonly campaign: number;
      readonly lead: number;
    };
    readonly baseline: { readonly spikeZ: number; readonly conversionDropZ: number };
  };
  readonly restriction: {
    readonly durationSeconds: number;
    readonly blockDurationSeconds: number;
    readonly maxSharedPopulation: number;
    readonly maxEscalation: number;
  };
  readonly established: {
    readonly populationCookieAgeSeconds: number;
    readonly trustedCookieAgeSeconds: number;
    readonly trustedMinSessions: number;
  };
  readonly conversion: { readonly trustedMaxScore: number };
  readonly clearanceTtlSeconds: number;
  readonly sessionIdleSeconds: number;
}

const DEFAULT_POINTS: Record<RiskReason, number> = {
  'network.hosting': 22,
  'network.tor': 18,
  'network.vpn': 16,
  'network.residential_proxy': 20,
  'network.public_proxy': 16,
  'network.origin_bypass': 40,
  'network.address_velocity': 15,
  'network.address_velocity_extreme': 35,
  'network.identity_churn': 20,
  'network.identity_churn_extreme': 35,
  'network.paid_velocity': 18,
  'network.paid_velocity_extreme': 32,
  'network.asn_paid_burst': 10,
  'network.conversion_velocity': 30,

  'client.user_agent_missing': 25,
  'client.automation_tool': 35,
  'client.crawler_impersonation': 45,
  'client.hints_brand_mismatch': 20,
  'client.hints_platform_mismatch': 10,
  'client.hints_missing': 8,
  'client.fetch_metadata_missing': 10,
  'client.navigation_accept_missing': 15,
  'client.accept_language_missing': 8,
  'client.forged_identity': 15,
  'client.script_automation': 35,

  'client.impossible_combination': 32,
  'client.platform_os_mismatch': 18,
  'client.mobile_touch_mismatch': 16,
  'client.hints_mobile_mismatch': 10,
  'client.feature_family_mismatch': 30,
  'client.hardware_inconsistency': 10,
  'client.timezone_locale_mismatch': 6,
  'client.storage_inconsistency': 8,
  'client.transport_mismatch': 18,

  'paid.visitor_click_velocity': 30,
  'paid.visitor_click_velocity_extreme': 45,
  'paid.click_reuse': 18,
  'paid.click_reuse_extreme': 30,
  'paid.malformed_attribution': 6,

  'behavior.visitor_velocity': 20,
  'behavior.visitor_velocity_extreme': 70,
  'behavior.mechanical_timing': 20,
  'behavior.action_velocity': 35,
  'behavior.conversion_velocity': 40,
  'behavior.repeat_offender': 15,
  'behavior.repeat_offender_extreme': 30,
  'behavior.direct_sensitive_access': 30,
  'behavior.script_unverified': 8,
  'behavior.origin_missing': 20,
  'behavior.honeypot': 40,
  'behavior.form_too_fast': 25,
  'behavior.form_token_missing': 35,
  'behavior.form_token_invalid': 35,
  'behavior.form_token_expired': 8,
  'behavior.form_token_replayed': 60,
  'behavior.repeated_message': 20,
  'behavior.burstiness': 16,
  'behavior.low_path_entropy': 14,
  'behavior.timing_clone': 28,
  'behavior.pointer_mechanical': 10,
  'behavior.conversion_timing': 18,
  'behavior.session_template': 16,

  'edge.bot_score_automated': 55,
  'edge.bot_score_likely': 35,

  'graph.behavior_cluster': 28,
  'graph.device_cluster': 18,
  'graph.timing_cluster': 24,
  'graph.click_cluster': 30,
  'graph.campaign_cluster': 20,
  'graph.lead_cluster': 32,

  'baseline.campaign_spike': 26,
  'baseline.conversion_rate_drop': 16,
  'baseline.asn_dominance': 14,
  'baseline.identity_spike': 16,

  'trust.established_visitor': 12,
  'trust.engaged_session': 10,
  'trust.script_verified': 6,
  'trust.human_interaction': 6,
  'trust.challenge_passed': 25,
  'trust.authenticated_user': 15,
  'trust.prior_conversion': 8,
  'trust.edge_likely_human': 10,
};

export const DEFAULT_POLICY: RiskPolicy = {
  version: '2026.10.2',
  thresholds: { monitor: 20, challenge: 45, restrict: 70, block: 90 },
  conversionThresholds: { monitor: 15, challenge: 30, restrict: 60, block: 85 },
  familyCaps: { network: 45, client: 45, paid: 45, behavior: 75, edge: 60, graph: 40, baseline: 35, consistency: 40 },
  familyDecay: 0.5,
  trust: { maxCredit: 35, highSeverityFactor: 0.5, criticalSeverityFactor: 0 },
  blockMinHighFamilies: 2,
  points: DEFAULT_POINTS,
  limits: {
    visitorRequestsPerMinute: { elevated: 90, extreme: 300 },
    addressRequestsPerMinute: { base: 180, perMember: 40, extremeFactor: 3 },
    visitorPaidClicks: { per5m: 3, per1h: 6, extremeFactor: 2 },
    networkPaidClicks: { per5m: 6, per1h: 15, perMember: 3, extremeFactor: 2 },
    asnPaidClicksPer5m: 40,
    clickReuseVisitors: { elevated: 3, extreme: 6 },
    networkFreshIdentities: { perHour: 20, perMember: 3, extremeFactor: 2 },
    visitorActionsPer10m: 20,
    visitorConversionsPerDay: 4,
    networkConversionsPerHour: { base: 6, perMember: 1 },
    mechanicalTiming: { minSamples: 8, maxCv: 0.12, maxMeanMs: 15_000 },
    burstiness: { minSamples: 8, minBurst: 0.88 },
    pathEntropy: { minDepth: 4, maxEntropy: 0.55 },
    pointerMechanicalCv: 0.06,
    conversionTimingMs: 3_000,
    form: { minFillMs: 2_500, maxAgeMs: 2 * 60 * 60 * 1000 },
    repeatedMessageContacts: 3,
    repeatOffender: { elevated: 1, extreme: 3 },
    graph: { behavior: 8, device: 12, timing: 10, click: 4, campaign: 25, lead: 5 },
    baseline: { spikeZ: 4, conversionDropZ: 3 },
  },
  restriction: { durationSeconds: 600, blockDurationSeconds: 3600, maxSharedPopulation: 2, maxEscalation: 4 },
  established: { populationCookieAgeSeconds: 3600, trustedCookieAgeSeconds: 86_400, trustedMinSessions: 2 },
  conversion: { trustedMaxScore: 30 },
  clearanceTtlSeconds: 1800,
  sessionIdleSeconds: 1800,
};

const score = z.number().min(0).max(100);
const positive = z.number().positive();
const count = z.number().int().min(0);

const thresholdsSchema = z
  .object({ monitor: score, challenge: score, restrict: score, block: score })
  .strict()
  .refine((t) => t.monitor < t.challenge && t.challenge < t.restrict && t.restrict <= t.block, {
    message: 'thresholds must increase: monitor < challenge < restrict <= block',
  });

const pointsSchema = z
  .object(Object.fromEntries(ALL_REASONS.map((reason) => [reason, score])) as Record<RiskReason, typeof score>)
  .strict();

const policySchema = z
  .object({
    version: z.string().min(1).max(40),
    thresholds: thresholdsSchema,
    conversionThresholds: thresholdsSchema,
    familyCaps: z
      .object({ network: score, client: score, paid: score, behavior: score, edge: score, graph: score, baseline: score, consistency: score })
      .strict(),
    familyDecay: z.number().min(0).max(1),
    trust: z
      .object({ maxCredit: score, highSeverityFactor: z.number().min(0).max(1), criticalSeverityFactor: z.number().min(0).max(1) })
      .strict(),
    blockMinHighFamilies: z.number().int().min(1).max(5),
    points: pointsSchema,
    limits: z
      .object({
        visitorRequestsPerMinute: z.object({ elevated: positive, extreme: positive }).strict(),
        addressRequestsPerMinute: z.object({ base: positive, perMember: count, extremeFactor: z.number().min(1) }).strict(),
        visitorPaidClicks: z.object({ per5m: positive, per1h: positive, extremeFactor: z.number().min(1) }).strict(),
        networkPaidClicks: z
          .object({ per5m: positive, per1h: positive, perMember: count, extremeFactor: z.number().min(1) })
          .strict(),
        asnPaidClicksPer5m: positive,
        clickReuseVisitors: z.object({ elevated: positive, extreme: positive }).strict(),
        networkFreshIdentities: z.object({ perHour: positive, perMember: count, extremeFactor: z.number().min(1) }).strict(),
        visitorActionsPer10m: positive,
        visitorConversionsPerDay: positive,
        networkConversionsPerHour: z.object({ base: positive, perMember: count }).strict(),
        mechanicalTiming: z.object({ minSamples: positive, maxCv: positive, maxMeanMs: positive }).strict(),
        burstiness: z.object({ minSamples: positive, minBurst: z.number().min(0).max(1) }).strict(),
        pathEntropy: z.object({ minDepth: positive, maxEntropy: z.number().min(0).max(8) }).strict(),
        pointerMechanicalCv: z.number().min(0).max(1),
        conversionTimingMs: positive,
        form: z.object({ minFillMs: count, maxAgeMs: positive }).strict(),
        repeatedMessageContacts: positive,
        repeatOffender: z.object({ elevated: positive, extreme: positive }).strict(),
        graph: z
          .object({ behavior: positive, device: positive, timing: positive, click: positive, campaign: positive, lead: positive })
          .strict(),
        baseline: z.object({ spikeZ: z.number().min(1), conversionDropZ: z.number().min(1) }).strict(),
      })
      .strict(),
    restriction: z
      .object({ durationSeconds: positive, blockDurationSeconds: positive, maxSharedPopulation: count, maxEscalation: z.number().min(1) })
      .strict(),
    established: z
      .object({ populationCookieAgeSeconds: count, trustedCookieAgeSeconds: count, trustedMinSessions: positive })
      .strict(),
    conversion: z.object({ trustedMaxScore: score }).strict(),
    clearanceTtlSeconds: positive,
    sessionIdleSeconds: positive,
  })
  .strict();

export interface PolicyOverrides {
  readonly file?: unknown;
  readonly thresholds?: Partial<Thresholds>;
}

export function buildPolicy(overrides: PolicyOverrides = {}): RiskPolicy {
  const merged = deepMerge(DEFAULT_POLICY, overrides.file ?? {});
  const withThresholds = deepMerge(merged, { thresholds: definedOnly(overrides.thresholds ?? {}) });
  const parsed = policySchema.safeParse(withThresholds);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`).join('; ');
    throw new Error(`invalid risk policy: ${detail}`);
  }
  return parsed.data;
}

function definedOnly(value: Partial<Thresholds>): Partial<Thresholds> {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined));
}

const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function deepMerge(base: unknown, patch: unknown): unknown {
  if (!isPlainObject(base) || !isPlainObject(patch)) return patch === undefined ? base : patch;
  const out: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (UNSAFE_KEYS.has(key)) continue;
    out[key] = Object.hasOwn(base, key) ? deepMerge(base[key], value) : value;
  }
  return out;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
