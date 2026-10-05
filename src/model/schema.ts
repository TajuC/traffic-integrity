export const FEATURE_NAMES = [
  'heuristic_score',
  'family_network',
  'family_client',
  'family_paid',
  'family_behavior',
  'family_edge',
  'family_graph',
  'family_baseline',
  'family_consistency',
  'trust_credit',
  'hosting',
  'tor',
  'vpn',
  'automation_ua',
  'script_automation',
  'paid_arrival',
  'click_reuse',
  'visitor_rate',
  'address_rate',
  'timing_cv',
  'established',
  'authenticated',
  'clearance',
  'edge_bot_score',
  'session_depth',
  'cluster_size',
  'campaign_z',
  'consistency_failures',
  'hour_of_day',
  'js_verified',
] as const;

export type FeatureName = (typeof FEATURE_NAMES)[number];
export const FEATURE_INDEX: Readonly<Record<FeatureName, number>> = Object.fromEntries(FEATURE_NAMES.map((name, index) => [name, index])) as Record<FeatureName, number>;

export interface FeatureVector {
  readonly schemaVersion: string;
  readonly names: readonly FeatureName[];
  readonly values: readonly number[];
}

export interface LabeledExample {
  readonly id: string;
  readonly label: number;
  readonly clazz: string;
  readonly vector: FeatureVector;
}

export function vectorValue(vector: FeatureVector, name: FeatureName): number {
  return vector.values[FEATURE_INDEX[name]] ?? 0;
}

export function clip01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}
