export type RiskDecision = 'ALLOW' | 'ALLOW_AND_MONITOR' | 'CHALLENGE' | 'TEMPORARILY_RESTRICT' | 'BLOCK';

export const DECISION_ORDER: readonly RiskDecision[] = [
  'ALLOW',
  'ALLOW_AND_MONITOR',
  'CHALLENGE',
  'TEMPORARILY_RESTRICT',
  'BLOCK',
];

export type RiskFamily = 'network' | 'client' | 'paid' | 'behavior' | 'edge' | 'trust';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

interface ReasonMeta {
  readonly family: RiskFamily;
  readonly severity: Severity;
}

export const RISK_REASONS = {
  'network.hosting': { family: 'network', severity: 'medium' },
  'network.tor': { family: 'network', severity: 'medium' },
  'network.origin_bypass': { family: 'network', severity: 'high' },
  'network.address_velocity': { family: 'network', severity: 'medium' },
  'network.address_velocity_extreme': { family: 'network', severity: 'high' },
  'network.identity_churn': { family: 'network', severity: 'medium' },
  'network.identity_churn_extreme': { family: 'network', severity: 'high' },
  'network.paid_velocity': { family: 'network', severity: 'medium' },
  'network.paid_velocity_extreme': { family: 'network', severity: 'high' },
  'network.asn_paid_burst': { family: 'network', severity: 'low' },
  'network.conversion_velocity': { family: 'network', severity: 'high' },

  'client.user_agent_missing': { family: 'client', severity: 'medium' },
  'client.automation_tool': { family: 'client', severity: 'high' },
  'client.crawler_impersonation': { family: 'client', severity: 'high' },
  'client.hints_brand_mismatch': { family: 'client', severity: 'medium' },
  'client.hints_platform_mismatch': { family: 'client', severity: 'low' },
  'client.hints_missing': { family: 'client', severity: 'low' },
  'client.fetch_metadata_missing': { family: 'client', severity: 'low' },
  'client.navigation_accept_missing': { family: 'client', severity: 'medium' },
  'client.accept_language_missing': { family: 'client', severity: 'low' },
  'client.forged_identity': { family: 'client', severity: 'medium' },
  'client.script_automation': { family: 'client', severity: 'high' },

  'paid.visitor_click_velocity': { family: 'paid', severity: 'high' },
  'paid.visitor_click_velocity_extreme': { family: 'paid', severity: 'critical' },
  'paid.click_reuse': { family: 'paid', severity: 'medium' },
  'paid.click_reuse_extreme': { family: 'paid', severity: 'high' },
  'paid.malformed_attribution': { family: 'paid', severity: 'low' },

  'behavior.visitor_velocity': { family: 'behavior', severity: 'medium' },
  'behavior.visitor_velocity_extreme': { family: 'behavior', severity: 'critical' },
  'behavior.mechanical_timing': { family: 'behavior', severity: 'medium' },
  'behavior.action_velocity': { family: 'behavior', severity: 'high' },
  'behavior.conversion_velocity': { family: 'behavior', severity: 'high' },
  'behavior.repeat_offender': { family: 'behavior', severity: 'medium' },
  'behavior.repeat_offender_extreme': { family: 'behavior', severity: 'high' },
  'behavior.direct_sensitive_access': { family: 'behavior', severity: 'high' },
  'behavior.script_unverified': { family: 'behavior', severity: 'low' },
  'behavior.origin_missing': { family: 'behavior', severity: 'medium' },
  'behavior.honeypot': { family: 'behavior', severity: 'high' },
  'behavior.form_too_fast': { family: 'behavior', severity: 'medium' },
  'behavior.form_token_missing': { family: 'behavior', severity: 'high' },
  'behavior.form_token_invalid': { family: 'behavior', severity: 'high' },
  'behavior.form_token_expired': { family: 'behavior', severity: 'low' },
  'behavior.form_token_replayed': { family: 'behavior', severity: 'critical' },
  'behavior.repeated_message': { family: 'behavior', severity: 'medium' },

  'edge.bot_score_automated': { family: 'edge', severity: 'critical' },
  'edge.bot_score_likely': { family: 'edge', severity: 'high' },

  'trust.established_visitor': { family: 'trust', severity: 'low' },
  'trust.engaged_session': { family: 'trust', severity: 'low' },
  'trust.script_verified': { family: 'trust', severity: 'low' },
  'trust.human_interaction': { family: 'trust', severity: 'low' },
  'trust.challenge_passed': { family: 'trust', severity: 'low' },
  'trust.authenticated_user': { family: 'trust', severity: 'low' },
  'trust.prior_conversion': { family: 'trust', severity: 'low' },
  'trust.edge_likely_human': { family: 'trust', severity: 'low' },
} as const satisfies Record<string, ReasonMeta>;

export type RiskReason = keyof typeof RISK_REASONS;

export const ALL_REASONS = Object.keys(RISK_REASONS) as RiskReason[];

export type Evidence = Readonly<Record<string, number | string | boolean>>;

export interface RiskSignal {
  readonly reason: RiskReason;
  readonly family: RiskFamily;
  readonly severity: Severity;
  readonly points: number;
  readonly evidence?: Evidence;
}

export interface RiskAssessment {
  readonly id: string;
  readonly score: number;
  readonly decision: RiskDecision;
  readonly signals: readonly RiskSignal[];
  readonly families: Readonly<Partial<Record<RiskFamily, number>>>;
  readonly trustCredit: number;
  readonly confidence: 'full' | 'reduced';
  readonly degraded: readonly string[];
  readonly policyVersion: string;
}

export function severityRank(severity: Severity): number {
  return severity === 'critical' ? 3 : severity === 'high' ? 2 : severity === 'medium' ? 1 : 0;
}

export function decisionRank(decision: RiskDecision): number {
  return DECISION_ORDER.indexOf(decision);
}
