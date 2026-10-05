export type RiskDecision = 'ALLOW' | 'ALLOW_AND_MONITOR' | 'CHALLENGE' | 'TEMPORARILY_RESTRICT' | 'BLOCK';

export const DECISION_ORDER: readonly RiskDecision[] = [
  'ALLOW',
  'ALLOW_AND_MONITOR',
  'CHALLENGE',
  'TEMPORARILY_RESTRICT',
  'BLOCK',
];

export type RiskFamily = 'network' | 'client' | 'paid' | 'behavior' | 'edge' | 'graph' | 'baseline' | 'consistency' | 'trust';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type SignalSource = 'network' | 'client' | 'paid' | 'behavior' | 'edge' | 'graph' | 'baseline' | 'consistency' | 'trust';

interface ReasonMeta {
  readonly family: RiskFamily;
  readonly severity: Severity;
  readonly source: SignalSource;
  readonly explanation: string;
}

export const RISK_REASONS = {
  'network.hosting': { family: 'network', severity: 'medium', source: 'network', explanation: 'Address belongs to hosting or cloud infrastructure.' },
  'network.tor': { family: 'network', severity: 'medium', source: 'network', explanation: 'Address is a Tor exit or reported as anonymous country T1.' },
  'network.vpn': { family: 'network', severity: 'medium', source: 'network', explanation: 'Address classified as a VPN egress with independent evidence.' },
  'network.residential_proxy': { family: 'network', severity: 'medium', source: 'network', explanation: 'Address classified as a residential proxy network, not a household ISP.' },
  'network.public_proxy': { family: 'network', severity: 'medium', source: 'network', explanation: 'Address classified as a public proxy.' },
  'network.origin_bypass': { family: 'network', severity: 'high', source: 'network', explanation: 'Edge was required but the request did not arrive through the trusted zone.' },
  'network.address_velocity': { family: 'network', severity: 'medium', source: 'network', explanation: 'Request rate from this address exceeds the population-scaled limit.' },
  'network.address_velocity_extreme': { family: 'network', severity: 'high', source: 'network', explanation: 'Request rate from this address is several times the scaled limit.' },
  'network.identity_churn': { family: 'network', severity: 'medium', source: 'network', explanation: 'Too many fresh visitor identities from this network for the established population.' },
  'network.identity_churn_extreme': { family: 'network', severity: 'high', source: 'network', explanation: 'Identity churn from this network is extreme relative to established users.' },
  'network.paid_velocity': { family: 'network', severity: 'medium', source: 'network', explanation: 'Distinct paid clicks from this network exceed the scaled limit.' },
  'network.paid_velocity_extreme': { family: 'network', severity: 'high', source: 'network', explanation: 'Paid click volume from this network is extreme.' },
  'network.asn_paid_burst': { family: 'network', severity: 'low', source: 'network', explanation: 'One ASN produced a short burst of distinct paid clicks.' },
  'network.conversion_velocity': { family: 'network', severity: 'high', source: 'network', explanation: 'Lead submissions from this network exceed the scaled limit.' },

  'client.user_agent_missing': { family: 'client', severity: 'medium', source: 'client', explanation: 'A page or form request arrived without a User-Agent.' },
  'client.automation_tool': { family: 'client', severity: 'high', source: 'client', explanation: 'The User-Agent or client hints name an HTTP library or headless browser.' },
  'client.crawler_impersonation': { family: 'client', severity: 'high', source: 'client', explanation: 'A crawler claim was disproven by published ranges or reverse DNS.' },
  'client.hints_brand_mismatch': { family: 'client', severity: 'medium', source: 'client', explanation: 'Chromium client hints were sent by a browser claiming to be Safari or Firefox.' },
  'client.hints_platform_mismatch': { family: 'client', severity: 'low', source: 'client', explanation: 'sec-ch-ua-platform contradicts the operating system in the User-Agent.' },
  'client.hints_missing': { family: 'client', severity: 'low', source: 'client', explanation: 'A modern Chromium browser over HTTPS sent fetch metadata but no client hints.' },
  'client.fetch_metadata_missing': { family: 'client', severity: 'low', source: 'client', explanation: 'A modern browser navigated over HTTPS without Sec-Fetch headers.' },
  'client.navigation_accept_missing': { family: 'client', severity: 'medium', source: 'client', explanation: 'A page navigation does not accept text/html.' },
  'client.accept_language_missing': { family: 'client', severity: 'low', source: 'client', explanation: 'A page navigation has no Accept-Language.' },
  'client.forged_identity': { family: 'client', severity: 'medium', source: 'client', explanation: 'The visitor cookie failed signature verification.' },
  'client.script_automation': { family: 'client', severity: 'high', source: 'client', explanation: 'The beacon reported webdriver or automation-framework artifacts.' },

  'client.impossible_combination': { family: 'consistency', severity: 'high', source: 'consistency', explanation: 'JavaScript platform and User-Agent operating system cannot occur together.' },
  'client.platform_os_mismatch': { family: 'consistency', severity: 'medium', source: 'consistency', explanation: 'Client hints platform and User-Agent OS disagree.' },
  'client.mobile_touch_mismatch': { family: 'consistency', severity: 'medium', source: 'consistency', explanation: 'A mobile device claim has no touch capability.' },
  'client.hints_mobile_mismatch': { family: 'consistency', severity: 'low', source: 'consistency', explanation: 'sec-ch-ua-mobile disagrees with the User-Agent device class.' },
  'client.feature_family_mismatch': { family: 'consistency', severity: 'high', source: 'consistency', explanation: 'APIs present in the page are incompatible with the claimed browser family.' },
  'client.hardware_inconsistency': { family: 'consistency', severity: 'low', source: 'consistency', explanation: 'Reported hardware or viewport values are outside realistic ranges.' },
  'client.timezone_locale_mismatch': { family: 'consistency', severity: 'low', source: 'consistency', explanation: 'Timezone and Accept-Language are an uncommon pairing. Weak evidence alone.' },
  'client.storage_inconsistency': { family: 'consistency', severity: 'low', source: 'consistency', explanation: 'Cookies and storage are both disabled in a browser that normally enables them.' },
  'client.transport_mismatch': { family: 'consistency', severity: 'medium', source: 'consistency', explanation: 'Trusted edge transport metadata disagrees with the claimed browser.' },

  'paid.visitor_click_velocity': { family: 'paid', severity: 'high', source: 'paid', explanation: 'One visitor produced more distinct click identifiers than expected.' },
  'paid.visitor_click_velocity_extreme': { family: 'paid', severity: 'critical', source: 'paid', explanation: 'One visitor produced an extreme number of distinct click identifiers.' },
  'paid.click_reuse': { family: 'paid', severity: 'medium', source: 'paid', explanation: 'One click identifier was seen from several identities.' },
  'paid.click_reuse_extreme': { family: 'paid', severity: 'high', source: 'paid', explanation: 'One click identifier was reused across many identities.' },
  'paid.malformed_attribution': { family: 'paid', severity: 'low', source: 'paid', explanation: 'Click or campaign parameters are malformed, oversized, or conflicting.' },

  'behavior.visitor_velocity': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'Visitor request rate is elevated.' },
  'behavior.visitor_velocity_extreme': { family: 'behavior', severity: 'critical', source: 'behavior', explanation: 'Visitor request rate is extreme.' },
  'behavior.mechanical_timing': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'Page navigation gaps are fast and unusually regular.' },
  'behavior.action_velocity': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'Sensitive actions from this visitor exceed the limit.' },
  'behavior.conversion_velocity': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'Lead submissions from this visitor exceed the daily limit.' },
  'behavior.repeat_offender': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'This visitor or personal address was restricted recently.' },
  'behavior.repeat_offender_extreme': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'This visitor or personal address was restricted repeatedly.' },
  'behavior.direct_sensitive_access': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'A lead or action arrived without a returning identity or proven page flow.' },
  'behavior.script_unverified': { family: 'behavior', severity: 'low', source: 'behavior', explanation: 'The visitor never completed the beacon handshake.' },
  'behavior.origin_missing': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'A lead submission has no Origin header.' },
  'behavior.honeypot': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'The hidden form field was filled.' },
  'behavior.form_too_fast': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'The form was submitted faster than a person can fill it.' },
  'behavior.form_token_missing': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'No form token was presented.' },
  'behavior.form_token_invalid': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'The form token was tampered with or bound to another visitor.' },
  'behavior.form_token_expired': { family: 'behavior', severity: 'low', source: 'behavior', explanation: 'The form token is older than two hours.' },
  'behavior.form_token_replayed': { family: 'behavior', severity: 'critical', source: 'behavior', explanation: 'The form token was already used.' },
  'behavior.repeated_message': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'The same message text came from several contacts.' },
  'behavior.burstiness': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'Inter-request timing is bursty in a way typical of scripted clients.' },
  'behavior.low_path_entropy': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'Navigation follows a repeated low-entropy path template.' },
  'behavior.timing_clone': { family: 'behavior', severity: 'high', source: 'behavior', explanation: 'This session shares a timing profile with many other identities.' },
  'behavior.pointer_mechanical': { family: 'behavior', severity: 'low', source: 'behavior', explanation: 'Pointer cadence is unusually regular. Simulated movement is not treated as proof of a person.' },
  'behavior.conversion_timing': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'The conversion happened too quickly after the paid landing.' },
  'behavior.session_template': { family: 'behavior', severity: 'medium', source: 'behavior', explanation: 'The session matches a repeated behavioral template seen across identities.' },

  'edge.bot_score_automated': { family: 'edge', severity: 'critical', source: 'edge', explanation: 'Trusted edge bot management scored this request as automated.' },
  'edge.bot_score_likely': { family: 'edge', severity: 'high', source: 'edge', explanation: 'Trusted edge bot management scored this request as likely automated.' },

  'graph.behavior_cluster': { family: 'graph', severity: 'high', source: 'graph', explanation: 'Many identities share the same behavioral signature.' },
  'graph.device_cluster': { family: 'graph', severity: 'medium', source: 'graph', explanation: 'Many identities share the same coarse device signature.' },
  'graph.timing_cluster': { family: 'graph', severity: 'high', source: 'graph', explanation: 'Many identities share the same inter-request timing profile.' },
  'graph.click_cluster': { family: 'graph', severity: 'high', source: 'graph', explanation: 'A click identifier is clustered across more identities than link-sharing explains.' },
  'graph.campaign_cluster': { family: 'graph', severity: 'medium', source: 'graph', explanation: 'One campaign and ASN pair is producing a correlated identity cluster.' },
  'graph.lead_cluster': { family: 'graph', severity: 'high', source: 'graph', explanation: 'Normalized lead content is repeating across identities.' },

  'baseline.campaign_spike': { family: 'baseline', severity: 'high', source: 'baseline', explanation: 'Paid click volume for this campaign deviates from its robust baseline.' },
  'baseline.conversion_rate_drop': { family: 'baseline', severity: 'medium', source: 'baseline', explanation: 'Conversion rate dropped while paid clicks rose for this campaign.' },
  'baseline.asn_dominance': { family: 'baseline', severity: 'medium', source: 'baseline', explanation: 'One ASN suddenly dominates a campaign that previously had mixed sources.' },
  'baseline.identity_spike': { family: 'baseline', severity: 'medium', source: 'baseline', explanation: 'New visitor identity creation spiked relative to the campaign baseline.' },

  'trust.established_visitor': { family: 'trust', severity: 'low', source: 'trust', explanation: 'Cookie is at least 24 hours old with multiple sessions.' },
  'trust.engaged_session': { family: 'trust', severity: 'low', source: 'trust', explanation: 'The session has several page views over at least a minute with interaction.' },
  'trust.script_verified': { family: 'trust', severity: 'low', source: 'trust', explanation: 'The beacon completed without automation flags.' },
  'trust.human_interaction': { family: 'trust', severity: 'low', source: 'trust', explanation: 'Pointer, keyboard, scroll, or touch activity was reported. This is not proof of a person.' },
  'trust.challenge_passed': { family: 'trust', severity: 'low', source: 'trust', explanation: 'A Turnstile clearance is valid. A solved challenge is not proof of a qualified visitor.' },
  'trust.authenticated_user': { family: 'trust', severity: 'low', source: 'trust', explanation: 'The host application reports a signed-in user.' },
  'trust.prior_conversion': { family: 'trust', severity: 'low', source: 'trust', explanation: 'This visitor has a previously accepted lead.' },
  'trust.edge_likely_human': { family: 'trust', severity: 'low', source: 'trust', explanation: 'Trusted edge bot management scored this request as likely human.' },
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
  readonly source?: SignalSource;
  readonly confidence?: number;
  readonly rawValue?: number | string | boolean;
  readonly normalizedValue?: number;
  readonly timestamp?: number;
  readonly explanation?: string;
  readonly detectorVersion?: string;
}

export interface RiskAssessment {
  readonly id: string;
  readonly score: number;
  readonly decision: RiskDecision;
  readonly signals: readonly RiskSignal[];
  readonly families: Readonly<Partial<Record<RiskFamily, number>>>;
  readonly trustCredit: number;
  readonly confidence: 'full' | 'reduced';
  readonly numericConfidence: number;
  readonly degraded: readonly string[];
  readonly policyVersion: string;
  readonly detectorVersion: string;
  readonly featureSchemaVersion: string;
  readonly modelVersion: string | undefined;
  readonly fraudProbability: number | undefined;
  readonly shadowDecision: RiskDecision | undefined;
  readonly cohort: string | undefined;
}

export function severityRank(severity: Severity): number {
  return severity === 'critical' ? 3 : severity === 'high' ? 2 : severity === 'medium' ? 1 : 0;
}

export function decisionRank(decision: RiskDecision): number {
  return DECISION_ORDER.indexOf(decision);
}

export function defaultConfidence(severity: Severity): number {
  return severity === 'critical' ? 0.9 : severity === 'high' ? 0.75 : severity === 'medium' ? 0.55 : 0.35;
}
