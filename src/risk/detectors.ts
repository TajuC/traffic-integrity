import { networkVelocityExempt } from '../observe/cohort.ts';
import { isChromium, type OsFamily } from '../request/user-agent.ts';
import type { RiskContext } from './context.ts';
import type { RiskPolicy } from './policy.ts';
import { RISK_REASONS, type Evidence, type RiskReason } from './types.ts';

export interface SignalExtras {
  readonly confidence?: number;
  readonly rawValue?: number | string | boolean;
  readonly normalizedValue?: number;
}

export type Emit = (reason: RiskReason, evidence?: Evidence, extras?: SignalExtras) => void;
export type Detector = (ctx: RiskContext, policy: RiskPolicy, emit: Emit) => void;

const PLATFORM_HINTS: Readonly<Record<string, OsFamily>> = {
  windows: 'windows',
  macos: 'macos',
  linux: 'linux',
  android: 'android',
  'chrome os': 'chromeos',
  'chromium os': 'chromeos',
  ios: 'ios',
};

const SENSITIVE = new Set(['conversion', 'action']);
const PAGE_LIKE = new Set(['page', 'conversion', 'action']);

export const detectNetwork: Detector = (ctx, policy, emit) => {
  if (ctx.edgeRequired && !ctx.address.viaEdge) emit('network.origin_bypass', { via: ctx.address.via });
  if (ctx.network.category === 'hosting' || ctx.network.category === 'cloud') {
    emit('network.hosting', { provider: ctx.network.provider ?? 'unknown', category: ctx.network.category });
  }
  if (ctx.network.category === 'tor') emit('network.tor');
  if (ctx.network.category === 'vpn') emit('network.vpn', { provider: ctx.network.provider ?? 'unknown' }, { confidence: 0.5 });
  if (ctx.network.category === 'residential_proxy') emit('network.residential_proxy', { provider: ctx.network.provider ?? 'unknown' }, { confidence: 0.55 });
  if (ctx.network.category === 'public_proxy') emit('network.public_proxy', { provider: ctx.network.provider ?? 'unknown' }, { confidence: 0.5 });

  const observed = ctx.observation;
  if (!observed) return;
  const limits = policy.limits;
  const nat = ctx.cohort !== undefined && networkVelocityExempt(ctx.cohort);

  const address = limits.addressRequestsPerMinute;
  const addressLimit = address.base + address.perMember * observed.address.population;
  const addressRatio = observed.address.requestRate / addressLimit;
  const addressEvidence = { rate: round(observed.address.requestRate), limit: addressLimit };
  if (!nat) {
    if (addressRatio >= address.extremeFactor) emit('network.address_velocity_extreme', addressEvidence);
    else if (addressRatio > 1) emit('network.address_velocity', addressEvidence);
  }

  if (ctx.network.category === 'privacy_relay') return;
  const population = observed.network.population;

  if (ctx.identity?.origin !== 'returning' && !nat) {
    const churn = limits.networkFreshIdentities;
    const churnLimit = churn.perHour + churn.perMember * population;
    const churnRatio = observed.network.freshIdentities / churnLimit;
    const churnEvidence = { fresh: observed.network.freshIdentities, population, limit: churnLimit };
    if (churnRatio >= churn.extremeFactor) emit('network.identity_churn_extreme', churnEvidence);
    else if (churnRatio > 1) emit('network.identity_churn', churnEvidence);
  }

  if (ctx.paidArrival) {
    const paid = limits.networkPaidClicks;
    const scale = paid.perMember * population;
    const paidRatio = Math.max(observed.network.paidClicks5m / (paid.per5m + scale), observed.network.paidClicks1h / (paid.per1h + scale));
    const paidEvidence = { clicks5m: observed.network.paidClicks5m, clicks1h: observed.network.paidClicks1h, population };
    if (paidRatio >= paid.extremeFactor) emit('network.paid_velocity_extreme', paidEvidence);
    else if (paidRatio > 1) emit('network.paid_velocity', paidEvidence);
    if (observed.asnPaidClicks5m !== undefined && observed.asnPaidClicks5m > limits.asnPaidClicksPer5m) {
      emit('network.asn_paid_burst', { asn: ctx.network.asn ?? 0, clicks5m: observed.asnPaidClicks5m });
    }
  }

  if (ctx.routeClass === 'conversion') {
    const conversions = limits.networkConversionsPerHour;
    const limit = conversions.base + conversions.perMember * population;
    if (observed.network.conversionRate > limit) emit('network.conversion_velocity', { rate: round(observed.network.conversionRate), limit });
  }
};

export const detectClient: Detector = (ctx, _policy, emit) => {
  const { ua, headers } = ctx;
  if (ctx.crawler.status === 'impersonation') emit('client.crawler_impersonation', { operator: ctx.crawler.operator, via: ctx.crawler.via });
  if (ctx.identity?.origin === 'forged') emit('client.forged_identity');
  if (!ua.present && PAGE_LIKE.has(ctx.routeClass)) emit('client.user_agent_missing');

  if (ua.automation) emit('client.automation_tool', { tool: ua.automation });
  else if (headers.secChUa?.includes('HeadlessChrome')) emit('client.automation_tool', { tool: 'headless-hints' });

  const flags = ctx.observation?.visitor?.automationFlags ?? 0;
  if (flags !== 0) emit('client.script_automation', { flags });

  if (!ua.present || ua.automation || ua.crawler || ua.preview || ua.engine === 'unknown') return;

  const chromium = isChromium(ua) && ua.os !== 'ios';
  if (headers.secChUa !== undefined && !chromium) emit('client.hints_brand_mismatch', { family: ua.family, engine: ua.engine });

  if (chromium && headers.secChUaPlatform) {
    const hinted = PLATFORM_HINTS[headers.secChUaPlatform.replaceAll('"', '').trim().toLowerCase()];
    const desktopModeOnAndroid = hinted === 'android' && ua.os === 'linux';
    if (hinted && hinted !== ua.os && !desktopModeOnAndroid) emit('client.hints_platform_mismatch', { hinted, claimed: ua.os });
  }

  const modern =
    ((ua.family === 'chrome' || ua.family === 'edge') && ua.engine === 'blink' && (ua.major ?? 0) >= 90) ||
    (ua.family === 'firefox' && ua.engine === 'gecko' && (ua.major ?? 0) >= 95);
  if (chromium && modern && ctx.secure && headers.secChUa === undefined && headers.secFetchMode !== undefined) {
    emit('client.hints_missing', { family: ua.family });
  }

  if (ctx.routeClass !== 'page') return;
  const navigating = headers.secFetchMode === undefined || headers.secFetchMode === 'navigate';
  if (!navigating) return;
  if (modern && ctx.secure && headers.secFetchMode === undefined) emit('client.fetch_metadata_missing', { family: ua.family });
  if (!(headers.accept ?? '').includes('text/html')) emit('client.navigation_accept_missing');
  if (!headers.acceptLanguage) emit('client.accept_language_missing');
};

export const detectPaid: Detector = (ctx, policy, emit) => {
  if (ctx.malformedAttribution.length > 0) emit('paid.malformed_attribution', { params: ctx.malformedAttribution.join(',') });
  const observed = ctx.observation;
  if (!ctx.paidArrival || !observed) return;

  const visitor = observed.visitor;
  if (visitor) {
    const limits = policy.limits.visitorPaidClicks;
    const ratio = Math.max(visitor.paidClicks5m / limits.per5m, visitor.paidClicks1h / limits.per1h);
    const evidence = { clicks5m: visitor.paidClicks5m, clicks1h: visitor.paidClicks1h };
    if (ratio >= limits.extremeFactor) emit('paid.visitor_click_velocity_extreme', evidence);
    else if (ratio > 1) emit('paid.visitor_click_velocity', evidence);
  }

  const reuse = observed.clickVisitors;
  const limits = policy.limits.clickReuseVisitors;
  if (reuse !== undefined && reuse >= limits.extreme) emit('paid.click_reuse_extreme', { visitors: reuse });
  else if (reuse !== undefined && reuse >= limits.elevated) emit('paid.click_reuse', { visitors: reuse });
};

export const detectBehavior: Detector = (ctx, policy, emit) => {
  const observed = ctx.observation;
  const visitor = observed?.visitor;
  const limits = policy.limits;

  if (visitor) {
    const velocity = limits.visitorRequestsPerMinute;
    const evidence = { rate: round(visitor.requestRate) };
    if (visitor.requestRate >= velocity.extreme) emit('behavior.visitor_velocity_extreme', evidence);
    else if (visitor.requestRate >= velocity.elevated) emit('behavior.visitor_velocity', evidence);

    const timing = limits.mechanicalTiming;
    if (visitor.timing.samples >= timing.minSamples && visitor.timing.meanMs < timing.maxMeanMs && visitor.timing.cv < timing.maxCv) {
      emit('behavior.mechanical_timing', { cv: round(visitor.timing.cv, 3), meanMs: Math.round(visitor.timing.meanMs) });
    }
    const burst = limits.burstiness;
    if (visitor.timing.samples >= burst.minSamples && visitor.timing.cv > 0) {
      const burstiness = 1 / (1 + visitor.timing.cv);
      if (burstiness >= burst.minBurst && visitor.timing.meanMs < timing.maxMeanMs) {
        emit('behavior.burstiness', { burstiness: round(burstiness, 3), cv: round(visitor.timing.cv, 3) }, { confidence: 0.4 });
      }
    }
    const entropy = ctx.action?.pathEntropy;
    if (entropy !== undefined && visitor.sessionDepth >= limits.pathEntropy.minDepth && entropy <= limits.pathEntropy.maxEntropy) {
      emit('behavior.low_path_entropy', { entropy: round(entropy, 3), depth: visitor.sessionDepth }, { confidence: 0.45 });
    }
    if (visitor.actionRate > limits.visitorActionsPer10m) emit('behavior.action_velocity', { rate: round(visitor.actionRate) });
    if (ctx.routeClass === 'conversion' && visitor.conversionRate > limits.visitorConversionsPerDay) {
      emit('behavior.conversion_velocity', { rate: round(visitor.conversionRate) });
    }
  }

  if (observed) {
    const addressIsPersonal = observed.address.population <= policy.restriction.maxSharedPopulation;
    const strikes = Math.max(visitor?.strikes ?? 0, addressIsPersonal ? observed.address.strikes : 0);
    if (strikes >= limits.repeatOffender.extreme) emit('behavior.repeat_offender_extreme', { strikes: round(strikes) });
    else if (strikes >= limits.repeatOffender.elevated) emit('behavior.repeat_offender', { strikes: round(strikes) });
  }

  if (!SENSITIVE.has(ctx.routeClass)) return;

  const action = ctx.action;
  const reliable = observed?.source === 'redis';
  const pageFlowProven = action?.formToken === 'valid' || action?.formToken === 'expired';
  const withoutIdentity = !ctx.identity || ctx.identity.origin !== 'returning';
  if (withoutIdentity || (reliable && !pageFlowProven && visitor !== undefined && visitor.sessionDepth === 0)) {
    emit('behavior.direct_sensitive_access', { identity: ctx.identity?.origin ?? 'none' });
  }
  if (reliable && visitor && visitor.scriptVerifiedAt === undefined && ctx.cohort !== 'js_blocked') emit('behavior.script_unverified');

  if (!action) return;
  if (!action.originPresent) emit('behavior.origin_missing');
  if (action.honeypot) emit('behavior.honeypot');
  if (action.formToken === 'missing') emit('behavior.form_token_missing');
  else if (action.formToken === 'invalid') emit('behavior.form_token_invalid');
  else if (action.formToken === 'expired') emit('behavior.form_token_expired');
  else if (action.formToken === 'replayed') emit('behavior.form_token_replayed');
  if (action.formToken === 'valid' && action.formAgeMs !== undefined && action.formAgeMs < limits.form.minFillMs) {
    emit('behavior.form_too_fast', { ms: action.formAgeMs });
  }
  if (action.repeatedMessageContacts >= limits.repeatedMessageContacts) {
    emit('behavior.repeated_message', { contacts: action.repeatedMessageContacts });
  }
  if (action.conversionAgeMs !== undefined && action.conversionAgeMs < limits.conversionTimingMs && ctx.paidArrival) {
    emit('behavior.conversion_timing', { ms: action.conversionAgeMs });
  }
};

export const detectEdge: Detector = (ctx, _policy, emit) => {
  const score = ctx.address.edge.botScore;
  if (!ctx.address.edgeVerified || score === undefined) return;
  if (score <= 1) emit('edge.bot_score_automated', { score });
  else if (score < 30) emit('edge.bot_score_likely', { score });
};

export const detectTrust: Detector = (ctx, policy, emit) => {
  const visitor = ctx.observation?.visitor;
  const established = policy.established;
  const clean = (visitor?.automationFlags ?? 0) === 0;

  if (
    ctx.identity?.origin === 'returning' &&
    ctx.identity.cookieAgeSeconds >= established.trustedCookieAgeSeconds &&
    (visitor?.sessionCount ?? 0) >= established.trustedMinSessions
  ) {
    emit('trust.established_visitor', { ageHours: Math.floor(ctx.identity.cookieAgeSeconds / 3600) });
  }
  if (visitor && visitor.sessionDepth >= 3 && ctx.now - visitor.sessionStartedAt >= 60_000 && visitor.interactionAt !== undefined) {
    emit('trust.engaged_session', { depth: visitor.sessionDepth });
  }
  if (visitor?.scriptVerifiedAt !== undefined && clean) emit('trust.script_verified');
  if (visitor?.interactionAt !== undefined && clean) emit('trust.human_interaction');
  if (ctx.clearanceValid) emit('trust.challenge_passed');
  if (ctx.authenticated) emit('trust.authenticated_user');
  if ((visitor?.acceptedConversions ?? 0) > 0 && ctx.routeClass !== 'conversion') emit('trust.prior_conversion');
  const score = ctx.address.edge.botScore;
  if (ctx.address.edgeVerified && score !== undefined && score >= 80) emit('trust.edge_likely_human', { score });
};

export const detectConsistency: Detector = (ctx, _policy, emit) => {
  for (const finding of ctx.consistency ?? []) {
    if (!(finding.code in RISK_REASONS)) continue;
    const reason = finding.code as RiskReason;
    if (RISK_REASONS[reason].family !== 'consistency') continue;
    emit(reason, finding.evidence, { confidence: finding.confidence });
  }
  const snapshot = ctx.snapshot;
  if (!snapshot) return;
  if (snapshot.pointerCv !== undefined && snapshot.pointerCv < 0.06 && (ctx.observation?.visitor?.timing.samples ?? 0) >= 6) {
    emit('behavior.pointer_mechanical', { cv: snapshot.pointerCv }, { confidence: 0.3 });
  }
};

export const detectGraph: Detector = (ctx, policy, emit) => {
  for (const hit of ctx.clusters ?? []) {
    const evidence = { members: hit.members, threshold: hit.threshold, key: hit.key.slice(0, 24) };
    switch (hit.kind) {
      case 'behavior':
        if (hit.members >= policy.limits.graph.behavior) emit('graph.behavior_cluster', evidence);
        break;
      case 'device':
        if (hit.members >= policy.limits.graph.device) emit('graph.device_cluster', evidence, { confidence: 0.45 });
        break;
      case 'timing':
        if (hit.members >= policy.limits.graph.timing) emit('graph.timing_cluster', evidence);
        break;
      case 'click':
        if (hit.members >= policy.limits.graph.click) emit('graph.click_cluster', evidence);
        break;
      case 'campaign_asn':
        if (hit.members >= policy.limits.graph.campaign) emit('graph.campaign_cluster', evidence);
        break;
      case 'lead':
        if (hit.members >= policy.limits.graph.lead) emit('graph.lead_cluster', evidence);
        break;
    }
  }
};

export const detectBaseline: Detector = (ctx, policy, emit) => {
  for (const sample of ctx.baselines ?? []) {
    if (!sample.spike || sample.samples < 8) continue;
    if (sample.robustZ >= policy.limits.baseline.spikeZ) {
      const reason = sample.key.includes(':asn:')
        ? 'baseline.asn_dominance'
        : sample.key.includes('identity')
          ? 'baseline.identity_spike'
          : sample.key.includes('conv')
            ? 'baseline.conversion_rate_drop'
            : 'baseline.campaign_spike';
      emit(reason, { z: round(sample.robustZ, 2), ewma: round(sample.ewma, 2), last: round(sample.last, 2) }, { confidence: 0.6, rawValue: sample.last, normalizedValue: sample.robustZ });
    }
  }
};

export const DETECTORS: readonly Detector[] = [
  detectNetwork,
  detectClient,
  detectPaid,
  detectBehavior,
  detectEdge,
  detectTrust,
  detectConsistency,
  detectGraph,
  detectBaseline,
];

function round(value: number, digits = 1): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}
