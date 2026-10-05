import { isChromium, type OsFamily } from '../request/user-agent.ts';
import type { RiskContext } from './context.ts';
import type { RiskPolicy } from './policy.ts';
import type { Evidence, RiskReason } from './types.ts';

export type Emit = (reason: RiskReason, evidence?: Evidence) => void;
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
  if (ctx.network.category === 'hosting') emit('network.hosting', { provider: ctx.network.provider ?? 'unknown' });
  if (ctx.network.category === 'tor') emit('network.tor');

  const observed = ctx.observation;
  if (!observed) return;
  const limits = policy.limits;

  const address = limits.addressRequestsPerMinute;
  const addressLimit = address.base + address.perMember * observed.address.population;
  const addressRatio = observed.address.requestRate / addressLimit;
  const addressEvidence = { rate: round(observed.address.requestRate), limit: addressLimit };
  if (addressRatio >= address.extremeFactor) emit('network.address_velocity_extreme', addressEvidence);
  else if (addressRatio > 1) emit('network.address_velocity', addressEvidence);

  if (ctx.network.category === 'privacy_relay') return;
  const population = observed.network.population;

  if (ctx.identity?.origin !== 'returning') {
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
  if (reliable && visitor && visitor.scriptVerifiedAt === undefined) emit('behavior.script_unverified');

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

export const DETECTORS: readonly Detector[] = [detectNetwork, detectClient, detectPaid, detectBehavior, detectEdge, detectTrust];

function round(value: number, digits = 1): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}
