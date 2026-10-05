import type { RiskContext } from '../risk/context.ts';

export type VisitorCohort =
  | 'authenticated'
  | 'returning_customer'
  | 'corporate_nat'
  | 'mobile_nat'
  | 'university'
  | 'privacy_relay'
  | 'vpn'
  | 'uncommon_browser'
  | 'privacy_browser'
  | 'js_blocked'
  | 'slow'
  | 'fast'
  | 'shared_network'
  | 'unknown';

const UNIVERSITY_ORG = /\b(university|universidad|universit[eé]|college|campus|edu(?:cation)?)\b/i;
const MOBILE_ORG = /\b(mobile|wireless|cellular|lte|5g|telefonica|vodafone|t-mobile|verizon wireless|att mobility|orange|telstra|singtel|airtel|jio)\b/i;
const ENTERPRISE_ORG = /\b(corp|enterprise|limited|ltd|inc|gmbh|sarl|plc|holdings)\b/i;
const PRIVACY_BROWSERS = new Set(['firefox']);

export function detectCohort(ctx: RiskContext): VisitorCohort {
  if (ctx.authenticated) return 'authenticated';
  if (ctx.network.category === 'privacy_relay') return 'privacy_relay';
  if (ctx.network.category === 'vpn') return 'vpn';
  if ((ctx.observation?.address.population ?? 0) >= 8) {
    const org = ctx.network.asOrg ?? '';
    if (UNIVERSITY_ORG.test(org)) return 'university';
    if (ctx.ua.device === 'mobile' || MOBILE_ORG.test(org)) return 'mobile_nat';
    if (ENTERPRISE_ORG.test(org) || (ctx.observation?.address.population ?? 0) >= 20) return 'corporate_nat';
    return 'shared_network';
  }
  if (ctx.identity?.origin === 'returning' && ctx.identity.cookieAgeSeconds >= 86_400) return 'returning_customer';
  if (ctx.ua.family === 'other' || ctx.ua.engine === 'unknown') return 'uncommon_browser';
  if (PRIVACY_BROWSERS.has(ctx.ua.family) && ctx.headers.secChUa === undefined) return 'privacy_browser';
  if (ctx.routeClass !== 'asset' && ctx.observation?.visitor && ctx.observation.visitor.scriptVerifiedAt === undefined) {
    return 'js_blocked';
  }
  const mean = ctx.observation?.visitor?.timing.meanMs ?? 0;
  if (mean >= 120_000) return 'slow';
  if (mean > 0 && mean < 2_000 && (ctx.observation?.visitor?.timing.samples ?? 0) >= 3) return 'fast';
  return 'unknown';
}

export function cohortDampening(cohort: VisitorCohort): number {
  switch (cohort) {
    case 'authenticated':
      return 0.45;
    case 'returning_customer':
      return 0.7;
    case 'corporate_nat':
    case 'mobile_nat':
    case 'university':
    case 'shared_network':
      return 0.55;
    case 'privacy_relay':
      return 0.6;
    case 'vpn':
      return 0.85;
    case 'privacy_browser':
    case 'uncommon_browser':
    case 'js_blocked':
      return 0.8;
    case 'slow':
      return 0.9;
    case 'fast':
    case 'unknown':
      return 1;
  }
}

export function networkVelocityExempt(cohort: VisitorCohort): boolean {
  return cohort === 'corporate_nat' || cohort === 'mobile_nat' || cohort === 'university' || cohort === 'privacy_relay' || cohort === 'shared_network';
}
