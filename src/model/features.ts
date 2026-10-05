import { FEATURE_NAMES, type FeatureVector } from './schema.ts';
import { FEATURE_SCHEMA_VERSION } from '../risk/versions.ts';
import type { RiskAssessment } from '../risk/types.ts';
import type { RiskContext } from '../risk/context.ts';
import { hourOfDay } from '../intel/stats.ts';

export function extractFeatures(ctx: RiskContext, assessment: RiskAssessment): FeatureVector {
  const visitor = ctx.observation?.visitor;
  const values = FEATURE_NAMES.map((name) => {
    switch (name) {
      case 'heuristic_score':
        return assessment.score / 100;
      case 'family_network':
        return (assessment.families.network ?? 0) / 45;
      case 'family_client':
        return (assessment.families.client ?? 0) / 45;
      case 'family_paid':
        return (assessment.families.paid ?? 0) / 45;
      case 'family_behavior':
        return (assessment.families.behavior ?? 0) / 75;
      case 'family_edge':
        return (assessment.families.edge ?? 0) / 60;
      case 'family_graph':
        return (assessment.families.graph ?? 0) / 40;
      case 'family_baseline':
        return (assessment.families.baseline ?? 0) / 35;
      case 'family_consistency':
        return (assessment.families.consistency ?? 0) / 40;
      case 'trust_credit':
        return assessment.trustCredit / 35;
      case 'hosting':
        return ctx.network.category === 'hosting' || ctx.network.category === 'cloud' ? 1 : 0;
      case 'tor':
        return ctx.network.category === 'tor' ? 1 : 0;
      case 'vpn':
        return ctx.network.category === 'vpn' ? 1 : 0;
      case 'automation_ua':
        return ctx.ua.automation ? 1 : 0;
      case 'script_automation':
        return (visitor?.automationFlags ?? 0) !== 0 ? 1 : 0;
      case 'paid_arrival':
        return ctx.paidArrival ? 1 : 0;
      case 'click_reuse':
        return Math.min(1, (ctx.observation?.clickVisitors ?? 0) / 10);
      case 'visitor_rate':
        return Math.min(1, (visitor?.requestRate ?? 0) / 300);
      case 'address_rate':
        return Math.min(1, (ctx.observation?.address.requestRate ?? 0) / 500);
      case 'timing_cv':
        return Math.min(1, visitor?.timing.cv ?? 0);
      case 'established':
        return ctx.identity?.origin === 'returning' && (ctx.identity.cookieAgeSeconds ?? 0) >= 86_400 ? 1 : 0;
      case 'authenticated':
        return ctx.authenticated ? 1 : 0;
      case 'clearance':
        return ctx.clearanceValid ? 1 : 0;
      case 'edge_bot_score':
        return ctx.address.edge.botScore !== undefined ? ctx.address.edge.botScore / 99 : 0.5;
      case 'session_depth':
        return Math.min(1, (visitor?.sessionDepth ?? 0) / 10);
      case 'cluster_size':
        return Math.min(1, Math.max(0, ...(ctx.clusters ?? []).map((hit) => hit.members)) / 40);
      case 'campaign_z':
        return Math.min(1, Math.max(0, ...(ctx.baselines ?? []).map((item) => item.robustZ)) / 10);
      case 'consistency_failures':
        return Math.min(1, (ctx.consistency?.length ?? 0) / 6);
      case 'hour_of_day':
        return hourOfDay(ctx.now) / 23;
      case 'js_verified':
        return visitor?.scriptVerifiedAt !== undefined ? 1 : 0;
    }
  });
  return { schemaVersion: FEATURE_SCHEMA_VERSION, names: FEATURE_NAMES, values };
}
