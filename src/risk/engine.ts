import { randomUUID } from 'node:crypto';
import type { RiskContext } from './context.ts';
import { DETECTORS, type Emit } from './detectors.ts';
import type { RiskPolicy, ScoredFamily, Thresholds } from './policy.ts';
import { RISK_REASONS, severityRank, type RiskAssessment, type RiskDecision, type RiskFamily, type RiskSignal } from './types.ts';

export interface ScoreBreakdown {
  readonly score: number;
  readonly decision: RiskDecision;
  readonly families: Readonly<Partial<Record<RiskFamily, number>>>;
  readonly trustCredit: number;
}

const CRAWLER_SAFE_ROUTES = new Set(['page', 'api', 'internal', 'asset', 'bypass']);

export function assessRisk(ctx: RiskContext, policy: RiskPolicy, id: string = randomUUID()): RiskAssessment {
  const signals: RiskSignal[] = [];
  const emit: Emit = (reason, evidence) => {
    const points = policy.points[reason];
    if (points <= 0) return;
    const meta = RISK_REASONS[reason];
    signals.push(evidence ? { reason, family: meta.family, severity: meta.severity, points, evidence } : { reason, family: meta.family, severity: meta.severity, points });
  };
  for (const detect of DETECTORS) detect(ctx, policy, emit);

  const thresholds = ctx.routeClass === 'conversion' || ctx.routeClass === 'action' ? policy.conversionThresholds : policy.thresholds;
  const scored = scoreSignals(signals, policy, thresholds);

  let decision = scored.decision;
  if (ctx.crawler.status === 'verified' && CRAWLER_SAFE_ROUTES.has(ctx.routeClass)) decision = 'ALLOW';
  else if (ctx.clearanceValid && decision === 'CHALLENGE') decision = 'ALLOW_AND_MONITOR';

  return {
    id,
    score: scored.score,
    decision,
    signals,
    families: scored.families,
    trustCredit: scored.trustCredit,
    confidence: ctx.degraded.length > 0 ? 'reduced' : 'full',
    degraded: ctx.degraded,
    policyVersion: policy.version,
  };
}

export function scoreSignals(signals: readonly RiskSignal[], policy: RiskPolicy, thresholds: Thresholds): ScoreBreakdown {
  const byFamily = new Map<ScoredFamily, number[]>();
  const highFamilies = new Set<ScoredFamily>();
  let trustPoints = 0;
  let highest = -1;
  let riskSignals = 0;

  for (const signal of signals) {
    if (signal.family === 'trust') {
      trustPoints += signal.points;
      continue;
    }
    const family = signal.family;
    riskSignals += 1;
    const rank = severityRank(signal.severity);
    highest = Math.max(highest, rank);
    if (rank >= 2) highFamilies.add(family);
    const list = byFamily.get(family);
    if (list) list.push(signal.points);
    else byFamily.set(family, [signal.points]);
  }

  const families: Partial<Record<RiskFamily, number>> = {};
  let raw = 0;
  for (const [family, points] of byFamily) {
    points.sort((a, b) => b - a);
    let total = 0;
    let weight = 1;
    for (const value of points) {
      total += value * weight;
      weight *= policy.familyDecay;
    }
    const capped = Math.min(total, policy.familyCaps[family]);
    families[family] = Math.round(capped * 10) / 10;
    raw += capped;
  }

  const factor = highest >= 3 ? policy.trust.criticalSeverityFactor : highest >= 2 ? policy.trust.highSeverityFactor : 1;
  const trustCredit = Math.round(Math.min(trustPoints, policy.trust.maxCredit) * factor * 10) / 10;
  if (trustPoints > 0) families.trust = -trustCredit;
  const score = Math.round(Math.min(Math.max(Math.min(raw, 100) - trustCredit, 0), 100));

  let decision: RiskDecision =
    score >= thresholds.block
      ? 'BLOCK'
      : score >= thresholds.restrict
        ? 'TEMPORARILY_RESTRICT'
        : score >= thresholds.challenge
          ? 'CHALLENGE'
          : score >= thresholds.monitor
            ? 'ALLOW_AND_MONITOR'
            : 'ALLOW';

  if (decision === 'BLOCK' && highFamilies.size < policy.blockMinHighFamilies) decision = 'TEMPORARILY_RESTRICT';
  if (decision === 'TEMPORARILY_RESTRICT' && highest < 2) decision = 'CHALLENGE';
  if (decision === 'CHALLENGE' && highest < 2 && riskSignals < 2) decision = 'ALLOW_AND_MONITOR';

  return { score, decision, families, trustCredit };
}
