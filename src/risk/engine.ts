import { randomUUID } from 'node:crypto';
import { detectCohort } from '../observe/cohort.ts';
import { FEATURE_SCHEMA_VERSION, DETECTOR_VERSION } from './versions.ts';
import type { RiskContext } from './context.ts';
import { DETECTORS, type Emit } from './detectors.ts';
import type { RiskPolicy, ScoredFamily, Thresholds } from './policy.ts';
import {
  RISK_REASONS,
  defaultConfidence,
  severityRank,
  type RiskAssessment,
  type RiskDecision,
  type RiskFamily,
  type RiskSignal,
} from './types.ts';

export interface ScoreBreakdown {
  readonly score: number;
  readonly decision: RiskDecision;
  readonly families: Readonly<Partial<Record<RiskFamily, number>>>;
  readonly trustCredit: number;
}

const CRAWLER_SAFE_ROUTES = new Set(['page', 'api', 'internal', 'asset', 'bypass']);

export interface AssessOptions {
  readonly id?: string;
  readonly modelVersion?: string;
  readonly fraudProbability?: number;
  readonly shadowDecision?: RiskDecision;
}

export function assessRisk(ctx: RiskContext, policy: RiskPolicy, idOrOptions: string | AssessOptions = {}): RiskAssessment {
  const options: AssessOptions = typeof idOrOptions === 'string' ? { id: idOrOptions } : idOrOptions;
  const signals: RiskSignal[] = [];
  const emit: Emit = (reason, evidence, extras) => {
    const points = policy.points[reason];
    if (points <= 0) return;
    const meta = RISK_REASONS[reason];
    signals.push({
      reason,
      family: meta.family,
      severity: meta.severity,
      points,
      ...(evidence ? { evidence } : {}),
      source: meta.source,
      confidence: extras?.confidence ?? defaultConfidence(meta.severity),
      ...(extras?.rawValue !== undefined ? { rawValue: extras.rawValue } : {}),
      ...(extras?.normalizedValue !== undefined ? { normalizedValue: extras.normalizedValue } : {}),
      timestamp: ctx.now,
      explanation: meta.explanation,
      detectorVersion: DETECTOR_VERSION,
    });
  };
  for (const detect of DETECTORS) detect(ctx, policy, emit);

  const thresholds = ctx.routeClass === 'conversion' || ctx.routeClass === 'action' ? policy.conversionThresholds : policy.thresholds;
  const scored = scoreSignals(signals, policy, thresholds);

  let decision = scored.decision;
  if (ctx.crawler.status === 'verified' && CRAWLER_SAFE_ROUTES.has(ctx.routeClass)) decision = 'ALLOW';
  else if (ctx.clearanceValid && decision === 'CHALLENGE') decision = 'ALLOW_AND_MONITOR';

  const cohort = ctx.cohort ?? detectCohort(ctx);
  const independent = new Set(signals.filter((signal) => signal.family !== 'trust').map((signal) => signal.family)).size;
  const meanConfidence =
    signals.length === 0 ? 1 : signals.reduce((sum, signal) => sum + (signal.confidence ?? defaultConfidence(signal.severity)), 0) / signals.length;
  const numericConfidence = ctx.degraded.length > 0 ? Math.min(0.7, meanConfidence) : Math.min(1, 0.35 + 0.2 * independent) * meanConfidence;

  return {
    id: options.id ?? randomUUID(),
    score: scored.score,
    decision,
    signals,
    families: scored.families,
    trustCredit: scored.trustCredit,
    confidence: ctx.degraded.length > 0 ? 'reduced' : 'full',
    numericConfidence: Math.round(numericConfidence * 1000) / 1000,
    degraded: ctx.degraded,
    policyVersion: policy.version,
    detectorVersion: DETECTOR_VERSION,
    featureSchemaVersion: FEATURE_SCHEMA_VERSION,
    modelVersion: options.modelVersion,
    fraudProbability: options.fraudProbability,
    shadowDecision: options.shadowDecision,
    cohort,
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

export function decideFromScore(score: number, thresholds: Thresholds): RiskDecision {
  if (score >= thresholds.block) return 'BLOCK';
  if (score >= thresholds.restrict) return 'TEMPORARILY_RESTRICT';
  if (score >= thresholds.challenge) return 'CHALLENGE';
  if (score >= thresholds.monitor) return 'ALLOW_AND_MONITOR';
  return 'ALLOW';
}
