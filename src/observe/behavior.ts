import type { Observation } from '../store/types.ts';

export interface BehaviorFeatures {
  readonly samples: number;
  readonly meanGapMs: number;
  readonly cv: number;
  readonly iqrMs: number;
  readonly burstiness: number;
  readonly pathEntropy: number;
  readonly depthBucket: number;
  readonly pointerCv: number | undefined;
  readonly keyCv: number | undefined;
  readonly scrollCv: number | undefined;
  readonly dwellMs: number | undefined;
  readonly conversionAgeMs: number | undefined;
}

export function behaviorFeatures(
  observation: Observation | undefined,
  extras: {
    readonly pointerCv?: number;
    readonly keyCv?: number;
    readonly scrollCv?: number;
    readonly dwellMs?: number;
    readonly conversionAgeMs?: number;
    readonly pathEntropy?: number;
  } = {},
): BehaviorFeatures | undefined {
  const visitor = observation?.visitor;
  if (!visitor) return undefined;
  const cv = visitor.timing.cv;
  const burstiness = cv > 0 ? 1 / (1 + cv) : visitor.timing.samples >= 4 ? 1 : 0;
  return {
    samples: visitor.timing.samples,
    meanGapMs: visitor.timing.meanMs,
    cv,
    iqrMs: visitor.timing.meanMs * cv * 1.349,
    burstiness,
    pathEntropy: extras.pathEntropy ?? 1,
    depthBucket: Math.min(6, Math.floor(visitor.sessionDepth / 2)),
    pointerCv: extras.pointerCv,
    keyCv: extras.keyCv,
    scrollCv: extras.scrollCv,
    dwellMs: extras.dwellMs,
    conversionAgeMs: extras.conversionAgeMs,
  };
}

export function intervalStats(gaps: readonly number[]): { mean: number; cv: number; iqr: number; burstiness: number } {
  if (gaps.length === 0) return { mean: 0, cv: 0, iqr: 0, burstiness: 0 };
  const sorted = [...gaps].sort((a, b) => a - b);
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  const variance = sorted.reduce((sum, value) => sum + (value - mean) ** 2, 0) / sorted.length;
  const cv = mean > 0 ? Math.sqrt(variance) / mean : 0;
  const q1 = sorted[Math.floor((sorted.length - 1) * 0.25)] ?? 0;
  const q3 = sorted[Math.floor((sorted.length - 1) * 0.75)] ?? 0;
  return { mean, cv, iqr: q3 - q1, burstiness: cv > 0 ? 1 / (1 + cv) : 1 };
}

export function shannonEntropy(counts: readonly number[]): number {
  const total = counts.reduce((sum, value) => sum + value, 0);
  if (total <= 0) return 0;
  let entropy = 0;
  for (const count of counts) {
    if (count <= 0) continue;
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
