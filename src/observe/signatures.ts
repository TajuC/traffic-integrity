import { createHash } from 'node:crypto';
import type { ClientSnapshot } from './consistency.ts';
import type { BehaviorFeatures } from './behavior.ts';

export function deviceSignature(snapshot: ClientSnapshot | undefined, uaFamily: string, uaOs: string, uaMajor: number | undefined): string {
  const parts = [
    uaFamily,
    uaOs,
    String(uaMajor ?? 0),
    snapshot?.platform ?? '',
    String(snapshot?.hardwareConcurrency ?? 0),
    String(snapshot?.maxTouchPoints ?? 0),
    snapshot?.timezone ?? '',
    (snapshot?.languages ?? []).slice(0, 3).join(','),
  ];
  return digest(parts.join('|'));
}

export function behaviorSignature(features: BehaviorFeatures | undefined): string | undefined {
  if (!features || features.samples < 4) return undefined;
  const bucketed = [
    quantize(features.meanGapMs, 250),
    quantize(features.cv * 100, 5),
    quantize(features.burstiness * 100, 5),
    quantize(features.pathEntropy * 10, 1),
    features.depthBucket,
  ];
  return digest(bucketed.join('|'));
}

export function timingSignature(features: BehaviorFeatures | undefined): string | undefined {
  if (!features || features.samples < 6) return undefined;
  return digest([quantize(features.meanGapMs, 100), quantize(features.cv * 1000, 10), quantize(features.iqrMs, 100)].join('|'));
}

function quantize(value: number, step: number): number {
  if (!Number.isFinite(value) || step <= 0) return 0;
  return Math.round(value / step) * step;
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url').slice(0, 22);
}
