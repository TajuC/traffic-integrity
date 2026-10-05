import { FEATURE_NAMES, type FeatureVector } from './schema.ts';

export interface LogisticModel {
  readonly version: string;
  readonly schemaVersion: string;
  readonly intercept: number;
  readonly weights: Readonly<Record<string, number>>;
  readonly calibration?: { readonly a: number; readonly b: number };
  readonly trainedOn: string;
}

export interface ModelScore {
  readonly probability: number;
  readonly calibrated: boolean;
  readonly version: string;
  readonly logit: number;
}

export function sigmoid(value: number): number {
  if (value >= 20) return 1;
  if (value <= -20) return 0;
  return 1 / (1 + Math.exp(-value));
}

export function scoreLogistic(model: LogisticModel, vector: FeatureVector): ModelScore {
  let logit = model.intercept;
  for (let i = 0; i < FEATURE_NAMES.length; i += 1) {
    const name = FEATURE_NAMES[i];
    if (!name) continue;
    logit += (model.weights[name] ?? 0) * (vector.values[i] ?? 0);
  }
  let probability = sigmoid(logit);
  let calibrated = false;
  if (model.calibration) {
    probability = sigmoid(model.calibration.a * logit + model.calibration.b);
    calibrated = true;
  }
  return { probability, calibrated, version: model.version, logit };
}

export function trainLogistic(
  examples: readonly { vector: FeatureVector; label: number }[],
  options: { iterations?: number; learningRate?: number; l2?: number } = {},
): LogisticModel {
  const iterations = options.iterations ?? 400;
  const learningRate = options.learningRate ?? 0.2;
  const l2 = options.l2 ?? 0.01;
  const weights = Object.fromEntries(FEATURE_NAMES.map((name) => [name, 0]));
  let intercept = 0;
  for (let step = 0; step < iterations; step += 1) {
    let interceptGrad = 0;
    const grads = Object.fromEntries(FEATURE_NAMES.map((name) => [name, 0])) as Record<string, number>;
    for (const example of examples) {
      const pred = predictRaw(intercept, weights, example.vector);
      const error = pred - example.label;
      interceptGrad += error;
      for (let i = 0; i < FEATURE_NAMES.length; i += 1) {
        const name = FEATURE_NAMES[i];
        if (!name) continue;
        grads[name] = (grads[name] ?? 0) + error * (example.vector.values[i] ?? 0);
      }
    }
    const n = Math.max(1, examples.length);
    intercept -= learningRate * (interceptGrad / n);
    for (const name of FEATURE_NAMES) {
      weights[name] = (weights[name] ?? 0) - learningRate * ((grads[name] ?? 0) / n + l2 * (weights[name] ?? 0));
    }
  }
  return {
    version: 'synthetic-logreg-1',
    schemaVersion: examples[0]?.vector.schemaVersion ?? '1',
    intercept,
    weights,
    trainedOn: 'synthetic',
  };
}

function predictRaw(intercept: number, weights: Record<string, number>, vector: FeatureVector): number {
  let logit = intercept;
  for (let i = 0; i < FEATURE_NAMES.length; i += 1) {
    const name = FEATURE_NAMES[i];
    if (!name) continue;
    logit += (weights[name] ?? 0) * (vector.values[i] ?? 0);
  }
  return sigmoid(logit);
}
