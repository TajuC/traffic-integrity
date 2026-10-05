import { readFileSync } from 'node:fs';
import { scoreLogistic, type LogisticModel, type ModelScore } from './logistic.ts';
import type { FeatureVector } from './schema.ts';

export class ModelRuntime {
  readonly model: LogisticModel | undefined;

  constructor(model?: LogisticModel) {
    this.model = model;
  }

  static fromFile(path: string | undefined): ModelRuntime {
    if (!path) return new ModelRuntime();
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as LogisticModel;
    if (typeof parsed.intercept !== 'number' || typeof parsed.weights !== 'object' || parsed.weights === null) {
      throw new Error('invalid model file');
    }
    return new ModelRuntime(parsed);
  }

  score(vector: FeatureVector): ModelScore | undefined {
    if (!this.model) return undefined;
    return scoreLogistic(this.model, vector);
  }
}
