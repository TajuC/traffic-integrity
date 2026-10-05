export interface Confusion {
  readonly tp: number;
  readonly fp: number;
  readonly tn: number;
  readonly fn: number;
}

export interface ClassMetrics {
  readonly clazz: string;
  readonly support: number;
  readonly recall?: number;
  readonly falsePositiveRate?: number;
}

export interface EvalReport {
  readonly generatedAt: string;
  readonly dataset: string;
  readonly notes: readonly string[];
  readonly n: number;
  readonly precision: number;
  readonly recall: number;
  readonly f1: number;
  readonly tpr: number;
  readonly fpr: number;
  readonly fnr: number;
  readonly specificity: number;
  readonly rocAuc: number;
  readonly prAuc: number;
  readonly calibrationError: number;
  readonly confusion: Confusion;
  readonly perClass: readonly ClassMetrics[];
}

export function confusion(scores: readonly { label: number; predicted: number }[]): Confusion {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const row of scores) {
    if (row.predicted === 1 && row.label === 1) tp += 1;
    else if (row.predicted === 1 && row.label === 0) fp += 1;
    else if (row.predicted === 0 && row.label === 0) tn += 1;
    else fn += 1;
  }
  return { tp, fp, tn, fn };
}

export function ratios(c: Confusion): { precision: number; recall: number; f1: number; tpr: number; fpr: number; fnr: number; specificity: number } {
  const precision = c.tp + c.fp === 0 ? 0 : c.tp / (c.tp + c.fp);
  const recall = c.tp + c.fn === 0 ? 0 : c.tp / (c.tp + c.fn);
  const tpr = recall;
  const fpr = c.fp + c.tn === 0 ? 0 : c.fp / (c.fp + c.tn);
  const fnr = c.tp + c.fn === 0 ? 0 : c.fn / (c.tp + c.fn);
  const specificity = c.tn + c.fp === 0 ? 0 : c.tn / (c.tn + c.fp);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1, tpr, fpr, fnr, specificity };
}

export function rocAuc(rows: readonly { label: number; score: number }[]): number {
  const ranked = [...rows].sort((a, b) => b.score - a.score);
  let tp = 0;
  let fp = 0;
  const positives = rows.filter((row) => row.label === 1).length;
  const negatives = rows.length - positives;
  if (positives === 0 || negatives === 0) return 0.5;
  let auc = 0;
  let prevFpr = 0;
  let prevTpr = 0;
  for (const row of ranked) {
    if (row.label === 1) tp += 1;
    else fp += 1;
    const tpr = tp / positives;
    const fpr = fp / negatives;
    auc += ((fpr - prevFpr) * (tpr + prevTpr)) / 2;
    prevFpr = fpr;
    prevTpr = tpr;
  }
  return auc;
}

export function prAuc(rows: readonly { label: number; score: number }[]): number {
  const ranked = [...rows].sort((a, b) => b.score - a.score);
  const positives = rows.filter((row) => row.label === 1).length;
  if (positives === 0) return 0;
  let tp = 0;
  let fp = 0;
  let auc = 0;
  let prevRecall = 0;
  let prevPrecision = 1;
  for (const row of ranked) {
    if (row.label === 1) tp += 1;
    else fp += 1;
    const precision = tp / (tp + fp);
    const recall = tp / positives;
    auc += (recall - prevRecall) * ((precision + prevPrecision) / 2);
    prevRecall = recall;
    prevPrecision = precision;
  }
  return auc;
}

export function expectedCalibrationError(rows: readonly { label: number; probability: number }[], bins = 10): number {
  if (rows.length === 0) return 0;
  const buckets = Array.from({ length: bins }, () => ({ n: 0, sumP: 0, sumY: 0 }));
  for (const row of rows) {
    const index = Math.min(bins - 1, Math.max(0, Math.floor(row.probability * bins)));
    const bucket = buckets[index];
    if (!bucket) continue;
    bucket.n += 1;
    bucket.sumP += row.probability;
    bucket.sumY += row.label;
  }
  let error = 0;
  for (const bucket of buckets) {
    if (bucket.n === 0) continue;
    error += (bucket.n / rows.length) * Math.abs(bucket.sumY / bucket.n - bucket.sumP / bucket.n);
  }
  return error;
}

export function round4(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}
