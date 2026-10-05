import { writeFileSync } from 'node:fs';
import { assessRisk } from '../risk/engine.ts';
import { DEFAULT_POLICY } from '../risk/policy.ts';
import { extractFeatures } from '../model/features.ts';
import { trainLogistic } from '../model/logistic.ts';
import type { AttackerClass } from './dataset.ts';
import { confusion, expectedCalibrationError, prAuc, ratios, rocAuc, round4, type EvalReport } from './metrics.ts';
import { syntheticCases } from './synthetic.ts';

export function runEvaluation(dataset = 'synthetic-v1'): EvalReport {
  const cases = syntheticCases();
  const rows = cases.map((item) => {
    const assessment = assessRisk(item.context, DEFAULT_POLICY);
    const predicted = assessment.decision === 'ALLOW' ? 0 : 1;
    const probability = assessment.fraudProbability ?? assessment.score / 100;
    return { item, assessment, predicted, probability, score: assessment.score };
  });

  const labeled = rows.filter((row) => row.item.clazz !== 'ambiguous');
  const conf = confusion(labeled.map((row) => ({ label: row.item.label, predicted: row.predicted })));
  const stats = ratios(conf);
  const perClass = unique(cases.map((item) => item.clazz)).map((clazz) => {
    const subset = rows.filter((row) => row.item.clazz === clazz);
    const positives = subset.filter((row) => row.item.label === 1);
    const negatives = subset.filter((row) => row.item.label === 0);
    return {
      clazz,
      support: subset.length,
      ...(positives.length > 0 ? { recall: round4(positives.filter((row) => row.predicted === 1).length / positives.length) } : {}),
      ...(negatives.length > 0 ? { falsePositiveRate: round4(negatives.filter((row) => row.predicted === 1).length / negatives.length) } : {}),
    };
  });

  const train = labeled.filter((_, index) => index % 5 !== 0);
  const model = trainLogistic(train.map((row) => ({ vector: extractFeatures(row.item.context, row.assessment), label: row.item.label })));
  const scored = labeled.map((row) => {
    const probability = scoreWith(model, extractFeatures(row.item.context, row.assessment));
    return { label: row.item.label, score: probability, probability };
  });

  return {
    generatedAt: new Date().toISOString(),
    dataset,
    notes: [
      'These numbers are from synthetic labeled sessions in src/eval/synthetic.ts.',
      'They measure detector behavior on constructed cases, not real-world fraud-detection accuracy.',
      'Stealth automation and residential-proxy rotation are expected failure classes at the origin.',
    ],
    n: labeled.length,
    precision: round4(stats.precision),
    recall: round4(stats.recall),
    f1: round4(stats.f1),
    tpr: round4(stats.tpr),
    fpr: round4(stats.fpr),
    fnr: round4(stats.fnr),
    specificity: round4(stats.specificity),
    rocAuc: round4(rocAuc(scored)),
    prAuc: round4(prAuc(scored)),
    calibrationError: round4(expectedCalibrationError(scored)),
    confusion: conf,
    perClass,
  };
}

export function formatReport(report: EvalReport): string {
  const lines = [
    `Evaluation report (${report.dataset})`,
    `Generated: ${report.generatedAt}`,
    ...report.notes.map((note) => `Note: ${note}`),
    `N=${report.n} precision=${report.precision} recall=${report.recall} f1=${report.f1}`,
    `TPR=${report.tpr} FPR=${report.fpr} FNR=${report.fnr} specificity=${report.specificity}`,
    `ROC-AUC=${report.rocAuc} PR-AUC=${report.prAuc} ECE=${report.calibrationError}`,
    `Confusion tp=${report.confusion.tp} fp=${report.confusion.fp} tn=${report.confusion.tn} fn=${report.confusion.fn}`,
    'Per-class:',
    ...report.perClass.map((row) => `  ${row.clazz} support=${row.support}${row.recall !== undefined ? ` recall=${row.recall}` : ''}${row.falsePositiveRate !== undefined ? ` fpr=${row.falsePositiveRate}` : ''}`),
  ];
  return `${lines.join('\n')}\n`;
}

function unique(values: readonly AttackerClass[]): AttackerClass[] {
  return [...new Set(values)];
}

function scoreWith(model: ReturnType<typeof trainLogistic>, vector: ReturnType<typeof extractFeatures>): number {
  let logit = model.intercept;
  for (let i = 0; i < vector.values.length; i += 1) {
    const name = vector.names[i];
    if (!name) continue;
    logit += (model.weights[name] ?? 0) * (vector.values[i] ?? 0);
  }
  if (logit >= 20) return 1;
  if (logit <= -20) return 0;
  return 1 / (1 + Math.exp(-logit));
}

export function writeReport(path: string): EvalReport {
  const report = runEvaluation();
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
  return report;
}
