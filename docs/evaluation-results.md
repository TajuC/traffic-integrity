# Evaluation results

This file contains only numbers produced by `npm run eval` against the synthetic
sessions in `src/eval/synthetic.ts`. It is not a real-world fraud-detection
benchmark. Do not cite these figures as production accuracy.

Command:

```bash
npm run eval
```

Run at 2026-10-05T20:58:40.389Z on this repository.

Dataset: `synthetic-v1`. N=216 labeled sessions after excluding the ambiguous
class. Decision `ALLOW` is treated as negative. Any other decision is treated as
a detection (including `ALLOW_AND_MONITOR`).

| Metric | Value |
| --- | --- |
| Precision | 1.0000 |
| Recall | 0.7436 |
| F1 | 0.8529 |
| True positive rate | 0.7436 |
| False positive rate | 0.0000 |
| False negative rate | 0.2564 |
| Specificity | 1.0000 |
| ROC-AUC (logistic fit on the same synthetic split) | 1.0000 |
| PR-AUC | 1.0000 |
| Expected calibration error | 0.1396 |

Confusion matrix: tp=116, fp=0, tn=60, fn=40.

Per-class recall (fraud classes) and false-positive rate (legitimate classes):

| Class | Support | Recall | FPR |
| --- | --- | --- | --- |
| legitimate | 52 |  | 0.00 |
| crawler | 8 |  | 0.00 |
| scripted_http | 40 | 1.00 |  |
| obvious_bot | 32 | 1.00 |  |
| datacenter_browser | 16 | 1.00 |  |
| repeated_click | 16 | 1.00 |  |
| conversion_spam | 12 | 1.00 |  |
| stealth_automation | 20 | 0.00 |  |
| residential_proxy | 20 | 0.00 |  |
| ambiguous | 10 |  | 0.00 |

The 40 false negatives are exactly the stealth-automation and residential-proxy
rotation cases. Those classes are constructed to look like ordinary browsers on
ordinary addresses. Origin-side software does not separate them from people on
this dataset, and the evaluation is written to show that failure rather than
hide it.

ROC-AUC and PR-AUC of 1.0 describe a logistic model fitted to the same synthetic
feature space. They are not evidence of calibration on live traffic. ECE of 0.14
already shows the probability outputs are not well calibrated.

If you later import anonymized production observations and labels, replace this
file with a new `npm run eval` report and keep the synthetic numbers labeled as
synthetic.
