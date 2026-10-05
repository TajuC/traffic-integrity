import { formatReport, runEvaluation, writeReport } from './run.ts';

const json = process.argv.includes('--json');
const out = process.argv.find((arg) => arg.startsWith('--out='))?.slice(6);
const report = out ? writeReport(out) : runEvaluation();
process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : formatReport(report));
