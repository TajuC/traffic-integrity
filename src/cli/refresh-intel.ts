import { readFile, rename, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { buildDataset } from '../net/intel-sources.ts';
import { datasetSchema, type NetworkDataset } from '../net/network-intel.ts';

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      out: { type: 'string', default: process.env.NETWORK_INTEL_PATH ?? 'data/network-intel.json' },
      'with-private-relay': { type: 'boolean', default: false },
    },
  });
  const out = values.out;
  const previous = await readPrevious(out);
  const { dataset, reports } = await buildDataset(fetchText, previous, { includeOptional: values['with-private-relay'], now: new Date() });

  for (const report of reports) {
    process.stderr.write(`${report.status.padEnd(8)} ${report.id.padEnd(22)} ${String(report.entries).padStart(7)}${report.error ? `  (${report.error})` : ''}\n`);
  }
  if (reports.every((report) => report.status === 'failed' || report.status === 'skipped')) throw new Error('no source could be refreshed');

  const temporary = `${out}.tmp`;
  await writeFile(temporary, JSON.stringify(dataset), 'utf8');
  await rename(temporary, out);
  process.stderr.write(`wrote ${out}\n`);
  if (reports.some((report) => report.status === 'failed')) process.exitCode = 2;
}

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000), headers: { accept: 'application/json, text/plain, text/csv, */*' } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.text();
}

async function readPrevious(path: string): Promise<NetworkDataset | undefined> {
  try {
    return datasetSchema.parse(JSON.parse(await readFile(path, 'utf8')));
  } catch {
    return undefined;
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
