import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { loadConfig } from '../config/env.ts';
import { googleAdsCsv } from '../conversion/export.ts';
import { markExported, qualifiedForExport } from '../conversion/repository.ts';
import { openDatabase } from '../db/sql.ts';

const DAY_MS = 86_400_000;

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { out: { type: 'string' }, days: { type: 'string', default: '90' } } });
  const days = Math.min(Math.max(Number(values.days) || 90, 1), 90);
  const config = loadConfig();
  if (!config.database) throw new Error('DATABASE_URL is not configured');
  const db = await openDatabase(config.database);
  try {
    const now = new Date();
    const rows = await qualifiedForExport(db, new Date(now.getTime() - days * DAY_MS));
    const { csv, exported } = googleAdsCsv(rows, config.conversion.timezone);
    if (values.out) await writeFile(values.out, csv, 'utf8');
    else process.stdout.write(csv);
    await markExported(db, exported, now);
    process.stderr.write(`exported ${exported.length} conversion(s)\n`);
  } finally {
    await db.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
