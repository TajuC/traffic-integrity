import { ConfigError, loadConfig } from '../config/env.ts';
import { migrate } from '../db/migrate.ts';
import { openDatabase } from '../db/sql.ts';

async function main(): Promise<void> {
  const config = loadConfig();
  if (!config.database) throw new Error('DATABASE_URL is not configured');
  const db = await openDatabase(config.database);
  try {
    const applied = await migrate(db);
    process.stdout.write(applied.length > 0 ? `applied: ${applied.join(', ')}\n` : 'schema is up to date\n');
  } finally {
    await db.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof ConfigError || error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
