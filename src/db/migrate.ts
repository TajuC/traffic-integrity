import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { SqlClient } from './sql.ts';

export const MIGRATIONS_DIRECTORY = fileURLToPath(new URL('../../migrations/', import.meta.url));

const MIGRATION_FILE = /^\d{3}_[a-z0-9_]+\.sql$/;

export async function pendingMigrations(db: SqlClient, directory = MIGRATIONS_DIRECTORY): Promise<string[]> {
  const files = await migrationFiles(directory);
  const exists = await db.query<{ present: boolean }>("SELECT to_regclass('ti_schema_migrations') IS NOT NULL AS present");
  if (!exists.rows[0]?.present) return files;
  const done = new Set((await db.query<{ version: string }>('SELECT version FROM ti_schema_migrations')).rows.map((row) => row.version));
  return files.filter((file) => !done.has(file));
}

export async function migrate(db: SqlClient, directory = MIGRATIONS_DIRECTORY): Promise<string[]> {
  const files = await migrationFiles(directory);
  await db.exec('CREATE TABLE IF NOT EXISTS ti_schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
  return db.transaction(async (tx) => {
    await tx.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['ti_schema_migrations']);
    const done = new Set((await tx.query<{ version: string }>('SELECT version FROM ti_schema_migrations')).rows.map((row) => row.version));
    const applied: string[] = [];
    for (const file of files) {
      if (done.has(file)) continue;
      await tx.exec(await readFile(`${directory}/${file}`, 'utf8'));
      await tx.query('INSERT INTO ti_schema_migrations (version) VALUES ($1)', [file]);
      applied.push(file);
    }
    return applied;
  });
}

async function migrationFiles(directory: string): Promise<string[]> {
  return (await readdir(directory)).filter((file) => MIGRATION_FILE.test(file)).sort();
}
