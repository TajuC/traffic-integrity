import pg from 'pg';

export interface SqlResult<T> {
  readonly rows: T[];
  readonly rowCount: number;
}

export interface SqlClient {
  query<T = Record<string, unknown>>(text: string, params?: readonly unknown[]): Promise<SqlResult<T>>;
  exec(script: string): Promise<void>;
  transaction<T>(work: (tx: SqlClient) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export interface DatabaseOptions {
  readonly url: string;
  readonly ssl: 'disable' | 'require' | 'verify-full';
  readonly poolMax: number;
  readonly searchPath?: string;
  readonly onError?: (error: Error) => void;
}

export async function openDatabase(options: DatabaseOptions): Promise<SqlClient> {
  return options.url.startsWith('pglite://') ? openPglite(options.url) : openPostgres(options);
}

export function isUniqueViolation(error: unknown, constraint?: string): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const { code, constraint: name } = error as { code?: unknown; constraint?: unknown };
  return code === '23505' && (constraint === undefined || name === constraint);
}

function openPostgres(options: DatabaseOptions): SqlClient {
  const searchPath = options.searchPath && /^[A-Za-z_][A-Za-z0-9_]*$/.test(options.searchPath) ? options.searchPath : undefined;
  const pool = new pg.Pool({
    connectionString: options.url,
    max: options.poolMax,
    ssl: options.ssl === 'disable' ? false : { rejectUnauthorized: options.ssl === 'verify-full' },
    connectionTimeoutMillis: 3000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 10_000,
    ...(searchPath ? { options: `-c search_path=${searchPath}` } : {}),
  });
  pool.on('error', (error) => options.onError?.(error));

  const bind = (runner: pg.Pool | pg.PoolClient, inTransaction: boolean): SqlClient => ({
    async query<T>(text: string, params: readonly unknown[] = []): Promise<SqlResult<T>> {
      const result = await runner.query(text, params as unknown[]);
      return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
    },
    async exec(script: string): Promise<void> {
      await runner.query(script);
    },
    async transaction<T>(work: (tx: SqlClient) => Promise<T>): Promise<T> {
      if (inTransaction) return work(this);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await work(bind(client, true));
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },
    async close(): Promise<void> {
      if (!inTransaction) await pool.end();
    },
  });
  return bind(pool, false);
}

async function openPglite(url: string): Promise<SqlClient> {
  const { PGlite } = await import('@electric-sql/pglite');
  const location = url.slice('pglite://'.length);
  const db = location === '' || location === 'memory' ? new PGlite() : new PGlite(location);

  interface Runner {
    query<T>(text: string, params?: unknown[]): Promise<{ rows: T[]; affectedRows?: number }>;
    exec(script: string): Promise<unknown>;
  }
  const bind = (runner: Runner, inTransaction: boolean): SqlClient => ({
    async query<T>(text: string, params: readonly unknown[] = []): Promise<SqlResult<T>> {
      const result = await runner.query<T>(text, [...params]);
      return { rows: result.rows, rowCount: result.affectedRows ?? result.rows.length };
    },
    async exec(script: string): Promise<void> {
      await runner.exec(script);
    },
    async transaction<T>(work: (tx: SqlClient) => Promise<T>): Promise<T> {
      if (inTransaction) return work(this);
      return db.transaction((tx) => work(bind(tx, true)));
    },
    async close(): Promise<void> {
      if (!inTransaction) await db.close();
    },
  });
  return bind(db, false);
}
