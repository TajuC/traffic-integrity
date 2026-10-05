import { createApp } from './app.ts';
import { ConfigError, loadConfig } from './config/env.ts';
import { migrate, pendingMigrations } from './db/migrate.ts';
import { createIntegrityGuard } from './http/guard.ts';
import { createRuntime } from './runtime.ts';

async function main(): Promise<void> {
  const config = loadConfig();
  const runtime = await createRuntime(config);
  const { logger } = runtime;
  for (const warning of config.warnings) logger.warn({ event: 'config_warning' }, warning);

  if (runtime.db) {
    if (config.database?.url.startsWith('pglite://')) {
      await migrate(runtime.db);
    } else {
      const pending = await pendingMigrations(runtime.db);
      if (pending.length > 0) logger.error({ event: 'schema_outdated', pending }, 'database migrations are pending; run npm run migrate');
    }
  }

  const guard = createIntegrityGuard(runtime, {
    onLeadAccepted: (lead) => {
      logger.info({ event: 'lead_received', leadId: lead.id, formId: lead.formId, conversion: lead.conversion }, 'lead received');
      return Promise.resolve();
    },
  });
  guard.maintenance.start();

  const server = createApp(runtime, guard).listen(config.server.port, config.server.host, () => {
    logger.info({ event: 'server_started', host: config.server.host, port: config.server.port, enforcement: config.enforcement }, 'server started');
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 65_000;

  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    logger.info({ event: 'server_stopping', signal }, 'shutting down');
    const force = setTimeout(() => process.exit(1), 15_000);
    force.unref();
    server.close(() => {
      void guard.maintenance
        .stop()
        .then(() => runtime.close())
        .then(() => process.exit(0));
    });
  };
  process.once('SIGTERM', () => stop('SIGTERM'));
  process.once('SIGINT', () => stop('SIGINT'));
}

main().catch((error: unknown) => {
  if (error instanceof ConfigError) {
    process.stderr.write(`${error.message}\n`);
  } else {
    process.stderr.write(`fatal: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
  }
  process.exit(1);
});
