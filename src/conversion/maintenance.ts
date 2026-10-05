import type { SqlClient } from '../db/sql.ts';
import type { Runtime } from '../runtime.ts';
import { deliverLead, MAX_DELIVERY_ATTEMPTS, type LeadHook } from './pipeline.ts';
import { pendingDeliveries, purgeExpired, qualifyDue } from './repository.ts';

export interface MaintenanceReport {
  readonly ran: boolean;
  readonly qualified: number;
  readonly redelivered: number;
  readonly purged: number;
}

const DAY_MS = 86_400_000;
const INTERVAL_MS = 60_000;
const PURGE_EVERY_MS = 60 * 60_000;

export class Maintenance {
  private readonly runtime: Runtime;
  private readonly hook: LeadHook | undefined;
  private timer: NodeJS.Timeout | undefined;
  private lastPurge = 0;
  private running: Promise<MaintenanceReport> | undefined;

  constructor(runtime: Runtime, hook: LeadHook | undefined) {
    this.runtime = runtime;
    this.hook = hook;
  }

  start(): void {
    if (this.timer || !this.runtime.db) return;
    this.timer = setInterval(() => {
      this.runOnce().catch((error: unknown) => {
        this.runtime.logger.error({ err: error }, 'maintenance run failed');
      });
    }, INTERVAL_MS);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running?.catch(() => undefined);
  }

  runOnce(): Promise<MaintenanceReport> {
    this.running ??= this.execute().finally(() => {
      this.running = undefined;
    });
    return this.running;
  }

  private async execute(): Promise<MaintenanceReport> {
    const db = this.runtime.db;
    if (!db) return { ran: false, qualified: 0, redelivered: 0, purged: 0 };
    const now = this.runtime.clock();
    const work = await withLock(db, 'ti:maintenance', async (tx) => {
      const qualified = await qualifyDue(tx, new Date(now));
      let purged = 0;
      if (now - this.lastPurge >= PURGE_EVERY_MS) {
        const retention = this.runtime.config.retention;
        purged = await purgeExpired(tx, {
          paidVisitsBefore: new Date(now - retention.paidVisitDays * DAY_MS),
          attemptsBefore: new Date(now - retention.attemptDays * DAY_MS),
          leadsBefore: new Date(now - retention.leadDays * DAY_MS),
        });
        this.lastPurge = now;
      }
      const deliveries = await pendingDeliveries(tx, new Date(now - 5 * 60_000), MAX_DELIVERY_ATTEMPTS, 50);
      return { qualified, purged, deliveries };
    });
    if (!work) return { ran: false, qualified: 0, redelivered: 0, purged: 0 };

    for (const conversion of work.qualified) {
      this.runtime.metrics.conversions.inc({ status: 'qualified' });
      this.runtime.events.emit('conversion_qualified', { conversionId: conversion.id, by: 'auto', attributed: conversion.attributed });
    }
    for (const lead of work.deliveries) {
      await deliverLead(this.runtime, this.hook, {
        id: lead.id,
        createdAt: new Date(lead.created_at),
        formId: lead.form_id,
        name: lead.name,
        email: lead.email ?? undefined,
        phone: lead.phone ?? undefined,
        message: lead.message ?? undefined,
        extra: lead.extra,
        conversion: { id: lead.conversion_id, status: lead.conversion_status, attributed: lead.attributed },
      });
    }
    return { ran: true, qualified: work.qualified.length, redelivered: work.deliveries.length, purged: work.purged };
  }
}

async function withLock<T>(db: SqlClient, name: string, work: (tx: SqlClient) => Promise<T>): Promise<T | undefined> {
  return db.transaction(async (tx) => {
    const lock = await tx.query<{ locked: boolean }>('SELECT pg_try_advisory_xact_lock(hashtext($1)) AS locked', [name]);
    if (!lock.rows[0]?.locked) return undefined;
    return work(tx);
  });
}
