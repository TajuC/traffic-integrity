import type { SqlClient } from '../db/sql.ts';

export interface AssessmentEvent {
  readonly id: string;
  readonly createdAt: Date;
  readonly visitorId: string | undefined;
  readonly sessionId: string | undefined;
  readonly ipHash: string;
  readonly networkPrefix: string;
  readonly asn: number | undefined;
  readonly campaignId: string | undefined;
  readonly route: string;
  readonly paid: boolean;
  readonly score: number;
  readonly decision: string;
  readonly shadowDecision: string | undefined;
  readonly reasons: readonly string[];
  readonly cohort: string | undefined;
  readonly policyVersion: string;
  readonly detectorVersion: string;
  readonly modelVersion: string | undefined;
  readonly fraudProbability: number | undefined;
  readonly clusterKind: string | undefined;
}

export class EventRecorder {
  private readonly db: SqlClient | undefined;
  private queue: AssessmentEvent[] = [];
  private timer: NodeJS.Timeout | undefined;
  private inflight: Promise<void> | undefined;
  private readonly maxQueue = 8_000;

  constructor(db: SqlClient | undefined) {
    this.db = db;
  }

  start(): void {
    if (this.timer || !this.db) return;
    this.timer = setInterval(() => {
      this.flush().catch(() => undefined);
    }, 1500);
    this.timer.unref();
  }

  record(event: AssessmentEvent): void {
    if (!this.db) return;
    if (this.queue.length >= this.maxQueue) this.queue.shift();
    this.queue.push(event);
  }

  async flush(): Promise<void> {
    if (!this.db || this.queue.length === 0) return;
    this.inflight ??= this.write().finally(() => {
      this.inflight = undefined;
    });
    await this.inflight;
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
  }

  private async write(): Promise<void> {
    const db = this.db;
    if (!db) return;
    const batch = this.queue.splice(0, 200);
    if (batch.length === 0) return;
    try {
      for (const event of batch) {
        await db.query(
          `INSERT INTO ti_assessments (
           id, created_at, visitor_id, session_id, ip_hash, network_prefix, asn, campaign_id, route, paid,
           score, decision, shadow_decision, reasons, cohort, policy_version, detector_version, model_version,
           fraud_probability, cluster_kind
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
         ON CONFLICT (id) DO NOTHING`,
          [
            event.id, event.createdAt, event.visitorId ?? null, event.sessionId ?? null, event.ipHash, event.networkPrefix,
            event.asn ?? null, event.campaignId ?? null, event.route, event.paid, event.score, event.decision,
            event.shadowDecision ?? null, [...event.reasons], event.cohort ?? null, event.policyVersion, event.detectorVersion,
            event.modelVersion ?? null, event.fraudProbability ?? null, event.clusterKind ?? null,
          ],
        );
      }
    } catch {
      return;
    }
  }
}

export async function purgeAssessments(db: SqlClient, before: Date, batchSize = 5000): Promise<number> {
  let removed = 0;
  for (;;) {
    const result = await db.query('DELETE FROM ti_assessments WHERE id IN (SELECT id FROM ti_assessments WHERE created_at < $1 LIMIT $2)', [before, batchSize]);
    removed += result.rowCount;
    if (result.rowCount < batchSize) break;
  }
  return removed;
}
