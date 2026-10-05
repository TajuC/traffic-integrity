import type { SqlClient } from '../db/sql.ts';

export interface PaidVisitRecord {
  readonly id: string;
  readonly landedAt: Date;
  readonly visitorId: string;
  readonly sessionId: string;
  readonly clickHash: string;
  readonly gclid: string | undefined;
  readonly gbraid: string | undefined;
  readonly wbraid: string | undefined;
  readonly gadSource: string | undefined;
  readonly gadCampaignId: string | undefined;
  readonly utmSource: string | undefined;
  readonly utmMedium: string | undefined;
  readonly utmCampaign: string | undefined;
  readonly utmTerm: string | undefined;
  readonly utmContent: string | undefined;
  readonly landingPath: string;
  readonly referrerHost: string | undefined;
  readonly ipHash: string;
  readonly networkPrefix: string;
  readonly ipAddress: string | undefined;
  readonly asn: number | undefined;
  readonly asOrg: string | undefined;
  readonly country: string | undefined;
  readonly networkCategory: string;
  readonly browserFamily: string;
  readonly browserMajor: number | undefined;
  readonly osFamily: string;
  readonly deviceType: string;
  readonly edgeBotScore: number | undefined;
  readonly identity: string;
  readonly riskScore: number;
  readonly decision: string;
  readonly reasons: readonly string[];
  readonly enforced: boolean;
}

const COLUMNS = [
  'id', 'landed_at', 'visitor_id', 'session_id', 'click_hash', 'gclid', 'gbraid', 'wbraid', 'gad_source', 'gad_campaign_id',
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'landing_path', 'referrer_host', 'ip_hash',
  'network_prefix', 'ip_address', 'asn', 'as_org', 'country', 'network_category', 'browser_family', 'browser_major',
  'os_family', 'device_type', 'edge_bot_score', 'identity', 'risk_score', 'decision', 'reasons', 'enforced',
] as const;

function row(visit: PaidVisitRecord): unknown[] {
  return [
    visit.id, visit.landedAt, visit.visitorId, visit.sessionId, visit.clickHash, visit.gclid ?? null, visit.gbraid ?? null,
    visit.wbraid ?? null, visit.gadSource ?? null, visit.gadCampaignId ?? null, visit.utmSource ?? null, visit.utmMedium ?? null,
    visit.utmCampaign ?? null, visit.utmTerm ?? null, visit.utmContent ?? null, visit.landingPath, visit.referrerHost ?? null,
    visit.ipHash, visit.networkPrefix, visit.ipAddress ?? null, visit.asn ?? null, visit.asOrg ?? null, visit.country ?? null,
    visit.networkCategory, visit.browserFamily, visit.browserMajor ?? null, visit.osFamily, visit.deviceType,
    visit.edgeBotScore ?? null, visit.identity, visit.riskScore, visit.decision, [...visit.reasons], visit.enforced,
  ];
}

export interface PaidVisitRecorderOptions {
  readonly maxQueue?: number;
  readonly batchSize?: number;
  readonly intervalMs?: number;
  readonly onResult?: (result: 'written' | 'dropped' | 'failed', count: number, error?: unknown) => void;
}

export class PaidVisitRecorder {
  private readonly db: SqlClient | undefined;
  private readonly maxQueue: number;
  private readonly batchSize: number;
  private readonly intervalMs: number;
  private readonly onResult: NonNullable<PaidVisitRecorderOptions['onResult']>;
  private queue: PaidVisitRecord[] = [];
  private timer: NodeJS.Timeout | undefined;
  private inflight: Promise<void> | undefined;

  constructor(db: SqlClient | undefined, options: PaidVisitRecorderOptions = {}) {
    this.db = db;
    this.maxQueue = options.maxQueue ?? 5000;
    this.batchSize = options.batchSize ?? 100;
    this.intervalMs = options.intervalMs ?? 1000;
    this.onResult = options.onResult ?? (() => undefined);
  }

  get pending(): number {
    return this.queue.length;
  }

  record(visit: PaidVisitRecord): void {
    if (!this.db) return;
    if (this.queue.length >= this.maxQueue) {
      this.onResult('dropped', 1);
      return;
    }
    this.queue.push(visit);
    if (this.queue.length >= this.batchSize) void this.flush();
  }

  start(): void {
    if (this.timer || !this.db) return;
    this.timer = setInterval(() => void this.flush(), this.intervalMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
  }

  async flush(): Promise<void> {
    while (this.inflight) await this.inflight;
    if (!this.db || this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.batchSize);
    this.inflight = this.write(this.db, batch).finally(() => {
      this.inflight = undefined;
    });
    await this.inflight;
    if (this.queue.length >= this.batchSize) await this.flush();
  }

  private async write(db: SqlClient, batch: PaidVisitRecord[]): Promise<void> {
    const params: unknown[] = [];
    const tuples = batch.map((visit) => {
      const values = row(visit);
      const placeholders = values.map((value) => {
        params.push(value);
        return `$${params.length}`;
      });
      return `(${placeholders.join(', ')})`;
    });
    try {
      await db.query(
        `INSERT INTO ti_paid_visits (${COLUMNS.join(', ')}) VALUES ${tuples.join(', ')} ON CONFLICT (visitor_id, click_hash) DO NOTHING`,
        params,
      );
      this.onResult('written', batch.length);
    } catch (error) {
      this.onResult('failed', batch.length, error);
    }
  }
}
