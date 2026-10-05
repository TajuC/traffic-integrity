import type { SqlClient } from '../db/sql.ts';

export type AttemptStatus = 'processing' | 'challenged' | 'rejected' | 'duplicate' | 'accepted' | 'failed';
export type Verification = 'not_required' | 'passed' | 'failed' | 'unavailable' | 'missing';
export type ConversionStatus = 'pending' | 'review' | 'qualified' | 'disqualified';

export interface AttemptStart {
  readonly id: string;
  readonly now: Date;
  readonly idempotencyKey: string;
  readonly formNonce: string | undefined;
  readonly formId: string;
  readonly visitorId: string;
  readonly sessionId: string;
  readonly ipHash: string;
  readonly networkPrefix: string;
  readonly asn: number | undefined;
  readonly country: string | undefined;
}

export type AttemptClaim =
  | { readonly kind: 'fresh'; readonly attemptId: string; readonly nonceReplayed: boolean }
  | { readonly kind: 'resumed'; readonly attemptId: string }
  | { readonly kind: 'busy' }
  | { readonly kind: 'replay'; readonly status: number; readonly body: unknown };

export interface AttemptOutcome {
  readonly status: AttemptStatus;
  readonly riskScore: number | undefined;
  readonly decision: string | undefined;
  readonly reasons: readonly string[];
  readonly verification: Verification | undefined;
  readonly responseStatus: number;
  readonly responseBody: unknown;
  readonly leadId: string | undefined;
}

export interface NewLead {
  readonly id: string;
  readonly createdAt: Date;
  readonly attemptId: string;
  readonly formId: string;
  readonly visitorId: string;
  readonly name: string;
  readonly email: string | undefined;
  readonly phone: string | undefined;
  readonly message: string | undefined;
  readonly extra: Readonly<Record<string, string>>;
  readonly emailFingerprint: string | undefined;
  readonly phoneFingerprint: string | undefined;
  readonly messageFingerprint: string | undefined;
}

export interface ClickAttribution {
  readonly gclid: string | undefined;
  readonly gbraid: string | undefined;
  readonly wbraid: string | undefined;
  readonly gadSource: string | undefined;
  readonly gadCampaignId: string | undefined;
}

export interface NewConversion extends ClickAttribution {
  readonly id: string;
  readonly createdAt: Date;
  readonly action: string;
  readonly status: 'pending' | 'review';
  readonly qualifyAfter: Date | undefined;
  readonly decisionReason: string | undefined;
  readonly value: number | undefined;
  readonly currency: string;
  readonly hashedEmail: string | undefined;
  readonly hashedPhone: string | undefined;
  readonly riskScore: number;
  readonly reasons: readonly string[];
}

export type LeadInsert =
  | { readonly kind: 'inserted' }
  | { readonly kind: 'duplicate'; readonly leadId: string; readonly conversionId: string | undefined };

export interface ExportRow extends ClickAttribution {
  readonly id: string;
  readonly created_at: Date;
  readonly conversion_action: string;
  readonly value: string | null;
  readonly currency: string;
  readonly hashed_email: string | null;
  readonly hashed_phone: string | null;
}

const STALE_PROCESSING_MS = 60_000;

export async function claimAttempt(db: SqlClient, start: AttemptStart): Promise<AttemptClaim> {
  const insert = (formNonce: string | undefined) =>
    db.query(
      `INSERT INTO ti_conversion_attempts
         (id, created_at, updated_at, idempotency_key, form_nonce, form_id, visitor_id, session_id, ip_hash, network_prefix, asn, country, status)
       VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'processing')
       ON CONFLICT DO NOTHING
       RETURNING id`,
      [start.id, start.now, start.idempotencyKey, formNonce ?? null, start.formId, start.visitorId, start.sessionId, start.ipHash,
        start.networkPrefix, start.asn ?? null, start.country ?? null],
    );

  if ((await insert(start.formNonce)).rowCount === 1) return { kind: 'fresh', attemptId: start.id, nonceReplayed: false };

  const existing = await db.query<{ id: string; status: AttemptStatus; visitor_id: string; response_status: number | null; response_body: unknown }>(
    'SELECT id, status, visitor_id, response_status, response_body FROM ti_conversion_attempts WHERE idempotency_key = $1',
    [start.idempotencyKey],
  );
  const row = existing.rows[0];
  if (!row) {
    if ((await insert(undefined)).rowCount === 1) return { kind: 'fresh', attemptId: start.id, nonceReplayed: true };
    return { kind: 'busy' };
  }
  if (row.visitor_id !== start.visitorId) return { kind: 'busy' };
  if (row.status === 'accepted' || row.status === 'duplicate' || row.status === 'rejected') {
    return { kind: 'replay', status: row.response_status ?? 200, body: row.response_body };
  }
  const resumed = await db.query(
    `UPDATE ti_conversion_attempts SET status = 'processing', updated_at = $2
     WHERE id = $1 AND (status IN ('challenged', 'failed') OR (status = 'processing' AND updated_at < $3))
     RETURNING id`,
    [row.id, start.now, new Date(start.now.getTime() - STALE_PROCESSING_MS)],
  );
  return resumed.rowCount === 1 ? { kind: 'resumed', attemptId: row.id } : { kind: 'busy' };
}

export async function finishAttempt(db: SqlClient, attemptId: string, outcome: AttemptOutcome, now: Date): Promise<void> {
  await db.query(
    `UPDATE ti_conversion_attempts
     SET status = $2, risk_score = $3, decision = $4, reasons = $5, verification = $6, response_status = $7, response_body = $8,
         lead_id = $9, updated_at = $10
     WHERE id = $1`,
    [attemptId, outcome.status, outcome.riskScore ?? null, outcome.decision ?? null, [...outcome.reasons], outcome.verification ?? null,
      outcome.responseStatus, JSON.stringify(outcome.responseBody), outcome.leadId ?? null, now],
  );
}

export async function countMessageContacts(db: SqlClient, messageFingerprint: string, since: Date): Promise<number> {
  const result = await db.query<{ contacts: string | number }>(
    `SELECT count(DISTINCT coalesce(email_fingerprint, phone_fingerprint)) AS contacts
     FROM ti_leads WHERE message_fingerprint = $1 AND created_at > $2`,
    [messageFingerprint, since],
  );
  return Number(result.rows[0]?.contacts ?? 0);
}

export async function latestPaidVisit(db: SqlClient, visitorId: string, since: Date): Promise<ClickAttribution | undefined> {
  const result = await db.query<{ gclid: string | null; gbraid: string | null; wbraid: string | null; gad_source: string | null; gad_campaign_id: string | null }>(
    `SELECT gclid, gbraid, wbraid, gad_source, gad_campaign_id FROM ti_paid_visits
     WHERE visitor_id = $1 AND landed_at > $2 ORDER BY landed_at DESC LIMIT 1`,
    [visitorId, since],
  );
  const row = result.rows[0];
  if (!row) return undefined;
  return {
    gclid: row.gclid ?? undefined,
    gbraid: row.gbraid ?? undefined,
    wbraid: row.wbraid ?? undefined,
    gadSource: row.gad_source ?? undefined,
    gadCampaignId: row.gad_campaign_id ?? undefined,
  };
}

export async function insertLeadIfNew(db: SqlClient, lead: NewLead, conversion: NewConversion, dedupeSince: Date): Promise<LeadInsert> {
  return db.transaction(async (tx) => {
    const keys = [lead.emailFingerprint, lead.phoneFingerprint].filter((key): key is string => key !== undefined).sort();
    for (const key of keys) await tx.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`lead:${lead.formId}:${key}`]);

    const duplicate = await tx.query<{ id: string; conversion_id: string | null }>(
      `SELECT l.id, c.id AS conversion_id FROM ti_leads l LEFT JOIN ti_conversions c ON c.lead_id = l.id
       WHERE l.form_id = $1 AND l.created_at > $2
         AND ((l.email_fingerprint IS NOT NULL AND l.email_fingerprint = $3) OR (l.phone_fingerprint IS NOT NULL AND l.phone_fingerprint = $4))
       ORDER BY l.created_at DESC LIMIT 1`,
      [lead.formId, dedupeSince, lead.emailFingerprint ?? null, lead.phoneFingerprint ?? null],
    );
    const found = duplicate.rows[0];
    if (found) return { kind: 'duplicate', leadId: found.id, conversionId: found.conversion_id ?? undefined };

    await tx.query(
      `INSERT INTO ti_leads (id, created_at, attempt_id, form_id, visitor_id, name, email, phone, message, extra,
                             email_fingerprint, phone_fingerprint, message_fingerprint)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [lead.id, lead.createdAt, lead.attemptId, lead.formId, lead.visitorId, lead.name, lead.email ?? null, lead.phone ?? null,
        lead.message ?? null, JSON.stringify(lead.extra), lead.emailFingerprint ?? null, lead.phoneFingerprint ?? null,
        lead.messageFingerprint ?? null],
    );
    await tx.query(
      `INSERT INTO ti_conversions (id, created_at, lead_id, conversion_action, status, qualify_after, decision_reason, value, currency,
                                   gclid, gbraid, wbraid, gad_source, gad_campaign_id, hashed_email, hashed_phone, risk_score, reasons)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
      [conversion.id, conversion.createdAt, lead.id, conversion.action, conversion.status, conversion.qualifyAfter ?? null,
        conversion.decisionReason ?? null, conversion.value ?? null, conversion.currency, conversion.gclid ?? null,
        conversion.gbraid ?? null, conversion.wbraid ?? null, conversion.gadSource ?? null, conversion.gadCampaignId ?? null,
        conversion.hashedEmail ?? null, conversion.hashedPhone ?? null, conversion.riskScore, [...conversion.reasons]],
    );
    return { kind: 'inserted' };
  });
}

export async function holdPendingSince(db: SqlClient, since: Date): Promise<number> {
  const result = await db.query(
    `UPDATE ti_conversions SET status = 'review', decision_reason = 'conversion_burst'
     WHERE status = 'pending' AND created_at > $1`,
    [since],
  );
  return result.rowCount;
}

export async function qualifyDue(db: SqlClient, now: Date): Promise<Array<{ id: string; attributed: boolean }>> {
  const result = await db.query<{ id: string; attributed: boolean }>(
    `UPDATE ti_conversions SET status = 'qualified', decided_at = $1, decided_by = 'auto'
     WHERE status = 'pending' AND qualify_after <= $1
     RETURNING id, (gclid IS NOT NULL OR gbraid IS NOT NULL OR wbraid IS NOT NULL) AS attributed`,
    [now],
  );
  return result.rows;
}

export async function decideConversion(
  db: SqlClient,
  id: string,
  status: 'qualified' | 'disqualified',
  decidedBy: string,
  reason: string | undefined,
  now: Date,
): Promise<{ id: string; exported: boolean } | undefined> {
  const allowed: ConversionStatus[] = status === 'qualified' ? ['pending', 'review'] : ['pending', 'review', 'qualified'];
  const result = await db.query<{ id: string; exported: boolean }>(
    `UPDATE ti_conversions SET status = $2, decided_at = $3, decided_by = $4, decision_reason = $5
     WHERE id = $1 AND status = ANY($6::text[])
     RETURNING id, first_exported_at IS NOT NULL AS exported`,
    [id, status, now, decidedBy, reason ?? null, allowed],
  );
  return result.rows[0];
}

export async function qualifiedForExport(db: SqlClient, since: Date): Promise<ExportRow[]> {
  const result = await db.query<{
    id: string;
    created_at: Date;
    conversion_action: string;
    value: string | null;
    currency: string;
    gclid: string | null;
    gbraid: string | null;
    wbraid: string | null;
    gad_source: string | null;
    gad_campaign_id: string | null;
    hashed_email: string | null;
    hashed_phone: string | null;
  }>(
    `SELECT id, created_at, conversion_action, value::text AS value, currency, gclid, gbraid, wbraid, gad_source, gad_campaign_id,
            hashed_email, hashed_phone
     FROM ti_conversions WHERE status = 'qualified' AND created_at > $1 ORDER BY created_at`,
    [since],
  );
  return result.rows.map((row) => ({
    id: row.id,
    created_at: new Date(row.created_at),
    conversion_action: row.conversion_action,
    value: row.value,
    currency: row.currency.trim(),
    hashed_email: row.hashed_email,
    hashed_phone: row.hashed_phone,
    gclid: row.gclid ?? undefined,
    gbraid: row.gbraid ?? undefined,
    wbraid: row.wbraid ?? undefined,
    gadSource: row.gad_source ?? undefined,
    gadCampaignId: row.gad_campaign_id ?? undefined,
  }));
}

export async function markExported(db: SqlClient, ids: readonly string[], now: Date): Promise<void> {
  if (ids.length === 0) return;
  await db.query('UPDATE ti_conversions SET first_exported_at = $2 WHERE id = ANY($1::uuid[]) AND first_exported_at IS NULL', [[...ids], now]);
}

export interface ExclusionCandidate {
  readonly target: string;
  readonly suspiciousVisits: number;
  readonly visitors: number;
  readonly campaigns: readonly string[];
  readonly lastSeen: Date;
}

export async function exclusionCandidates(db: SqlClient, since: Date, minScore: number, minVisits: number): Promise<ExclusionCandidate[]> {
  const result = await db.query<{ target: string; visits: string | number; visitors: string | number; campaigns: string[] | null; last_seen: Date }>(
    `SELECT coalesce(host(ip_address), network_prefix) AS target, count(*) AS visits, count(DISTINCT visitor_id) AS visitors,
            array_remove(array_agg(DISTINCT gad_campaign_id), NULL) AS campaigns, max(landed_at) AS last_seen
     FROM ti_paid_visits WHERE landed_at > $1 AND risk_score >= $2
     GROUP BY 1 HAVING count(*) >= $3 ORDER BY count(*) DESC LIMIT 500`,
    [since, minScore, minVisits],
  );
  return result.rows.map((row) => ({
    target: row.target,
    suspiciousVisits: Number(row.visits),
    visitors: Number(row.visitors),
    campaigns: row.campaigns ?? [],
    lastSeen: new Date(row.last_seen),
  }));
}

export interface TrafficSummary {
  readonly paidVisits: ReadonlyArray<{ decision: string; visits: number }>;
  readonly campaigns: ReadonlyArray<{ campaign: string; visits: number; suspicious: number }>;
  readonly networks: ReadonlyArray<{ asn: number | null; category: string; visits: number; suspicious: number }>;
  readonly reasons: ReadonlyArray<{ reason: string; visits: number }>;
  readonly attempts: ReadonlyArray<{ status: string; attempts: number }>;
  readonly conversions: ReadonlyArray<{ status: string; conversions: number }>;
}

export async function trafficSummary(db: SqlClient, since: Date): Promise<TrafficSummary> {
  const numeric = <T extends Record<string, unknown>>(rows: T[], keys: readonly (keyof T)[]): T[] =>
    rows.map((row) => {
      const copy: Record<string, unknown> = { ...row };
      for (const key of keys) copy[key as string] = Number(row[key]);
      return copy as T;
    });
  const [paid, campaigns, networks, reasons, attempts, conversions] = await Promise.all([
    db.query<{ decision: string; visits: number }>('SELECT decision, count(*) AS visits FROM ti_paid_visits WHERE landed_at > $1 GROUP BY 1 ORDER BY 2 DESC', [since]),
    db.query<{ campaign: string; visits: number; suspicious: number }>(
      `SELECT coalesce(gad_campaign_id, utm_campaign, 'unknown') AS campaign, count(*) AS visits, count(*) FILTER (WHERE risk_score >= 20) AS suspicious
       FROM ti_paid_visits WHERE landed_at > $1 GROUP BY 1 ORDER BY 3 DESC, 2 DESC LIMIT 50`,
      [since],
    ),
    db.query<{ asn: number | null; category: string; visits: number; suspicious: number }>(
      `SELECT asn, network_category AS category, count(*) AS visits, count(*) FILTER (WHERE risk_score >= 20) AS suspicious
       FROM ti_paid_visits WHERE landed_at > $1 GROUP BY 1, 2 ORDER BY 4 DESC, 3 DESC LIMIT 50`,
      [since],
    ),
    db.query<{ reason: string; visits: number }>(
      `SELECT reason, count(*) AS visits FROM ti_paid_visits, unnest(reasons) AS reason WHERE landed_at > $1 GROUP BY 1 ORDER BY 2 DESC LIMIT 50`,
      [since],
    ),
    db.query<{ status: string; attempts: number }>('SELECT status, count(*) AS attempts FROM ti_conversion_attempts WHERE created_at > $1 GROUP BY 1', [since]),
    db.query<{ status: string; conversions: number }>('SELECT status, count(*) AS conversions FROM ti_conversions WHERE created_at > $1 GROUP BY 1', [since]),
  ]);
  return {
    paidVisits: numeric(paid.rows, ['visits']),
    campaigns: numeric(campaigns.rows, ['visits', 'suspicious']),
    networks: numeric(networks.rows, ['visits', 'suspicious']).map((row) => ({ ...row, asn: row.asn === null ? null : Number(row.asn) })),
    reasons: numeric(reasons.rows, ['visits']),
    attempts: numeric(attempts.rows, ['attempts']),
    conversions: numeric(conversions.rows, ['conversions']),
  };
}

export interface PendingDelivery {
  readonly id: string;
  readonly form_id: string;
  readonly name: string;
  readonly email: string | null;
  readonly phone: string | null;
  readonly message: string | null;
  readonly extra: Record<string, string>;
  readonly created_at: Date;
  readonly conversion_id: string;
  readonly conversion_status: ConversionStatus;
  readonly attributed: boolean;
}

export async function pendingDeliveries(db: SqlClient, olderThan: Date, maxAttempts: number, limit: number): Promise<PendingDelivery[]> {
  const result = await db.query<PendingDelivery>(
    `SELECT l.id, l.form_id, l.name, l.email, l.phone, l.message, l.extra, l.created_at,
            c.id AS conversion_id, c.status AS conversion_status,
            (c.gclid IS NOT NULL OR c.gbraid IS NOT NULL OR c.wbraid IS NOT NULL) AS attributed
     FROM ti_leads l JOIN ti_conversions c ON c.lead_id = l.id
     WHERE l.delivery_status = 'pending' AND l.created_at < $1 AND l.delivery_attempts < $2
     ORDER BY l.created_at LIMIT $3`,
    [olderThan, maxAttempts, limit],
  );
  return result.rows;
}

export async function recordDelivery(db: SqlClient, leadId: string, delivered: boolean, maxAttempts: number): Promise<void> {
  await db.query(
    `UPDATE ti_leads SET delivery_attempts = delivery_attempts + 1,
       delivery_status = CASE WHEN $2 THEN 'delivered' WHEN delivery_attempts + 1 >= $3 THEN 'failed' ELSE 'pending' END
     WHERE id = $1`,
    [leadId, delivered, maxAttempts],
  );
}

export interface Retention {
  readonly paidVisitsBefore: Date;
  readonly attemptsBefore: Date;
  readonly leadsBefore: Date;
}

export async function purgeExpired(db: SqlClient, retention: Retention, batchSize = 5000): Promise<number> {
  const statements: ReadonlyArray<readonly [string, Date]> = [
    ['DELETE FROM ti_paid_visits WHERE id IN (SELECT id FROM ti_paid_visits WHERE landed_at < $1 LIMIT $2)', retention.paidVisitsBefore],
    ['DELETE FROM ti_conversion_attempts WHERE id IN (SELECT id FROM ti_conversion_attempts WHERE created_at < $1 LIMIT $2)', retention.attemptsBefore],
    ['DELETE FROM ti_leads WHERE id IN (SELECT id FROM ti_leads WHERE created_at < $1 LIMIT $2)', retention.leadsBefore],
  ];
  let removed = 0;
  for (const [statement, before] of statements) {
    for (;;) {
      const result = await db.query(statement, [before, batchSize]);
      removed += result.rowCount;
      if (result.rowCount < batchSize) break;
    }
  }
  return removed;
}
