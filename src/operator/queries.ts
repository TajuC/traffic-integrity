import type { SqlClient } from '../db/sql.ts';

export async function recentAssessments(
  db: SqlClient,
  since: Date,
  options: { readonly minScore?: number; readonly paid?: boolean; readonly limit?: number } = {},
): Promise<Array<Record<string, unknown>>> {
  const result = await db.query(
    `SELECT id, created_at, visitor_id, campaign_id, route, paid, score, decision, shadow_decision, reasons, cohort, cluster_kind
     FROM ti_assessments
     WHERE created_at > $1 AND score >= $2 AND ($3::boolean IS NULL OR paid = $3)
     ORDER BY created_at DESC LIMIT $4`,
    [since, options.minScore ?? 20, options.paid ?? null, options.limit ?? 100],
  );
  return result.rows;
}

export async function campaignAbuse(db: SqlClient, since: Date): Promise<Array<Record<string, unknown>>> {
  const result = await db.query(
    `SELECT coalesce(campaign_id, 'unknown') AS campaign, count(*) AS visits,
            count(*) FILTER (WHERE score >= 20) AS suspicious,
            count(*) FILTER (WHERE decision IN ('CHALLENGE', 'TEMPORARILY_RESTRICT', 'BLOCK')) AS enforced_like
     FROM ti_assessments WHERE created_at > $1 AND paid GROUP BY 1 ORDER BY 3 DESC, 2 DESC LIMIT 50`,
    [since],
  );
  return result.rows.map((row) => ({
    campaign: row.campaign,
    visits: Number(row.visits),
    suspicious: Number(row.suspicious),
    enforcedLike: Number(row.enforced_like),
  }));
}

export async function clusterSummary(db: SqlClient, since: Date): Promise<Array<Record<string, unknown>>> {
  const result = await db.query(
    `SELECT cluster_kind AS kind, count(*) AS hits, count(DISTINCT visitor_id) AS visitors
     FROM ti_assessments WHERE created_at > $1 AND cluster_kind IS NOT NULL
     GROUP BY 1 ORDER BY 2 DESC`,
    [since],
  );
  return result.rows.map((row) => ({ kind: row.kind, hits: Number(row.hits), visitors: Number(row.visitors) }));
}

export async function assessmentById(db: SqlClient, id: string): Promise<Record<string, unknown> | undefined> {
  const result = await db.query(
    `SELECT id, created_at, visitor_id, session_id, ip_hash, network_prefix, asn, campaign_id, route, paid,
            score, decision, shadow_decision, reasons, cohort, policy_version, detector_version, model_version,
            fraud_probability, cluster_kind
     FROM ti_assessments WHERE id = $1`,
    [id],
  );
  return result.rows[0];
}

export async function insertLabel(
  db: SqlClient,
  label: {
    readonly id: string;
    readonly createdAt: Date;
    readonly subjectType: string;
    readonly subjectId: string;
    readonly label: string;
    readonly source: string;
    readonly confidence: number;
    readonly provenance: string;
    readonly notes?: string;
  },
): Promise<void> {
  await db.query(
    `INSERT INTO ti_labels (id, created_at, subject_type, subject_id, label, source, confidence, provenance, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT (subject_type, subject_id, label, source) DO UPDATE SET confidence = EXCLUDED.confidence, notes = EXCLUDED.notes, created_at = EXCLUDED.created_at`,
    [label.id, label.createdAt, label.subjectType, label.subjectId, label.label, label.source, label.confidence, label.provenance, label.notes ?? null],
  );
}
