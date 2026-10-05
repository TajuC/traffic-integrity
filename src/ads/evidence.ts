import { createHash } from 'node:crypto';
import type { RequestIntegrity } from '../guard/inspect.ts';
import type { RiskAssessment } from '../risk/types.ts';

export interface EvidenceBundle {
  readonly generatedAt: string;
  readonly assessmentId?: string;
  readonly timeRange: { readonly from: string; readonly to: string };
  readonly campaign?: string;
  readonly clickHash?: string;
  readonly visitorId?: string;
  readonly sessionId?: string;
  readonly decision: string;
  readonly score: number;
  readonly fraudProbability?: number;
  readonly cohort?: string;
  readonly network: {
    readonly category: string;
    readonly asn?: number;
    readonly country?: string;
    readonly prefix: string;
  };
  readonly signals: ReadonlyArray<{
    readonly reason: string;
    readonly family: string;
    readonly severity: string;
    readonly confidence?: number;
    readonly explanation?: string;
    readonly evidence?: Readonly<Record<string, number | string | boolean>>;
  }>;
  readonly clusters: ReadonlyArray<{ readonly kind: string; readonly members: number }>;
  readonly relatedSessionCount?: number;
  readonly conversion?: { readonly status: string; readonly trusted: boolean };
  readonly policyVersion?: string;
  readonly detectorVersion?: string;
  readonly modelVersion?: string;
  readonly paid?: boolean;
  readonly limitation: string;
}

export function evidenceBundle(
  integrity: RequestIntegrity,
  extras: { readonly relatedSessionCount?: number; readonly conversionStatus?: string; readonly conversionTrusted?: boolean; readonly clickHash?: string } = {},
): EvidenceBundle {
  const { assessment, context, identity, subject, attribution } = integrity;
  return {
    generatedAt: new Date(integrity.now).toISOString(),
    assessmentId: assessment.id,
    timeRange: { from: new Date(integrity.now - 3_600_000).toISOString(), to: new Date(integrity.now).toISOString() },
    campaign: attribution?.gadCampaignId ?? attribution?.utm.utm_campaign,
    clickHash: extras.clickHash ?? clickIdHash(attribution?.primary?.value),
    visitorId: identity?.visitorId,
    sessionId: identity?.sessionId,
    decision: assessment.decision,
    score: assessment.score,
    fraudProbability: assessment.fraudProbability,
    cohort: assessment.cohort,
    network: {
      category: context.network.category,
      asn: context.network.asn,
      country: context.network.country,
      prefix: subject.networkPrefix,
    },
    signals: assessment.signals
      .filter((signal) => signal.family !== 'trust')
      .map((signal) => ({
        reason: signal.reason,
        family: signal.family,
        severity: signal.severity,
        confidence: signal.confidence,
        explanation: signal.explanation,
        evidence: signal.evidence,
      })),
    clusters: (context.clusters ?? []).map((hit) => ({ kind: hit.kind, members: hit.members })),
    relatedSessionCount: extras.relatedSessionCount,
    conversion:
      extras.conversionStatus !== undefined
        ? { status: extras.conversionStatus, trusted: extras.conversionTrusted === true }
        : undefined,
    limitation:
      'This bundle supports an invalid-click investigation. It does not prove that Google billed a click, and it cannot reverse a Google Ads charge.',
  };
}

export function summarizeAssessment(assessment: RiskAssessment): string {
  const reasons = assessment.signals.filter((signal) => signal.family !== 'trust').map((signal) => signal.reason);
  return `${assessment.decision} score=${assessment.score} reasons=${reasons.join(',') || 'none'}`;
}

export function storedEvidenceBundle(row: {
  readonly id: string;
  readonly created_at: Date | string;
  readonly visitor_id: string | null;
  readonly session_id: string | null;
  readonly campaign_id: string | null;
  readonly score: number;
  readonly decision: string;
  readonly reasons: readonly string[] | null;
  readonly cohort: string | null;
  readonly cluster_kind: string | null;
  readonly fraud_probability: number | null;
  readonly policy_version: string;
  readonly detector_version: string;
  readonly model_version: string | null;
  readonly paid: boolean;
  readonly network_prefix: string;
  readonly asn: number | string | null;
}): EvidenceBundle {
  const created = new Date(row.created_at);
  return {
    generatedAt: new Date().toISOString(),
    assessmentId: row.id,
    timeRange: { from: new Date(created.getTime() - 3_600_000).toISOString(), to: created.toISOString() },
    campaign: row.campaign_id ?? undefined,
    visitorId: row.visitor_id ?? undefined,
    sessionId: row.session_id ?? undefined,
    decision: row.decision,
    score: Number(row.score),
    fraudProbability: row.fraud_probability ?? undefined,
    cohort: row.cohort ?? undefined,
    network: {
      category: 'unknown',
      asn: row.asn === null ? undefined : Number(row.asn),
      prefix: row.network_prefix,
    },
    signals: (row.reasons ?? []).map((reason) => ({ reason, family: 'unknown', severity: 'unknown' })),
    clusters: row.cluster_kind ? [{ kind: row.cluster_kind, members: 0 }] : [],
    policyVersion: row.policy_version,
    detectorVersion: row.detector_version,
    modelVersion: row.model_version ?? undefined,
    paid: row.paid,
    limitation:
      'This bundle supports an invalid-click investigation. It does not prove that Google billed a click, and it cannot reverse a Google Ads charge.',
  };
}

function clickIdHash(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return createHash('sha256').update(`gads-click:${value}`).digest('hex').slice(0, 32);
}
