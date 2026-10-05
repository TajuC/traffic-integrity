import { randomUUID } from 'node:crypto';

export type OutcomeLabel =
  | 'legitimate'
  | 'suspicious'
  | 'fraud'
  | 'qualified_conversion'
  | 'unqualified_conversion'
  | 'duplicate'
  | 'spam'
  | 'customer'
  | 'rejected_lead'
  | 'chargeback';

export type LabelSource = 'operator' | 'crm' | 'system' | 'evaluation';

export interface LabelRecord {
  readonly id: string;
  readonly createdAt: Date;
  readonly subjectType: 'assessment' | 'visitor' | 'lead' | 'conversion' | 'cluster';
  readonly subjectId: string;
  readonly label: OutcomeLabel;
  readonly source: LabelSource;
  readonly confidence: number;
  readonly provenance: string;
  readonly notes?: string;
}

const SYSTEM_LABELS = new Set<OutcomeLabel>(['duplicate', 'spam']);

export function acceptLabel(record: Omit<LabelRecord, 'id' | 'createdAt'> & { readonly id?: string; readonly createdAt?: Date }): LabelRecord | undefined {
  if (record.confidence < 0 || record.confidence > 1) return undefined;
  if (record.source === 'system' && !SYSTEM_LABELS.has(record.label)) return undefined;
  if (record.source === 'evaluation' && record.confidence < 0.5) return undefined;
  if (record.provenance.trim().length < 3) return undefined;
  return {
    id: record.id ?? randomUUID(),
    createdAt: record.createdAt ?? new Date(),
    subjectType: record.subjectType,
    subjectId: record.subjectId,
    label: record.label,
    source: record.source,
    confidence: record.confidence,
    provenance: record.provenance.slice(0, 200),
    notes: record.notes?.slice(0, 500),
  };
}

export function labelWeight(record: LabelRecord): number {
  const sourceWeight = record.source === 'operator' ? 1 : record.source === 'crm' ? 0.85 : record.source === 'evaluation' ? 0.4 : 0.2;
  return record.confidence * sourceWeight;
}
