import { Counter, Histogram, Registry } from '@prometheus-io/client';

export class IntegrityMetrics {
  readonly registry = new Registry();
  readonly assessments: Counter<'route' | 'decision' | 'enforced'>;
  readonly signals: Counter<'reason'>;
  readonly challenges: Counter<'kind' | 'outcome'>;
  readonly conversions: Counter<'status'>;
  readonly paidArrivals: Counter<'category' | 'decision'>;
  readonly storeFallbacks: Counter<'operation'>;
  readonly paidVisitWrites: Counter<'result'>;
  readonly assessmentSeconds: Histogram<'route'>;
  readonly turnstileSeconds: Histogram<'outcome'>;
  readonly shadowDecisions: Counter<'would'>;
  readonly clusters: Counter<'kind'>;
  readonly modelScores: Histogram<'version'>;
  readonly edgeListProposals: Counter<'action'>;
  readonly labels: Counter<'label'>;
  readonly degraded: Counter<'component'>;

  constructor() {
    const registers = [this.registry];
    this.assessments = new Counter({
      name: 'ti_assessments_total',
      help: 'Risk assessments by route class, decision and whether the decision was enforced',
      labelNames: ['route', 'decision', 'enforced'],
      registers,
    });
    this.signals = new Counter({ name: 'ti_signals_total', help: 'Risk signals emitted, by reason code', labelNames: ['reason'], registers });
    this.challenges = new Counter({
      name: 'ti_challenges_total',
      help: 'Human verification challenges by kind and outcome',
      labelNames: ['kind', 'outcome'],
      registers,
    });
    this.conversions = new Counter({ name: 'ti_conversions_total', help: 'Conversion attempts by final status', labelNames: ['status'], registers });
    this.paidArrivals = new Counter({
      name: 'ti_paid_arrivals_total',
      help: 'Paid ad arrivals by network category and decision',
      labelNames: ['category', 'decision'],
      registers,
    });
    this.storeFallbacks = new Counter({
      name: 'ti_store_fallbacks_total',
      help: 'Shared store operations served by the in-process fallback',
      labelNames: ['operation'],
      registers,
    });
    this.paidVisitWrites = new Counter({
      name: 'ti_paid_visit_writes_total',
      help: 'Paid visit persistence outcomes',
      labelNames: ['result'],
      registers,
    });
    this.assessmentSeconds = new Histogram({
      name: 'ti_assessment_duration_seconds',
      help: 'Guard middleware latency including the shared store round trip',
      labelNames: ['route'],
      buckets: [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25],
      registers,
    });
    this.turnstileSeconds = new Histogram({
      name: 'ti_turnstile_duration_seconds',
      help: 'Turnstile siteverify latency by outcome',
      labelNames: ['outcome'],
      buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
      registers,
    });
    this.shadowDecisions = new Counter({
      name: 'ti_shadow_decisions_total',
      help: 'Shadow or monitor-mode decisions that would have been enforced',
      labelNames: ['would'],
      registers,
    });
    this.clusters = new Counter({ name: 'ti_clusters_total', help: 'Observed attack-cluster hits by kind', labelNames: ['kind'], registers });
    this.modelScores = new Histogram({
      name: 'ti_model_score',
      help: 'Optional model fraud probability',
      labelNames: ['version'],
      buckets: [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95],
      registers,
    });
    this.edgeListProposals = new Counter({
      name: 'ti_edge_list_proposals_total',
      help: 'Short-lived upstream block or challenge list proposals',
      labelNames: ['action'],
      registers,
    });
    this.labels = new Counter({ name: 'ti_labels_total', help: 'Operator or CRM labels recorded', labelNames: ['label'], registers });
    this.degraded = new Counter({ name: 'ti_degraded_total', help: 'Subsystem degradation events', labelNames: ['component'], registers });
  }
}
