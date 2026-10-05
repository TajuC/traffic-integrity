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
  }
}
