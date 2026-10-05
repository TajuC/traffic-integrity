import type { Runtime } from '../runtime.ts';
import type { RiskAssessment } from '../risk/types.ts';
import { correlation, type RequestIntegrity } from './inspect.ts';

export type EnforcementAction =
  | { readonly kind: 'pass' }
  | { readonly kind: 'challenge' }
  | { readonly kind: 'restrict'; readonly retryAfterSeconds: number }
  | { readonly kind: 'block' };

const PASS: EnforcementAction = Object.freeze({ kind: 'pass' });
const CHALLENGE_EXEMPT = new Set(['internal', 'conversion']);

export async function enforcementFor(runtime: Runtime, integrity: RequestIntegrity): Promise<EnforcementAction> {
  const enforcing = runtime.config.enforcement === 'enforce';
  const { assessment, shape } = integrity;

  if (integrity.restrictedUntil !== undefined) {
    const retryAfterSeconds = Math.max(1, Math.ceil((integrity.restrictedUntil - integrity.now) / 1000));
    runtime.events.emitOnce(`rate:${integrity.subject.addressKey}:${integrity.identity?.visitorId ?? ''}`, 60_000, 'rate_limit', {
      ...correlation(integrity),
      route: shape.routeClass,
      retryAfterSeconds,
      enforced: enforcing,
    });
    return enforcing ? { kind: 'restrict', retryAfterSeconds } : PASS;
  }

  if (shape.routeClass === 'conversion') return PASS;

  switch (assessment.decision) {
    case 'BLOCK': {
      await applyRestriction(runtime, integrity, assessment, 'block');
      return enforcing ? { kind: 'block' } : PASS;
    }
    case 'TEMPORARILY_RESTRICT': {
      const until = await applyRestriction(runtime, integrity, assessment, 'restrict');
      return enforcing ? { kind: 'restrict', retryAfterSeconds: Math.max(1, Math.ceil((until - integrity.now) / 1000)) } : PASS;
    }
    case 'CHALLENGE': {
      if (!runtime.turnstile || !integrity.identity || CHALLENGE_EXEMPT.has(shape.routeClass)) return PASS;
      runtime.metrics.challenges.inc({ kind: shape.routeClass === 'page' ? 'page' : 'request', outcome: enforcing ? 'issued' : 'would_issue' });
      runtime.events.emitOnce(`challenge:${integrity.identity.visitorId}`, 60_000, 'challenge_required', {
        ...correlation(integrity),
        route: shape.routeClass,
        score: assessment.score,
        reasons: assessment.signals.map((signal) => signal.reason),
        enforced: enforcing,
      });
      return enforcing ? { kind: 'challenge' } : PASS;
    }
    case 'ALLOW_AND_MONITOR':
    case 'ALLOW':
      return PASS;
  }
}

export async function applyRestriction(
  runtime: Runtime,
  integrity: RequestIntegrity,
  assessment: RiskAssessment,
  kind: 'restrict' | 'block',
): Promise<number> {
  const { policy, config } = runtime;
  const now = integrity.now;
  const observation = integrity.context.observation;
  const personal = (observation?.address.population ?? 0) <= policy.restriction.maxSharedPopulation;
  const strikes = Math.max(observation?.visitor?.strikes ?? 0, personal ? (observation?.address.strikes ?? 0) : 0);
  const base = kind === 'block' ? policy.restriction.blockDurationSeconds : policy.restriction.durationSeconds;
  const until = now + base * 1000 * Math.min(1 + Math.floor(strikes), policy.restriction.maxEscalation);
  const visitorId = integrity.identity?.origin === 'returning' ? integrity.identity.visitorId : undefined;
  const addressKey = personal && integrity.context.address.ip ? integrity.subject.addressKey : undefined;
  const enforcing = config.enforcement === 'enforce';

  if (enforcing && (visitorId || addressKey)) {
    await runtime.store.restrict({ ...(visitorId ? { visitorId } : {}), ...(addressKey ? { addressKey } : {}) }, until, now);
    if (visitorId) runtime.restrictions.set(`v:${visitorId}`, until);
    if (addressKey) runtime.restrictions.set(addressKey, until);
  }

  runtime.events.emitOnce(
    `${kind}:${visitorId ?? integrity.subject.addressKey}`,
    60_000,
    kind === 'block' ? 'hard_block' : 'temporary_restriction',
    {
      ...correlation(integrity),
      ip: integrity.context.address.text,
      route: integrity.shape.routeClass,
      score: assessment.score,
      reasons: assessment.signals.map((signal) => signal.reason),
      until: new Date(until).toISOString(),
      restrictedVisitor: visitorId !== undefined,
      restrictedAddress: addressKey !== undefined,
      enforced: enforcing,
    },
    'warn',
  );
  return until;
}
