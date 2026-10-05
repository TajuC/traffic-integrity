import { randomUUID } from 'node:crypto';
import { applyRestriction } from '../guard/enforce.ts';
import { assessAction, correlation, readStoredAttribution, type RequestIntegrity } from '../guard/inspect.ts';
import type { FormTokenState } from '../risk/context.ts';
import { decisionRank, severityRank, type RiskAssessment } from '../risk/types.ts';
import type { Runtime } from '../runtime.ts';
import { bucket } from '../store/types.ts';
import { leadSchema, normalizeContact } from './lead.ts';
import {
  claimAttempt,
  countMessageContacts,
  finishAttempt,
  holdPendingSince,
  insertLeadIfNew,
  latestPaidVisit,
  recordDelivery,
  type AttemptStatus,
  type ClickAttribution,
  type ConversionStatus,
  type Verification,
} from './repository.ts';

export interface AcceptedLead {
  readonly id: string;
  readonly createdAt: Date;
  readonly formId: string;
  readonly name: string;
  readonly email: string | undefined;
  readonly phone: string | undefined;
  readonly message: string | undefined;
  readonly extra: Readonly<Record<string, string>>;
  readonly conversion: { readonly id: string; readonly status: ConversionStatus; readonly attributed: boolean };
}

export type LeadHook = (lead: AcceptedLead) => Promise<void>;

export interface ConversionRequest {
  readonly integrity: RequestIntegrity;
  readonly body: unknown;
  readonly originPresent: boolean;
}

export interface ConversionOutcome {
  readonly status: number;
  readonly body: unknown;
  readonly retryAfterSeconds?: number;
}

export const MAX_DELIVERY_ATTEMPTS = 5;

const DAY_MS = 86_400_000;
const CLICK_WINDOW_MS = 90 * DAY_MS;
const REJECTED = Object.freeze({ error: 'request_rejected' });
const RATE_LIMITED = Object.freeze({ error: 'rate_limited' });
const UNAVAILABLE = Object.freeze({ error: 'temporarily_unavailable' });

export async function processConversion(runtime: Runtime, request: ConversionRequest, hook: LeadHook | undefined): Promise<ConversionOutcome> {
  const { config, policy, events, metrics } = runtime;
  const { integrity } = request;
  const db = runtime.db;
  const identity = integrity.identity;
  const reject = (reason: string, status = 403, body: unknown = REJECTED): ConversionOutcome => {
    metrics.conversions.inc({ status: 'rejected' });
    events.emitOnce(`conversion-reject:${integrity.subject.addressKey}:${reason}`, 60_000, 'conversion_rejected', { ...correlation(integrity), reason }, 'warn');
    return { status, body };
  };

  if (!db) return { status: 503, body: UNAVAILABLE, retryAfterSeconds: 60 };
  if (!identity) return reject('automated_client');
  if (integrity.restrictedUntil !== undefined && config.enforcement === 'enforce') {
    return { ...reject('restricted_subject', 429, RATE_LIMITED), retryAfterSeconds: Math.ceil((integrity.restrictedUntil - integrity.now) / 1000) };
  }

  const raw = typeof request.body === 'object' && request.body !== null && !Array.isArray(request.body) ? (request.body as Record<string, unknown>) : undefined;
  const parsed = raw ? leadSchema.safeParse(raw) : undefined;
  if (!raw || !parsed?.success) {
    const fields = parsed?.success === false ? [...new Set(parsed.error.issues.map((issue) => String(issue.path[0] ?? 'body')))] : ['body'];
    return reject('invalid_input', 400, { error: 'invalid_request', fields });
  }
  const lead = parsed.data;
  if (!config.conversion.formIds.includes(lead.formId)) return reject('unknown_form', 400, { error: 'invalid_request', fields: ['formId'] });

  const honeypotValue = raw[config.conversion.honeypotField];
  const honeypot = typeof honeypotValue === 'string' ? honeypotValue.trim() !== '' : honeypotValue !== undefined && honeypotValue !== null;
  const now = runtime.clock();
  const token = runtime.formTokens.check(lead.formToken, identity.visitorId, lead.formId, now);
  const enforcing = config.enforcement === 'enforce';
  const facts = (formToken: FormTokenState, repeatedMessageContacts: number) => ({
    honeypot,
    formToken,
    formAgeMs: token.ageMs,
    originPresent: request.originPresent,
    repeatedMessageContacts,
  });
  const refuse = async (assessment: RiskAssessment): Promise<ConversionOutcome> => {
    const blocked = assessment.decision === 'BLOCK';
    const until = await applyRestriction(runtime, integrity, assessment, blocked ? 'block' : 'restrict');
    metrics.conversions.inc({ status: 'rejected' });
    return blocked
      ? { status: 403, body: REJECTED }
      : { status: 429, body: RATE_LIMITED, retryAfterSeconds: Math.max(1, Math.ceil((until - now) / 1000)) };
  };

  const preliminary = assessAction(runtime, integrity, facts(token.state, 0));
  if (enforcing && refuses(preliminary)) {
    events.emitOnce(`conversion-refused:${integrity.subject.addressKey}`, 60_000, 'conversion_rejected', {
      ...correlation(integrity),
      stage: 'preliminary',
      decision: preliminary.decision,
      score: preliminary.score,
      reasons: preliminary.signals.map((signal) => signal.reason),
    }, 'warn');
    return refuse(preliminary);
  }

  const claim = await claimAttempt(db, {
    id: randomUUID(),
    now: new Date(now),
    idempotencyKey: lead.idempotencyKey,
    formNonce: token.nonce,
    formId: lead.formId,
    visitorId: identity.visitorId,
    sessionId: identity.sessionId,
    ipHash: integrity.subject.addressKey,
    networkPrefix: integrity.subject.networkPrefix,
    asn: integrity.context.network.asn,
    country: integrity.context.network.country,
  });
  if (claim.kind === 'busy') return { status: 409, body: { error: 'in_progress' }, retryAfterSeconds: 2 };
  if (claim.kind === 'replay') return { status: claim.status, body: claim.body };

  const attemptId = claim.attemptId;
  const formTokenState: FormTokenState = claim.kind === 'fresh' && claim.nonceReplayed ? 'replayed' : token.state;
  events.emit('conversion_attempt', { ...correlation(integrity), attemptId, formId: lead.formId, formTokenState, resumed: claim.kind === 'resumed' });

  const contact = normalizeContact(lead, runtime.keyring, config.conversion.phoneCountryCode);
  const repeatedMessageContacts = contact.messageFingerprint ? await countMessageContacts(db, contact.messageFingerprint, new Date(now - DAY_MS)) : 0;
  const assessment = assessAction(runtime, integrity, facts(formTokenState, repeatedMessageContacts));
  const reasons = assessment.signals.filter((signal) => signal.family !== 'trust').map((signal) => signal.reason);
  const finish = (status: AttemptStatus, verification: Verification | undefined, outcome: ConversionOutcome, leadId?: string): Promise<void> =>
    finishAttempt(
      db,
      attemptId,
      {
        status,
        riskScore: assessment.score,
        decision: assessment.decision,
        reasons,
        verification,
        responseStatus: outcome.status,
        responseBody: outcome.body,
        leadId,
      },
      new Date(runtime.clock()),
    );

  if (enforcing && refuses(assessment)) {
    const outcome = await refuse(assessment);
    await finish('rejected', undefined, outcome);
    events.emit('conversion_rejected', { ...correlation(integrity), attemptId, stage: 'final', decision: assessment.decision, score: assessment.score, reasons }, 'warn');
    return outcome;
  }

  const verified = await verifyHuman(runtime, integrity, assessment, lead.formId, lead.turnstileToken, token.cdata ?? runtime.keyring.digest('subject', `attempt:${attemptId}`, 16));
  if (verified.outcome) {
    await finish(verified.status, verified.verification, verified.outcome);
    return verified.outcome;
  }
  const verification = verified.verification;

  const attribution = (await resolveAttribution(runtime, integrity)) ?? {};
  const globalRate = await runtime.store.countGlobalConversion(now);
  const holdMs = config.conversion.holdMinutes * 60_000;
  const burst = globalRate > config.conversion.burstPerHour;
  if (burst && (await runtime.store.claimOnce(`burst:${bucket(now, 3_600_000)}`, 3_600_000))) {
    const held = await holdPendingSince(db, new Date(now - holdMs));
    events.emit('conversion_burst', { rate: Math.round(globalRate), limit: config.conversion.burstPerHour, held }, 'warn');
  }

  const highest = assessment.signals.reduce((max, signal) => (signal.family === 'trust' ? max : Math.max(max, severityRank(signal.severity))), -1);
  const humanVerified = verification === 'passed' || (verification === 'not_required' && runtime.turnstile !== undefined);
  const lowRisk = assessment.score < policy.conversion.trustedMaxScore && highest < 2;
  const trusted = humanVerified && lowRisk && !burst;
  const status = trusted ? 'pending' : 'review';
  const decisionReason = trusted ? undefined : !humanVerified ? `verification_${verification}` : burst ? 'conversion_burst' : 'elevated_risk';
  const attributed = Boolean(attribution.gclid || attribution.gbraid || attribution.wbraid);

  const leadId = randomUUID();
  const conversionId = randomUUID();
  const createdAt = new Date(now);
  const inserted = await insertLeadIfNew(
    db,
    {
      id: leadId,
      createdAt,
      attemptId,
      formId: lead.formId,
      visitorId: identity.visitorId,
      name: lead.name,
      email: contact.email,
      phone: lead.phone,
      message: lead.message,
      extra: lead.extra ?? {},
      emailFingerprint: contact.emailFingerprint,
      phoneFingerprint: contact.phoneFingerprint,
      messageFingerprint: contact.messageFingerprint,
    },
    {
      id: conversionId,
      createdAt,
      action: config.conversion.actionName,
      status,
      qualifyAfter: trusted ? new Date(now + holdMs) : undefined,
      decisionReason,
      value: config.conversion.value,
      currency: config.conversion.currency,
      gclid: attribution.gclid,
      gbraid: attribution.gbraid,
      wbraid: attribution.wbraid,
      gadSource: attribution.gadSource,
      gadCampaignId: attribution.gadCampaignId,
      hashedEmail: contact.hashedEmail,
      hashedPhone: contact.hashedPhone,
      riskScore: assessment.score,
      reasons,
    },
    new Date(now - DAY_MS),
  );

  if (inserted.kind === 'duplicate') {
    const outcome: ConversionOutcome = { status: 200, body: { ok: true, leadId: inserted.leadId, conversion: { id: inserted.conversionId ?? null, fire: false } } };
    await finish('duplicate', verification, outcome, inserted.leadId);
    metrics.conversions.inc({ status: 'duplicate' });
    events.emit('conversion_duplicate', { ...correlation(integrity), attemptId, leadId: inserted.leadId });
    return outcome;
  }

  const outcome: ConversionOutcome = { status: 200, body: { ok: true, leadId, conversion: { id: conversionId, fire: trusted } } };
  await finish('accepted', verification, outcome, leadId);
  await runtime.store.patchVisitor(identity.visitorId, { acceptedConversion: true }, now);
  metrics.conversions.inc({ status });
  events.emit('conversion_accepted', {
    ...correlation(integrity),
    attemptId,
    leadId,
    conversionId,
    status,
    decisionReason,
    score: assessment.score,
    reasons,
    verification,
    attributed,
    campaign: attribution.gadCampaignId,
  });

  void deliverLead(runtime, hook, {
    id: leadId,
    createdAt,
    formId: lead.formId,
    name: lead.name,
    email: contact.email,
    phone: lead.phone,
    message: lead.message,
    extra: lead.extra ?? {},
    conversion: { id: conversionId, status, attributed },
  });
  return outcome;
}

function refuses(assessment: RiskAssessment): boolean {
  return assessment.decision === 'BLOCK' || assessment.decision === 'TEMPORARILY_RESTRICT';
}

interface Verified {
  readonly verification: Verification;
  readonly status: AttemptStatus;
  readonly outcome?: ConversionOutcome;
}

async function verifyHuman(
  runtime: Runtime,
  integrity: RequestIntegrity,
  assessment: RiskAssessment,
  formId: string,
  token: string | undefined,
  cdata: string,
): Promise<Verified> {
  const { config, metrics, events, policy } = runtime;
  const turnstile = runtime.turnstile;
  const siteKey = config.turnstile?.siteKey;
  const risky = decisionRank(assessment.decision) >= decisionRank('CHALLENGE');
  if (!turnstile || !siteKey) return { verification: 'not_required', status: 'processing' };
  if (config.conversion.challenge === 'risk' && !risky) return { verification: 'not_required', status: 'processing' };

  const challenge = { siteKey, action: `lead_${formId}`, cdata };
  if (!token) {
    metrics.challenges.inc({ kind: 'conversion', outcome: 'issued' });
    events.emit('challenge_required', { ...correlation(integrity), route: 'conversion', score: assessment.score });
    return { verification: 'missing', status: 'challenged', outcome: { status: 403, body: { error: 'verification_required', turnstile: challenge } } };
  }

  const started = performance.now();
  const result = await turnstile.verify({
    token,
    remoteIp: integrity.context.address.ip ? integrity.context.address.text : undefined,
    action: challenge.action,
    cdata,
  });
  metrics.turnstileSeconds.observe({ outcome: result.status }, (performance.now() - started) / 1000);
  metrics.challenges.inc({ kind: 'conversion', outcome: result.status });

  if (result.status === 'passed') {
    events.emit('challenge_success', { ...correlation(integrity), route: 'conversion' });
    return { verification: 'passed', status: 'processing' };
  }
  if (result.status === 'failed') {
    events.emit('challenge_failure', { ...correlation(integrity), route: 'conversion', reason: result.reason }, 'warn');
    return { verification: 'failed', status: 'challenged', outcome: { status: 403, body: { error: 'verification_failed', turnstile: challenge } } };
  }
  events.emit('challenge_failure', { ...correlation(integrity), route: 'conversion', reason: 'unavailable', detail: result.reason }, 'warn');
  if (assessment.score >= policy.conversionThresholds.challenge) {
    return { verification: 'unavailable', status: 'failed', outcome: { status: 503, body: UNAVAILABLE, retryAfterSeconds: 30 } };
  }
  return { verification: 'unavailable', status: 'processing' };
}

async function resolveAttribution(runtime: Runtime, integrity: RequestIntegrity): Promise<Partial<ClickAttribution> | undefined> {
  const stored = readStoredAttribution(integrity, CLICK_WINDOW_MS);
  if (stored) return stored;
  if (!runtime.db || !integrity.identity) return undefined;
  return latestPaidVisit(runtime.db, integrity.identity.visitorId, new Date(integrity.now - CLICK_WINDOW_MS));
}

export async function deliverLead(runtime: Runtime, hook: LeadHook | undefined, lead: AcceptedLead): Promise<void> {
  const db = runtime.db;
  if (!db) return;
  try {
    if (hook) await hook(lead);
    await recordDelivery(db, lead.id, true, MAX_DELIVERY_ATTEMPTS);
  } catch (error) {
    runtime.events.emit('lead_delivery_failed', { leadId: lead.id, error: error instanceof Error ? error.message : String(error) }, 'error');
    await recordDelivery(db, lead.id, false, MAX_DELIVERY_ATTEMPTS).catch(() => undefined);
  }
}
