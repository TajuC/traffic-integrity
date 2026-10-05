import type { Logger } from 'pino';

export type SecurityEvent =
  | 'paid_visit'
  | 'risk_assessment'
  | 'challenge_required'
  | 'challenge_success'
  | 'challenge_failure'
  | 'rate_limit'
  | 'temporary_restriction'
  | 'hard_block'
  | 'conversion_attempt'
  | 'conversion_rejected'
  | 'conversion_accepted'
  | 'conversion_duplicate'
  | 'conversion_qualified'
  | 'conversion_disqualified'
  | 'conversion_burst'
  | 'lead_delivery_failed'
  | 'suspicious_network_activity'
  | 'origin_bypass'
  | 'crawler_impersonation'
  | 'security_degraded';

export type EventLevel = 'info' | 'warn' | 'error';

const MAX_TRACKED_KEYS = 20_000;

export class SecurityEvents {
  private readonly log: Logger;
  private readonly now: () => number;
  private readonly recent = new Map<string, number>();

  constructor(logger: Logger, now: () => number = Date.now) {
    this.log = logger.child({ channel: 'security' });
    this.now = now;
  }

  emit(event: SecurityEvent, fields: Readonly<Record<string, unknown>>, level: EventLevel = 'info'): void {
    this.log[level]({ event, ...fields }, event);
  }

  emitOnce(key: string, windowMs: number, event: SecurityEvent, fields: Readonly<Record<string, unknown>>, level: EventLevel = 'info'): boolean {
    const now = this.now();
    const last = this.recent.get(key);
    if (last !== undefined && now - last < windowMs) return false;
    this.recent.delete(key);
    this.recent.set(key, now);
    if (this.recent.size > MAX_TRACKED_KEYS) {
      const oldest = this.recent.keys().next().value;
      if (oldest !== undefined) this.recent.delete(oldest);
    }
    this.emit(event, fields, level);
    return true;
  }
}
