import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { parseIp } from '../src/net/ip.ts';
import { parseUserAgent } from '../src/request/user-agent.ts';
import { assessRisk, scoreSignals } from '../src/risk/engine.ts';
import { buildPolicy, DEFAULT_POLICY } from '../src/risk/policy.ts';
import type { RiskAssessment, RiskReason, RiskSignal } from '../src/risk/types.ts';
import { ESTABLISHED, observation, riskContext } from './helpers/context.ts';
import { START } from './helpers/harness.ts';

const policy = DEFAULT_POLICY;
const reasons = (assessment: RiskAssessment): RiskReason[] => assessment.signals.map((signal) => signal.reason);
const SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15';
const HEADLESS = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36';
const AWS = { asn: 16509, asOrg: 'AMAZON-02', country: 'US', category: 'hosting', provider: 'amazon', asnSource: 'database' } as const;

describe('risk engine scenarios', () => {
  test('an ordinary first-time visitor is allowed without signals', () => {
    const assessment = assessRisk(riskContext(), policy);
    assert.equal(assessment.decision, 'ALLOW');
    assert.equal(assessment.score, 0);
    assert.deepEqual(reasons(assessment), []);
  });

  test('a legitimate returning paid visitor is allowed and earns trust', () => {
    const assessment = assessRisk(
      riskContext({
        identity: ESTABLISHED,
        paidArrival: true,
        observation: observation({ visitor: { sessionCount: 4, paidClicks5m: 1, paidClicks1h: 2, scriptVerifiedAt: START - 1000, interactionAt: START - 500 } }),
      }),
      policy,
    );
    assert.equal(assessment.decision, 'ALLOW');
    assert.ok(assessment.trustCredit > 0);
    assert.ok(reasons(assessment).includes('trust.established_visitor'));
  });

  test('many people behind one NAT stay allowed because limits scale with the established population', () => {
    const assessment = assessRisk(
      riskContext({
        observation: observation({
          address: { requestRate: 900, population: 60 },
          network: { requestRate: 1200, freshIdentities: 45, population: 60 },
        }),
      }),
      policy,
    );
    assert.equal(assessment.decision, 'ALLOW');
    assert.deepEqual(reasons(assessment), []);
  });

  test('rapid automated requests from one visitor are temporarily restricted, not blocked', () => {
    const assessment = assessRisk(riskContext({ identity: ESTABLISHED, observation: observation({ visitor: { requestRate: 420 } }) }), policy);
    assert.equal(assessment.decision, 'TEMPORARILY_RESTRICT');
    assert.ok(reasons(assessment).includes('behavior.visitor_velocity_extreme'));
  });

  test('repeated paid arrivals from one visitor escalate from monitoring to a challenge', () => {
    const mild = assessRisk(riskContext({ paidArrival: true, observation: observation({ visitor: { paidClicks5m: 4, paidClicks1h: 4 } }) }), policy);
    assert.equal(mild.decision, 'ALLOW_AND_MONITOR');
    const severe = assessRisk(riskContext({ paidArrival: true, observation: observation({ visitor: { paidClicks5m: 7, paidClicks1h: 9 } }) }), policy);
    assert.equal(severe.decision, 'CHALLENGE');
    assert.ok(reasons(severe).includes('paid.visitor_click_velocity_extreme'));
  });

  test('a paid-click flood from one network challenges fresh identities but not established visitors', () => {
    const network = { paidClicks5m: 12, paidClicks1h: 40, freshIdentities: 45, population: 0 };
    const fresh = assessRisk(riskContext({ paidArrival: true, observation: observation({ network }) }), policy);
    assert.equal(fresh.decision, 'CHALLENGE');
    assert.ok(reasons(fresh).includes('network.paid_velocity_extreme'));
    assert.ok(reasons(fresh).includes('network.identity_churn_extreme'));

    const regular = assessRisk(
      riskContext({ identity: ESTABLISHED, paidArrival: true, observation: observation({ network, visitor: { sessionCount: 5 } }) }),
      policy,
    );
    assert.ok(regular.decision === 'ALLOW' || regular.decision === 'ALLOW_AND_MONITOR');
    assert.ok(!reasons(regular).includes('network.identity_churn_extreme'));
  });

  test('cookie rotation alone is monitored and becomes a challenge with corroborating evidence', () => {
    const rotation = observation({ network: { freshIdentities: 60, population: 0 } });
    const alone = assessRisk(riskContext({ observation: rotation }), policy);
    assert.equal(alone.decision, 'ALLOW_AND_MONITOR');
    assert.ok(reasons(alone).includes('network.identity_churn_extreme'));

    const corroborated = assessRisk(
      riskContext({ observation: rotation, headers: { ...riskContext().headers, acceptLanguage: undefined, secFetchMode: undefined, accept: '*/*' } }),
      policy,
    );
    assert.equal(corroborated.decision, 'CHALLENGE');
  });

  test('a fake user agent is only a supporting signal', () => {
    const spoofed = assessRisk(riskContext({ ua: parseUserAgent(SAFARI) }), policy);
    assert.equal(spoofed.decision, 'ALLOW_AND_MONITOR');
    assert.ok(reasons(spoofed).includes('client.hints_brand_mismatch'));
  });

  test('datacenter traffic with automation indicators is challenged and restricted when it also moves fast', () => {
    const headless = assessRisk(riskContext({ ua: parseUserAgent(HEADLESS), network: AWS }), policy);
    assert.equal(headless.decision, 'CHALLENGE');
    const fast = assessRisk(
      riskContext({ ua: parseUserAgent(HEADLESS), network: AWS, identity: ESTABLISHED, observation: observation({ visitor: { requestRate: 120 } }) }),
      policy,
    );
    assert.equal(fast.decision, 'TEMPORARILY_RESTRICT');
  });

  test('a passed challenge settles moderate suspicion', () => {
    const suspicious = riskContext({
      network: AWS,
      ua: parseUserAgent(SAFARI),
      headers: { ...riskContext().headers, acceptLanguage: undefined },
    });
    assert.equal(assessRisk(suspicious, policy).decision, 'CHALLENGE');
    const cleared = assessRisk({ ...suspicious, clearanceValid: true }, policy);
    assert.equal(cleared.decision, 'ALLOW_AND_MONITOR');
    assert.ok(reasons(cleared).includes('trust.challenge_passed'));
  });

  test('severe abuse is restricted even with a passed challenge', () => {
    const assessment = assessRisk(
      riskContext({ identity: ESTABLISHED, clearanceValid: true, observation: observation({ visitor: { requestRate: 600, sessionCount: 4 } }) }),
      policy,
    );
    assert.equal(assessment.decision, 'TEMPORARILY_RESTRICT');
    assert.equal(assessment.trustCredit, 0);
  });

  test('a verified crawler is always allowed on pages', () => {
    const assessment = assessRisk(
      riskContext({
        ua: parseUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'),
        crawler: { status: 'verified', operator: 'google', via: 'ranges' },
        identity: undefined,
        observation: observation({ visitor: null, address: { requestRate: 2000 } }),
      }),
      policy,
    );
    assert.equal(assessment.decision, 'ALLOW');
  });

  test('a spoofed crawler user agent is challenged rather than trusted or blocked', () => {
    const assessment = assessRisk(
      riskContext({
        ua: parseUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'),
        crawler: { status: 'impersonation', operator: 'google', via: 'ranges' },
      }),
      policy,
    );
    assert.equal(assessment.decision, 'CHALLENGE');
    assert.ok(reasons(assessment).includes('client.crawler_impersonation'));
  });

  test('a shared IP with one abusive identity does not punish its other users', () => {
    const shared = observation({ address: { requestRate: 700, population: 40, strikes: 3 }, network: { freshIdentities: 30, population: 40 } });
    const neighbour = assessRisk(riskContext({ observation: shared }), policy);
    assert.equal(neighbour.decision, 'ALLOW');
    assert.ok(!reasons(neighbour).includes('behavior.repeat_offender_extreme'));
  });

  test('a VPN user on hosting infrastructure is only monitored', () => {
    const assessment = assessRisk(riskContext({ network: { ...AWS, provider: 'm247', asn: 9009 } }), policy);
    assert.equal(assessment.decision, 'ALLOW_AND_MONITOR');
  });

  test('origin bypass is a strong network signal when the edge is required', () => {
    const assessment = assessRisk(riskContext({ edgeRequired: true }), policy);
    assert.ok(reasons(assessment).includes('network.origin_bypass'));
  });

  test('direct API conversion attempts without the frontend are blocked', () => {
    const assessment = assessRisk(
      riskContext({
        routeClass: 'conversion',
        ua: parseUserAgent('python-requests/2.32.3'),
        headers: { accept: '*/*', acceptLanguage: undefined, secFetchMode: undefined, secFetchSite: undefined, secChUa: undefined, secChUaPlatform: undefined, origin: undefined },
        observation: observation({ visitor: { sessionDepth: 0 } }),
        action: { honeypot: false, formToken: 'missing', formAgeMs: undefined, originPresent: false, repeatedMessageContacts: 0 },
      }),
      policy,
    );
    assert.equal(assessment.decision, 'BLOCK');
  });

  test('a careful human conversion with a valid form token is allowed', () => {
    const assessment = assessRisk(
      riskContext({
        routeClass: 'conversion',
        identity: { origin: 'returning', cookieAgeSeconds: 600 },
        observation: observation({ visitor: { sessionDepth: 2, scriptVerifiedAt: START - 60_000, interactionAt: START - 10_000 } }),
        action: { honeypot: false, formToken: 'valid', formAgeMs: 45_000, originPresent: true, repeatedMessageContacts: 0 },
      }),
      policy,
    );
    assert.equal(assessment.decision, 'ALLOW');
  });

  test('reduced confidence is reported when signals are degraded', () => {
    const assessment = assessRisk(
      riskContext({ degraded: ['counters:local'], address: { ip: parseIp('198.51.100.1'), text: '198.51.100.1', via: 'direct', viaEdge: false, edgeVerified: false, edge: {} } }),
      policy,
    );
    assert.equal(assessment.confidence, 'reduced');
  });
});

describe('scoring', () => {
  const signal = (reason: RiskReason, family: RiskSignal['family'], severity: RiskSignal['severity'], points: number): RiskSignal => ({ reason, family, severity, points });

  test('applies diminishing returns inside a family and caps each family', () => {
    const scored = scoreSignals(
      [
        signal('client.hints_brand_mismatch', 'client', 'medium', 20),
        signal('client.accept_language_missing', 'client', 'low', 8),
        signal('client.navigation_accept_missing', 'client', 'medium', 15),
      ],
      policy,
      policy.thresholds,
    );
    assert.equal(scored.families.client, 20 + 7.5 + 2);
    assert.equal(scored.score, 30);
  });

  test('never blocks on a single family, even at maximum score', () => {
    const scored = scoreSignals(
      [signal('behavior.visitor_velocity_extreme', 'behavior', 'critical', 70), signal('behavior.form_token_replayed', 'behavior', 'critical', 60)],
      policy,
      policy.thresholds,
    );
    assert.equal(scored.score, 75);
    assert.equal(scored.decision, 'TEMPORARILY_RESTRICT');
  });

  test('requires a high-severity signal before restricting', () => {
    const scored = scoreSignals(
      [
        signal('network.hosting', 'network', 'medium', 22),
        signal('client.hints_brand_mismatch', 'client', 'medium', 20),
        signal('behavior.visitor_velocity', 'behavior', 'medium', 20),
        signal('behavior.mechanical_timing', 'behavior', 'medium', 20),
      ],
      policy,
      policy.thresholds,
    );
    assert.equal(scored.score, 72);
    assert.equal(scored.decision, 'CHALLENGE');
  });
});

describe('policy', () => {
  test('rejects thresholds that do not increase', () => {
    assert.throws(() => buildPolicy({ thresholds: { monitor: 50, challenge: 40 } }), /thresholds must increase/);
  });

  test('rejects unknown policy keys and merges valid overrides', () => {
    assert.throws(() => buildPolicy({ file: { points: { 'network.unknown': 5 } } }), /invalid risk policy/);
    const tuned = buildPolicy({ file: { points: { 'network.hosting': 10 }, limits: { visitorPaidClicks: { per5m: 5 } } } });
    assert.equal(tuned.points['network.hosting'], 10);
    assert.equal(tuned.limits.visitorPaidClicks.per5m, 5);
    assert.equal(tuned.limits.visitorPaidClicks.per1h, DEFAULT_POLICY.limits.visitorPaidClicks.per1h);
  });
});
