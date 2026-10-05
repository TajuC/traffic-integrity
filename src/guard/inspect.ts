import type { IncomingHttpHeaders } from 'node:http';
import { parseAttribution, type PaidAttribution } from '../attribution/attribution.ts';
import { hourOfDay } from '../intel/stats.ts';
import { readCookies, type CookieSpec } from '../identity/cookies.ts';
import type { VisitorIdentity } from '../identity/visitor.ts';
import { extractFeatures } from '../model/features.ts';
import { addressBucket, networkBucket } from '../net/ip.ts';
import { detectCohort } from '../observe/cohort.ts';
import { behaviorFeatures } from '../observe/behavior.ts';
import { analyzeConsistency, parseClientHints } from '../observe/consistency.ts';
import { behaviorSignature, deviceSignature, timingSignature } from '../observe/signatures.ts';
import { classifyRequest, type RequestShape } from '../request/classify.ts';
import { parseUserAgent } from '../request/user-agent.ts';
import type { HeaderFacts, RiskContext } from '../risk/context.ts';
import { assessRisk } from '../risk/engine.ts';
import type { RiskPolicy } from '../risk/policy.ts';
import { severityRank, type RiskAssessment } from '../risk/types.ts';
import type { Runtime } from '../runtime.ts';
import type { ObservedKind, Observation } from '../store/types.ts';

export interface InspectInput {
  readonly method: string;
  readonly path: string;
  readonly url: string;
  readonly headers: IncomingHttpHeaders;
  readonly socketAddress: string | undefined;
  readonly authenticated: boolean;
}

export interface Subject {
  readonly addressKey: string;
  readonly networkKey: string;
  readonly networkPrefix: string;
}

export interface StoredAttribution {
  readonly gclid?: string;
  readonly gbraid?: string;
  readonly wbraid?: string;
  readonly gadSource?: string;
  readonly gadCampaignId?: string;
  readonly landedAt: number;
}

export interface RequestIntegrity {
  readonly requestId: string;
  readonly now: number;
  readonly shape: RequestShape;
  readonly context: RiskContext;
  readonly identity: VisitorIdentity | undefined;
  readonly subject: Subject;
  readonly attribution: PaidAttribution | undefined;
  readonly assessment: RiskAssessment;
  readonly restrictedUntil: number | undefined;
}

export interface Inspection {
  readonly integrity: RequestIntegrity | undefined;
  readonly cookies: readonly CookieSpec[];
  readonly originBypass: boolean;
}

const SKIPPED: Inspection = Object.freeze({ integrity: undefined, cookies: Object.freeze([]), originBypass: false });

export async function inspectRequest(runtime: Runtime, input: InspectInput): Promise<Inspection> {
  const shape = classifyRequest(input.method, input.path, input.headers, runtime.routes);
  if (shape.routeClass === 'bypass' || shape.routeClass === 'asset') return SKIPPED;

  const { config, policy, keyring } = runtime;
  const started = performance.now();
  const now = runtime.clock();
  const nowSeconds = Math.floor(now / 1000);
  const address = runtime.addresses.resolve(input.socketAddress, input.headers);

  if (config.edge.mode === 'enforce' && !address.viaEdge) {
    runtime.events.emitOnce(`bypass:${address.text}`, 60_000, 'origin_bypass', { ip: address.text, via: address.via, path: input.path }, 'warn');
    return { integrity: undefined, cookies: [], originBypass: true };
  }

  const ua = parseUserAgent(single(input.headers['user-agent']));
  const network = runtime.intel.profile(address);
  const crawler = runtime.crawlers.verify(ua.crawler, address.ip, address.text, address.edge);
  const automated = crawler.status === 'verified' || ua.preview !== undefined;

  let identity: VisitorIdentity | undefined;
  let cookies: readonly CookieSpec[] = [];
  let clearanceToken: string | undefined;
  if (!automated) {
    const names = runtime.cookieNames;
    const jar = readCookies(single(input.headers.cookie), [names.visitor, names.session, names.clearance]);
    const resolved = runtime.identities.resolve({ visitorCookie: jar.get(names.visitor), sessionCookie: jar.get(names.session) }, nowSeconds);
    identity = resolved.identity;
    cookies = resolved.cookies;
    clearanceToken = jar.get(names.clearance);
  }

  const subject: Subject = address.ip
    ? {
        addressKey: keyring.digest('subject', `a:${addressBucket(address.ip)}`),
        networkKey: keyring.digest('subject', `n:${networkBucket(address.ip)}`),
        networkPrefix: networkBucket(address.ip),
      }
    : { addressKey: 'unknown', networkKey: 'unknown', networkPrefix: 'unknown' };

  const parsed = shape.routeClass === 'page' && shape.navigation ? parseAttribution(searchParams(input.url)) : undefined;
  const paidArrival = identity !== undefined && parsed?.attribution !== undefined && !shape.prefetch;
  const attribution = paidArrival ? parsed?.attribution : undefined;
  const cookieAgeSeconds = identity ? Math.max(0, nowSeconds - identity.issuedAt) : 0;
  const established = identity?.origin === 'returning' && cookieAgeSeconds >= policy.established.populationCookieAgeSeconds;

  const cachedRestriction =
    crawler.status === 'verified'
      ? undefined
      : (runtime.restrictions.until(subject.addressKey, now) ?? (identity ? runtime.restrictions.until(`v:${identity.visitorId}`, now) : undefined));

  const degraded: string[] = [];
  let observation: Observation | undefined;
  if (cachedRestriction === undefined) {
    const clickMember =
      attribution && identity
        ? keyring.digest('subject', `c:${attribution.primary?.value ?? `${identity.visitorId}:${identity.sessionId}`}`)
        : undefined;
    try {
      observation = await runtime.store.observe({
        now,
        kind: observedKind(shape),
        sessionIdleMs: policy.sessionIdleSeconds * 1000,
        visitor: identity ? { id: identity.visitorId, sessionId: identity.sessionId, fresh: identity.origin !== 'returning', established } : undefined,
        addressKey: subject.addressKey,
        networkKey: subject.networkKey,
        asn: network.asn,
        paidClick: clickMember,
        attribution: attribution ? JSON.stringify(storedAttribution(attribution, now)) : undefined,
      });
    } catch (error) {
      degraded.push('counters');
      runtime.events.emitOnce('observe-failure', 30_000, 'security_degraded', { component: 'observe', error: String(error) }, 'warn');
    }
  }
  if (observation?.source === 'memory' && config.redis) degraded.push('counters:local');
  if (network.asnSource === 'none') degraded.push('asn');

  const clearanceValid =
    identity !== undefined &&
    runtime.clearance.isValid(clearanceToken, identity.visitorId, nowSeconds) &&
    (observation?.source !== 'redis' || (observation.visitor?.clearanceUntil ?? 0) >= now);

  const hints = parseClientHints({
    secChUa: single(input.headers['sec-ch-ua']),
    secChUaPlatform: single(input.headers['sec-ch-ua-platform']),
    secChUaMobile: single(input.headers['sec-ch-ua-mobile']),
    secChUaArch: single(input.headers['sec-ch-ua-arch']),
    secChUaBitness: single(input.headers['sec-ch-ua-bitness']),
  });
  const transport = address.edgeVerified
    ? {
        tls: address.edge.tls,
        ja3: address.edge.ja3,
        ja4: address.edge.ja4,
        http2: address.edge.http2,
        headerOrder: address.edge.headerOrder,
        protocol: address.edge.protocol,
        alpn: address.edge.alpn,
        cipher: address.edge.cipher,
      }
    : undefined;
  const snapshot = runtime.snapshots.get(identity?.visitorId, now);
  const consistency = analyzeConsistency({
    ua,
    hints,
    ...(snapshot ? { snapshot } : {}),
    headerLanguage: single(input.headers['accept-language']),
    ...(transport ? { transport } : {}),
    secure: config.origin.secure,
  });
  const features = behaviorFeatures(observation, {
    pointerCv: snapshot?.pointerCv,
    keyCv: snapshot?.keyCv,
    scrollCv: snapshot?.scrollCv,
    dwellMs: snapshot?.dwellMs,
  });
  const campaignId = attribution?.gadCampaignId ?? attribution?.utm.utm_campaign;
  const intel = runtime.intelligence.observe(
    {
      now,
      visitorId: identity?.visitorId,
      addressKey: subject.addressKey,
      networkKey: subject.networkKey,
      asn: network.asn,
      clickHash: attribution && identity ? keyring.digest('subject', `c:${attribution.primary?.value ?? `${identity.visitorId}:${identity.sessionId}`}`) : undefined,
      campaign: campaignId,
      landing: input.path.slice(0, 128),
      behaviorSig: behaviorSignature(features),
      deviceSig: snapshot ? deviceSignature(snapshot, ua.family, ua.os, ua.major) : undefined,
      timingSig: timingSignature(features),
    },
    {
      campaignClicks: observation?.network.paidClicks5m,
      hour: hourOfDay(now),
    },
  );

  const context: RiskContext = {
    now,
    routeClass: shape.routeClass,
    secure: config.origin.secure,
    headers: headerFacts(input.headers),
    ua,
    crawler,
    address,
    network,
    edgeRequired: config.edge.mode !== 'off',
    identity: identity ? { origin: identity.origin, cookieAgeSeconds } : undefined,
    paidArrival,
    malformedAttribution: parsed?.malformed ?? [],
    observation,
    clearanceValid,
    authenticated: input.authenticated,
    action: undefined,
    degraded,
    snapshot,
    consistency,
    clusters: intel.clusters,
    baselines: intel.baselines,
    ...(transport ? { transport } : {}),
    campaignId,
    landingPath: input.path.slice(0, 512),
    cohort: undefined,
  };
  const scoredContext = { ...context, cohort: detectCohort(context) };
  const heuristic = assessRisk(scoredContext, policy);
  const vector = extractFeatures(scoredContext, heuristic);
  const modelScore = runtime.model.score(vector);
  const shadowDecision = runtime.shadowPolicy ? assessRisk(scoredContext, runtime.shadowPolicy).decision : undefined;
  const assessment: RiskAssessment = {
    ...heuristic,
    modelVersion: modelScore?.version,
    fraudProbability: modelScore?.probability,
    shadowDecision,
  };

  const restrictedUntil = crawler.status === 'verified' ? undefined : (cachedRestriction ?? activeRestriction(observation, now, policy));
  if (restrictedUntil !== undefined && cachedRestriction === undefined) {
    if (identity && (observation?.visitor?.restrictedUntil ?? 0) > now) runtime.restrictions.set(`v:${identity.visitorId}`, restrictedUntil);
    else runtime.restrictions.set(subject.addressKey, restrictedUntil);
  }

  const integrity: RequestIntegrity = { requestId: assessment.id, now, shape, context: scoredContext, identity, subject, attribution, assessment, restrictedUntil };
  record(runtime, integrity, input, performance.now() - started, cachedRestriction !== undefined);
  return { integrity, cookies, originBypass: false };
}

export function assessAction(runtime: Runtime, integrity: RequestIntegrity, action: RiskContext['action']): RiskAssessment {
  return assessRisk({ ...integrity.context, routeClass: 'conversion', action }, runtime.policy);
}

export function correlation(integrity: RequestIntegrity): Record<string, unknown> {
  const { context, identity, subject } = integrity;
  return {
    requestId: integrity.requestId,
    ray: context.address.ray,
    visitorId: identity?.visitorId,
    sessionId: identity?.sessionId,
    identity: identity?.origin ?? 'none',
    ipHash: subject.addressKey,
    networkPrefix: subject.networkPrefix,
    asn: context.network.asn,
    country: context.network.country,
    networkCategory: context.network.category,
  };
}

export function readStoredAttribution(integrity: RequestIntegrity, maxAgeMs: number): StoredAttribution | undefined {
  if (integrity.attribution) return storedAttribution(integrity.attribution, integrity.now);
  const raw = integrity.context.observation?.visitor?.attribution;
  if (!raw) return undefined;
  try {
    const value = JSON.parse(raw) as Partial<StoredAttribution>;
    if (typeof value.landedAt !== 'number' || integrity.now - value.landedAt > maxAgeMs) return undefined;
    return value as StoredAttribution;
  } catch {
    return undefined;
  }
}

function record(runtime: Runtime, integrity: RequestIntegrity, input: InspectInput, elapsedMs: number, alreadyRestricted: boolean): void {
  const { metrics, events, config } = runtime;
  const { assessment, context, shape } = integrity;
  const enforced = config.enforcement === 'enforce' ? 'yes' : 'no';
  metrics.assessments.inc({ route: shape.routeClass, decision: alreadyRestricted ? 'RESTRICTED' : assessment.decision, enforced });
  metrics.assessmentSeconds.observe({ route: shape.routeClass }, elapsedMs / 1000);
  if (!alreadyRestricted) for (const signal of assessment.signals) metrics.signals.inc({ reason: signal.reason });
  if (enforced === 'no' && (assessment.decision === 'BLOCK' || assessment.decision === 'CHALLENGE' || assessment.decision === 'TEMPORARILY_RESTRICT')) {
    metrics.shadowDecisions.inc({ would: assessment.decision === 'BLOCK' ? 'block' : assessment.decision === 'CHALLENGE' ? 'challenge' : 'restrict' });
  }
  for (const hit of context.clusters ?? []) metrics.clusters.inc({ kind: hit.kind });
  if (assessment.fraudProbability !== undefined) metrics.modelScores.observe({ version: assessment.modelVersion ?? 'none' }, assessment.fraudProbability);
  runtime.eventsLog.record({
    id: assessment.id,
    createdAt: new Date(integrity.now),
    visitorId: integrity.identity?.visitorId,
    sessionId: integrity.identity?.sessionId,
    ipHash: integrity.subject.addressKey,
    networkPrefix: integrity.subject.networkPrefix,
    asn: context.network.asn,
    campaignId: integrity.attribution?.gadCampaignId ?? integrity.attribution?.utm.utm_campaign,
    route: shape.routeClass,
    paid: context.paidArrival,
    score: assessment.score,
    decision: alreadyRestricted ? 'TEMPORARILY_RESTRICT' : assessment.decision,
    shadowDecision: assessment.shadowDecision,
    reasons: assessment.signals.filter((signal) => signal.family !== 'trust').map((signal) => signal.reason),
    cohort: assessment.cohort,
    policyVersion: assessment.policyVersion,
    detectorVersion: assessment.detectorVersion,
    modelVersion: assessment.modelVersion,
    fraudProbability: assessment.fraudProbability,
    clusterKind: context.clusters?.[0]?.kind,
  });

  const summary = {
    ...correlation(integrity),
    route: shape.routeClass,
    method: input.method,
    path: input.path,
    decision: assessment.decision,
    score: assessment.score,
    enforced: enforced === 'yes',
    reasons: assessment.signals.map((signal) => signal.reason),
    families: assessment.families,
    trustCredit: assessment.trustCredit,
    confidence: assessment.confidence,
    degraded: assessment.degraded,
    browser: context.ua.family,
    browserMajor: context.ua.major,
    os: context.ua.os,
    device: context.ua.device,
    crawler: context.crawler.status,
    edgeBotScore: context.address.edge.botScore,
    paid: context.paidArrival,
    campaign: integrity.attribution?.gadCampaignId ?? integrity.attribution?.utm.utm_campaign,
  };

  const detail = { ...summary, signals: assessment.signals, alreadyRestricted };
  if (context.paidArrival || shape.routeClass === 'conversion') {
    events.emit('risk_assessment', detail);
  } else if (alreadyRestricted) {
    return;
  } else if (assessment.decision !== 'ALLOW') {
    const subjectKey = integrity.identity?.visitorId ?? integrity.subject.addressKey;
    events.emitOnce(`assess:${subjectKey}:${assessment.decision}:${shape.routeClass}`, 60_000, 'risk_assessment', detail);
  } else if (Math.random() < config.logging.assessmentSampleRate) {
    events.emit('risk_assessment', detail);
  }

  if (context.crawler.status === 'impersonation') {
    events.emitOnce(`crawler:${context.address.text}`, 600_000, 'crawler_impersonation', { ...summary, operator: context.crawler.operator }, 'warn');
  }
  const networkAlarm = assessment.signals.find((signal) => signal.family === 'network' && severityRank(signal.severity) >= 2 && signal.reason !== 'network.origin_bypass');
  if (networkAlarm) {
    events.emitOnce(`network:${integrity.subject.networkKey}`, 600_000, 'suspicious_network_activity', { ...summary, trigger: networkAlarm.reason, evidence: networkAlarm.evidence }, 'warn');
  }
  if (context.edgeRequired && !context.address.viaEdge) {
    events.emitOnce(`bypass:${context.address.text}`, 600_000, 'origin_bypass', { ...summary, ip: context.address.text }, 'warn');
  }

  if (context.paidArrival && integrity.attribution && integrity.identity) {
    const decision = alreadyRestricted ? 'TEMPORARILY_RESTRICT' : assessment.decision;
    const riskScore = alreadyRestricted ? Math.max(assessment.score, runtime.policy.thresholds.restrict) : assessment.score;
    metrics.paidArrivals.inc({ category: context.network.category, decision });
    events.emit('paid_visit', { ...summary, decision, score: riskScore });
    const attribution = integrity.attribution;
    const suspicious = decision !== 'ALLOW' && decision !== 'ALLOW_AND_MONITOR';
    runtime.paidVisits.record({
      id: assessment.id,
      landedAt: new Date(integrity.now),
      visitorId: integrity.identity.visitorId,
      sessionId: integrity.identity.sessionId,
      clickHash: runtime.keyring.digest('subject', `c:${attribution.primary?.value ?? `${integrity.identity.visitorId}:${integrity.identity.sessionId}`}`),
      gclid: attribution.clickIds.gclid,
      gbraid: attribution.clickIds.gbraid,
      wbraid: attribution.clickIds.wbraid,
      gadSource: attribution.gadSource,
      gadCampaignId: attribution.gadCampaignId,
      utmSource: attribution.utm.utm_source,
      utmMedium: attribution.utm.utm_medium,
      utmCampaign: attribution.utm.utm_campaign,
      utmTerm: attribution.utm.utm_term,
      utmContent: attribution.utm.utm_content,
      landingPath: input.path.slice(0, 512),
      referrerHost: referrerHost(single(input.headers.referer)),
      ipHash: integrity.subject.addressKey,
      networkPrefix: integrity.subject.networkPrefix,
      ipAddress: suspicious || riskScore >= runtime.policy.thresholds.monitor ? context.address.text : undefined,
      asn: context.network.asn,
      asOrg: context.network.asOrg,
      country: context.network.country,
      networkCategory: context.network.category,
      browserFamily: context.ua.family,
      browserMajor: context.ua.major,
      osFamily: context.ua.os,
      deviceType: context.ua.device,
      edgeBotScore: context.address.edge.botScore,
      identity: integrity.identity.origin,
      riskScore,
      decision,
      reasons: assessment.signals.filter((signal) => signal.family !== 'trust').map((signal) => signal.reason),
      enforced: enforced === 'yes',
    });
  }
}

function activeRestriction(observation: Observation | undefined, now: number, policy: RiskPolicy): number | undefined {
  if (!observation) return undefined;
  const visitor = observation.visitor?.restrictedUntil ?? 0;
  const address = observation.address.population <= policy.restriction.maxSharedPopulation ? (observation.address.restrictedUntil ?? 0) : 0;
  const until = Math.max(visitor, address);
  return until > now ? until : undefined;
}

function observedKind(shape: RequestShape): ObservedKind {
  if (shape.prefetch || shape.routeClass === 'internal') return 'internal';
  if (shape.routeClass === 'page') return shape.navigation ? 'page' : 'api';
  if (shape.routeClass === 'conversion') return 'conversion';
  if (shape.routeClass === 'action') return 'action';
  return 'api';
}

function storedAttribution(attribution: PaidAttribution, now: number): StoredAttribution {
  return {
    ...(attribution.clickIds.gclid ? { gclid: attribution.clickIds.gclid } : {}),
    ...(attribution.clickIds.gbraid ? { gbraid: attribution.clickIds.gbraid } : {}),
    ...(attribution.clickIds.wbraid ? { wbraid: attribution.clickIds.wbraid } : {}),
    ...(attribution.gadSource ? { gadSource: attribution.gadSource } : {}),
    ...(attribution.gadCampaignId ? { gadCampaignId: attribution.gadCampaignId } : {}),
    landedAt: now,
  };
}

function headerFacts(headers: IncomingHttpHeaders): HeaderFacts {
  return {
    accept: single(headers.accept),
    acceptLanguage: single(headers['accept-language']),
    secFetchMode: single(headers['sec-fetch-mode']),
    secFetchSite: single(headers['sec-fetch-site']),
    secChUa: single(headers['sec-ch-ua']),
    secChUaPlatform: single(headers['sec-ch-ua-platform']),
    secChUaMobile: single(headers['sec-ch-ua-mobile']),
    secChUaArch: single(headers['sec-ch-ua-arch']),
    secChUaBitness: single(headers['sec-ch-ua-bitness']),
    origin: single(headers.origin),
  };
}

function searchParams(url: string): URLSearchParams {
  const query = url.indexOf('?');
  if (query < 0) return new URLSearchParams();
  const hash = url.indexOf('#', query);
  return new URLSearchParams(url.slice(query + 1, hash < 0 ? undefined : hash));
}

function referrerHost(referer: string | undefined): string | undefined {
  if (!referer) return undefined;
  try {
    return new URL(referer).hostname.slice(0, 255) || undefined;
  } catch {
    return undefined;
  }
}

function single(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
