import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import express, { Router, type Request, type RequestHandler, type Response } from 'express';
import { z } from 'zod';
import { apiConversions, googleAdsCsv, googleAdsExclusion } from '../conversion/export.ts';
import { decideConversion, exclusionCandidates, markExported, qualifiedForExport, trafficSummary } from '../conversion/repository.ts';
import { randomId, safeEqual } from '../crypto/keyring.ts';
import { correlation, type RequestIntegrity } from '../guard/inspect.ts';
import { serializeCookie } from '../identity/cookies.ts';
import { storedEvidenceBundle } from '../ads/evidence.ts';
import { campaignRecommendation } from '../ads/recommendations.ts';
import { acceptLabel } from '../feedback/labels.ts';
import { assessmentById, campaignAbuse, clusterSummary, insertLabel, recentAssessments } from '../operator/queries.ts';
import { AUTOMATION_FLAGS } from '../risk/context.ts';
import type { Runtime } from '../runtime.ts';
import { cloudflareListPayload, proposeEdgeAction } from '../upstream/lists.ts';
import { noStore, originState } from './responses.ts';

const DAY_MS = 86_400_000;
const BEACON_NONCE_TTL_MS = 30 * 60_000;
const DEGRADED_CLEARANCE_SECONDS = 300;
const SCRIPTS = ['beacon.js', 'challenge.js', 'forms.js'] as const;

const counter = z.number().int().min(0).max(1_000_000);
const beaconSchema = z.object({
  nonce: z.string().max(300),
  phase: z.enum(['load', 'leave']),
  automation: z
    .object({
      webdriver: z.boolean(),
      headless: z.boolean(),
      languages: z.number().int().min(0).max(100),
      phantom: z.boolean(),
      selenium: z.boolean(),
      playwright: z.boolean(),
      viewport: z.tuple([z.number().int().min(0).max(100_000), z.number().int().min(0).max(100_000)]),
      chromeRuntime: z.boolean(),
      safariPush: z.boolean(),
      installTrigger: z.boolean(),
    })
    .partial()
    .optional(),
  snapshot: z
    .object({
      platform: z.string().max(64),
      vendor: z.string().max(64),
      languages: z.array(z.string().max(16)).max(12),
      timezone: z.string().max(64),
      locale: z.string().max(32),
      hardwareConcurrency: z.number().int().min(0).max(256),
      deviceMemory: z.number().min(0).max(128),
      maxTouchPoints: z.number().int().min(0).max(64),
      touch: z.boolean(),
      pointerFine: z.boolean(),
      dpr: z.number().min(0).max(8),
      screen: z.tuple([z.number().int().min(0).max(100_000), z.number().int().min(0).max(100_000)]),
      viewport: z.tuple([z.number().int().min(0).max(100_000), z.number().int().min(0).max(100_000)]),
      cookieEnabled: z.boolean(),
      storage: z.boolean(),
      pointerCv: z.number().min(0).max(10),
      keyCv: z.number().min(0).max(10),
      scrollCv: z.number().min(0).max(10),
      dwellMs: z.number().int().min(0).max(DAY_MS),
    })
    .partial()
    .optional(),
  interaction: z
    .object({
      pointer: counter,
      keys: counter,
      scroll: counter,
      touch: counter,
      firstMs: z.number().int().min(0).max(DAY_MS).nullable(),
      dwellMs: z.number().int().min(0).max(DAY_MS),
    })
    .partial()
    .optional(),
});

const challengeSchema = z.object({ token: z.string().min(1).max(2048), nonce: z.string().min(1).max(300) });
const decisionSchema = z.object({ reason: z.string().trim().max(200).optional() });

export function createInternalRouter(runtime: Runtime, integrityOf: (req: Request) => RequestIntegrity | undefined): Router {
  const { config, keyring, store, events, metrics } = runtime;
  const router = Router();

  for (const name of SCRIPTS) {
    const body = readFileSync(new URL(`../../public/ti/${name}`, import.meta.url));
    const etag = `"${createHash('sha256').update(body).digest('base64url').slice(0, 16)}"`;
    router.get(`/${name}`, (req, res) => {
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.setHeader('ETag', etag);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      if (req.headers['if-none-match'] === etag) {
        res.status(304).end();
        return;
      }
      res.type('text/javascript').send(body);
    });
  }

  router.get('/nonce', (req, res) => {
    noStore(res);
    const identity = integrityOf(req)?.identity;
    if (!identity) {
      res.status(204).end();
      return;
    }
    const now = runtime.clock();
    res.json({ nonce: keyring.seal('beacon', [randomId(12), identity.visitorId, identity.sessionId, now.toString(36)]) });
  });

  const recordBeacon = async (req: Request): Promise<void> => {
    const integrity = integrityOf(req);
    const identity = integrity?.identity;
    if (!identity || originState(req, config.origin.allowed) !== 'match' || typeof req.body !== 'string') return;
    const parsed = beaconSchema.safeParse(safeJson(req.body));
    if (!parsed.success) return;
    const fields = keyring.open('beacon', parsed.data.nonce, 4);
    if (!fields) return;
    const [id, visitorId, sessionId, issued] = fields as [string, string, string, string];
    const now = runtime.clock();
    if (visitorId !== identity.visitorId || sessionId !== identity.sessionId || now - parseInt(issued, 36) > BEACON_NONCE_TTL_MS) return;
    if (!(await store.claimOnce(`bn:${id}:${parsed.data.phase}`, BEACON_NONCE_TTL_MS))) return;

    const interaction = parsed.data.interaction;
    const interacted = Boolean(interaction && ((interaction.pointer ?? 0) + (interaction.keys ?? 0) + (interaction.touch ?? 0) + (interaction.scroll ?? 0) > 0));
    if (parsed.data.snapshot) {
      runtime.snapshots.set(identity.visitorId, {
        ...parsed.data.snapshot,
        webdriver: parsed.data.automation?.webdriver,
        headless: parsed.data.automation?.headless,
        selenium: parsed.data.automation?.selenium,
        playwright: parsed.data.automation?.playwright,
        phantom: parsed.data.automation?.phantom,
        chromeRuntime: parsed.data.automation?.chromeRuntime,
        safariPush: parsed.data.automation?.safariPush,
        installTrigger: parsed.data.automation?.installTrigger,
        dwellMs: parsed.data.snapshot.dwellMs ?? parsed.data.interaction?.dwellMs,
      }, now);
    }
    await store.patchVisitor(
      identity.visitorId,
      {
        ...(parsed.data.phase === 'load' ? { scriptVerifiedAt: now, automationFlags: automationFlags(parsed.data.automation) } : {}),
        ...(interacted ? { interactionAt: now } : {}),
      },
      now,
    );
  };

  router.post('/beacon', express.text({ type: ['text/plain', 'application/json'], limit: '8kb' }), (req, res) => {
    res.status(204).end();
    recordBeacon(req).catch((error: unknown) => runtime.logger.warn({ err: error }, 'beacon processing failed'));
  });

  router.post('/challenge', express.json({ limit: '4kb' }), async (req, res) => {
    noStore(res);
    const integrity = integrityOf(req);
    const identity = integrity?.identity;
    const turnstile = runtime.turnstile;
    const parsed = challengeSchema.safeParse(req.body);
    if (!integrity || !identity || !turnstile || !parsed.success || originState(req, config.origin.allowed) !== 'match') {
      res.status(403).json({ error: 'verification_failed' });
      return;
    }
    const now = runtime.clock();
    const nowSeconds = Math.floor(now / 1000);
    const nonce = runtime.clearance.openChallengeNonce(parsed.data.nonce, identity.visitorId, nowSeconds);
    if (!nonce || !(await store.claimOnce(`cn:${nonce.id}`, 15 * 60_000))) {
      events.emit('challenge_failure', { ...correlation(integrity), route: 'clearance', reason: 'nonce' }, 'warn');
      res.status(403).json({ error: 'verification_failed' });
      return;
    }

    const started = performance.now();
    const result = await turnstile.verify({
      token: parsed.data.token,
      remoteIp: integrity.context.address.ip ? integrity.context.address.text : undefined,
      action: 'clearance',
      cdata: nonce.cdata,
    });
    metrics.turnstileSeconds.observe({ outcome: result.status }, (performance.now() - started) / 1000);
    metrics.challenges.inc({ kind: 'clearance', outcome: result.status });

    if (result.status === 'failed') {
      events.emit('challenge_failure', { ...correlation(integrity), route: 'clearance', reason: result.reason }, 'warn');
      res.status(403).json({ error: 'verification_failed' });
      return;
    }
    const degraded = result.status === 'unavailable';
    const issued = degraded
      ? runtime.clearance.issue(identity.visitorId, nowSeconds, DEGRADED_CLEARANCE_SECONDS)
      : runtime.clearance.issue(identity.visitorId, nowSeconds);
    await store.patchVisitor(identity.visitorId, { clearanceUntil: issued.untilMs }, now);
    res.append('Set-Cookie', serializeCookie(issued.cookie, config.origin.secure));
    events.emit(
      degraded ? 'challenge_failure' : 'challenge_success',
      { ...correlation(integrity), route: 'clearance', ...(degraded ? { reason: 'unavailable', failOpenSeconds: DEGRADED_CLEARANCE_SECONDS } : {}) },
      degraded ? 'warn' : 'info',
    );
    res.status(204).end();
  });

  router.get('/form', (req, res) => {
    noStore(res);
    const identity = integrityOf(req)?.identity;
    const formId = typeof req.query.form === 'string' ? req.query.form : '';
    if (!identity || !config.conversion.formIds.includes(formId)) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    const issued = runtime.formTokens.issue(identity.visitorId, formId, runtime.clock());
    res.json({
      token: issued.token,
      honeypot: config.conversion.honeypotField,
      challenge: config.conversion.challenge,
      turnstile: config.turnstile ? { siteKey: config.turnstile.siteKey, action: `lead_${formId}`, cdata: issued.cdata } : null,
    });
  });

  const bearer: RequestHandler = (req, res, next) => {
    noStore(res);
    const token = config.admin?.token;
    if (!token) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    const header = req.headers.authorization ?? '';
    if (!header.startsWith('Bearer ') || !safeEqual(header.slice(7).trim(), token)) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    next();
  };

  const basic: RequestHandler = (req, res, next) => {
    noStore(res);
    const auth = config.conversion.exportAuth;
    if (!auth) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    const header = req.headers.authorization ?? '';
    const decoded = header.startsWith('Basic ') ? Buffer.from(header.slice(6).trim(), 'base64').toString('utf8') : '';
    const split = decoded.indexOf(':');
    const ok = split > 0 && safeEqual(decoded.slice(0, split), auth.username) && safeEqual(decoded.slice(split + 1), auth.password);
    if (!ok) {
      res.setHeader('WWW-Authenticate', 'Basic realm="conversions", charset="UTF-8"');
      res.status(401).end();
      return;
    }
    next();
  };

  const database = (res: Response): NonNullable<Runtime['db']> | undefined => {
    if (runtime.db) return runtime.db;
    res.status(503).json({ error: 'database_unavailable' });
    return undefined;
  };

  router.get('/metrics', bearer, async (_req, res) => {
    res.type(metrics.registry.contentType).send(await metrics.registry.metrics());
  });

  router.get('/admin/summary.json', bearer, async (req, res) => {
    const db = database(res);
    if (!db) return;
    const hours = clampNumber(req.query.hours, 1, 24 * 90, 24);
    res.json({ since: new Date(runtime.clock() - hours * 3_600_000).toISOString(), ...(await trafficSummary(db, new Date(runtime.clock() - hours * 3_600_000))) });
  });

  router.get('/admin/conversions.json', bearer, async (req, res) => {
    const db = database(res);
    if (!db) return;
    const days = clampNumber(req.query.days, 1, 90, 90);
    const rows = await qualifiedForExport(db, new Date(runtime.clock() - days * DAY_MS));
    res.json({ conversions: apiConversions(rows, config.conversion.timezone) });
  });

  router.get('/admin/conversions.csv', basic, async (_req, res) => {
    const db = database(res);
    if (!db) return;
    const now = runtime.clock();
    const rows = await qualifiedForExport(db, new Date(now - 90 * DAY_MS));
    const { csv, exported } = googleAdsCsv(rows, config.conversion.timezone);
    await markExported(db, exported, new Date(now));
    res.type('text/csv').setHeader('Content-Disposition', 'attachment; filename="conversions.csv"');
    res.send(csv);
  });

  router.post('/admin/conversions/:id/:decision', bearer, express.json({ limit: '2kb' }), async (req, res) => {
    const db = database(res);
    if (!db) return;
    const id = String(req.params.id);
    const decision = req.params.decision === 'qualify' ? 'qualified' : req.params.decision === 'disqualify' ? 'disqualified' : undefined;
    const body = decisionSchema.safeParse(req.body ?? {});
    if (!decision || !/^[0-9a-f-]{36}$/i.test(id) || !body.success) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    const updated = await decideConversion(db, id, decision, 'admin', body.data.reason, new Date(runtime.clock()));
    if (!updated) {
      res.status(409).json({ error: 'not_applicable' });
      return;
    }
    events.emit(decision === 'qualified' ? 'conversion_qualified' : 'conversion_disqualified', {
      conversionId: id,
      by: 'admin',
      reason: body.data.reason,
      requiresAdjustment: decision === 'disqualified' && updated.exported,
    });
    res.json({ id, status: decision, requiresAdjustment: decision === 'disqualified' && updated.exported });
  });

  router.get('/admin/exclusions.json', bearer, async (req, res) => {
    const db = database(res);
    if (!db) return;
    const days = clampNumber(req.query.days, 1, 90, 30);
    const minScore = clampNumber(req.query.minScore, 0, 100, runtime.policy.thresholds.challenge);
    const minVisits = clampNumber(req.query.minVisits, 1, 10_000, 3);
    const candidates = await exclusionCandidates(db, new Date(runtime.clock() - days * DAY_MS), minScore, minVisits);
    res.json({ candidates: candidates.map((candidate) => ({ ...candidate, googleAds: googleAdsExclusion(candidate) })) });
  });

  router.get('/admin/sessions.json', bearer, async (req, res) => {
    const db = database(res);
    if (!db) return;
    await runtime.eventsLog.flush();
    const hours = clampNumber(req.query.hours, 1, 24 * 90, 24);
    const minScore = clampNumber(req.query.minScore, 0, 100, 20);
    res.json({ sessions: await recentAssessments(db, new Date(runtime.clock() - hours * 3_600_000), { minScore, paid: req.query.paid === 'true' }) });
  });

  router.get('/admin/evidence/:id.json', bearer, async (req, res) => {
    const db = database(res);
    if (!db) return;
    await runtime.eventsLog.flush();
    const id = String(req.params.id ?? '');
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    const row = await assessmentById(db, id);
    if (!row) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    res.json(
      storedEvidenceBundle({
        id: String(row.id),
        created_at: row.created_at as Date | string,
        visitor_id: (row.visitor_id as string | null) ?? null,
        session_id: (row.session_id as string | null) ?? null,
        campaign_id: (row.campaign_id as string | null) ?? null,
        score: Number(row.score),
        decision: String(row.decision),
        reasons: (row.reasons as string[] | null) ?? [],
        cohort: (row.cohort as string | null) ?? null,
        cluster_kind: (row.cluster_kind as string | null) ?? null,
        fraud_probability: (row.fraud_probability as number | null) ?? null,
        policy_version: String(row.policy_version),
        detector_version: String(row.detector_version),
        model_version: (row.model_version as string | null) ?? null,
        paid: Boolean(row.paid),
        network_prefix: String(row.network_prefix),
        asn: (row.asn as number | string | null) ?? null,
      }),
    );
  });

  router.get('/admin/campaigns.json', bearer, async (req, res) => {
    const db = database(res);
    if (!db) return;
    await runtime.eventsLog.flush();
    const hours = clampNumber(req.query.hours, 1, 24 * 90, 24);
    const rows = await campaignAbuse(db, new Date(runtime.clock() - hours * 3_600_000));
    res.json({
      campaigns: rows.map((row) => ({
        ...row,
        recommendation: campaignRecommendation({
          campaign: String(row.campaign),
          visits: Number(row.visits),
          suspicious: Number(row.suspicious),
          cpcUsd: config.ads.cpcUsd,
        }),
      })),
    });
  });

  router.get('/admin/clusters.json', bearer, async (req, res) => {
    const db = database(res);
    if (!db) return;
    await runtime.eventsLog.flush();
    const hours = clampNumber(req.query.hours, 1, 24 * 90, 24);
    res.json({ clusters: await clusterSummary(db, new Date(runtime.clock() - hours * 3_600_000)) });
  });

  router.get('/admin/edge-lists.json', bearer, (_req, res) => {
    const proposed = proposeEdgeAction({
      decision: 'TEMPORARILY_RESTRICT',
      numericConfidence: 0.93,
      clusterSize: 12,
      personalAddress: true,
      ipHash: 'preview',
      reasons: ['graph.behavior_cluster'],
    });
    res.json({
      note: 'Lists are short-lived proposals. Automatic edge blocks require high confidence and are never applied from this endpoint.',
      lists: proposed ? cloudflareListPayload([proposed]) : [],
    });
  });

  const labelSchema = z.object({
    subjectType: z.enum(['assessment', 'visitor', 'lead', 'conversion', 'cluster']),
    subjectId: z.string().min(1).max(80),
    label: z.enum([
      'legitimate',
      'suspicious',
      'fraud',
      'qualified_conversion',
      'unqualified_conversion',
      'duplicate',
      'spam',
      'customer',
      'rejected_lead',
      'chargeback',
    ]),
    source: z.enum(['operator', 'crm']).default('operator'),
    confidence: z.number().min(0).max(1).default(1),
    provenance: z.string().min(3).max(200),
    notes: z.string().max(500).optional(),
  });

  router.post('/admin/labels', bearer, express.json({ limit: '4kb' }), async (req, res) => {
    const db = database(res);
    if (!db) return;
    const parsed = labelSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    const accepted = acceptLabel({ ...parsed.data, id: randomUUID(), createdAt: new Date(runtime.clock()) });
    if (!accepted) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    await insertLabel(db, accepted);
    runtime.metrics.labels.inc({ label: accepted.label });
    res.status(201).json({ id: accepted.id, label: accepted.label });
  });

  return router;
}

function automationFlags(automation: z.infer<typeof beaconSchema>['automation']): number {
  if (!automation) return 0;
  let flags = 0;
  if (automation.webdriver) flags |= AUTOMATION_FLAGS.webdriver;
  if (automation.headless) flags |= AUTOMATION_FLAGS.headless;
  if (automation.languages === 0) flags |= AUTOMATION_FLAGS.noLanguages;
  if (automation.phantom) flags |= AUTOMATION_FLAGS.phantom;
  if (automation.selenium) flags |= AUTOMATION_FLAGS.selenium;
  if (automation.playwright) flags |= AUTOMATION_FLAGS.playwright;
  if (automation.viewport && (automation.viewport[0] === 0 || automation.viewport[1] === 0)) flags |= AUTOMATION_FLAGS.zeroViewport;
  return flags;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function clampNumber(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === 'string' ? Number(value) : Number.NaN;
  return Number.isFinite(parsed) ? Math.min(Math.max(Math.trunc(parsed), min), max) : fallback;
}
