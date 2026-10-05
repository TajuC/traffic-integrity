import express, { type Request, type RequestHandler, type Router } from 'express';
import { Maintenance } from '../conversion/maintenance.ts';
import { processConversion, type LeadHook } from '../conversion/pipeline.ts';
import { enforcementFor, type EnforcementAction } from '../guard/enforce.ts';
import { inspectRequest, type Inspection, type RequestIntegrity } from '../guard/inspect.ts';
import { serializeCookie } from '../identity/cookies.ts';
import type { Runtime } from '../runtime.ts';
import { createInternalRouter } from './internal-routes.ts';
import { noStore, originState, sendBlocked, sendChallenge, sendRestricted } from './responses.ts';

export interface GuardOptions {
  readonly onLeadAccepted?: LeadHook;
  readonly isAuthenticated?: (req: Request) => boolean;
}

export interface IntegrityGuard {
  readonly middleware: RequestHandler;
  readonly router: Router;
  readonly leadHandlers: readonly RequestHandler[];
  readonly maintenance: Maintenance;
}

const integrities = new WeakMap<Request, RequestIntegrity>();

export function integrityOf(req: Request): RequestIntegrity | undefined {
  return integrities.get(req);
}

export function createIntegrityGuard(runtime: Runtime, options: GuardOptions = {}): IntegrityGuard {
  const { config, logger } = runtime;

  const middleware: RequestHandler = async (req, res, next) => {
    let inspection: Inspection;
    try {
      inspection = await inspectRequest(runtime, {
        method: req.method,
        path: req.path,
        url: req.originalUrl,
        headers: req.headers,
        socketAddress: req.socket.remoteAddress,
        authenticated: options.isAuthenticated?.(req) ?? false,
      });
    } catch (error) {
      logger.error({ err: error, path: req.path }, 'integrity inspection failed; request allowed');
      next();
      return;
    }

    if (inspection.originBypass) {
      sendBlocked(req, res);
      return;
    }
    for (const cookie of inspection.cookies) res.append('Set-Cookie', serializeCookie(cookie, config.origin.secure));
    const integrity = inspection.integrity;
    if (!integrity) {
      next();
      return;
    }
    integrities.set(req, integrity);

    let action: EnforcementAction;
    try {
      action = await enforcementFor(runtime, integrity);
    } catch (error) {
      logger.error({ err: error, requestId: integrity.requestId }, 'enforcement failed; request allowed');
      next();
      return;
    }

    switch (action.kind) {
      case 'restrict':
        sendRestricted(req, res, action.retryAfterSeconds);
        return;
      case 'block':
        sendBlocked(req, res);
        return;
      case 'challenge': {
        const identity = integrity.identity;
        const siteKey = config.turnstile?.siteKey;
        if (!identity || !siteKey) {
          next();
          return;
        }
        const { nonce, cdata } = runtime.clearance.challengeNonce(identity.visitorId, Math.floor(integrity.now / 1000));
        sendChallenge(req, res, { siteKey, action: 'clearance', cdata, nonce, internalPrefix: config.routes.internalPrefix });
        return;
      }
      case 'pass':
        next();
    }
  };

  const leadHandler: RequestHandler = async (req, res) => {
    noStore(res);
    const integrity = integrityOf(req);
    if (!integrity) {
      logger.error({ path: req.path }, 'lead handler mounted without the integrity middleware');
      res.status(500).json({ error: 'internal_error' });
      return;
    }
    if (!req.is('application/json') && !req.is('application/x-www-form-urlencoded')) {
      res.status(415).json({ error: 'unsupported_media_type' });
      return;
    }
    const origin = originState(req, config.origin.allowed);
    if (origin === 'mismatch') {
      res.status(403).json({ error: 'request_rejected' });
      return;
    }
    const outcome = await processConversion(runtime, { integrity, body: req.body as unknown, originPresent: origin === 'match' }, options.onLeadAccepted);
    if (outcome.retryAfterSeconds !== undefined) res.setHeader('Retry-After', String(outcome.retryAfterSeconds));
    res.status(outcome.status).json(outcome.body);
  };

  return {
    middleware,
    router: createInternalRouter(runtime, integrityOf),
    leadHandlers: [
      express.json({ limit: '16kb', type: 'application/json' }),
      express.urlencoded({ extended: false, limit: '16kb', parameterLimit: 50, type: 'application/x-www-form-urlencoded' }),
      leadHandler,
    ],
    maintenance: new Maintenance(runtime, options.onLeadAccepted),
  };
}
