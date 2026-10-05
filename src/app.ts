import { fileURLToPath } from 'node:url';
import express, { type ErrorRequestHandler, type Express, type RequestHandler } from 'express';
import type { IntegrityGuard } from './http/guard.ts';
import type { Runtime } from './runtime.ts';

export const PUBLIC_DIRECTORY = fileURLToPath(new URL('../public/', import.meta.url));

const SITE_CSP = [
  "default-src 'self'",
  "script-src 'self' https://challenges.cloudflare.com",
  'frame-src https://challenges.cloudflare.com',
  "connect-src 'self'",
  "img-src 'self' data:",
  "style-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export function createApp(runtime: Runtime, guard: IntegrityGuard): Express {
  const { config } = runtime;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);

  app.use(securityHeaders(config.origin.secure));
  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.get('/readyz', async (_req, res) => {
    const [database, store] = await Promise.all([
      runtime.db ? runtime.db.query('SELECT 1').then(() => 'ok', () => 'error') : Promise.resolve('disabled'),
      runtime.store.health(),
    ]);
    const ready = database !== 'error';
    res.status(ready ? 200 : 503).json({ status: ready ? 'ok' : 'degraded', database, sharedStore: store === 'shared' ? 'ok' : 'local' });
  });

  app.use(guard.middleware);
  app.use(config.routes.internalPrefix, guard.router);
  app.post(config.conversion.path, ...guard.leadHandlers);
  app.use(
    express.static(PUBLIC_DIRECTORY, {
      index: 'index.html',
      extensions: ['html'],
      maxAge: '1h',
      setHeaders: (res, path) => {
        if (path.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
      },
    }),
  );

  app.use((req, res) => {
    res.status(404);
    if ((req.headers.accept ?? '').includes('text/html')) res.type('html').send('<!doctype html><title>Not found</title><h1>Not found</h1>');
    else res.json({ error: 'not_found' });
  });

  const errors: ErrorRequestHandler = (error: unknown, req, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }
    const type = typeof error === 'object' && error !== null ? (error as { type?: unknown }).type : undefined;
    if (type === 'entity.too.large') {
      res.status(413).json({ error: 'payload_too_large' });
      return;
    }
    if (type === 'entity.parse.failed' || type === 'encoding.unsupported' || type === 'charset.unsupported') {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    runtime.logger.error({ err: error, path: req.path }, 'unhandled request error');
    res.status(500).json({ error: 'internal_error' });
  };
  app.use(errors);
  return app;
}

function securityHeaders(secure: boolean): RequestHandler {
  return (_req, res, next) => {
    res.setHeader('Content-Security-Policy', SITE_CSP);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    if (secure) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    next();
  };
}
