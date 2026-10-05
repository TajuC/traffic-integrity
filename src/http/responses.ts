import type { Request, Response } from 'express';
import { renderChallengePage, renderStatusPage, type ChallengePageInput } from '../challenge/page.ts';

const CHALLENGE_CSP = [
  "default-src 'none'",
  "script-src 'self' https://challenges.cloudflare.com",
  'frame-src https://challenges.cloudflare.com',
  "connect-src 'self'",
  "style-src 'unsafe-inline'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const STATUS_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export type OriginState = 'match' | 'missing' | 'mismatch';

export function prefersHtml(req: Request): boolean {
  return (req.method === 'GET' || req.method === 'HEAD') && (req.headers.accept ?? '').includes('text/html');
}

export function noStore(res: Response): void {
  res.setHeader('Cache-Control', 'no-store');
}

export function originState(req: Request, allowed: ReadonlySet<string>): OriginState {
  const origin = req.headers.origin;
  if (origin === undefined || origin === 'null') return req.headers['sec-fetch-site'] === 'cross-site' ? 'mismatch' : 'missing';
  return allowed.has(origin) ? 'match' : 'mismatch';
}

export function sendRestricted(req: Request, res: Response, retryAfterSeconds: number): void {
  noStore(res);
  res.setHeader('Retry-After', String(retryAfterSeconds));
  res.status(429);
  if (prefersHtml(req)) {
    res.setHeader('Content-Security-Policy', STATUS_CSP);
    res.type('html').send(
      renderStatusPage({
        title: 'Please try again shortly',
        message: 'We received too many requests from your connection. Please wait a few minutes and try again.',
      }),
    );
    return;
  }
  res.json({ error: 'rate_limited' });
}

export function sendBlocked(req: Request, res: Response): void {
  noStore(res);
  res.status(403);
  if (prefersHtml(req)) {
    res.setHeader('Content-Security-Policy', STATUS_CSP);
    res.type('html').send(renderStatusPage({ title: 'Access denied', message: 'This request could not be completed.' }));
    return;
  }
  res.json({ error: 'request_rejected' });
}

export function sendChallenge(req: Request, res: Response, input: ChallengePageInput): void {
  noStore(res);
  res.status(403);
  if (prefersHtml(req)) {
    res.setHeader('Content-Security-Policy', CHALLENGE_CSP);
    res.type('html').send(renderChallengePage(input));
    return;
  }
  res.json({ error: 'verification_required', turnstile: { siteKey: input.siteKey, action: input.action, cdata: input.cdata, nonce: input.nonce } });
}
