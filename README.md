# Traffic Integrity

Server-side protection and measurement for websites that buy traffic through Google Ads. **v1.1.0**.

[![CI](https://github.com/TajuC/traffic-integrity/actions/workflows/ci.yml/badge.svg)](https://github.com/TajuC/traffic-integrity/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%3E%3D22.18-339933)
![TypeScript](https://img.shields.io/badge/typescript-strict-3178c6)

Traffic Integrity identifies automated and abusive paid traffic, applies progressive
enforcement without putting a CAPTCHA in front of ordinary visitors, records
privacy-conscious forensic telemetry for every paid arrival, and reports only
server-validated, qualified leads back to Google Ads as conversions.

It is a detection, mitigation, conversion-integrity, and evidence platform.
It does not and cannot stop Google from recording a paid click. The click is billed
before the visitor reaches your origin. What this system does is make abuse
expensive, keep fake leads out of the conversion data that trains Smart Bidding,
and give you the evidence needed for IP exclusions and invalid-click investigations.
The full list of residual risks is in [docs/security-review.md](docs/security-review.md).
Measured synthetic detector numbers, labeled as synthetic, are in
[docs/evaluation-results.md](docs/evaluation-results.md).

## What ships

- **Library.** `createIntegrityGuard` mounts on an existing Express 5 application.
  Inspection and enforcement (`inspectRequest`, `enforcementFor`) take plain request
  facts, so the Express adapter in `src/http` is the only framework-specific layer.
- **Reference server.** `npm run dev` serves a complete landing page, lead form,
  challenge flow, health endpoints, and Prometheus metrics.
- **Operations suite.** Migrations, network-intelligence refresh, Google Ads
  conversion export, and a request-path benchmark.

## Why this exists

Most origin-side "bot protection" either challenges everyone or trusts a single
signal (an IP, a CAPTCHA, a `gclid`). Both fail on paid traffic. A household NAT
is not a botnet. A solved Turnstile is not a qualified lead. A click identifier
is attribution data, not proof the click was human.

Traffic Integrity treats those as independent families of evidence, scores them
together, and picks the mildest decision the evidence supports:

`ALLOW` → `ALLOW_AND_MONITOR` → `CHALLENGE` → `TEMPORARILY_RESTRICT` → `BLOCK`

New visitors start on the left. Enforcement tightens only as independent families
agree. No family, including the client address, can carry a request to `BLOCK` on
its own.

## Feature highlights

**Observation (one Redis round trip)**

- Trusted-proxy IP resolution. `X-Forwarded-For` is walked from the right through
  hops you listed. `CF-Connecting-IP` is used only when the hop that reached you
  is a Cloudflare address.
- Cloudflare signal headers (`x-edge-asn`, `x-edge-verified-bot`, and friends)
  are ignored unless the request also carries the edge secret you set in a
  Transform Rule. `CLOUDFLARE_MODE=enforce` rejects anything that did not arrive
  through your zone.
- Network classification from local data: hosting ASNs, published cloud ranges,
  Tor exits, Apple Private Relay. Nothing calls a reputation API on the request
  path.
- Crawler verification against Google and Bing published ranges. Googlebot is
  not accepted via `googleusercontent.com` or App Engine fetchers. Verified
  crawlers receive no cookies, are never challenged, and are not counted.
- Signed first-party visitor identity. On HTTPS the cookie uses the `__Host-`
  prefix (`Secure`, `Path=/`, no `Domain`).
- Paid attribution capture: `gclid`, `gbraid`, `wbraid`, `gad_source`,
  `gad_campaignid`, and UTM values. Treated as attribution, never as trust.
- Atomic Redis Lua counters with HyperLogLog sketches, hash-tagged keys, NAT-aware
  scaled limits, and an in-process fallback behind a circuit breaker. Redis
  failures fail open on the request path.

**Risk and enforcement**

- Independent signal families (identity, network, velocity, client, attribution,
  conversion) with per-family caps, so one noisy source cannot dominate.
- Progressive decisions, not a binary allow/deny. Monitor mode logs every
  decision without acting on it, which is how you tune before going live.
- Cloudflare Turnstile on `CHALLENGE`, bound to the visitor and the action.
  Cloudflare's public testing keys are rejected at startup in production.
- Temporary restrictions answered from memory, so a flood does not hammer Redis.
- Log flood control: notable decisions are deduplicated per subject per minute.

**Conversion integrity**

- Signed single-use form tokens bound to the visitor and the form.
- Origin check, Turnstile, idempotency, replay and duplicate detection, a hold
  period, and a sitewide burst breaker before anything is exported.
- Obvious direct attacks are refused before a database write.
- Qualified conversions export as Google Ads click-identifier CSV (or the
  enhanced-conversion shape). The website tag is secondary and fires only when
  the server marks the conversion as trusted.

**Measured overhead**

On this development machine, `npm run bench` against the in-process store reported p50 0.190 ms, p95 0.295 ms, p99 0.382 ms, p99.9 1.425 ms, about 4882 sequential requests per second over 5000 requests. That is not a concurrent load test and Redis was not attached. Re-run `npm run bench` with `TEST_REDIS_URL` set to measure the Redis path on your hardware.

## Requirements

- Node.js 22.18 or newer (developed and tested on Node 24)
- Redis 7, required as soon as more than one application instance serves traffic
- PostgreSQL 16, required for conversion persistence (PGlite is accepted in
  development only)
- Cloudflare Turnstile site keys
- Optional: Cloudflare in front of the origin, a MaxMind ASN database

## Quick start

```bash
npm install
cp .env.example .env
```

For a local run without Postgres or Redis, set these values in `.env`:

```bash
NODE_ENV=development
PUBLIC_ORIGIN=http://localhost:3000
INTEGRITY_SECRET=local-development-only-change-me-0123456789
DATABASE_URL=pglite://./data/dev-db
ENFORCEMENT_MODE=enforce
TURNSTILE_SITE_KEY=1x00000000000000000000AA
TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA
```

Then start the reference site and open http://localhost:3000:

```bash
npm run dev
```

The two Turnstile values above are Cloudflare's public testing keys. They always
pass, work on localhost, and are rejected by the configuration loader in
production.

## Using it in an existing Express application

```ts
import express from 'express';
import { createIntegrityGuard, createRuntime, loadConfig } from 'traffic-integrity';

const config = loadConfig();
const runtime = await createRuntime(config);
const guard = createIntegrityGuard(runtime, {
  onLeadAccepted: async (lead) => {
    await sendToCrm(lead);
  },
  isAuthenticated: (req) => Boolean(req.user),
});

const app = express();
app.use(guard.middleware);
app.use(config.routes.internalPrefix, guard.router);
app.post(config.conversion.path, ...guard.leadHandlers);
guard.maintenance.start();
```

Load `/_ti/beacon.js` on every page and `/_ti/forms.js` on pages with a lead
form, then call `TrafficIntegrity.protectForm(form, { conversionSendTo: 'AW-XXXXXXXXX/label' })`.
The helper fetches a form token, renders Turnstile when required, retries after
a challenge without losing what the visitor typed, and fires the Google Ads tag
only when the server marks the conversion as trusted.
[public/index.html](public/index.html) and [public/site.js](public/site.js) show
a complete page.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Run the reference site from source with `.env` |
| `npm run build` | Compile to `dist/` |
| `npm start` | Run the compiled server |
| `npm test` | Run the test suite (set `TEST_REDIS_URL` to include the Redis suites) |
| `npm run typecheck` / `npm run lint` | Static checks |
| `npm run check` | Typecheck, lint, test, synthetic eval, and build |
| `npm run migrate` | Apply database migrations |
| `npm run intel:refresh` | Download crawler, cloud, Tor, and optionally Apple Private Relay ranges (`-- --with-private-relay`) |
| `npm run conversions:export` | Write the Google Ads conversion CSV to stdout or `-- --out file.csv` |
| `npm run bench` | Measure guard overhead per request (p50/p95/p99/p99.9) |
| `npm run eval` | Score the synthetic labeled dataset and print metrics |
| `npm run eval:report` | Write the same report as JSON |
| `npm run adversarial` | HTTP attacker-class tests, including documented origin-side gaps |
| `npm run coverage` | Test suite with V8 coverage (70% line floor) |
| `npm run sbom` | CycloneDX SBOM for production dependencies |

## Repository layout

| Path | Contents |
| --- | --- |
| `src/config` | Environment schema and typed configuration |
| `src/risk` | Signal vocabulary, policy, detectors, scoring, and decisions |
| `src/observe` | Browser consistency, cohorts, behavior features, snapshot cache |
| `src/intel` | In-process graph correlation and robust campaign baselines |
| `src/model` | Feature schema and optional logistic model |
| `src/eval` | Synthetic dataset, metrics, and evaluation CLI |
| `src/ads` | Evidence bundles and campaign recommendations |
| `src/feedback` | Outcome labels with provenance |
| `src/upstream` | Short-lived edge block/challenge proposals |
| `src/operator` | Investigation queries for the admin API |
| `src/events` | Assessment event persistence |
| `src/net` | IP parsing, range tables, client address resolution, network intelligence, crawler verification |
| `src/identity`, `src/attribution`, `src/request` | Visitor and session identity, paid attribution, request classification and user agent parsing |
| `src/store` | Redis Lua counters, in-process fallback, and circuit breaker |
| `src/guard` | Framework-independent inspection and enforcement |
| `src/challenge` | Turnstile verification, clearance tokens, challenge page |
| `src/conversion` | Lead validation, conversion pipeline, repository, Google Ads export, maintenance |
| `src/telemetry` | Logger, security events, metrics, paid visit persistence |
| `src/http` | Express middleware, internal endpoints, and lead handler |
| `migrations` | PostgreSQL schema |
| `public` | Reference landing page and the browser scripts under `public/ti` |
| `test` | Unit, integration, and end-to-end suites |
| `docs` | Architecture, risk model, deployment, Google Ads, Cloudflare, tuning, security review, testing |

## Documentation

| Document | Covers |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Components, request lifecycle, data model, failure modes, privacy |
| [docs/risk-model.md](docs/risk-model.md) | Signals, scoring, thresholds, decisions, and false-positive protections |
| [docs/deployment.md](docs/deployment.md) | Infrastructure, environment variables, deployment checklist |
| [docs/google-ads.md](docs/google-ads.md) | Google Ads settings that application code cannot change |
| [docs/cloudflare.md](docs/cloudflare.md) | What the code does with Cloudflare and what to configure in the dashboard |
| [docs/tuning.md](docs/tuning.md) | What to measure before tightening enforcement, with queries |
| [docs/security-review.md](docs/security-review.md) | Adversarial review, fixes made, residual risks, and limitations |
| [docs/testing.md](docs/testing.md) | Test inventory and scenario coverage |
| [docs/research-methodology.md](docs/research-methodology.md) | Threat model, hypotheses, evaluation, labeling, bias |
| [docs/evaluation-results.md](docs/evaluation-results.md) | Numbers from `npm run eval` only. Synthetic, not production accuracy |
| [docs/production-readiness.md](docs/production-readiness.md) | Honest scorecard and first-deploy sequence |

## Quality bar

Every change must pass the same gates CI enforces, before review:

```bash
npm run check
```

That is typecheck, lint, the Node test runner, the synthetic evaluation CLI, and a production build. With
Redis available, set `TEST_REDIS_URL` so the contract tests and the
multi-instance suite run as well. With PostgreSQL available, set
`TEST_DATABASE_URL` so conversion and migration tests run against a real
server. New behavior needs tests.

The default branch is protected: a change reaches `main` only through a pull
request whose required status checks pass.

## Security

Do not open a public issue for a vulnerability. Report it privately through
GitHub Security Advisories, using "Report a vulnerability" on the repository
Security tab. See [SECURITY.md](.github/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
