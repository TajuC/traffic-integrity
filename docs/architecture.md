# Architecture

## Scope

The system has four jobs: give every visitor a durable first-party identity, assess each meaningful request against independent evidence, apply the mildest enforcement that the evidence justifies, and keep untrusted leads out of the conversion data that Google Ads optimizes on. It sits inside the web application, after any CDN and reverse proxy, because only the origin sees cookies, form submissions and conversion outcomes together.

It cannot prevent Google from registering and billing an ad click. Google records the click before the browser is redirected to the landing page. Everything here operates after that moment.

## Topology

```
Browser
  |  HTTPS
Cloudflare (optional, recommended)     sets CF-Connecting-IP, x-edge-auth, x-edge-asn, x-edge-verified-bot
  |
Reverse proxy or load balancer (optional)   appends X-Forwarded-For
  |
Node.js application
  guard middleware  ->  site routes, /_ti internal routes, lead endpoint
  |                 \
Redis (shared counters, restrictions, replay guards)    PostgreSQL (paid visits, attempts, leads, conversions)
```

Redis is required as soon as more than one application instance serves traffic. Without it every instance counts on its own and replay guards are per process. PostgreSQL is required for the conversion pipeline and for paid visit persistence. For local development `pglite://` runs an in-process PostgreSQL engine.

## Request lifecycle

1. Classification. Static assets, health checks, `robots.txt` and the scripts under `/_ti` are skipped immediately with no cookie, no counter and no log line. Remaining requests are classed as page, api, action (configured sensitive endpoints), conversion (the lead endpoint) or internal.
2. Client address. The socket peer is the starting point. `X-Forwarded-For` is walked from the right and trusted only through hops listed in `TRUSTED_PROXIES`. `CF-Connecting-IP` is used only when the hop that reached the trusted infrastructure is a Cloudflare address, and Cloudflare signal headers are used only when that request also carries the edge secret configured in a Transform Rule. With `CLOUDFLARE_MODE=enforce`, anything that did not come through your zone receives a 403 before any other work.
3. Network profile. Tor exit lists, Apple Private Relay egress ranges, published cloud ranges (AWS, Google Cloud, Oracle, DigitalOcean) and a curated list of hosting ASNs classify the network. The ASN comes from Cloudflare or from an optional local MMDB file. All of this is local data refreshed by `npm run intel:refresh`; nothing calls a remote reputation API on the request path.
4. Crawler verification. A crawler claim in the user agent is verified against Google's and Bing's published ranges. When the range data is stale, a forward-confirmed reverse DNS check runs in the background and its result is cached. Verified crawlers receive no cookies, are never challenged and are not counted as visitors.
5. Identity. A signed visitor cookie and a session cookie are read or issued. A cookie with an invalid signature is treated as a new visitor and recorded as a forged identity signal.
6. Attribution. On page navigations the click identifiers and UTM values are parsed and validated. They are treated as attribution data, never as proof of a real ad click.
7. Observation. One pipelined Redis round trip runs up to five Lua scripts that update and read the counters for the visitor, the address, the network, the ASN and the click identifier. Results come back in the same call.
8. Assessment. Detectors emit signals, the scoring function combines them by family and the policy maps the score to a decision. This step is pure computation.
9. Enforcement. The decision is applied according to the route class and `ENFORCEMENT_MODE`. In monitor mode nothing is enforced but every decision is logged as if it were.
10. Telemetry. Metrics are updated, notable decisions are logged with flood control, and paid arrivals are queued for batched insertion into PostgreSQL.

Measured overhead on a development machine: 0.05 ms median and 0.12 ms at the 99th percentile with the in-process store, and 0.70 ms median and 1.04 ms at the 99th percentile including the Redis round trip to a Docker container. The Redis call dominates, so keep Redis on the same host or in the same availability zone.

## Components

| Module | Responsibility |
| --- | --- |
| `config/env.ts` | Parses every environment variable once, rejects invalid or unsafe production settings, produces a typed `Config` |
| `risk/types.ts`, `risk/policy.ts` | The reason vocabulary and the single place where weights, thresholds and limits live |
| `risk/detectors.ts`, `risk/engine.ts` | Signal detection and scoring |
| `net/*` | IP arithmetic, longest-prefix range tables, client address resolution, network intelligence, crawler verification |
| `identity/*` | Cookie parsing and the signed visitor and session identity |
| `store/*` | The `IntegrityStore` contract, the Redis implementation, the in-process fallback and the circuit breaker |
| `guard/*` | Framework-independent inspection and enforcement, plus the local restriction cache |
| `challenge/*` | Turnstile siteverify client, clearance tokens and the challenge page |
| `conversion/*` | Lead validation and normalization, the qualification pipeline, SQL, export formats and background maintenance |
| `telemetry/*` | pino logger with redaction, typed security events, Prometheus metrics, paid visit recorder |
| `http/*` | Express middleware, the internal router under `/_ti` and the lead handler |

## Identity

The visitor cookie holds a random 128-bit identifier, its issue time and its last renewal time, sealed with HMAC-SHA256. It is `HttpOnly`, `SameSite=Lax`, and on HTTPS uses the `__Host-` prefix, which forces `Secure`, `Path=/` and no `Domain`, so a subdomain cannot plant one. Because the issue time is signed, cookie age can be used as a trust signal without being forgeable. The cookie is renewed weekly and expires after `VISITOR_COOKIE_DAYS` without a visit.

All keys are derived with HKDF from `INTEGRITY_SECRET`, one key per purpose (visitor, session, clearance, challenge, form, beacon, subject hashing, fingerprinting). A token sealed for one purpose cannot be replayed as another. Setting `INTEGRITY_SECRET_PREVIOUS` keeps tokens issued under the previous secret valid during a rotation.

Addresses never appear in Redis keys or in most telemetry. They are replaced by keyed hashes of the address (IPv4 /32, IPv6 /64) and of the network (IPv4 /24, IPv6 /48).

## Counters

Rates are exponentially decayed counters stored as a value and a timestamp in a Redis hash. Each event multiplies the stored value by `exp(-elapsed/tau)` and adds one, so the value approximates events per tau with no window boundary effects and constant memory. Request rates use a one minute tau, sensitive actions ten minutes and visitor conversions one day.

Distinct counts (paid clicks per visitor, network and ASN, fresh identities per network, established population of an address or network, visitors per click identifier) use HyperLogLog in fixed buckets, counted as the union of the current and previous bucket. The memory per key is bounded regardless of attack volume.

Every key carries a TTL. A visitor that has not yet proven it keeps cookies gets a ten minute provisional state; returning visitors keep seven days. Keys are grouped with hash tags (`ti:{v:<id>}:...`) so each Lua script touches a single slot and the design works on Redis Cluster. Scripts are atomic, so concurrent requests from many instances cannot lose updates; the tests verify exact counts under 200 concurrent requests and across three application instances.

## Conversion pipeline

```
submission
  -> origin and content type checks
  -> schema validation
  -> form token check (signed, bound to visitor and form, age measured)
  -> preliminary risk assessment (obvious attacks refused here, before any database write)
  -> attempt claim (idempotency key and form nonce are unique in PostgreSQL)
  -> final risk assessment (adds replay and repeated message evidence)
  -> Turnstile (always, or only when risky, per CONVERSION_CHALLENGE)
  -> duplicate detection under advisory locks (same email or phone within 24 hours)
  -> lead stored, delivery hook called, conversion stored as pending or review
  -> hold period, then automatic qualification of pending conversions
  -> export of qualified conversions with click identifiers to Google Ads
```

A conversion is `pending` only if a human check passed (or was legitimately not required), the score is below `conversion.trustedMaxScore`, no high or critical signal fired and no sitewide burst is in progress. Everything else is `review`. Pending conversions qualify automatically after `CONVERSION_HOLD_MINUTES`; review conversions wait for an operator or CRM call to `/_ti/admin/conversions/:id/qualify`. When the hourly sitewide conversion rate exceeds `CONVERSION_BURST_PER_HOUR`, the new conversion and every pending conversion inside the hold window are moved to review.

The browser never declares a conversion. The lead response carries a `fire` flag that is true only for pending conversions, and the form helper fires the Google Ads tag with the server-issued conversion id as `transaction_id` only when it is true.

## Data model

| Table | One row per | Retention |
| --- | --- | --- |
| `ti_paid_visits` | Paid arrival per visitor and click identifier | `PAID_VISIT_RETENTION_DAYS` (90) |
| `ti_conversion_attempts` | Lead submission attempt that passed the preliminary check | `ATTEMPT_RETENTION_DAYS` (30) |
| `ti_leads` | Accepted lead | `LEAD_RETENTION_DAYS` (365) |
| `ti_conversions` | Conversion record for a lead | Deleted with its lead |

Raw IP addresses are stored only on paid visits that scored at or above the monitor threshold, because those are the rows an operator may need for Google Ads IP exclusions. Everything else uses the keyed address hash and the network prefix. Lead contact data is stored because the business needs the lead; logs never contain it, enforced by the logger redaction list.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Redis unreachable or slow | Commands fail fast (no offline queue, 150 ms timeout). After three failures the circuit opens for five seconds and an in-process store takes over. Enforcement continues per instance. Sessions and challenge clearances issued before the outage are honoured from their signed cookies. A `security_degraded` event and metrics record the fallback. |
| PostgreSQL unreachable | Browsing is unaffected. The lead endpoint answers 503 with `Retry-After` and the form keeps the visitor's input. Paid visit writes are dropped after the batch fails and counted. |
| Turnstile unreachable | Page challenges fail open with a five minute clearance. Lead submissions from low-risk visitors are accepted but held for review; risky ones receive 503 and can retry. Misconfigured or testing keys in production raise an error-level event. |
| Network data missing or stale | Classification continues with what is available. Crawler impersonation is only asserted when range data is fresh or reverse DNS confirms it. |
| ASN unavailable | Assessments are marked `reduced` confidence; ASN-based signals are skipped. |
| Bug in the guard | The middleware logs the error and lets the request through. A security layer must not become the outage. |
