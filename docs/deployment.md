# Deployment

## Infrastructure

| Component | Requirement |
| --- | --- |
| Node.js | 22.18 or newer. Developed and tested on Node 24. |
| PostgreSQL | 14 or newer. Required in production for leads, conversions, attempts and paid visits. Migrations are plain SQL in `migrations/`, applied by `npm run migrate` under an advisory lock. |
| Redis | 7 or newer, or a compatible server with Lua scripting and HyperLogLog. Required when more than one instance serves traffic. Persistence is not needed; every key has a TTL. Set `maxmemory` with `maxmemory-policy volatile-ttl` so pressure evicts the shortest-lived counters first. A small instance is enough: a visitor key is a few hundred bytes and lives for at most seven days. |
| Cloudflare | Recommended. All plans work; Bot Management (Enterprise) adds the bot score signal. See [cloudflare.md](cloudflare.md). |
| Cloudflare Turnstile | Recommended. Free. Without it, challenges degrade to monitoring and every conversion is held for review. |
| ASN database | Optional MMDB file (MaxMind GeoLite2 ASN, DB-IP ASN Lite or IPinfo Lite). Not needed when Cloudflare forwards the ASN through a Transform Rule. |
| Scheduled job | `npm run intel:refresh` once a day, for example from cron or a CI schedule. |

## Environment variables

Required means the application refuses to start without it in production. Values are validated at startup and secrets are never printed in error messages.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `NODE_ENV` | yes | `development` | `production` enables strict validation |
| `PUBLIC_ORIGIN` | yes | none | Canonical `https://` origin; used for cookie security, Origin checks and Turnstile hostname checks |
| `ALLOWED_ORIGINS` | no | none | Additional origins of the same site, comma separated |
| `INTEGRITY_SECRET` | yes | none | At least 32 random characters; all signing keys are derived from it |
| `INTEGRITY_SECRET_PREVIOUS` | no | none | Previous secret, accepted for verification during rotation |
| `DATABASE_URL` | yes in production | none | `postgres://` URL; `pglite://` for local development only |
| `DATABASE_SSL` | no | `disable` | `require` or `verify-full` for managed databases |
| `DATABASE_POOL_MAX` | no | `10` | Connection pool size per instance |
| `REDIS_URL` | yes for more than one instance | none | `redis://` or `rediss://` |
| `REDIS_KEY_PREFIX` | no | `ti:` | Namespace when Redis is shared |
| `REDIS_COMMAND_TIMEOUT_MS` | no | `150` | After this the request falls back to the local store |
| `TRUSTED_PROXIES` | no | `loopback` | `loopback`, `private`, or IPs and CIDRs of your reverse proxy or load balancer |
| `CLOUDFLARE_MODE` | no | `off` | `monitor` records origin bypass, `enforce` rejects it |
| `CLOUDFLARE_EDGE_SECRET` | yes for `enforce` | none | Value of the `x-edge-auth` Transform Rule; two comma separated values during rotation |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` | recommended, set together | none | Turnstile widget keys; testing keys are refused in production |
| `TURNSTILE_TIMEOUT_MS` | no | `2500` | Per attempt; one retry with the same idempotency key |
| `TURNSTILE_MAX_AGE_SECONDS` | no | `300` | Oldest acceptable challenge |
| `ENFORCEMENT_MODE` | no | `monitor` | `shadow` and `monitor` log without enforcing. Switch to `enforce` after tuning |
| `SHADOW_POLICY_PATH` | no | none | Second policy scored on every request and stored, never enforced |
| `MODEL_PATH` | no | none | Optional logistic model JSON. Request path works without it |
| `RISK_POLICY_PATH` | no | none | JSON file overriding any part of the policy |
| `RISK_MONITOR_THRESHOLD`, `RISK_CHALLENGE_THRESHOLD`, `RISK_RESTRICT_THRESHOLD`, `RISK_BLOCK_THRESHOLD` | no | 20, 45, 70, 90 | Page and API thresholds |
| `NETWORK_INTEL_PATH` | no | `data/network-intel.json` | Output of `npm run intel:refresh`, reloaded every ten minutes |
| `ASN_DATABASE_PATH` | no | none | MMDB file with ASN data |
| `CRAWLER_REVERSE_DNS` | no | `true` | Background reverse DNS verification when range data is stale |
| `INTERNAL_PATH_PREFIX` | no | `/_ti` | Prefix of the beacon, challenge, form token, metrics and admin endpoints |
| `API_PREFIXES` | no | `/api/` | Paths treated as API requests |
| `SENSITIVE_ACTION_PATHS` | no | none | Exact paths of other sensitive POST endpoints such as signup |
| `BYPASS_PATHS` | no | health, robots, favicon, sitemap | Paths that skip the guard entirely |
| `VISITOR_COOKIE_DAYS` | no | `180` | Visitor identity lifetime without a visit |
| `LEAD_PATH` | no | `/api/leads` | Lead endpoint |
| `FORM_IDS` | no | `contact,quote` | Accepted form identifiers |
| `CONVERSION_CHALLENGE` | no | `always` | `always` requires Turnstile on every lead; `risk` only when the submission looks risky |
| `CONVERSION_ACTION_NAME` | no | `Qualified lead` | Must match the Google Ads conversion action name exactly |
| `CONVERSION_VALUE`, `CONVERSION_CURRENCY` | no | none, `USD` | Value reported per qualified conversion |
| `CONVERSION_HOLD_MINUTES` | no | `120` | Delay before a trusted conversion qualifies automatically |
| `CONVERSION_BURST_PER_HOUR` | no | `30` | Sitewide hourly rate above which new conversions go to review |
| `CONVERSION_TIMEZONE` | no | `UTC` | IANA zone used for conversion times in exports |
| `FORM_HONEYPOT_FIELD` | no | `company_website` | Name of the hidden field |
| `PHONE_COUNTRY_CODE` | no | none | Country calling code for local numbers, needed for hashed phone matching |
| `EXPORT_USERNAME`, `EXPORT_PASSWORD` | for scheduled uploads, set together | none | Basic auth for `/_ti/admin/conversions.csv` |
| `ADMIN_TOKEN` | for admin APIs | none | Bearer token for metrics, summaries, exclusions and qualification |
| `LOG_LEVEL` | no | `info` | pino level |
| `ASSESSMENT_LOG_SAMPLE_RATE` | no | `0.02` | Share of allowed requests logged |
| `PAID_VISIT_RETENTION_DAYS`, `ATTEMPT_RETENTION_DAYS`, `LEAD_RETENTION_DAYS`, `ASSESSMENT_RETENTION_DAYS` | no | 90, 30, 365, 45 | Retention enforced by the hourly maintenance job |
| `GOOGLE_ADS_CPC_USD` | no | none | Optional average CPC for spend-at-risk estimates only |
| `GOOGLE_ADS_APPLY_CHANGES` | no | `false` | Must stay false unless an operator has authorized Ads API writes |

## Reverse proxy

If nginx or a load balancer sits in front of the application, it must append to `X-Forwarded-For` and its address must be listed in `TRUSTED_PROXIES`. For nginx on the same host:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

With `TRUSTED_PROXIES=loopback` this is complete. Behind a cloud load balancer, list the load balancer subnet instead. Never list `0.0.0.0/0`.

## Deployment checklist

1. Provision PostgreSQL and Redis in the same region as the application. Restrict both to the application network.
2. Generate secrets: `INTEGRITY_SECRET` (`openssl rand -base64 48`), `ADMIN_TOKEN`, `EXPORT_PASSWORD` and `CLOUDFLARE_EDGE_SECRET`. Store them in the platform secret store, never in the repository.
3. Create the Turnstile widget for your hostnames and copy its keys.
4. Set the environment variables with `ENFORCEMENT_MODE=shadow` or `monitor` and `CLOUDFLARE_MODE=monitor` if Cloudflare is used. Apply both SQL migrations (`001` and `002`).
5. `npm ci`, `npm run check`, then `npm run migrate` against the production database.
6. Run `npm run intel:refresh -- --with-private-relay` once and schedule it daily. Place the output at `NETWORK_INTEL_PATH` on every instance or on shared storage.
7. Deploy the application and confirm `/readyz` reports `database: ok` and `sharedStore: ok`.
8. Configure the Cloudflare Transform Rules from [cloudflare.md](cloudflare.md) and confirm that the logs show `origin_bypass` events only for traffic you expect to bypass Cloudflare.
9. Lock the origin down to Cloudflare (firewall allowlist, Authenticated Origin Pulls or Cloudflare Tunnel), then set `CLOUDFLARE_MODE=enforce`.
10. Click your own ad and submit a test lead. Confirm a `paid_visit` event with the campaign id, a `conversion_accepted` event with `attributed: true`, and the row in `/_ti/admin/conversions.json` after qualification.
11. Configure the Google Ads conversion action and scheduled upload from [google-ads.md](google-ads.md).
12. Run in monitor mode for one to two weeks and review the measurements in [tuning.md](tuning.md).
13. Switch to `ENFORCEMENT_MODE=enforce`. Keep watching the challenge pass rate for the first days.

## Rotation

Integrity secret: set the current value as `INTEGRITY_SECRET_PREVIOUS`, a new value as `INTEGRITY_SECRET`, deploy, and remove the previous value after `VISITOR_COOKIE_DAYS`. Address hashes change with the secret, so counters and duplicate detection restart from zero.

Edge secret: add the new value to `CLOUDFLARE_EDGE_SECRET` alongside the old one, deploy, change the Transform Rule to the new value, then remove the old value.
