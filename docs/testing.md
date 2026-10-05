# Testing

The suites use Node's built-in test runner and run TypeScript directly through Node's type stripping.

```bash
npm test
TEST_REDIS_URL=redis://127.0.0.1:6379/0 npm test
```

Without `TEST_REDIS_URL` the Redis contract and the multi-instance suite are skipped and everything else runs against the in-process store and an in-process PostgreSQL engine (PGlite), so no external service is needed. With it, the same store contract runs against real Redis and three application instances share one Redis. A disposable Redis for the second form:

```bash
docker run -d --name ti-redis -p 6390:6379 redis:7.4-alpine
TEST_REDIS_URL=redis://127.0.0.1:6390/0 npm test
```

| Suite | Scope |
| --- | --- |
| `test/net.test.ts` | IP parsing, range tables and compaction, client address resolution, Cloudflare trust, crawler verification, network classification |
| `test/identity.test.ts` | Keyring and rotation, visitor identity, cookies, attribution parsing, user agents, enhanced conversion normalization |
| `test/risk.test.ts` | Risk engine scenarios, scoring arithmetic, gates, policy validation |
| `test/store.test.ts` | Store contract for the in-process store and Redis, concurrency, restrictions, fallback and circuit breaker |
| `test/turnstile.test.ts` | Siteverify handling, binding checks, expiry, replay, timeouts, retries, testing keys |
| `test/http.test.ts` | End-to-end traffic scenarios through the Express application |
| `test/conversion.test.ts` | End-to-end lead pipeline against PostgreSQL |
| `test/redis-e2e.test.ts` | Several application instances sharing one Redis |
| `test/config.test.ts`, `test/data.test.ts` | Configuration validation, migrations, network data refresh, Google Ads export formats |

## Required scenarios

| Scenario | Tests |
| --- | --- |
| Ordinary legitimate visitor | http: an ordinary visitor browses without friction and receives one durable identity; risk: an ordinary first-time visitor is allowed without signals |
| Legitimate returning paid visitor | http: a returning paid visitor clicking ads on different days is not challenged; risk: a legitimate returning paid visitor is allowed and earns trust |
| Multiple users behind one NAT | http: many users behind one NAT are all allowed; risk: many people behind one NAT stay allowed |
| Rapid bot requests | http: rapid bot requests are restricted and released after the restriction expires; risk: rapid automated requests are temporarily restricted, not blocked |
| Repeated paid arrivals from one visitor | http and risk: repeated paid arrivals from one visitor end in a challenge |
| Repeated paid arrivals from one network | http and risk: a paid-click flood from one network challenges new identities but not an established visitor; redis-e2e: the flood spread across instances |
| Cookie rotation | http: cookie rotation with paid clicks from one address is detected; risk: cookie rotation alone is monitored and escalates with corroboration |
| Fake user agent | http: a fake user agent alone does not interrupt browsing; risk: a fake user agent is only a supporting signal |
| Datacenter network plus bot indicators | http: headless automation from a datacenter is challenged; risk: datacenter automation is challenged and restricted when fast |
| Suspicious behaviour with successful Turnstile | http: a suspicious visitor who passes Turnstile continues; risk: a passed challenge settles moderate suspicion |
| Severe abuse despite one positive signal | http and risk: severe abuse is restricted even after passing a challenge |
| Verified crawler | http: a verified crawler is served without cookies or challenges; net: verifies Googlebot by published ranges |
| Spoofed crawler user agent | http: a spoofed crawler user agent is challenged; net: a Google Cloud customer VM must not pass as Googlebot |
| Conversion replay | conversion: a replayed form token is rejected; turnstile: replayed tokens are blocked locally; http: a challenge nonce is single use |
| Duplicate submission | conversion: idempotent retries and duplicate submissions never create a second conversion |
| Direct API attack without frontend | conversion: a direct API attack creates no lead and no database row; risk: direct API conversion attempts are blocked |
| Redis unavailable | http: the site keeps serving and protecting when the shared store is unavailable; store: fallback and circuit breaker |
| Turnstile unavailable | conversion: low-risk leads are kept for review and risky ones must retry; turnstile: timeouts and internal errors |
| Malformed attribution values | http: malformed attribution is ignored; identity: malformed and conflicting values are rejected |
| Forged visitor cookie | http: a forged visitor cookie is replaced; identity: forged or tampered cookies become new identities |
| Expired challenge | http: clearance expiry triggers a new challenge; turnstile: expired challenges are rejected; conversion: expired form tokens are recorded |
| Rate-limit expiry | http: restriction released after expiry; store: restrictions expire; redis-e2e: expiry seen by another instance |
| Concurrency around counters | store: exact counters under 200 concurrent requests and single-winner one-time claims, on both stores; redis-e2e: exact counters across three instances |
| False-positive-sensitive shared IP | http: one abusive identity on a shared address does not lock out its neighbours; risk: a shared IP with one abusive identity |
| Successful qualified conversion | conversion: a qualified conversion flows from a paid click to the Google Ads export |

Further tests cover monitor mode, origin bypass enforcement, edge secret rotation, honeypots, invalid input, the conversion burst breaker, operator qualification and adjustment flags, crawler lead submissions, the database outage path, configuration safety, migrations and export formatting.
