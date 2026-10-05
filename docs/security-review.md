# Security review

This review was written after the implementation, from the point of view of someone trying to defeat it. It lists what each class of attacker can do, what slows them down, and what remains possible. Nothing in this system is unbypassable, and nothing in it should be described that way.

## Attacks and residual risk

| Attacker technique | What stops or slows it | What remains possible |
| --- | --- | --- |
| Scripted HTTP clients (curl, Python, Go) hitting pages | Automation user agent signal, missing fetch metadata, client hint and Accept anomalies, velocity, cookie churn | A client that copies a real browser's headers and keeps cookies looks like a browser at the HTTP layer |
| Direct calls to the lead endpoint without the frontend | Origin check, signed form token bound to the visitor and form, direct access signal, Turnstile on every lead, refusal before any database write | A script that first loads a page, fetches a form token and pays a CAPTCHA solving service can submit leads; those leads still face duplicate, repeated message, velocity and burst checks, and only qualify after the hold period |
| Headless browsers (Playwright, Puppeteer, Selenium) | HeadlessChrome in the user agent or client hints, webdriver and framework artifacts reported by the beacon, mechanical timing, velocity, Turnstile | Patched stealth browsers hide these artifacts; Turnstile and Cloudflare Bot Management are then the main defence |
| Real Chromium driven by a human-like script | Velocity, mechanical timing, paid click velocity, Turnstile on leads | Slow, jittered automation through a real browser is hard to distinguish from a person at the origin |
| Rotating residential proxies | Network, ASN and campaign aggregates, paid click reuse across identities, conversion qualification | Each request from a new household address with a new cookie carries little evidence; this is the class where Google's own invalid traffic detection and Cloudflare's machine learning see more than the origin can |
| Cookie rotation | Identity churn per network scaled by the established population, which rotation cannot inflate because it only counts cookies older than an hour | Rotation spread across many networks at low rate |
| User agent rotation | User agent is a supporting signal only; the identity, network and velocity evidence does not depend on it | Nothing is lost by the defender here |
| Many low-rate identities | ASN paid bursts, campaign summaries, sitewide conversion burst breaker, hold period | Distributed low-rate clicking is mostly invisible per request |
| Header spoofing of `X-Forwarded-For` or `CF-Connecting-IP` | Forwarding headers are only read through configured proxies and Cloudflare addresses; Cloudflare signal headers additionally require the edge secret | An attacker inside a trusted proxy network |
| Another Cloudflare account pointed at the origin | Edge signals require the `x-edge-auth` secret; `CLOUDFLARE_MODE=enforce` rejects the request | None once the origin is locked to your zone |
| Fake Googlebot user agent | Published crawler ranges and forward-confirmed reverse DNS limited to `googlebot.com` and `google.com`; impersonation is a challenge-level signal | When range data is stale and reverse DNS is disabled, the claim is neutral rather than trusted |
| Replaying tokens | Form nonces are unique in PostgreSQL, Turnstile tokens are claimed once locally and are single use at Cloudflare, beacon and challenge nonces are claimed once, idempotency keys replay the stored response | During a Redis outage local replay guards are per instance; Cloudflare and the database still reject replays |
| Sharing one clearance cookie across a bot farm | Clearance is bound to the visitor identity, so the farm shares one visitor and its counters, and is restricted together | None worth noting |
| Attribution spoofing with invented or harvested `gclid` values | Click identifiers are attribution data, never trust; conversions are only exported after qualification; unknown click ids are ignored by Google on import | Harvested real click ids attached to fake leads that pass every check |
| Conversion poisoning to steer Smart Bidding | Server-only conversion decisions, duplicate and repeated message detection, burst breaker, hold period, manual review queue, website tag kept secondary | A patient attacker with real browsers, solved challenges and unique contact details can still create leads; the review queue and lead quality follow-up are the last line |
| Tripping the burst breaker on purpose | Only holds conversions for review, nothing is lost | Conversion reporting to Google Ads is delayed until an operator qualifies the held leads |
| Flooding to exhaust resources | Static assets bypass the guard, restricted subjects are answered from memory without Redis, preliminary refusal avoids database writes, bounded caches everywhere, request and header timeouts, log flood control | Volumetric attacks belong at the CDN; the origin should be locked to Cloudflare |

## Issues found during the review and fixed

1. Cloudflare signal headers were trusted on IP evidence alone when no edge secret was configured, which would let a foreign Cloudflare zone inject a verified bot flag. Signal headers now require the secret; IP evidence is only used to recognise that traffic arrived through Cloudflare.
2. Google's `user-triggered-fetchers.json` covers App Engine egress shared by Google Cloud customers, and `googleusercontent.com` reverse DNS belongs to customer virtual machines. Both would have allowed a cloud VM to pass as Googlebot. They are no longer accepted as crawler proof, and a test covers the case.
3. Obvious direct API attacks inserted an attempt row before being refused. They are now refused before any database write.
4. Every non-allowed decision was logged, so a flood meant a log flood. Decisions, restrictions and refusals are now deduplicated per subject per minute, while paid visits and lead submissions are always logged.
5. Reverse DNS checks triggered by spoofed crawler claims were unbounded. They are capped at 64 concurrent lookups.
6. A visitor who left the form open past the session idle timeout was treated as having skipped the page. A valid or expired form token now proves the page flow.
7. Mechanical timing included API calls, which would flag single page applications that poll. Only page navigations are sampled now.
8. Cloudflare's testing keys produce responses without hostname or action. They are accepted outside production only, and refused at startup in production.
9. Paid visits from visitors already under restriction were recorded with the score of a request that skipped the counters. They are now recorded as restricted, so they appear in the exclusion report.
10. The network data refresh overflowed the call stack on Apple's 285,000 relay prefixes and produced a 14 MB file. Ranges are now merged into a minimal set of CIDR blocks, which shrinks the file to under 1 MB and cuts load time from about 750 ms to under 100 ms.
11. A single edge secret could not be rotated without rejecting traffic. Two values are accepted during rotation.
12. Policy override files are merged without honouring `__proto__`, `constructor` or `prototype` keys.

## Limitations

The website cannot prevent Google from registering, and billing, a paid click. The click is recorded when it happens on Google's side, before the visitor reaches your servers. Server-side blocking reduces what an abuser gets out of the click (no page, no lead, no conversion credit) and produces evidence for exclusions and investigations, but the charge itself is only reversed by Google's invalid traffic systems.

Sophisticated automation running real browsers through residential proxies, with solved challenges, will get through as individual requests. The system makes it slower and more expensive, prevents it from turning into trusted conversions, and surfaces it in aggregate reports, but cannot reliably separate it from people at the origin.

Turnstile is the strongest human signal in the system and it can be defeated by paid solving services. Requiring it on every lead raises the cost of each fake lead rather than making fake leads impossible.

The browser beacon reports what the page's JavaScript can observe. An attacker can fake it; it only ever adds small amounts of trust or flags obvious automation.

Shared networks force a trade-off. To avoid locking out offices, campuses and mobile carriers, the system never restricts an address shared by more than two established visitors. An attacker on such a network can only be stopped per identity.

During a Redis outage protection continues per instance with local counters. Limits effectively multiply by the number of instances and replay guards become local until Redis returns.

Network classification depends on published ranges and ASN data. Unlisted hosting providers, new cloud regions and residential proxy pools are not recognised as hosting.

Privacy is a design constraint. The system does not use canvas, WebGL, audio or font fingerprinting, and it does not store raw addresses except on suspicious paid visits. That deliberately leaves some identification power unused.
