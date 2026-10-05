# Risk model

## Concepts

A `RiskContext` holds everything known about one request: route class, header facts, parsed user agent, crawler verdict, resolved address and Cloudflare signals, network profile, identity state, attribution, the counter observation from the shared store, challenge clearance, authentication and, for lead submissions, the action facts (honeypot, form token state, form age, origin, repeated message count).

Detectors read the context and emit `RiskSignal`s. Each signal has a reason code, a family, a severity and points. Family and severity are fixed per reason in `src/risk/types.ts`; points and every limit live in the `RiskPolicy` in `src/risk/policy.ts`, which can be overridden by a JSON file (`RISK_POLICY_PATH`) and by threshold environment variables without touching request handlers. Unknown keys and non-increasing thresholds are rejected at startup.

The engine produces a `RiskAssessment`: score from 0 to 100, decision, signals,
per-family subtotals, trust credit, confidence (`full` or `reduced` when data was
degraded), numeric confidence, policy version, detector version, feature schema
version, optional model version and fraud probability, optional shadow decision,
and cohort.

Signals include source, family, severity, points, optional raw/normalized values,
timestamp, explanation, detector version, and a confidence in 0-1. Assessments are
reproducible from the recorded context and the same policy version.

## Scoring

1. Signals are grouped by family: network, client, paid, behavior, edge, graph, baseline and consistency. Within a family the points are sorted and combined with diminishing returns (each further signal counts half as much as the previous one), then capped. Correlated evidence about the same thing therefore cannot pile up without limit.
2. Family subtotals are added and capped at 100.
3. Trust signals add up to a credit capped at 35. The credit is halved when any high-severity signal is present and removed entirely when any critical signal is present, so one positive signal cannot cancel severe evidence.
4. The score is compared with the thresholds of the route class.
5. Gates then apply: `BLOCK` needs high-severity signals in at least two families, otherwise it becomes `TEMPORARILY_RESTRICT`; `TEMPORARILY_RESTRICT` needs at least one high or critical signal, otherwise it becomes `CHALLENGE`; `CHALLENGE` needs a high signal or at least two signals, otherwise it becomes `ALLOW_AND_MONITOR`.
6. Overrides: a verified crawler is always `ALLOW` on pages and APIs, and a valid challenge clearance turns `CHALLENGE` into `ALLOW_AND_MONITOR`.

| Family | Cap |
| --- | --- |
| network | 45 |
| client | 45 |
| paid | 45 |
| behavior | 75 |
| edge | 60 |
| graph | 40 |
| baseline | 35 |
| consistency | 40 |

| Threshold | Pages and APIs | Lead submissions and sensitive actions |
| --- | --- | --- |
| Monitor | 20 | 15 |
| Challenge | 45 | 30 |
| Restrict | 70 | 60 |
| Block | 90 | 85 |

A lead becomes a trusted (pending) conversion only when its score is below `conversion.trustedMaxScore` (30) and no high or critical signal fired.

## Signals

Points are the defaults. The population used for scaling is the number of distinct established visitors (cookie at least one hour old) seen from the same address or network in the last twelve to twenty-four hours.

| Reason | Severity | Points | Fires when |
| --- | --- | --- | --- |
| `network.hosting` | medium | 22 | Address is in a published cloud range or the ASN is a known hosting provider |
| `network.tor` | medium | 18 | Address is a Tor exit, or Cloudflare reports country `T1` |
| `network.origin_bypass` | high | 40 | Cloudflare is expected but the request did not come through your zone (monitor mode; enforce mode rejects outright) |
| `network.address_velocity` | medium | 15 | Requests per minute from the address exceed 180 plus 40 per established visitor |
| `network.address_velocity_extreme` | high | 35 | Three times that limit |
| `network.identity_churn` | medium | 20 | Fresh identities from the network exceed 20 per hour plus 3 per established visitor; applied only to visitors without a returning identity |
| `network.identity_churn_extreme` | high | 35 | Twice that limit |
| `network.paid_velocity` | medium | 18 | Distinct paid clicks from the network exceed 6 per 5 minutes or 15 per hour, plus 3 per established visitor |
| `network.paid_velocity_extreme` | high | 32 | Twice that limit |
| `network.asn_paid_burst` | low | 10 | More than 40 distinct paid clicks from one ASN in 5 to 10 minutes |
| `network.conversion_velocity` | high | 30 | Lead submissions from the network exceed 6 per hour plus 1 per established visitor |
| `client.user_agent_missing` | medium | 25 | Page, action or lead request without a user agent |
| `client.automation_tool` | high | 35 | User agent names an HTTP library or headless browser, or client hints list HeadlessChrome |
| `client.crawler_impersonation` | high | 45 | A crawler claim is disproven by fresh published ranges, reverse DNS or Cloudflare |
| `client.hints_brand_mismatch` | medium | 20 | Chromium client hints sent by a browser claiming to be Safari or Firefox |
| `client.hints_platform_mismatch` | low | 10 | `sec-ch-ua-platform` contradicts the operating system in the user agent |
| `client.hints_missing` | low | 8 | Modern Chrome or Edge over HTTPS sends fetch metadata but no client hints |
| `client.fetch_metadata_missing` | low | 10 | Modern Chrome, Edge or Firefox navigates over HTTPS without `Sec-Fetch-*` headers |
| `client.navigation_accept_missing` | medium | 15 | A page navigation does not accept `text/html` |
| `client.accept_language_missing` | low | 8 | A page navigation has no `Accept-Language` |
| `client.forged_identity` | medium | 15 | The visitor cookie failed signature verification |
| `client.script_automation` | high | 35 | The beacon reported webdriver, headless, Selenium, Playwright or PhantomJS artifacts, no languages or a zero viewport |
| `paid.visitor_click_velocity` | high | 30 | One visitor produced more than 3 distinct click identifiers in 5 minutes or 6 in an hour |
| `paid.visitor_click_velocity_extreme` | critical | 45 | Twice that limit |
| `paid.click_reuse` | medium | 18 | One click identifier was seen from 3 or more identities |
| `paid.click_reuse_extreme` | high | 30 | From 6 or more identities |
| `paid.malformed_attribution` | low | 6 | Click or campaign parameters are malformed, oversized or conflicting |
| `behavior.visitor_velocity` | medium | 20 | Visitor request rate of 90 per minute or more |
| `behavior.visitor_velocity_extreme` | critical | 70 | 300 per minute or more |
| `behavior.mechanical_timing` | medium | 20 | At least 8 page navigations with a mean gap under 15 seconds and a coefficient of variation under 0.12 |
| `behavior.action_velocity` | high | 35 | More than 20 sensitive actions per 10 minutes |
| `behavior.conversion_velocity` | high | 40 | More than 4 lead submissions per visitor per day |
| `behavior.repeat_offender` | medium | 15 | The visitor (or a personal address) was restricted in the last day |
| `behavior.repeat_offender_extreme` | high | 30 | Restricted three or more times |
| `behavior.direct_sensitive_access` | high | 30 | A lead or action arrives without a returning identity, or with no page view in the session when no form token proves the page flow |
| `behavior.script_unverified` | low | 8 | The visitor never completed the beacon handshake |
| `behavior.origin_missing` | medium | 20 | A lead submission has no `Origin` header |
| `behavior.honeypot` | high | 40 | The hidden form field was filled |
| `behavior.form_too_fast` | medium | 25 | The form was submitted less than 2.5 seconds after its token was issued |
| `behavior.form_token_missing` | high | 35 | No form token |
| `behavior.form_token_invalid` | high | 35 | Form token tampered with or bound to another visitor or form |
| `behavior.form_token_expired` | low | 8 | Form token older than two hours |
| `behavior.form_token_replayed` | critical | 60 | Form token already used by another submission |
| `behavior.repeated_message` | medium | 20 | The same message text came from 3 or more contacts in 24 hours |
| `edge.bot_score_automated` | critical | 55 | Cloudflare Bot Management score of 1 |
| `edge.bot_score_likely` | high | 35 | Score from 2 to 29 |
| `client.impossible_combination` | high | 32 | Claimed platform and observed JS/UA facts cannot both be true |
| `client.platform_os_mismatch` | medium | 18 | Client hint platform contradicts the User-Agent OS |
| `client.mobile_touch_mismatch` | medium | 16 | Mobile claim without touch support |
| `client.feature_family_mismatch` | high | 30 | Safari/Firefox claim with Chromium-only APIs |
| `client.hardware_inconsistency` | low | 10 | Implausible cores, memory, viewport, or DPR |
| `graph.behavior_cluster` | high | 28 | Many identities share one behavioral signature |
| `graph.timing_cluster` | high | 24 | Many identities share one timing profile |
| `graph.click_cluster` | high | 30 | One click identifier clusters across more identities than link sharing explains |
| `graph.lead_cluster` | high | 32 | Normalized lead content repeats across identities |
| `baseline.campaign_spike` | high | 26 | Campaign paid volume exceeds its robust (MAD) baseline |
| `baseline.conversion_rate_drop` | medium | 16 | Conversion rate dropped while paid clicks rose |
| `baseline.asn_dominance` | medium | 14 | One ASN suddenly dominates a previously mixed campaign |

| Trust signal | Credit | Fires when |
| --- | --- | --- |
| `trust.established_visitor` | 12 | Cookie at least 24 hours old with at least two sessions |
| `trust.engaged_session` | 10 | Three or more page views over at least a minute with real interaction |
| `trust.script_verified` | 6 | Beacon verified with no automation flags |
| `trust.human_interaction` | 6 | Pointer, keyboard, scroll or touch activity reported |
| `trust.challenge_passed` | 25 | Valid Turnstile clearance |
| `trust.authenticated_user` | 15 | The host application reports a signed-in user |
| `trust.prior_conversion` | 8 | The visitor has an accepted lead (not applied to new lead submissions) |
| `trust.edge_likely_human` | 10 | Cloudflare bot score of 80 or more |

## Decisions and enforcement

| Decision | Pages | APIs and sensitive actions | Lead endpoint |
| --- | --- | --- | --- |
| `ALLOW` | Served | Served | Pipeline continues |
| `ALLOW_AND_MONITOR` | Served and logged | Served and logged | Pipeline continues; conversion not trusted if the score reaches the trusted maximum |
| `CHALLENGE` | 403 interstitial with Turnstile; on success a 30 minute clearance is issued and the same URL reloads | 403 JSON with challenge parameters; `TrafficIntegrity.guardedFetch` clears and retries | Turnstile token required in the submission |
| `TEMPORARILY_RESTRICT` | 429 with `Retry-After` | 429 | 429 |
| `BLOCK` | 403 | 403 | 403 |

A restriction applies to the visitor identity and, only when no more than two established visitors share it, to the address. It lasts ten minutes (one hour for a block) multiplied by one plus the recent strike count, capped at four times. While it lasts, requests are answered from an in-process cache without touching Redis. Nothing is permanent. If Turnstile is not configured, `CHALLENGE` degrades to monitoring.

External responses never reveal reason codes. They are limited to `rate_limited`, `request_rejected`, `verification_required`, `verification_failed`, `invalid_request` with field names, and `temporarily_unavailable`.

## False-positive protections

Network, client and paid evidence are each capped at 45 points, which equals the challenge threshold, so none of them alone can restrict or block. A restriction needs high-severity evidence and a block needs high-severity evidence from two independent families.

Corporate offices, universities, hotels and mobile carriers are handled by scaling every address and network limit with the established population behind it. That population only counts visitors whose cookie is at least an hour old, so an attacker cannot inflate it by rotating cookies. Established visitors never receive the identity churn signal, addresses are only restricted when two or fewer established visitors use them, and an address's restriction history only counts against it when it is personal.

VPN and cloud egress is a medium signal on its own. Apple Private Relay egress is recognised and excluded from network-level churn and paid velocity checks, because thousands of unrelated people share it.

Unusual browsers and privacy settings only produce low or medium signals. WebKit browsers on iOS are exempt from client hint checks, Android desktop mode is recognised, and fetch metadata and client hint checks only run over HTTPS where browsers actually send those headers. A missing beacon is a low signal and only matters on lead submissions.

Returning customers accumulate trust, and paid click limits are per five minutes and per hour, so clicking ads on different days is normal. A shared link that carries a `gclid` needs three separate identities before it is even a medium signal, and link preview bots are never counted as visitors.

When the shared store is degraded, checks that depend on session history are skipped and the assessment is marked as reduced confidence. Every new deployment starts in `ENFORCEMENT_MODE=monitor`, so the rules can be measured against real traffic before they act on it, and a visitor who is challenged on a form never loses what they typed.
