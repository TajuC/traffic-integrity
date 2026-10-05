# Production readiness

Scores are 0-10. A 9 or 10 requires production evidence this repository does
not yet have. None of the categories below is a 9.

## Scorecard

| Category | Score | What blocks a higher score |
| --- | --- | --- |
| Architecture | 8 | Observation, detection, scoring, policy, enforcement, and feedback are separated. Graph and baseline state is still in-process, so multiple instances do not share those sketches. |
| Code quality | 8 | Typed, tested, linted. Some new event writes are per-row rather than copy-based batches. |
| Security | 8 | Trusted-proxy and edge-auth rules remain strict. Transport fingerprints are ignored unless the edge secret matches. Admin metrics stay behind a bearer token. Not a full independent pentest. |
| Bot detection | 7 | Obvious automation, scripted HTTP, and naive headless browsers are caught in tests. Stealth browsers and unique residential IPs are not, by construction. |
| Distributed fraud detection | 7 | Correlation exists for behavior, timing, click reuse, campaign/ASN, and lead content. It is not a durable shared graph store. |
| False-positive protection | 8 | Family caps, two-family block gate, NAT scaling, cohort dampening, and no single-signal blocks remain. Device clustering was deliberately not keyed off User-Agent alone after it failed a NAT test. |
| Conversion protection | 8 | Signed form tokens, replay guards, hold period, burst breaker, and server-side export remain. Patient unique-contact spam can still create review-queue leads. |
| Click-abuse mitigation | 7 | Evidence bundles, exclusion candidates, spend-at-risk estimates, and campaign recommendations exist. Google Ads changes never apply automatically. The click bill itself is out of scope. |
| Production maturity | 7 | Shadow and monitor modes, policy versions, migrations, and a circuit breaker ship. There is no load test at 5,000 req/s in CI and no trained production model. |
| Observability | 7 | Prometheus metrics include decisions, signals, shadow would-enforce counts, clusters, and model scores. Structured logs keep correlation ids. Event storage depends on Postgres being migrated. |
| Scalability | 6 | Request-path scoring is still one Redis round trip plus in-process work. Graph/baseline memory is bounded but not clustered. Assessment inserts are sequential. |
| Resilience | 7 | Redis fail-open, Postgres fail-closed on conversions, Turnstile fail-open on pages. Mixed-version rolling deploys are policy-versioned but not compatibility-tested in CI. |
| Empirical validation | 5 | Unit, HTTP, adversarial, and synthetic evaluation tests exist. There is no labeled production dataset. See [evaluation-results.md](evaluation-results.md). |
| Research quality | 7 | Threat model, hypotheses, synthetic generator, and an evaluation harness exist. The methodology is honest about gaps. It is not a peer-reviewed measurement study. |
| Documentation | 8 | Architecture, risk model, deployment, Google Ads, Cloudflare, and this scorecard. Residual limitations are stated in the README. |

## Recommended first deployment

1. `ENFORCEMENT_MODE=shadow` or `monitor`.
2. Cloudflare in front with `CLOUDFLARE_MODE=enforce` and an edge secret.
3. Redis on the same host or AZ.
4. Postgres with both migrations applied.
5. Watch `/_ti/admin/summary.json` and Prometheus `ti_shadow_decisions_total`
   before switching to `enforce`.
6. Do not load a model file until you have operator labels and a holdout.

## What this is

A measurable origin-side traffic-integrity platform: detection, mitigation,
conversion protection, and evidence generation for Google Ads invalid-click
work.

## What this is not

A system that can guarantee Google will not bill a click, reverse a charge, or
catch patched residential automation one request at a time.
