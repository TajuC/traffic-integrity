# Security Policy

## Scope

Traffic Integrity sits on the origin of a website that buys paid traffic. It
resolves client addresses, issues signed cookies, talks to Redis and PostgreSQL,
verifies Cloudflare Turnstile tokens, and decides which leads may be reported
to Google Ads. The relevant concerns are authentication of edge signals,
integrity of visitor identity, replay of challenge and form tokens, and keeping
unqualified conversions out of bidding data.

## Trust boundaries and accepted risks

The guard fails open when Redis is unreachable: requests are assessed against
the in-process store for that instance, replay guards become per-process, and
the process continues serving. That is deliberate. A Redis outage must not take
the site down. Operators who need fail-closed behavior should fail at the load
balancer, not inside this library.

Cloudflare Bot Management, Google's own invalid-traffic filters, and residential
proxy quality are outside this repository. This origin cannot see a click before
Google records it, and it cannot see more about a household IP than the request
headers and the local network tables provide.

## Change control

The default branch is protected: a change reaches `main` only through a pull
request whose required status checks (typecheck and lint, the test suite
including Redis, and secret scanning) all pass. They are enforced for every
contributor. Administrator enforcement (`enforce_admins`) and required reviews
are left off while the project has a single maintainer; they are the obvious
next controls if that changes.

## Supported versions

Security fixes target the latest commit on the default branch.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through GitHub Security Advisories, using "Report a vulnerability" on the
repository Security tab.

Include the affected version or commit, a description of the issue, and a
minimal reproduction if you have one. You can expect an initial response within
a few days.
