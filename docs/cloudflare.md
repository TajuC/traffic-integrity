# Cloudflare

Cloudflare is optional. Everything works without it, but with it the application gets a trustworthy client address, the visitor's ASN and country, Cloudflare's verified bot verdict, the bot score on Enterprise plans, and a way to make the origin unreachable except through your zone. Plan availability below was checked against Cloudflare's documentation in October 2026.

## What the code does

| Behaviour | Where |
| --- | --- |
| Ships Cloudflare's published IP ranges and refreshes them with `npm run intel:refresh` | `src/net/client-address.ts`, `src/net/intel-sources.ts` |
| Uses `CF-Connecting-IP` only when the hop that reached your infrastructure is a Cloudflare address | `ClientAddressResolver` |
| Trusts `x-edge-asn`, `x-edge-verified-bot`, `x-edge-bot-score` and `cf-ipcountry` only when the request also carries the `x-edge-auth` secret, so another Cloudflare account pointed at your origin cannot inject them | `ClientAddressResolver` |
| Records requests that bypass Cloudflare (`CLOUDFLARE_MODE=monitor`) or rejects them with 403 (`enforce`) | `src/guard/inspect.ts` |
| Treats Cloudflare verified bots as verified crawlers, and a verified bot verdict of `false` on a Googlebot or Bingbot claim as impersonation | `src/net/crawler.ts` |
| Uses the bot score as a signal: 1 is critical, 2 to 29 is high, 80 and above earns trust | `src/risk/detectors.ts` |
| Adds the Cloudflare Ray ID to every security event for cross-referencing with Cloudflare logs | `correlation()` |
| Verifies Turnstile tokens server side with hostname, action, cData, age and single-use checks | `src/challenge/turnstile.ts` |

## Dashboard configuration

DNS and TLS. Proxy every hostname that serves the site (orange cloud). Use SSL/TLS mode Full (strict) with a valid origin certificate.

Request header Transform Rules (Rules, Transform Rules, modify request header). Use Set for every header so a value sent by the visitor is always overwritten. Cloudflare does not allow rules to set headers whose names start with `cf-` or `x-cf-`, which is why these use the `x-edge-` prefix.

| Header | Set | Value |
| --- | --- | --- |
| `x-edge-auth` | static | The value of `CLOUDFLARE_EDGE_SECRET` |
| `x-edge-asn` | dynamic | `to_string(ip.src.asnum)` |
| `x-edge-verified-bot` | dynamic | `to_string(cf.client.bot)` |
| `x-edge-bot-score` | dynamic | `to_string(cf.bot_management.score)`, Enterprise Bot Management only |

Turn on IP Geolocation so Cloudflare sends `cf-ipcountry`.

Origin lockdown, strongest first. Cloudflare Tunnel removes the public origin address entirely. Otherwise allow inbound HTTPS at the firewall only from the ranges at https://www.cloudflare.com/ips/, and optionally enable Authenticated Origin Pulls. The `x-edge-auth` secret is the application-level check on top of that; once logs confirm all real traffic carries it, set `CLOUDFLARE_MODE=enforce`.

## WAF custom rules

Free plans allow 5 custom rules, Pro 20 and Business 100. `not cf.client.bot` keeps verified crawlers out of a rule.

| Purpose | Expression | Action |
| --- | --- | --- |
| Only POST reaches the lead endpoint | `http.request.uri.path eq "/api/leads" and http.request.method ne "POST"` | Block |
| Keep admin endpoints off the internet, except the CSV that Google Ads fetches | `starts_with(http.request.uri.path, "/_ti/admin") and http.request.uri.path ne "/_ti/admin/conversions.csv" and not ip.src in {203.0.113.10}` | Block |
| Challenge likely bots on the lead endpoint (Enterprise Bot Management) | `http.request.uri.path eq "/api/leads" and cf.bot_management.score lt 30 and not cf.bot_management.verified_bot` | Managed Challenge |

Replace the example address with your office or VPN egress, or protect `/_ti/admin` with Cloudflare Access instead. The conversion CSV must stay reachable by Google's fetcher and is protected by basic auth.

## Rate limiting rules

Free plans have one rate limiting rule with a 10 second period, counting by IP, with Block or Log as actions. Pro has two rules and adds Managed Challenge; Business has five and can match on method and user agent. A good single rule is the lead endpoint: path equals `/api/leads`, 5 requests per 10 seconds per IP, Managed Challenge where available and Block on Free. The application applies its own NAT-aware limits on top, so keep the edge rule loose enough for shared offices.

## Bot features

Bot Fight Mode (Free) cannot be skipped by WAF rules or Page Rules. If it challenges legitimate API calls or the Google Ads conversion fetch, the only remedy is to turn it off.

Super Bot Fight Mode (Pro and above) lets you choose an action per category: "Definitely automated" (bot score 1, Pro and above), "Likely automated" (scores 2 to 29, Business and above) and "Verified bots". Set verified bots to Allow so Googlebot and AdsBot are never challenged, use Managed Challenge rather than Block for automated traffic, and leave static resource protection off. WAF custom rules with the Skip action run before Super Bot Fight Mode and can exempt specific paths.

Bot Management (Enterprise) exposes `cf.bot_management.score` to rules and, through the Transform Rule above, to this application.

## Turnstile

Create a widget under Turnstile, add every hostname that shows the form, and use Managed mode. Copy the site key and secret key into `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`. Cloudflare's testing keys work locally and are refused in production by the configuration loader.

## Avoiding unnecessary challenges

Do not leave "I'm Under Attack" mode on: it challenges every visitor, including the paid ones you are paying for. Do not put Managed Challenge on landing pages broadly; let the application challenge only the visitors whose evidence justifies it. Keep `not cf.client.bot` in every challenge rule so ad landing page checks and crawlers pass. Do not cache HTML responses that set cookies, and bypass the cache for `/_ti/` and `/api/`.
