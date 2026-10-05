# Tuning

Start with `ENFORCEMENT_MODE=monitor`. Every decision is computed and logged exactly as in enforcement, with `enforced: false`, so the numbers below describe what enforcement would have done. Collect at least one to two weeks, including a weekend and a campaign change, before enforcing.

## What to measure

Metrics are served by `/_ti/metrics` with the admin bearer token. The four that matter most:

| Measure | How | Healthy | Action when outside |
| --- | --- | --- | --- |
| Share of page traffic that would be challenged | `sum(rate(ti_assessments_total{route="page",decision="CHALLENGE"}[1d])) / sum(rate(ti_assessments_total{route="page"}[1d]))` | Well under 2 percent outside an attack | Find the dominant reason in `ti_signals_total` and lower its points or raise its limit |
| Challenge pass rate | `sum(rate(ti_challenges_total{kind="clearance",outcome="passed"}[1d])) / sum(rate(ti_challenges_total{kind="page",outcome="issued"}[1d]))` | Low. Bots rarely pass | A high pass rate means humans are being challenged: raise `RISK_CHALLENGE_THRESHOLD` or reduce the signal that drives it |
| Conversions held for review | `ti_conversions_total{status="review"}` against `pending` | A small minority | Check `decision_reason` in `ti_conversions`; adjust `conversion.trustedMaxScore` or the responsible signal |
| Local store fallbacks | `ti_store_fallbacks_total` | Zero | Fix Redis sizing, latency or `REDIS_COMMAND_TIMEOUT_MS` |

Also watch `ti_assessment_duration_seconds` (the Redis round trip dominates), `ti_turnstile_duration_seconds`, and `ti_paid_visit_writes_total{result!="written"}`.

## Investigation queries

Campaigns receiving suspicious traffic:

```sql
SELECT coalesce(gad_campaign_id, utm_campaign, 'unknown') AS campaign,
       count(*) AS paid_visits,
       count(*) FILTER (WHERE risk_score >= 20) AS suspicious,
       round(100.0 * count(*) FILTER (WHERE risk_score >= 20) / count(*), 1) AS suspicious_pct
FROM ti_paid_visits
WHERE landed_at > now() - interval '7 days'
GROUP BY 1
ORDER BY suspicious DESC;
```

ASNs producing abnormal paid traffic:

```sql
SELECT asn, as_org, network_category, count(*) AS paid_visits, count(DISTINCT visitor_id) AS visitors,
       count(*) FILTER (WHERE decision IN ('CHALLENGE', 'TEMPORARILY_RESTRICT', 'BLOCK')) AS enforced
FROM ti_paid_visits
WHERE landed_at > now() - interval '7 days' AND asn IS NOT NULL
GROUP BY 1, 2, 3
ORDER BY enforced DESC, paid_visits DESC
LIMIT 25;
```

Networks that keep resetting identities:

```sql
SELECT network_prefix, count(*) AS paid_visits,
       count(*) FILTER (WHERE identity <> 'returning') AS fresh_identities,
       count(DISTINCT visitor_id) AS visitors
FROM ti_paid_visits
WHERE landed_at > now() - interval '7 days'
GROUP BY 1
HAVING count(*) >= 10
ORDER BY fresh_identities DESC
LIMIT 25;
```

Visitors who repeatedly arrive through ads:

```sql
SELECT visitor_id, count(*) AS paid_arrivals, count(DISTINCT date_trunc('day', landed_at)) AS days,
       min(landed_at) AS first_seen, max(landed_at) AS last_seen, max(risk_score) AS worst_score
FROM ti_paid_visits
WHERE landed_at > now() - interval '30 days'
GROUP BY 1
HAVING count(*) >= 4
ORDER BY paid_arrivals DESC
LIMIT 50;
```

Rules behind challenges of paid visitors:

```sql
SELECT reason, count(*) AS visits
FROM ti_paid_visits, unnest(reasons) AS reason
WHERE decision = 'CHALLENGE' AND landed_at > now() - interval '7 days'
GROUP BY 1
ORDER BY 2 DESC;
```

Lead attempts by outcome (refusals before the database are counted in `ti_conversions_total{status="rejected"}` and logged as `conversion_rejected` with `stage: preliminary`):

```sql
SELECT status, verification, count(*)
FROM ti_conversion_attempts
WHERE created_at > now() - interval '7 days'
GROUP BY 1, 2
ORDER BY 3 DESC;
```

A false positive trend indicator, challenged paid visitors who later became qualified customers:

```sql
SELECT date_trunc('week', c.created_at) AS week, count(*) AS qualified_after_challenge
FROM ti_conversions c
JOIN ti_leads l ON l.id = c.lead_id
WHERE c.status = 'qualified'
  AND EXISTS (SELECT 1 FROM ti_paid_visits p WHERE p.visitor_id = l.visitor_id AND p.decision = 'CHALLENGE')
GROUP BY 1
ORDER BY 1;
```

The same questions can be answered from the logs: every event carries `event`, `reasons`, `decision`, `campaign`, `asn`, `networkPrefix`, `visitorId` and the Cloudflare `ray`.

## Adjusting the policy

Thresholds can be set with `RISK_MONITOR_THRESHOLD`, `RISK_CHALLENGE_THRESHOLD`, `RISK_RESTRICT_THRESHOLD` and `RISK_BLOCK_THRESHOLD`. Anything else goes into a JSON file referenced by `RISK_POLICY_PATH`; only the keys you include change, and the result is validated at startup:

```json
{
  "version": "site-2026-11",
  "points": { "network.hosting": 15 },
  "limits": {
    "visitorPaidClicks": { "per5m": 4, "per1h": 8, "extremeFactor": 2 },
    "addressRequestsPerMinute": { "base": 300, "perMember": 40, "extremeFactor": 3 }
  },
  "conversion": { "trustedMaxScore": 25 }
}
```

Typical adjustments:

| Situation | Change |
| --- | --- |
| Audience that commonly uses VPNs | Lower `network.hosting` points |
| Large offices or campuses among your customers | Raise `addressRequestsPerMinute.base` |
| Long consideration cycles where people click your ad several times a day | Raise `visitorPaidClicks.per1h` |
| Single page application with frequent API calls | Raise `visitorRequestsPerMinute`, or list polling endpoints in `BYPASS_PATHS` |
| Larger advertiser with heavy volume from major ISPs | Raise `asnPaidClicksPer5m` |
| More leads than expected in review | Inspect `decision_reason`; raise `conversion.trustedMaxScore` only if the reviewed leads are genuine |
| `CONVERSION_BURST_PER_HOUR` | Set to about three times your busiest normal hour |

## Moving to enforcement

Enforcement is all or nothing per instance, so phase it in through thresholds. Switch to `ENFORCEMENT_MODE=enforce` with raised thresholds (for example challenge 60, restrict 80, block 95), watch the challenge pass rate for a few days, then lower them step by step toward the defaults. Re-check after every campaign launch, landing page change or new traffic source.
