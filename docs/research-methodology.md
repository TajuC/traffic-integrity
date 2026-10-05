# Research methodology

## Threat model

An attacker wants Google Ads to pay for clicks that do not produce qualified
demand, or wants to poison Smart Bidding with fake conversions. The click is
recorded on Google's side before the landing page request reaches the origin.
This software therefore cannot prevent the initial bill. It can detect
suspicious arrivals, withhold page value, keep junk out of conversion exports,
and produce evidence for invalid-click investigations.

Trust boundary: only the origin plus an explicitly authenticated edge (Cloudflare
with `x-edge-auth`) may supply transport fingerprints, bot scores, or client
addresses. Client-supplied JA3, ASN, or bot-score headers are ignored.

## Hypotheses

1. Independent families of evidence (network, client, paid, behavior, edge,
   graph, baseline, consistency) reduce domination by any one spoofable signal.
2. Inconsistency detection is more robust than attempting a globally unique
   browser fingerprint.
3. Distributed low-and-slow campaigns are visible in relationship graphs even
   when per-request scores are low.
4. Campaign-level robust baselines catch bursts that static thresholds miss.
5. A solved CAPTCHA is not a qualified lead.
6. Residential IPs are not proof of legitimacy. Datacenter IPs are not proof of
   fraud.

## Feature definitions

Feature names and order live in `src/model/schema.ts` (`FEATURE_SCHEMA_VERSION`).
They are derived from a `RiskContext` plus a heuristic `RiskAssessment`. The
runtime still decides from rules when no model file is configured. Model output
is advisory unless an operator loads weights and accepts the blend.

Browser consistency features prefer mismatches (Safari plus Chromium APIs,
mobile without touch, Client Hint contradictions) over uniqueness.

## Evaluation methodology

Labeled sessions are constructed in `src/eval/synthetic.ts` with attacker
classes listed in `src/eval/dataset.ts`. `npm run eval` scores each session
with the default policy, computes precision, recall, F1, TPR, FPR, FNR,
specificity, ROC-AUC, PR-AUC, calibration error, a confusion matrix, and
per-class rates.

Train/validation/test splits are used only for the optional logistic fit inside
the same synthetic pool. They do not create an independent real-world holdout.

`npm run adversarial` drives HTTP-level attacker classes through the reference
server. Tests that describe expected gaps (stealth browsers, unique residential
IPs) assert that those gaps still exist.

## Labeling strategy

Production labels (`src/feedback/labels.ts`) require provenance and a
confidence. System labels cannot mark traffic as legitimate. Operator and CRM
labels are the intended training signal. Evaluation labels are synthetic and
must not be mixed into production training without an explicit import path.

## Bias risks

- Synthetic bots over-represent header mistakes and under-represent patched
  browsers.
- NAT, privacy relays, and accessibility tools are easy to over-penalize if
  device signatures are too coarse. Device clustering is disabled unless a
  beacon snapshot is present for that reason.
- Campaign baselines fitted on a new campaign have too few samples to spike.
- Labels from sales teams encode business quality, not bot certainty.

## Limitations

- No production labeled dataset ships with the repository.
- Graph and baseline state is in-process. Multi-instance deployments do not yet
  share those sketches through Redis.
- Fingerprints are inconsistent by design and are spoofable.
- Turnstile can be solved by a paid service.

## Dataset requirements for a later real evaluation

Import anonymized observations with: stable feature schema version, policy
version, decision, later business outcome, and attacker class when known.
Keep raw emails, phones, and full click identifiers out of the training export.
Hash click identifiers with the same keyed digest used in production.

## Reproducibility

```bash
npm ci
npm run eval
npm run adversarial
npm test
```

The evaluation report is deterministic for a given policy version and synthetic
generator. Timestamps in the report are not.
