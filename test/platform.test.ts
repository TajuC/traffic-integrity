import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { analyzeConsistency } from '../src/observe/consistency.ts';
import { detectCohort } from '../src/observe/cohort.ts';
import { parseUserAgent } from '../src/request/user-agent.ts';
import { assessRisk } from '../src/risk/engine.ts';
import { DEFAULT_POLICY } from '../src/risk/policy.ts';
import { CorrelationEngine } from '../src/intel/graph.ts';
import { BaselineTracker } from '../src/intel/baseline.ts';
import { riskContext, observation } from './helpers/context.ts';
import { START } from './helpers/harness.ts';

const CHROME = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36');
const SAFARI = parseUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15');

describe('browser consistency', () => {
  test('claimed Safari with a Chromium-only API is a high-confidence mismatch', () => {
    const findings = analyzeConsistency({
      ua: SAFARI,
      hints: {},
      snapshot: { chromeRuntime: true, platform: 'MacIntel' },
      secure: true,
    });
    assert.ok(findings.some((finding) => finding.code === 'client.feature_family_mismatch'));
  });

  test('Windows Chrome with a macOS platform hint is flagged', () => {
    const findings = analyzeConsistency({
      ua: CHROME,
      hints: { platform: 'macOS' },
      secure: true,
    });
    assert.ok(findings.some((finding) => finding.code === 'client.platform_os_mismatch'));
  });

  test('a mobile claim without touch support is flagged', () => {
    const findings = analyzeConsistency({
      ua: parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1'),
      hints: { mobile: true },
      snapshot: { touch: false, maxTouchPoints: 0 },
      secure: true,
    });
    assert.ok(findings.some((finding) => finding.code === 'client.mobile_touch_mismatch'));
  });
});

describe('cohorts', () => {
  test('a large established population is treated as shared NAT, not a botnet', () => {
    const ctx = riskContext({
      network: { asn: 64500, asOrg: 'Example Corp', country: 'US', category: 'unclassified', provider: undefined, asnSource: 'database' },
      observation: observation({ address: { requestRate: 400, population: 40 }, network: { population: 40 } }),
    });
    assert.equal(detectCohort(ctx), 'corporate_nat');
    const assessment = assessRisk({ ...ctx, cohort: 'corporate_nat' }, DEFAULT_POLICY);
    assert.equal(assessment.decision, 'ALLOW');
  });
});

describe('graph correlation', () => {
  test('many identities sharing one behavior signature form a cluster', () => {
    const graph = new CorrelationEngine();
    let hit = 0;
    for (let i = 0; i < 10; i += 1) {
      const found = graph.observe({ now: START, visitorId: `v${i}`, addressKey: `a${i}`, networkKey: `n${i}`, behaviorSig: 'same-behavior' });
      hit = Math.max(hit, found.find((item) => item.kind === 'behavior')?.members ?? 0);
    }
    assert.ok(hit >= 8);
  });
});

describe('baselines', () => {
  test('a sudden spike against a stable EWMA is marked', () => {
    const tracker = new BaselineTracker();
    for (let i = 0; i < 20; i += 1) tracker.sample('campaign:1:h12', 4, START + i * 60_000);
    const spike = tracker.sample('campaign:1:h12', 80, START + 21 * 60_000);
    assert.equal(spike.spike, true);
    assert.ok(spike.robustZ >= 4);
  });
});
