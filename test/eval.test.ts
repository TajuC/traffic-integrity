import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { assessRisk } from '../src/risk/engine.ts';
import { DEFAULT_POLICY } from '../src/risk/policy.ts';
import { syntheticCases } from '../src/eval/synthetic.ts';
import { runEvaluation } from '../src/eval/run.ts';

const ACTIONABLE = new Set(['CHALLENGE', 'TEMPORARILY_RESTRICT', 'BLOCK']);

describe('synthetic evaluation', () => {
  test('produces a complete report from labeled synthetic sessions', () => {
    const report = runEvaluation();
    assert.ok(report.n > 50);
    assert.ok(report.precision >= 0);
    assert.ok(report.recall >= 0);
    assert.ok(report.notes.some((note) => note.includes('synthetic')));
    assert.ok(report.perClass.some((row) => row.clazz === 'scripted_http' && (row.recall ?? 0) >= 0.9));
    assert.ok(report.perClass.some((row) => row.clazz === 'legitimate' && (row.falsePositiveRate ?? 1) <= 0.1));
  });

  test('records expected origin-side failures for stealth and residential rotation', () => {
    const stealth = syntheticCases().filter((item) => item.clazz === 'stealth_automation');
    const missed = stealth.filter((item) => !ACTIONABLE.has(assessRisk(item.context, DEFAULT_POLICY).decision));
    assert.ok(missed.length > 0, 'stealth automation should remain an origin-side gap');
    const residential = syntheticCases().filter((item) => item.clazz === 'residential_proxy');
    const allowed = residential.filter((item) => !ACTIONABLE.has(assessRisk(item.context, DEFAULT_POLICY).decision));
    assert.ok(allowed.length > 0, 'unique residential IPs with real browser headers should often be allowed');
  });
});
