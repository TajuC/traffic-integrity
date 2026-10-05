import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { acceptLabel } from '../src/feedback/labels.ts';
import { proposeEdgeAction } from '../src/upstream/lists.ts';
import { campaignRecommendation, spendAtRisk } from '../src/ads/recommendations.ts';
import { evidenceBundle } from '../src/ads/evidence.ts';
import type { RequestIntegrity } from '../src/guard/inspect.ts';
import { scoreLogistic, trainLogistic } from '../src/model/logistic.ts';
import { FEATURE_NAMES, type FeatureVector } from '../src/model/schema.ts';

describe('feedback poisoning guards', () => {
  test('rejects system labels that are not duplicate or spam', () => {
    assert.equal(
      acceptLabel({
        subjectType: 'visitor',
        subjectId: 'v1',
        label: 'legitimate',
        source: 'system',
        confidence: 1,
        provenance: 'auto',
      }),
      undefined,
    );
  });

  test('accepts operator labels with provenance', () => {
    const accepted = acceptLabel({
      subjectType: 'assessment',
      subjectId: 'a1',
      label: 'fraud',
      source: 'operator',
      confidence: 0.9,
      provenance: 'analyst-queue',
    });
    assert.ok(accepted);
    assert.equal(accepted?.label, 'fraud');
  });
});

describe('upstream lists', () => {
  test('does not propose an edge block from weak evidence', () => {
    assert.equal(
      proposeEdgeAction({
        decision: 'ALLOW_AND_MONITOR',
        numericConfidence: 0.4,
        clusterSize: 1,
        personalAddress: true,
        ipHash: 'abc',
        reasons: ['network.hosting'],
      }),
      undefined,
    );
  });

  test('proposes a short-lived challenge for a high-confidence cluster', () => {
    const proposed = proposeEdgeAction({
      decision: 'TEMPORARILY_RESTRICT',
      numericConfidence: 0.94,
      clusterSize: 20,
      personalAddress: true,
      ipHash: 'abc',
      reasons: ['graph.behavior_cluster'],
    });
    assert.ok(proposed);
    assert.ok(proposed.ttlSeconds <= 1800);
  });
});

describe('google ads recommendations', () => {
  test('never marks campaign changes as automatic', () => {
    const rec = campaignRecommendation({ campaign: '1', visits: 100, suspicious: 80, cpcUsd: 2 });
    assert.equal(rec.applyAutomatically, false);
    assert.equal(spendAtRisk(80, 2), 160);
    assert.ok(rec.note.includes('cannot stop Google'));
  });

  test('evidence bundles hash click identifiers instead of copying them', () => {
    const bundle = evidenceBundle({
      now: Date.parse('2026-10-05T12:00:00.000Z'),
      identity: { visitorId: 'v1', sessionId: 's1', origin: 'new', issuedAt: 0 },
      subject: { addressKey: 'addr-key', networkKey: 'net-key', networkPrefix: '203.0.113.0/24' },
      attribution: {
        primary: { type: 'gclid', value: 'Cj0KCQjwSecretClickId' },
        clickIds: { gclid: 'Cj0KCQjwSecretClickId' },
        gadCampaignId: '99',
        gadSource: undefined,
        utm: {},
      },
      context: { network: { category: 'unclassified', asnSource: 'none' } },
      assessment: {
        id: '00000000-0000-4000-8000-000000000001',
        score: 40,
        decision: 'ALLOW_AND_MONITOR',
        signals: [],
        families: {},
        trustCredit: 0,
        confidence: 'full',
        numericConfidence: 0.8,
        degraded: [],
        policyVersion: '2026.10.2',
        detectorVersion: '1',
        featureSchemaVersion: '1',
      },
    } as unknown as RequestIntegrity);
    assert.equal(bundle.clickHash?.length, 32);
    assert.notEqual(bundle.clickHash, 'addr-key');
    assert.ok(!JSON.stringify(bundle).includes('Cj0KCQjwSecretClickId'));
    assert.match(bundle.limitation, /cannot reverse/);
  });
});

describe('logistic model', () => {
  test('learns a separable synthetic pattern', () => {
    const vector = (hosting: number, automation: number): FeatureVector => ({
      schemaVersion: '1',
      names: FEATURE_NAMES,
      values: FEATURE_NAMES.map((name) => (name === 'hosting' ? hosting : name === 'automation_ua' ? automation : 0)),
    });
    const model = trainLogistic(
      [
        { vector: vector(1, 1), label: 1 },
        { vector: vector(1, 1), label: 1 },
        { vector: vector(0, 0), label: 0 },
        { vector: vector(0, 0), label: 0 },
      ],
      { iterations: 200, learningRate: 0.5, l2: 0 },
    );
    assert.ok(scoreLogistic(model, vector(1, 1)).probability > scoreLogistic(model, vector(0, 0)).probability);
  });
});
