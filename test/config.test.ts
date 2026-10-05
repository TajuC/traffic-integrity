import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { ConfigError, loadConfig } from '../src/config/env.ts';
import { BASE_ENV } from './helpers/harness.ts';

const PRODUCTION = {
  NODE_ENV: 'production',
  PUBLIC_ORIGIN: 'https://www.example.com',
  INTEGRITY_SECRET: 'Zq3vR8kP1xW6nB0tY4mC7hJ2sL9dF5gA',
  DATABASE_URL: 'postgres://user:pass@db.internal:5432/traffic',
};

function issues(env: Record<string, string>): readonly string[] {
  try {
    loadConfig(env);
    return [];
  } catch (error) {
    assert.ok(error instanceof ConfigError);
    return error.issues;
  }
}

describe('configuration', () => {
  test('accepts a complete production configuration and reports operational warnings', () => {
    const config = loadConfig(PRODUCTION);
    assert.equal(config.origin.secure, true);
    assert.equal(config.enforcement, 'monitor');
    assert.ok(config.warnings.some((warning) => warning.includes('REDIS_URL')));
    assert.ok(config.warnings.some((warning) => warning.includes('Turnstile')));
  });

  test('rejects insecure or incomplete production settings', () => {
    const found = issues({ ...PRODUCTION, PUBLIC_ORIGIN: 'http://www.example.com', DATABASE_URL: '', INTEGRITY_SECRET: 'change-me-change-me-change-me-change-me' });
    assert.ok(found.some((issue) => issue.startsWith('PUBLIC_ORIGIN')));
    assert.ok(found.some((issue) => issue.startsWith('DATABASE_URL')));
    assert.ok(found.some((issue) => issue.startsWith('INTEGRITY_SECRET')));
  });

  test('refuses Cloudflare testing keys in production', () => {
    const found = issues({ ...PRODUCTION, TURNSTILE_SITE_KEY: '1x00000000000000000000AA', TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA' });
    assert.ok(found.some((issue) => issue.includes('testing keys are not allowed in production')));
  });

  test('requires paired secrets and the edge secret for enforced Cloudflare mode', () => {
    const found = issues({ ...BASE_ENV, TURNSTILE_SECRET_KEY: '', CLOUDFLARE_MODE: 'enforce', EXPORT_PASSWORD: '' });
    assert.ok(found.some((issue) => issue.includes('TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY')));
    assert.ok(found.some((issue) => issue.includes('CLOUDFLARE_EDGE_SECRET')));
    assert.ok(found.some((issue) => issue.includes('EXPORT_USERNAME and EXPORT_PASSWORD')));
  });

  test('validates proxies, form ids, time zones and thresholds', () => {
    const found = issues({ ...BASE_ENV, TRUSTED_PROXIES: 'loopback,not-a-cidr', FORM_IDS: 'quote,Bad Id', CONVERSION_TIMEZONE: 'Mars/Olympus', RISK_CHALLENGE_THRESHOLD: '10' });
    assert.ok(found.some((issue) => issue.includes('not-a-cidr')));
    assert.ok(found.some((issue) => issue.includes('Bad Id')));
    assert.ok(found.some((issue) => issue.includes('Mars/Olympus')));
    assert.ok(found.some((issue) => issue.includes('thresholds must increase')));
  });

  test('never echoes secret values in validation errors', () => {
    const secret = 'short-secret';
    const found = issues({ ...BASE_ENV, INTEGRITY_SECRET: secret });
    assert.ok(found.length > 0);
    assert.ok(found.every((issue) => !issue.includes(secret)));
  });

  test('treats empty values as unset', () => {
    const config = loadConfig({ ...BASE_ENV, REDIS_URL: '', ASN_DATABASE_PATH: '  ' });
    assert.equal(config.redis, undefined);
    assert.equal(config.intel.asnDatabasePath, undefined);
  });
});
