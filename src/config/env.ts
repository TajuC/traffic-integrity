import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { parseCidr } from '../net/ip.ts';
import { buildPolicy, type RiskPolicy } from '../risk/policy.ts';

export type Environment = 'development' | 'test' | 'production';
export type EdgeMode = 'off' | 'monitor' | 'enforce';
export type EnforcementMode = 'monitor' | 'enforce';
export type ConversionChallenge = 'always' | 'risk';

export interface Config {
  readonly env: Environment;
  readonly server: { readonly host: string; readonly port: number };
  readonly origin: {
    readonly public: URL;
    readonly allowed: ReadonlySet<string>;
    readonly hostnames: ReadonlySet<string>;
    readonly secure: boolean;
  };
  readonly secrets: { readonly current: string; readonly previous: string | undefined };
  readonly redis: { readonly url: string; readonly keyPrefix: string; readonly commandTimeoutMs: number } | undefined;
  readonly database: { readonly url: string; readonly ssl: 'disable' | 'require' | 'verify-full'; readonly poolMax: number } | undefined;
  readonly proxy: { readonly trusted: readonly string[] };
  readonly edge: { readonly mode: EdgeMode; readonly secrets: readonly string[] };
  readonly turnstile:
    | { readonly siteKey: string; readonly secretKey: string; readonly timeoutMs: number; readonly maxAgeSeconds: number }
    | undefined;
  readonly enforcement: EnforcementMode;
  readonly intel: { readonly path: string; readonly asnDatabasePath: string | undefined; readonly reverseDns: boolean };
  readonly routes: {
    readonly internalPrefix: string;
    readonly apiPrefixes: readonly string[];
    readonly actionPaths: readonly string[];
    readonly bypassPaths: readonly string[];
  };
  readonly cookies: { readonly visitorDays: number };
  readonly conversion: {
    readonly path: string;
    readonly formIds: readonly string[];
    readonly challenge: ConversionChallenge;
    readonly actionName: string;
    readonly value: number | undefined;
    readonly currency: string;
    readonly holdMinutes: number;
    readonly burstPerHour: number;
    readonly timezone: string;
    readonly honeypotField: string;
    readonly phoneCountryCode: string | undefined;
    readonly exportAuth: { readonly username: string; readonly password: string } | undefined;
  };
  readonly admin: { readonly token: string } | undefined;
  readonly logging: { readonly level: string; readonly assessmentSampleRate: number };
  readonly retention: { readonly paidVisitDays: number; readonly attemptDays: number; readonly leadDays: number };
  readonly policy: RiskPolicy;
  readonly warnings: readonly string[];
}

const PLACEHOLDER = /change[-_ ]?me|replace[-_ ]?me|example|placeholder|^x+$/i;
const FORM_ID = /^[a-z0-9_-]{1,24}$/;
const PATH = /^\/[A-Za-z0-9/_.-]*$/;

const flag = z.enum(['true', 'false', 'on', 'off', '1', '0']).transform((v) => v === 'true' || v === 'on' || v === '1');
const list = z.string().transform((v) => v.split(',').map((item) => item.trim()).filter(Boolean));
const threshold = z.coerce.number().min(0).max(100).optional();

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  PUBLIC_ORIGIN: z.url(),
  ALLOWED_ORIGINS: list.default([]),

  INTEGRITY_SECRET: z.string().min(32, 'must be at least 32 characters of random data'),
  INTEGRITY_SECRET_PREVIOUS: z.string().min(32).optional(),

  REDIS_URL: z.string().regex(/^rediss?:\/\//, 'must start with redis:// or rediss://').optional(),
  REDIS_KEY_PREFIX: z.string().regex(/^[A-Za-z0-9:_-]{1,32}$/).default('ti:'),
  REDIS_COMMAND_TIMEOUT_MS: z.coerce.number().int().min(5).max(5000).default(150),

  DATABASE_URL: z.string().regex(/^(postgres(ql)?|pglite):\/\//, 'must be a postgres:// or pglite:// URL').optional(),
  DATABASE_SSL: z.enum(['disable', 'require', 'verify-full']).default('disable'),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),

  TRUSTED_PROXIES: list.default(['loopback']),
  CLOUDFLARE_MODE: z.enum(['off', 'monitor', 'enforce']).default('off'),
  CLOUDFLARE_EDGE_SECRET: list
    .pipe(z.array(z.string().min(24, 'each edge secret must be at least 24 characters')).max(2, 'at most two edge secrets (current and previous)'))
    .optional(),

  TURNSTILE_SITE_KEY: z.string().min(10).optional(),
  TURNSTILE_SECRET_KEY: z.string().min(10).optional(),
  TURNSTILE_TIMEOUT_MS: z.coerce.number().int().min(250).max(10_000).default(2500),
  TURNSTILE_MAX_AGE_SECONDS: z.coerce.number().int().min(30).max(300).default(300),

  ENFORCEMENT_MODE: z.enum(['monitor', 'enforce']).default('monitor'),
  RISK_POLICY_PATH: z.string().optional(),
  RISK_MONITOR_THRESHOLD: threshold,
  RISK_CHALLENGE_THRESHOLD: threshold,
  RISK_RESTRICT_THRESHOLD: threshold,
  RISK_BLOCK_THRESHOLD: threshold,

  NETWORK_INTEL_PATH: z.string().default('data/network-intel.json'),
  ASN_DATABASE_PATH: z.string().optional(),
  CRAWLER_REVERSE_DNS: flag.default(true),

  INTERNAL_PATH_PREFIX: z.string().regex(/^\/[A-Za-z0-9_-]+$/).default('/_ti'),
  API_PREFIXES: list.default(['/api/']),
  SENSITIVE_ACTION_PATHS: list.default([]),
  BYPASS_PATHS: list.default(['/healthz', '/readyz', '/robots.txt', '/favicon.ico', '/sitemap.xml']),
  VISITOR_COOKIE_DAYS: z.coerce.number().int().min(1).max(400).default(180),

  LEAD_PATH: z.string().regex(PATH).default('/api/leads'),
  FORM_IDS: list.default(['contact', 'quote']),
  CONVERSION_CHALLENGE: z.enum(['always', 'risk']).default('always'),
  CONVERSION_ACTION_NAME: z.string().min(1).max(100).default('Qualified lead'),
  CONVERSION_VALUE: z.coerce.number().min(0).optional(),
  CONVERSION_CURRENCY: z.string().regex(/^[A-Z]{3}$/).default('USD'),
  CONVERSION_HOLD_MINUTES: z.coerce.number().int().min(0).max(10_080).default(120),
  CONVERSION_BURST_PER_HOUR: z.coerce.number().int().min(1).max(100_000).default(30),
  CONVERSION_TIMEZONE: z.string().default('UTC'),
  FORM_HONEYPOT_FIELD: z.string().regex(/^[a-z][a-z0-9_]{2,40}$/).default('company_website'),
  PHONE_COUNTRY_CODE: z.string().regex(/^[1-9][0-9]{0,2}$/).optional(),
  EXPORT_USERNAME: z.string().min(3).optional(),
  EXPORT_PASSWORD: z.string().min(16).optional(),

  ADMIN_TOKEN: z.string().min(32).optional(),

  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  ASSESSMENT_LOG_SAMPLE_RATE: z.coerce.number().min(0).max(1).default(0.02),

  PAID_VISIT_RETENTION_DAYS: z.coerce.number().int().min(1).max(730).default(90),
  ATTEMPT_RETENTION_DAYS: z.coerce.number().int().min(1).max(730).default(30),
  LEAD_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(365),
});

export class ConfigError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`invalid configuration:\n  ${issues.join('\n  ')}`);
    this.name = 'ConfigError';
    this.issues = issues;
  }
}

export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  const present = Object.fromEntries(
    Object.entries(source).filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].trim() !== ''),
  );
  const parsed = schema.safeParse(present);
  if (!parsed.success) {
    throw new ConfigError(parsed.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`));
  }
  const env = parsed.data;
  const issues: string[] = [];
  const warnings: string[] = [];
  const production = env.NODE_ENV === 'production';

  const publicOrigin = new URL(env.PUBLIC_ORIGIN);
  if (publicOrigin.origin !== env.PUBLIC_ORIGIN.replace(/\/$/, '')) issues.push('PUBLIC_ORIGIN: must be an origin without a path');
  if (production && publicOrigin.protocol !== 'https:') issues.push('PUBLIC_ORIGIN: must use https in production');

  const allowed = new Set<string>([publicOrigin.origin]);
  const hostnames = new Set<string>([publicOrigin.hostname]);
  for (const origin of env.ALLOWED_ORIGINS) {
    try {
      const url = new URL(origin);
      allowed.add(url.origin);
      hostnames.add(url.hostname);
    } catch {
      issues.push(`ALLOWED_ORIGINS: "${origin}" is not a valid origin`);
    }
  }

  for (const name of ['INTEGRITY_SECRET', 'INTEGRITY_SECRET_PREVIOUS', 'ADMIN_TOKEN', 'EXPORT_PASSWORD'] as const) {
    const value = env[name];
    if (production && value !== undefined && PLACEHOLDER.test(value)) issues.push(`${name}: looks like a placeholder value`);
  }
  if (production && env.CLOUDFLARE_EDGE_SECRET?.some((secret) => PLACEHOLDER.test(secret))) {
    issues.push('CLOUDFLARE_EDGE_SECRET: looks like a placeholder value');
  }

  for (const token of env.TRUSTED_PROXIES) {
    if (token !== 'loopback' && token !== 'private' && !parseCidr(token)) {
      issues.push(`TRUSTED_PROXIES: "${token}" is not loopback, private, an IP or a CIDR`);
    }
  }

  if (env.CLOUDFLARE_MODE === 'enforce' && !env.CLOUDFLARE_EDGE_SECRET?.length) {
    issues.push('CLOUDFLARE_EDGE_SECRET: required when CLOUDFLARE_MODE=enforce');
  }
  if (Boolean(env.TURNSTILE_SITE_KEY) !== Boolean(env.TURNSTILE_SECRET_KEY)) {
    issues.push('TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY must be set together');
  }
  if (production && [env.TURNSTILE_SITE_KEY, env.TURNSTILE_SECRET_KEY].some((key) => key !== undefined && /^[123]x0{10,}/.test(key))) {
    issues.push('TURNSTILE_SITE_KEY / TURNSTILE_SECRET_KEY: Cloudflare testing keys are not allowed in production');
  }
  if (Boolean(env.EXPORT_USERNAME) !== Boolean(env.EXPORT_PASSWORD)) {
    issues.push('EXPORT_USERNAME and EXPORT_PASSWORD must be set together');
  }
  for (const id of env.FORM_IDS) {
    if (!FORM_ID.test(id)) issues.push(`FORM_IDS: "${id}" must match ${FORM_ID.source}`);
  }
  for (const path of [...env.API_PREFIXES, ...env.SENSITIVE_ACTION_PATHS, ...env.BYPASS_PATHS]) {
    if (!PATH.test(path)) issues.push(`route path "${path}" must start with / and contain only URL-safe characters`);
  }
  if (!isTimeZone(env.CONVERSION_TIMEZONE)) issues.push(`CONVERSION_TIMEZONE: "${env.CONVERSION_TIMEZONE}" is not an IANA time zone`);
  if (production && !env.DATABASE_URL) issues.push('DATABASE_URL: required in production');
  if (production && env.DATABASE_URL?.startsWith('pglite:')) issues.push('DATABASE_URL: pglite is for local development only');

  let policy: RiskPolicy | undefined;
  try {
    policy = buildPolicy({
      file: env.RISK_POLICY_PATH ? JSON.parse(readFileSync(env.RISK_POLICY_PATH, 'utf8')) : undefined,
      thresholds: {
        monitor: env.RISK_MONITOR_THRESHOLD,
        challenge: env.RISK_CHALLENGE_THRESHOLD,
        restrict: env.RISK_RESTRICT_THRESHOLD,
        block: env.RISK_BLOCK_THRESHOLD,
      },
    });
  } catch (error) {
    issues.push(`RISK_POLICY: ${error instanceof Error ? error.message : String(error)}`);
  }

  if (issues.length > 0 || !policy) throw new ConfigError(issues);

  if (!env.REDIS_URL) warnings.push('REDIS_URL is not set: counters and replay guards are per-process only');
  if (!env.TURNSTILE_SECRET_KEY) {
    warnings.push('Turnstile is not configured: challenges degrade to monitoring and conversions are held for review');
  }
  if (env.ENFORCEMENT_MODE === 'monitor') warnings.push('ENFORCEMENT_MODE=monitor: decisions are logged but not enforced');
  if (production && env.CLOUDFLARE_MODE === 'off') warnings.push('CLOUDFLARE_MODE=off: edge signals are ignored');

  return {
    env: env.NODE_ENV,
    server: { host: env.HOST, port: env.PORT },
    origin: { public: publicOrigin, allowed, hostnames, secure: publicOrigin.protocol === 'https:' },
    secrets: { current: env.INTEGRITY_SECRET, previous: env.INTEGRITY_SECRET_PREVIOUS },
    redis: env.REDIS_URL
      ? { url: env.REDIS_URL, keyPrefix: env.REDIS_KEY_PREFIX, commandTimeoutMs: env.REDIS_COMMAND_TIMEOUT_MS }
      : undefined,
    database: env.DATABASE_URL ? { url: env.DATABASE_URL, ssl: env.DATABASE_SSL, poolMax: env.DATABASE_POOL_MAX } : undefined,
    proxy: { trusted: env.TRUSTED_PROXIES },
    edge: { mode: env.CLOUDFLARE_MODE, secrets: env.CLOUDFLARE_EDGE_SECRET ?? [] },
    turnstile:
      env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY
        ? {
            siteKey: env.TURNSTILE_SITE_KEY,
            secretKey: env.TURNSTILE_SECRET_KEY,
            timeoutMs: env.TURNSTILE_TIMEOUT_MS,
            maxAgeSeconds: env.TURNSTILE_MAX_AGE_SECONDS,
          }
        : undefined,
    enforcement: env.ENFORCEMENT_MODE,
    intel: { path: env.NETWORK_INTEL_PATH, asnDatabasePath: env.ASN_DATABASE_PATH, reverseDns: env.CRAWLER_REVERSE_DNS },
    routes: {
      internalPrefix: env.INTERNAL_PATH_PREFIX,
      apiPrefixes: env.API_PREFIXES,
      actionPaths: env.SENSITIVE_ACTION_PATHS,
      bypassPaths: env.BYPASS_PATHS,
    },
    cookies: { visitorDays: env.VISITOR_COOKIE_DAYS },
    conversion: {
      path: env.LEAD_PATH,
      formIds: env.FORM_IDS,
      challenge: env.CONVERSION_CHALLENGE,
      actionName: env.CONVERSION_ACTION_NAME,
      value: env.CONVERSION_VALUE,
      currency: env.CONVERSION_CURRENCY,
      holdMinutes: env.CONVERSION_HOLD_MINUTES,
      burstPerHour: env.CONVERSION_BURST_PER_HOUR,
      timezone: env.CONVERSION_TIMEZONE,
      honeypotField: env.FORM_HONEYPOT_FIELD,
      phoneCountryCode: env.PHONE_COUNTRY_CODE,
      exportAuth:
        env.EXPORT_USERNAME && env.EXPORT_PASSWORD ? { username: env.EXPORT_USERNAME, password: env.EXPORT_PASSWORD } : undefined,
    },
    admin: env.ADMIN_TOKEN ? { token: env.ADMIN_TOKEN } : undefined,
    logging: { level: env.LOG_LEVEL, assessmentSampleRate: env.ASSESSMENT_LOG_SAMPLE_RATE },
    retention: {
      paidVisitDays: env.PAID_VISIT_RETENTION_DAYS,
      attemptDays: env.ATTEMPT_RETENTION_DAYS,
      leadDays: env.LEAD_RETENTION_DAYS,
    },
    policy,
    warnings,
  };
}

function isTimeZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}
