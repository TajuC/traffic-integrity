import { isChromium, type UserAgentInfo } from '../request/user-agent.ts';
import type { Evidence } from '../risk/types.ts';

export interface ClientHints {
  readonly ua?: string;
  readonly platform?: string;
  readonly mobile?: boolean;
  readonly arch?: string;
  readonly bitness?: string;
  readonly model?: string;
}

export interface TransportFingerprint {
  readonly tls?: string;
  readonly ja3?: string;
  readonly ja4?: string;
  readonly http2?: string;
  readonly headerOrder?: string;
  readonly protocol?: string;
  readonly alpn?: string;
  readonly cipher?: string;
}

export interface ClientSnapshot {
  readonly userAgent?: string;
  readonly platform?: string;
  readonly vendor?: string;
  readonly languages?: readonly string[];
  readonly timezone?: string;
  readonly locale?: string;
  readonly hardwareConcurrency?: number;
  readonly deviceMemory?: number;
  readonly maxTouchPoints?: number;
  readonly touch?: boolean;
  readonly pointerFine?: boolean;
  readonly dpr?: number;
  readonly screen?: readonly [number, number];
  readonly viewport?: readonly [number, number];
  readonly cookieEnabled?: boolean;
  readonly storage?: boolean;
  readonly webdriver?: boolean;
  readonly headless?: boolean;
  readonly selenium?: boolean;
  readonly playwright?: boolean;
  readonly phantom?: boolean;
  readonly chromeRuntime?: boolean;
  readonly safariPush?: boolean;
  readonly installTrigger?: boolean;
  readonly visibilityChanges?: number;
  readonly timingNavMs?: number;
  readonly pointerCv?: number;
  readonly keyCv?: number;
  readonly scrollCv?: number;
  readonly dwellMs?: number;
}

export interface ConsistencyFinding {
  readonly code: string;
  readonly confidence: number;
  readonly evidence: Evidence;
}

export interface ConsistencyInput {
  readonly ua: UserAgentInfo;
  readonly hints: ClientHints;
  readonly snapshot?: ClientSnapshot;
  readonly headerLanguage?: string;
  readonly transport?: TransportFingerprint;
  readonly secure: boolean;
}

export function analyzeConsistency(input: ConsistencyInput): ConsistencyFinding[] {
  const findings: ConsistencyFinding[] = [];
  const { ua, hints, snapshot } = input;
  if (!ua.present || ua.automation || ua.crawler || ua.preview) return findings;

  if (hints.ua && !isChromium(ua) && ua.os !== 'ios') {
    findings.push({ code: 'client.hints_brand_mismatch', confidence: 0.7, evidence: { family: ua.family, engine: ua.engine } });
  }

  if (hints.platform) {
    const hinted = normalizePlatform(hints.platform);
    const desktopAndroid = hinted === 'android' && ua.os === 'linux';
    if (hinted && hinted !== ua.os && !desktopAndroid) {
      findings.push({
        code: 'client.platform_os_mismatch',
        confidence: 0.65,
        evidence: { hinted, claimed: ua.os },
      });
    }
  }

  if (hints.mobile !== undefined) {
    const mobileUa = ua.device === 'mobile' || ua.device === 'tablet';
    if (hints.mobile !== mobileUa && !(ua.os === 'android' && ua.device === 'desktop')) {
      findings.push({
        code: 'client.hints_mobile_mismatch',
        confidence: 0.5,
        evidence: { hintedMobile: hints.mobile, device: ua.device },
      });
    }
  }

  if (snapshot?.platform) {
    const snapOs = platformToOs(snapshot.platform);
    if (snapOs && snapOs !== ua.os && !(snapOs === 'android' && ua.os === 'linux')) {
      findings.push({ code: 'client.impossible_combination', confidence: 0.8, evidence: { jsPlatform: snapshot.platform, uaOs: ua.os } });
    }
  }

  if (ua.family === 'safari' && snapshot?.chromeRuntime === true) {
    findings.push({ code: 'client.feature_family_mismatch', confidence: 0.85, evidence: { family: 'safari', api: 'chrome' } });
  }
  if (ua.family === 'firefox' && snapshot?.chromeRuntime === true) {
    findings.push({ code: 'client.feature_family_mismatch', confidence: 0.8, evidence: { family: 'firefox', api: 'chrome' } });
  }
  if (ua.engine === 'gecko' && snapshot?.safariPush === true) {
    findings.push({ code: 'client.feature_family_mismatch', confidence: 0.55, evidence: { engine: 'gecko', api: 'safariPush' } });
  }
  if (isChromium(ua) && snapshot?.installTrigger === true) {
    findings.push({ code: 'client.feature_family_mismatch', confidence: 0.7, evidence: { family: ua.family, api: 'InstallTrigger' } });
  }

  const mobileClaim = ua.device === 'mobile' || hints.mobile === true;
  if (mobileClaim && snapshot && snapshot.touch === false && (snapshot.maxTouchPoints ?? 0) === 0) {
    findings.push({ code: 'client.mobile_touch_mismatch', confidence: 0.6, evidence: { device: ua.device, maxTouchPoints: snapshot.maxTouchPoints ?? 0 } });
  }

  if (snapshot) {
    const cores = snapshot.hardwareConcurrency;
    if (cores !== undefined && (cores <= 0 || cores > 256)) {
      findings.push({ code: 'client.hardware_inconsistency', confidence: 0.55, evidence: { hardwareConcurrency: cores } });
    }
    const memory = snapshot.deviceMemory;
    if (memory !== undefined && (memory <= 0 || memory > 128)) {
      findings.push({ code: 'client.hardware_inconsistency', confidence: 0.45, evidence: { deviceMemory: memory } });
    }
    const viewport = snapshot.viewport;
    if (viewport && (viewport[0] === 0 || viewport[1] === 0)) {
      findings.push({ code: 'client.hardware_inconsistency', confidence: 0.7, evidence: { viewport: `${viewport[0]}x${viewport[1]}` } });
    }
    const screen = snapshot.screen;
    if (screen && viewport && (viewport[0] > screen[0] * 3 || viewport[1] > screen[1] * 3)) {
      findings.push({ code: 'client.hardware_inconsistency', confidence: 0.4, evidence: { screen: `${screen[0]}x${screen[1]}`, viewport: `${viewport[0]}x${viewport[1]}` } });
    }
    if (snapshot.dpr !== undefined && (snapshot.dpr < 0.5 || snapshot.dpr > 8)) {
      findings.push({ code: 'client.hardware_inconsistency', confidence: 0.4, evidence: { dpr: snapshot.dpr } });
    }
    if (snapshot.cookieEnabled === false && snapshot.storage === false && ua.family === 'chrome') {
      findings.push({ code: 'client.storage_inconsistency', confidence: 0.35, evidence: { cookieEnabled: false, storage: false } });
    }
  }

  if (snapshot?.timezone && input.headerLanguage) {
    const locale = primaryLocale(input.headerLanguage);
    if (locale && timezoneConflictsLocale(snapshot.timezone, locale)) {
      findings.push({
        code: 'client.timezone_locale_mismatch',
        confidence: 0.25,
        evidence: { timezone: snapshot.timezone, locale },
      });
    }
  }

  if (input.transport?.alpn && input.secure) {
    const alpn = input.transport.alpn.toLowerCase();
    if (isChromium(ua) && ua.major !== undefined && ua.major >= 110 && alpn === 'http/1.1' && input.transport.protocol === 'http/1.1') {
      findings.push({ code: 'client.transport_mismatch', confidence: 0.35, evidence: { family: ua.family, alpn } });
    }
  }

  return findings;
}

export function parseClientHints(headers: {
  readonly secChUa?: string;
  readonly secChUaPlatform?: string;
  readonly secChUaMobile?: string;
  readonly secChUaArch?: string;
  readonly secChUaBitness?: string;
  readonly secChUaModel?: string;
}): ClientHints {
  return {
    ua: headers.secChUa,
    platform: headers.secChUaPlatform?.replaceAll('"', '').trim(),
    mobile: parseOptionalBool(headers.secChUaMobile),
    arch: headers.secChUaArch?.replaceAll('"', '').trim(),
    bitness: headers.secChUaBitness?.replaceAll('"', '').trim(),
    model: headers.secChUaModel?.replaceAll('"', '').trim(),
  };
}

function parseOptionalBool(value: string | undefined): boolean | undefined {
  if (value === '?1' || value === '1' || value === 'true') return true;
  if (value === '?0' || value === '0' || value === 'false') return false;
  return undefined;
}

function normalizePlatform(value: string): string | undefined {
  const key = value.replaceAll('"', '').trim().toLowerCase();
  if (key === 'windows') return 'windows';
  if (key === 'macos' || key === 'mac os') return 'macos';
  if (key === 'linux') return 'linux';
  if (key === 'android') return 'android';
  if (key === 'chrome os' || key === 'chromium os') return 'chromeos';
  if (key === 'ios' || key === 'ipados') return 'ios';
  return undefined;
}

function platformToOs(platform: string): string | undefined {
  const value = platform.toLowerCase();
  if (value.startsWith('win')) return 'windows';
  if (value === 'macintel' || value.startsWith('mac')) return 'macos';
  if (value === 'iphone' || value === 'ipad' || value === 'ipod') return 'ios';
  if (value.includes('android')) return 'android';
  if (value === 'linux x86_64' || value === 'linux aarch64' || value === 'linux i686') return 'linux';
  if (value.includes('cros') || value.includes('chrom')) return 'chromeos';
  return undefined;
}

function primaryLocale(header: string): string | undefined {
  const token = header.split(',')[0]?.split(';')[0]?.trim().toLowerCase();
  return token || undefined;
}

function timezoneConflictsLocale(timezone: string, locale: string): boolean {
  const lang = locale.split('-')[0];
  if (!lang) return false;
  if (lang === 'ja' && timezone.startsWith('America/')) return true;
  if (lang === 'he' && timezone.startsWith('America/') && !timezone.includes('Sao_Paulo')) return true;
  if (lang === 'zh' && timezone.startsWith('Europe/') && timezone !== 'Europe/Moscow') return true;
  return false;
}
