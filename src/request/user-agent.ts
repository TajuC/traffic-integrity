import type { CrawlerClaim, CrawlerOperator } from '../net/crawler.ts';

export type BrowserFamily = 'chrome' | 'edge' | 'opera' | 'samsung' | 'chromium' | 'firefox' | 'safari' | 'other';
export type Engine = 'blink' | 'gecko' | 'webkit' | 'unknown';
export type OsFamily = 'windows' | 'macos' | 'ios' | 'android' | 'linux' | 'chromeos' | 'other';
export type DeviceType = 'mobile' | 'tablet' | 'desktop' | 'unknown';

export interface UserAgentInfo {
  readonly present: boolean;
  readonly family: BrowserFamily;
  readonly major: number | undefined;
  readonly engine: Engine;
  readonly os: OsFamily;
  readonly device: DeviceType;
  readonly automation: string | undefined;
  readonly crawler: CrawlerClaim | undefined;
  readonly preview: string | undefined;
}

const MAX_UA_LENGTH = 512;

const AUTOMATION: ReadonlyArray<readonly [RegExp, string]> = [
  [/HeadlessChrome/, 'headless-chrome'],
  [/PhantomJS/, 'phantomjs'],
  [/Selenium|Puppeteer|Playwright|Cypress/i, 'browser-automation'],
  [/\bcurl\//i, 'curl'],
  [/\bWget\//i, 'wget'],
  [/python-requests|python-urllib|python-httpx|aiohttp|\bPython\/\d/i, 'python'],
  [/Go-http-client/, 'go'],
  [/\bJava\/\d|Apache-HttpClient|\bokhttp\//i, 'jvm'],
  [/^node$|\baxios\/|node-fetch|\bundici\b/i, 'node'],
  [/libwww-perl|\bLWP::|WWW-Mechanize/i, 'perl'],
  [/Scrapy/i, 'scrapy'],
  [/PostmanRuntime|insomnia\/|HTTPie\//i, 'api-client'],
  [/\bFaraday v|^Ruby$|\bmechanize\b/i, 'ruby'],
];

const CRAWLERS: ReadonlyArray<readonly [RegExp, CrawlerOperator]> = [
  [
    /Googlebot|AdsBot-Google|Mediapartners-Google|Google-InspectionTool|GoogleOther|Storebot-Google|FeedFetcher-Google|Google-Read-Aloud|APIs-Google|Google-Site-Verification|Google-Safety|Google-CloudVertexBot|Google-Agent/,
    'google',
  ],
  [/bingbot|BingPreview|adidxbot|msnbot/i, 'bing'],
  [/Applebot/, 'apple'],
  [/YandexBot|YandexMobileBot|YandexImages/, 'yandex'],
];

const PREVIEW =
  /facebookexternalhit|Facebot|\bWhatsApp\/\d|Slackbot|Twitterbot|LinkedInBot|TelegramBot|Discordbot|SkypeUriPreview|Pinterestbot|redditbot|Embedly|Iframely|vkShare/i;

export function parseUserAgent(raw: string | undefined): UserAgentInfo {
  const ua = (raw ?? '').slice(0, MAX_UA_LENGTH).trim();
  const browser = detectBrowser(ua);
  return {
    present: ua.length > 0,
    family: browser.family,
    major: browser.major,
    engine: browser.engine,
    os: detectOs(ua),
    device: detectDevice(ua),
    automation: firstMatch(AUTOMATION, ua),
    crawler: detectCrawler(ua),
    preview: PREVIEW.exec(ua)?.[0]?.toLowerCase().replace(/\/\d+$/, ''),
  };
}

export function isChromium(info: UserAgentInfo): boolean {
  return info.engine === 'blink' && (info.family === 'chrome' || info.family === 'edge' || info.family === 'opera' || info.family === 'samsung' || info.family === 'chromium');
}

function firstMatch(patterns: ReadonlyArray<readonly [RegExp, string]>, ua: string): string | undefined {
  for (const [pattern, label] of patterns) if (pattern.test(ua)) return label;
  return undefined;
}

function detectCrawler(ua: string): CrawlerClaim | undefined {
  for (const [pattern, operator] of CRAWLERS) {
    const match = pattern.exec(ua);
    if (match) return { operator, token: match[0] };
  }
  return undefined;
}

function detectBrowser(ua: string): { family: BrowserFamily; major: number | undefined; engine: Engine } {
  const ios = /iPhone|iPad|iPod/.test(ua);
  const rules: ReadonlyArray<readonly [RegExp, BrowserFamily, Engine]> = [
    [/\bEdg(?:e|A|iOS)?\/(\d+)/, 'edge', ios ? 'webkit' : 'blink'],
    [/\b(?:OPR|OPiOS)\/(\d+)/, 'opera', ios ? 'webkit' : 'blink'],
    [/SamsungBrowser\/(\d+)/, 'samsung', 'blink'],
    [/\bCriOS\/(\d+)/, 'chrome', 'webkit'],
    [/\bFxiOS\/(\d+)/, 'firefox', 'webkit'],
    [/\bFirefox\/(\d+)/, 'firefox', 'gecko'],
    [/\bChromium\/(\d+)/, 'chromium', 'blink'],
    [/\bChrome\/(\d+)/, 'chrome', 'blink'],
    [/\bVersion\/(\d+)[\d.]*(?: Mobile\/\S+)? Safari\//, 'safari', 'webkit'],
  ];
  for (const [pattern, family, engine] of rules) {
    const match = pattern.exec(ua);
    if (match) return { family, major: Number(match[1]), engine };
  }
  if (/AppleWebKit/.test(ua)) return { family: 'other', major: undefined, engine: 'webkit' };
  if (/Gecko\/\d/.test(ua)) return { family: 'other', major: undefined, engine: 'gecko' };
  return { family: 'other', major: undefined, engine: 'unknown' };
}

function detectOs(ua: string): OsFamily {
  if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
  if (/Android/.test(ua)) return 'android';
  if (/CrOS/.test(ua)) return 'chromeos';
  if (/Windows NT|Windows Phone/.test(ua)) return 'windows';
  if (/Macintosh|Mac OS X/.test(ua)) return 'macos';
  if (/Linux|X11/.test(ua)) return 'linux';
  return 'other';
}

function detectDevice(ua: string): DeviceType {
  if (/iPad|Tablet/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua))) return 'tablet';
  if (/Mobi|iPhone|iPod|Android/.test(ua)) return 'mobile';
  if (/Windows NT|Macintosh|X11|Linux|CrOS/.test(ua)) return 'desktop';
  return 'unknown';
}
