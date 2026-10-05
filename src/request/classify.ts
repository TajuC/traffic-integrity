import type { IncomingHttpHeaders } from 'node:http';

export type RouteClass = 'bypass' | 'asset' | 'internal' | 'conversion' | 'action' | 'api' | 'page';

export interface RouteRules {
  readonly internalPrefix: string;
  readonly conversionPath: string;
  readonly actionPaths: ReadonlySet<string>;
  readonly apiPrefixes: readonly string[];
  readonly bypassPaths: ReadonlySet<string>;
}

export interface RequestShape {
  readonly routeClass: RouteClass;
  readonly navigation: boolean;
  readonly prefetch: boolean;
}

const ASSET_EXTENSIONS = new Set([
  'js', 'mjs', 'css', 'map', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'ico', 'bmp',
  'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp4', 'webm', 'mp3', 'ogg', 'wav', 'pdf', 'txt', 'xml',
  'json', 'webmanifest', 'zip', 'gz',
]);

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function classifyRequest(method: string, path: string, headers: IncomingHttpHeaders, rules: RouteRules): RequestShape {
  const upper = method.toUpperCase();
  const navigation = (upper === 'GET' || upper === 'HEAD') && isNavigation(headers);
  const prefetch = isPrefetch(headers);
  const shape = (routeClass: RouteClass): RequestShape => ({ routeClass, navigation, prefetch });

  if (upper === 'OPTIONS' || rules.bypassPaths.has(path)) return shape('bypass');
  if (path === rules.internalPrefix || path.startsWith(`${rules.internalPrefix}/`)) {
    return shape(SAFE_METHODS.has(upper) && ASSET_EXTENSIONS.has(extension(path)) ? 'asset' : 'internal');
  }
  if (path === rules.conversionPath) return shape(upper === 'POST' ? 'conversion' : 'api');
  if (!SAFE_METHODS.has(upper) && rules.actionPaths.has(path)) return shape('action');
  if (rules.apiPrefixes.some((prefix) => path.startsWith(prefix))) return shape('api');
  if (ASSET_EXTENSIONS.has(extension(path))) return shape('asset');
  return shape(SAFE_METHODS.has(upper) ? 'page' : 'api');
}

function isNavigation(headers: IncomingHttpHeaders): boolean {
  const mode = headers['sec-fetch-mode'];
  if (mode !== undefined) return mode === 'navigate';
  return (headers.accept ?? '').includes('text/html');
}

function isPrefetch(headers: IncomingHttpHeaders): boolean {
  const purpose = headers['sec-purpose'] ?? headers.purpose ?? headers['x-moz'] ?? headers['x-purpose'];
  return typeof purpose === 'string' && /prefetch|prerender|preview/i.test(purpose);
}

function extension(path: string): string {
  const slash = path.lastIndexOf('/');
  const dot = path.lastIndexOf('.');
  return dot > slash ? path.slice(dot + 1).toLowerCase() : '';
}
