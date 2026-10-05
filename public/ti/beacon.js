(() => {
  'use strict';
  const script = document.currentScript;
  if (!script || typeof window.fetch !== 'function') return;

  const base = new URL('.', script.src).pathname.replace(/\/$/, '');
  const started = performance.now();
  const counts = { pointer: 0, keys: 0, scroll: 0, touch: 0 };
  const gaps = { pointer: [], keys: [], scroll: [] };
  const last = { pointer: 0, keys: 0, scroll: 0 };
  let firstMs = null;
  let nonce = null;
  let left = false;
  let visibilityChanges = 0;

  const elapsed = () => Math.round(performance.now() - started);
  const cv = (values) => {
    if (values.length < 3) return null;
    const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
    if (mean <= 0) return 0;
    const variance = values.reduce((sum, value) => sum + (value - mean) * (value - mean), 0) / values.length;
    return Math.round(Math.sqrt(variance) / mean * 1000) / 1000;
  };
  const mark = (kind) => () => {
    counts[kind] += 1;
    const now = performance.now();
    if (firstMs === null) firstMs = elapsed();
    if (kind !== 'touch' && last[kind]) {
      const gap = now - last[kind];
      if (gap > 8 && gap < 30_000 && gaps[kind].length < 40) gaps[kind].push(Math.round(gap));
    }
    if (kind !== 'touch') last[kind] = now;
  };
  const throttle = (handler) => {
    let previous = 0;
    return () => {
      const now = performance.now();
      if (now - previous < 250) return;
      previous = now;
      handler();
    };
  };

  const listen = { passive: true, capture: true };
  addEventListener('pointermove', throttle(mark('pointer')), listen);
  addEventListener('pointerdown', mark('pointer'), listen);
  addEventListener('keydown', mark('keys'), listen);
  addEventListener('scroll', throttle(mark('scroll')), listen);
  addEventListener('touchstart', mark('touch'), listen);
  document.addEventListener('visibilitychange', () => {
    visibilityChanges += 1;
    if (document.visibilityState === 'hidden') leave();
  });

  const nav = navigator;
  const automation = {
    webdriver: nav.webdriver === true,
    headless: /HeadlessChrome/.test(nav.userAgent),
    languages: Array.isArray(nav.languages) ? nav.languages.length : 0,
    phantom: 'callPhantom' in window || '_phantom' in window,
    selenium:
      '__selenium_unwrapped' in document ||
      '__webdriver_evaluate' in document ||
      Object.keys(document).some((key) => key.startsWith('$cdc_') || key.startsWith('$wdc_')),
    playwright: '__playwright__binding__' in window || '__pwInitScripts' in window,
    viewport: [Math.max(0, Math.round(window.innerWidth || 0)), Math.max(0, Math.round(window.innerHeight || 0))],
    chromeRuntime: typeof window.chrome === 'object' && window.chrome !== null,
    safariPush: 'safari' in window && window.safari && 'pushNotification' in window.safari,
    installTrigger: 'InstallTrigger' in window,
  };

  const snapshot = () => {
    const readStorage = () => {
      try {
        return Boolean(window.localStorage);
      } catch {
        return false;
      }
    };
    return {
      platform: String(nav.platform || '').slice(0, 64),
      vendor: String(nav.vendor || '').slice(0, 64),
      languages: Array.isArray(nav.languages) ? nav.languages.slice(0, 8).map((item) => String(item).slice(0, 16)) : [],
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
      locale: Intl.DateTimeFormat().resolvedOptions().locale || '',
      hardwareConcurrency: Number(nav.hardwareConcurrency) || 0,
      deviceMemory: Number(nav.deviceMemory) || 0,
      maxTouchPoints: Number(nav.maxTouchPoints) || 0,
      touch: nav.maxTouchPoints > 0 || 'ontouchstart' in window,
      pointerFine: Boolean(window.matchMedia && window.matchMedia('(pointer: fine)').matches),
      dpr: Number(window.devicePixelRatio) || 0,
      screen: [Math.max(0, Math.round((window.screen && window.screen.width) || 0)), Math.max(0, Math.round((window.screen && window.screen.height) || 0))],
      viewport: automation.viewport,
      cookieEnabled: nav.cookieEnabled === true,
      storage: readStorage(),
      pointerCv: cv(gaps.pointer),
      keyCv: cv(gaps.keys),
      scrollCv: cv(gaps.scroll),
      dwellMs: elapsed(),
    };
  };

  const payload = (phase) =>
    JSON.stringify({ nonce, phase, automation, snapshot: snapshot(), interaction: { ...counts, firstMs, dwellMs: elapsed(), visibilityChanges } });

  const send = (phase) => {
    if (!nonce) return;
    const body = payload(phase);
    if (phase === 'leave' && typeof nav.sendBeacon === 'function' && nav.sendBeacon(`${base}/beacon`, new Blob([body], { type: 'text/plain' }))) return;
    fetch(`${base}/beacon`, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'text/plain' }, body, keepalive: true }).catch(() => {});
  };

  const leave = () => {
    if (left) return;
    left = true;
    send('leave');
  };
  addEventListener('pagehide', leave);

  fetch(`${base}/nonce`, { credentials: 'same-origin', cache: 'no-store' })
    .then((response) => (response.status === 200 ? response.json() : null))
    .then((data) => {
      if (!data || typeof data.nonce !== 'string') return;
      nonce = data.nonce;
      send('load');
    })
    .catch(() => {});
})();
