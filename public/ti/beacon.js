(() => {
  'use strict';
  const script = document.currentScript;
  if (!script || typeof window.fetch !== 'function') return;

  const base = new URL('.', script.src).pathname.replace(/\/$/, '');
  const started = performance.now();
  const counts = { pointer: 0, keys: 0, scroll: 0, touch: 0 };
  let firstMs = null;
  let nonce = null;
  let left = false;

  const elapsed = () => Math.round(performance.now() - started);
  const mark = (kind) => () => {
    counts[kind] += 1;
    if (firstMs === null) firstMs = elapsed();
  };
  const throttle = (handler) => {
    let last = 0;
    return () => {
      const now = performance.now();
      if (now - last < 250) return;
      last = now;
      handler();
    };
  };

  const listen = { passive: true, capture: true };
  addEventListener('pointermove', throttle(mark('pointer')), listen);
  addEventListener('pointerdown', mark('pointer'), listen);
  addEventListener('keydown', mark('keys'), listen);
  addEventListener('scroll', throttle(mark('scroll')), listen);
  addEventListener('touchstart', mark('touch'), listen);

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
  };

  const payload = (phase) =>
    JSON.stringify({ nonce, phase, automation, interaction: { ...counts, firstMs, dwellMs: elapsed() } });

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
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') leave();
  });

  fetch(`${base}/nonce`, { credentials: 'same-origin', cache: 'no-store' })
    .then((response) => (response.status === 200 ? response.json() : null))
    .then((data) => {
      if (!data || typeof data.nonce !== 'string') return;
      nonce = data.nonce;
      send('load');
    })
    .catch(() => {});
})();
