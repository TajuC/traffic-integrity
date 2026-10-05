(() => {
  'use strict';
  const script = document.currentScript;
  const base = script ? new URL('.', script.src).pathname.replace(/\/$/, '') : '/_ti';
  const STANDARD = new Set(['name', 'email', 'phone', 'message']);
  const EXTRA = /^[a-z][a-z0-9_]{0,39}$/;
  const TOKEN_MAX_AGE_MS = 240000;
  let loading = null;

  const loadTurnstile = () => {
    if (window.turnstile) return Promise.resolve(window.turnstile);
    if (!loading) {
      loading = new Promise((resolve, reject) => {
        const tag = document.createElement('script');
        tag.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
        tag.async = true;
        tag.onload = () => resolve(window.turnstile);
        tag.onerror = () => {
          loading = null;
          reject(new Error('verification_unavailable'));
        };
        document.head.appendChild(tag);
      });
    }
    return loading;
  };

  const solve = async (container, challenge) => {
    const turnstile = await loadTurnstile();
    return new Promise((resolve, reject) => {
      container.hidden = false;
      container.replaceChildren();
      const slot = document.createElement('div');
      container.appendChild(slot);
      turnstile.render(slot, {
        sitekey: challenge.siteKey,
        action: challenge.action,
        cData: challenge.cdata,
        appearance: 'interaction-only',
        callback: (token) => resolve(token),
        'error-callback': () => reject(new Error('verification_failed')),
        'expired-callback': () => reject(new Error('verification_expired')),
      });
    });
  };

  const randomKey = () => {
    if (crypto.randomUUID) return crypto.randomUUID();
    return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('');
  };

  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const emit = (form, name, detail) => form.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));

  const clearRequest = async (challenge) => {
    const container = document.createElement('div');
    container.className = 'ti-challenge';
    document.body.appendChild(container);
    try {
      const token = await solve(container, challenge);
      const response = await fetch(`${base}/challenge`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token, nonce: challenge.nonce }),
      });
      return response.ok;
    } finally {
      container.remove();
    }
  };

  const guardedFetch = async (input, init) => {
    const response = await fetch(input, init);
    if (response.status !== 403) return response;
    const data = await response.clone().json().catch(() => null);
    if (!data || data.error !== 'verification_required' || !data.turnstile || !data.turnstile.nonce) return response;
    return (await clearRequest(data.turnstile)) ? fetch(input, init) : response;
  };

  const protectForm = (form, options = {}) => {
    const formId = options.formId || form.dataset.formId;
    const container = options.challengeContainer || form.querySelector('[data-challenge]') || form.appendChild(document.createElement('div'));
    container.hidden = true;
    let settings = null;
    let key = randomKey();
    let busy = false;
    let presolved = null;

    const ensureHoneypot = () => {
      if (form.querySelector(`[name="${settings.honeypot}"]`)) return;
      const wrapper = document.createElement('div');
      wrapper.setAttribute('aria-hidden', 'true');
      wrapper.className = 'ti-hp';
      wrapper.style.cssText = 'position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden';
      const input = document.createElement('input');
      input.type = 'text';
      input.name = settings.honeypot;
      input.tabIndex = -1;
      input.autocomplete = 'off';
      wrapper.appendChild(input);
      form.appendChild(wrapper);
    };

    const refresh = async () => {
      const response = await fetch(`${base}/form?form=${encodeURIComponent(formId)}`, { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error('form_unavailable');
      settings = await response.json();
      ensureHoneypot();
      presolved = null;
    };

    const presolve = () => {
      if (presolved || !settings || !settings.turnstile || settings.challenge !== 'always') return;
      const startedAt = Date.now();
      presolved = { startedAt, token: solve(container, settings.turnstile) };
      presolved.token.catch(() => {
        presolved = null;
      });
    };

    const tokenForSubmit = async () => {
      if (!settings.turnstile || settings.challenge !== 'always') return null;
      if (presolved && Date.now() - presolved.startedAt < TOKEN_MAX_AGE_MS) {
        const pending = presolved.token;
        presolved = null;
        return pending;
      }
      presolved = null;
      return solve(container, settings.turnstile);
    };

    const body = (turnstileToken) => {
      const values = {};
      for (const [name, value] of new FormData(form)) if (typeof value === 'string') values[name] = value;
      const extra = {};
      for (const [name, value] of Object.entries(values)) {
        if (!STANDARD.has(name) && name !== settings.honeypot && EXTRA.test(name)) extra[name] = value;
      }
      return JSON.stringify({
        formId,
        name: values.name,
        email: values.email,
        phone: values.phone,
        message: values.message,
        extra,
        formToken: settings.token,
        idempotencyKey: key,
        [settings.honeypot]: values[settings.honeypot] || '',
        ...(turnstileToken ? { turnstileToken } : {}),
      });
    };

    const send = async (turnstileToken) => {
      const response = await fetch(form.action, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: body(turnstileToken),
      });
      return { response, data: await response.json().catch(() => ({})) };
    };

    form.addEventListener('focusin', presolve, { once: true });
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (busy) return;
      busy = true;
      emit(form, 'ti:pending', {});
      try {
        if (!settings) await refresh();
        let result = await send(await tokenForSubmit());
        if (result.response.status === 403 && result.data && result.data.turnstile) result = await send(await solve(container, result.data.turnstile));
        if (result.response.status === 409) {
          await wait(1500);
          result = await send(null);
        }
        const { response, data } = result;
        if (response.ok && data.ok) {
          container.hidden = true;
          emit(form, 'ti:success', data);
          if (data.conversion && data.conversion.fire && options.conversionSendTo && typeof window.gtag === 'function') {
            window.gtag('event', 'conversion', { send_to: options.conversionSendTo, transaction_id: data.conversion.id });
          }
          key = randomKey();
          settings = null;
          refresh().catch(() => {});
          return;
        }
        emit(form, response.status === 400 ? 'ti:invalid' : 'ti:error', {
          status: response.status,
          fields: Array.isArray(data.fields) ? data.fields : [],
          retryable: response.status === 429 || response.status >= 500 || response.status === 403,
          retryAfter: Number(response.headers.get('retry-after')) || null,
        });
      } catch (error) {
        emit(form, 'ti:error', { status: 0, fields: [], retryable: true, error: String((error && error.message) || error) });
      } finally {
        busy = false;
      }
    });

    refresh().catch(() => {});
  };

  window.TrafficIntegrity = Object.freeze({ protectForm, guardedFetch });
})();
