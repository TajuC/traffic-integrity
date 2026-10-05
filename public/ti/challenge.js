(() => {
  'use strict';
  const target = document.getElementById('challenge');
  const status = document.getElementById('challenge-status');
  if (!target) return;

  const say = (text) => {
    if (status) status.textContent = text;
  };
  const retry = (delay) => setTimeout(() => location.reload(), delay);

  const verify = (token) => {
    say('Verified. Loading the page...');
    fetch(target.dataset.verify, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, nonce: target.dataset.nonce }),
    })
      .then((response) => {
        if (response.ok) {
          location.reload();
          return;
        }
        say('Verification did not complete. Trying again...');
        retry(1500);
      })
      .catch(() => {
        say('Connection problem. Trying again...');
        retry(3000);
      });
  };

  const loader = document.createElement('script');
  loader.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  loader.async = true;
  loader.onload = () => {
    window.turnstile.render(target, {
      sitekey: target.dataset.sitekey,
      action: target.dataset.action,
      cData: target.dataset.cdata,
      callback: verify,
      'error-callback': () => say('Verification could not be completed. Please refresh the page.'),
      'expired-callback': () => retry(0),
    });
  };
  loader.onerror = () => say('The verification service could not be reached. Please refresh the page.');
  document.head.appendChild(loader);
})();
