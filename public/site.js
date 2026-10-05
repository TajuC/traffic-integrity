(() => {
  'use strict';
  const form = document.getElementById('quote-form');
  if (!form || !window.TrafficIntegrity) return;
  const status = form.querySelector('.form-status');
  const button = form.querySelector('button[type="submit"]');
  const say = (text, tone) => {
    status.textContent = text;
    status.dataset.tone = tone;
  };

  form.addEventListener('ti:pending', () => {
    button.disabled = true;
    say('Sending...', 'info');
  });
  form.addEventListener('ti:success', () => {
    button.disabled = false;
    form.reset();
    say('Thank you. Your request was received and we will contact you shortly.', 'success');
  });
  form.addEventListener('ti:invalid', (event) => {
    button.disabled = false;
    const fields = event.detail.fields.filter((name) => name !== 'body');
    say(fields.length > 0 ? `Please check: ${fields.join(', ')}.` : 'Please check the form and try again.', 'error');
  });
  form.addEventListener('ti:error', (event) => {
    button.disabled = false;
    const wait = event.detail.retryAfter ? ` in about ${Math.ceil(event.detail.retryAfter / 60)} minute(s)` : '';
    say(`We could not send your request right now. Your details are still here, please try again${wait}.`, 'error');
  });

  window.TrafficIntegrity.protectForm(form, { conversionSendTo: form.dataset.conversionSendTo });
})();
