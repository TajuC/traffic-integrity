export interface ChallengePageInput {
  readonly siteKey: string;
  readonly action: string;
  readonly cdata: string;
  readonly nonce: string;
  readonly internalPrefix: string;
}

export interface StatusPageInput {
  readonly title: string;
  readonly message: string;
}

export function renderChallengePage(input: ChallengePageInput): string {
  const data = [
    `data-sitekey="${escapeHtml(input.siteKey)}"`,
    `data-action="${escapeHtml(input.action)}"`,
    `data-cdata="${escapeHtml(input.cdata)}"`,
    `data-nonce="${escapeHtml(input.nonce)}"`,
    `data-verify="${escapeHtml(`${input.internalPrefix}/challenge`)}"`,
  ].join(' ');
  return layout(
    'Checking your connection',
    `<main>
  <h1>One moment</h1>
  <p>We are confirming that this connection is secure. This usually takes a few seconds.</p>
  <div id="challenge" ${data}></div>
  <p id="challenge-status" role="status" aria-live="polite"></p>
</main>
<script src="${escapeHtml(input.internalPrefix)}/challenge.js" defer></script>`,
  );
}

export function renderStatusPage(input: StatusPageInput): string {
  return layout(input.title, `<main><h1>${escapeHtml(input.title)}</h1><p>${escapeHtml(input.message)}</p></main>`);
}

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f6f7f9;color:#1d2330}
main{max-width:30rem;padding:2rem;text-align:center}
h1{font-size:1.4rem;margin:0 0 .75rem}
#challenge{display:flex;justify-content:center;margin:1.5rem 0}
</style>
</head>
<body>
${body}
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}
