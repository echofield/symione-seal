// Operator pages: server-rendered HTML, no script, phone first. SYMIONE internal lane (paper-cream tokens from
// symione-platform/dashboard).

import type { ApprovalRow, RunRow } from './engine';
import type * as engine from './engine';

export const esc = (v: unknown) =>
  String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const CSS = `
:root{--paper:#F7F5EF;--paper-dark:#F0EDE5;--card:#FBFAF7;--ink:#1F1F1A;--muted:#7D7A70;--faint:#A8A49A;--border:#E7E2D8;
--green:#365C4A;--green-light:#4A7A62;--red:#C86A5A;--serif:"Instrument Serif",Georgia,"Times New Roman",serif;
--sans:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 var(--sans)}
main{max-width:44rem;margin:0 auto;padding:20px 16px 64px}
header.top{display:flex;justify-content:space-between;align-items:baseline;border-bottom:1px solid var(--border);padding-bottom:12px;margin-bottom:20px}
.brand{font:13px var(--mono);letter-spacing:.22em;text-transform:uppercase;color:var(--ink);text-decoration:none}
.label{font:11px var(--mono);letter-spacing:.22em;text-transform:uppercase;color:var(--muted)}
h1{font:400 30px/1.15 var(--serif);margin:0 0 6px}
h2{font:400 22px/1.2 var(--serif);margin:28px 0 10px}
p{margin:0 0 12px}.muted{color:var(--muted)}.faint{color:var(--faint)}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;margin:0 0 12px}
.row{display:flex;justify-content:space-between;gap:12px;align-items:baseline}
.tag{display:inline-block;font:11px var(--mono);letter-spacing:.14em;text-transform:uppercase;border:1px solid var(--border);border-radius:999px;padding:2px 8px;color:var(--muted);background:var(--paper)}
.tag.sealed,.tag.done,.tag.completed{color:var(--green);border-color:#cfdcd3}
.tag.refused,.tag.failed,.tag.stopped,.tag.expired{color:var(--red);border-color:#ecd2cc}
.tag.waiting,.tag.waiting_seal{color:var(--ink);border-color:var(--ink)}
pre{font:12.5px/1.5 var(--mono);background:var(--paper-dark);border:1px solid var(--border);border-radius:8px;padding:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin:8px 0 0}
code,.mono{font-family:var(--mono);font-size:12.5px;word-break:break-all}
a{color:var(--green)}
ol.steps{padding-left:20px;margin:6px 0 0}ol.steps li{margin:4px 0}
.decide{display:grid;gap:10px;margin-top:16px}
textarea,input[type=password]{width:100%;font:15px var(--sans);padding:12px;border:1px solid var(--border);border-radius:8px;background:#fff;color:var(--ink)}
button{font:500 16px var(--sans);padding:15px 18px;border-radius:10px;border:1px solid var(--ink);cursor:pointer;width:100%}
button.seal{background:var(--green);border-color:var(--green);color:#fff}
button.refuse{background:var(--card);color:var(--red);border-color:var(--red)}
button.plain{background:var(--ink);color:var(--paper)}
.ev{font:12px var(--mono);border-top:1px solid var(--border);padding:8px 0;word-break:break-word}
.ev:first-child{border-top:0}
.money{font:400 40px/1.1 var(--serif);margin:4px 0 2px}
footer{margin-top:40px;font:11px var(--mono);letter-spacing:.18em;text-transform:uppercase;color:var(--faint)}
`;

export function page(title: string, body: string, signedIn = false): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${esc(title)} · SYMIONE SEAL</title><style>${CSS}</style></head><body><main>
<header class="top"><a class="brand" href="/">SYMIONE · SEAL</a>${signedIn ? '<form method="post" action="/logout" style="margin:0"><button class="plain" style="width:auto;padding:6px 12px;font-size:12px">Sign out</button></form>' : '<span class="label">Operator</span>'}</header>
${body}
<footer>${STEPS}</footer>
</main></body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// Arrows are drawn, never typed: a phone can turn an arrow character into a colour emoji.
const ARROW = '<svg width="14" height="8" viewBox="0 0 14 8" aria-hidden="true" style="vertical-align:middle;margin:0 6px"><path d="M0 4h12M9 1l3 3-3 3" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>';
const STEPS = ['intent', 'rules', 'action', 'seal', 'proof', 'trace'].join(ARROW);

// Minor units per currency, as Stripe counts them. Anything else has two.
const ZERO_DECIMAL = new Set(['bif', 'clp', 'djf', 'gnf', 'jpy', 'kmf', 'krw', 'mga', 'pyg', 'rwf', 'ugx', 'vnd', 'vuv', 'xaf', 'xof', 'xpf']);
const THREE_DECIMAL = new Set(['bhd', 'jod', 'kwd', 'omr', 'tnd']);

/** For a payment, the amount the person is about to allow, computed from the sealed input itself (never from the
 *  agent's own summary). Null when the input has no integer amount and three-letter currency. */
export function moneyLine(kind: string, input: unknown): string | null {
  if (kind !== 'charge_payment' || !input || typeof input !== 'object') return null;
  const { amount, currency } = input as { amount?: unknown; currency?: unknown };
  if (typeof amount !== 'number' || !Number.isSafeInteger(amount) || typeof currency !== 'string' || !/^[a-z]{3}$/i.test(currency)) return null;
  const cur = currency.toLowerCase();
  const digits = ZERO_DECIMAL.has(cur) ? 0 : THREE_DECIMAL.has(cur) ? 3 : 2;
  const abs = String(Math.abs(amount)).padStart(digits + 1, '0');
  const major = digits ? `${abs.slice(0, -digits)}.${abs.slice(-digits)}` : abs;
  return `${amount < 0 ? '-' : ''}${major.replace(/\B(?=(\d{3})+(?!\d))/g, ',')} ${cur.toUpperCase()}`;
}

const tag = (s: string) => `<span class="tag ${esc(s)}">${esc(s.replace('_', ' '))}</span>`;
const pretty = (v: unknown) => esc(JSON.stringify(v, null, 2));
const when = (iso: string | null | undefined) => iso ? esc(iso.replace('T', ' ').slice(0, 16) + ' UTC') : '';

export function loginPage(next: string, message = ''): Response {
  return page('Sign in', `
<h1>Sign in</h1><p class="muted">The operator seals or refuses what agents ask to do.</p>
${message ? `<div class="card"><p>${esc(message)}</p></div>` : ''}
<form method="post" action="/login" class="decide">
<input type="hidden" name="next" value="${esc(next)}">
<input type="password" name="password" autocomplete="current-password" placeholder="Password" required>
<button class="plain">Sign in</button></form>`);
}

export function inboxPage(data: Awaited<ReturnType<typeof engine.inbox>>): Response {
  const waiting = data.waiting.length
    ? data.waiting.map(w => `<a href="/seal/${esc(w.id)}" style="text-decoration:none;color:inherit"><div class="card">
<div class="row"><span class="label">${esc(w.kind)}</span>${tag('waiting')}</div>
<p style="margin:8px 0 4px;font-size:17px">${esc(w.summary)}</p>
<p class="muted" style="margin:0">${esc(w.agent)} · ${esc(w.intent)}</p>
<p class="faint" style="margin:6px 0 0;font-size:13px">Expires ${when(w.expires_at)}</p></div></a>`).join('')
    : '<div class="card"><p class="muted" style="margin:0">Every request is decided.</p></div>';
  const runs = data.runs.map((r: RunRow) => `<a href="/runs/${esc(r.id)}" style="text-decoration:none;color:inherit"><div class="card">
<div class="row"><span class="mono">${esc(r.agent)}</span>${tag(r.status)}</div>
<p style="margin:6px 0 0">${esc(r.intent)}</p><p class="faint" style="margin:4px 0 0;font-size:13px">${when(r.created_at)} · ${r.cursor}/${r.action_count} actions</p></div></a>`).join('');
  return page('Inbox', `<h1>Waiting for your seal</h1>${waiting}<h2>Recent runs</h2>${runs || '<p class="muted">No runs yet.</p>'}`, true);
}

type View = Awaited<ReturnType<typeof engine.status>>;

function actionsBlock(view: View, highlight: number | null): string {
  return view.actions.map(a => `<div class="card"${a.index === highlight ? ' style="border-color:var(--ink)"' : ''}>
<div class="row"><span class="label">${a.index + 1}. ${esc(a.kind)} · ${esc(a.risk)}</span>${tag(a.status)}</div>
<p style="margin:8px 0 0">${esc(a.summary)}</p>
${a.evidence && Object.keys(a.evidence as object).length ? `<p class="muted" style="margin:8px 0 0">Evidence</p><pre>${pretty(a.evidence)}</pre>` : ''}
</div>`).join('');
}

function ledgerBlock(view: View): string {
  return `<div class="card">${view.events.map(e => `<div class="ev"><b>#${e.seq}</b> ${esc(e.action)} · ${esc(e.actor)} · ${when(e.at)}<br><span class="faint">${esc(e.hash)}</span></div>`).join('')}</div>`;
}

export function sealPage(approval: ApprovalRow, view: View, formToken: string): Response {
  const action = view.actions.find(a => a.index === approval.idx)!;
  const open = approval.status === 'waiting';
  const money = moneyLine(action.kind, action.input);
  const decided = open ? '' : `<div class="card"><div class="row"><span class="label">Decision</span>${tag(approval.status)}</div>
${approval.decided_at ? `<p class="muted" style="margin:8px 0 0">${esc(approval.decided_by)} · ${when(approval.decided_at)}</p>` : ''}
${approval.note ? `<p style="margin:8px 0 0">${esc(approval.note)}</p>` : ''}</div>`;
  const form = open ? `<form method="post" action="/seal/${esc(approval.id)}" class="decide">
<input type="hidden" name="t" value="${esc(formToken)}">
<textarea name="note" rows="2" maxlength="500" placeholder="Note for the ledger (optional)"></textarea>
<button class="seal" name="decision" value="seal">Seal: let it happen</button>
<button class="refuse" name="decision" value="refuse">Refuse: stop the run</button>
</form><p class="faint" style="margin-top:10px;font-size:13px">The receipt is valid 15 minutes after the seal, for this exact input, once. This request expires ${when(approval.expires_at)}.</p>` : '';
  return page('Seal request', `
<p class="label">${esc(view.run.agent)} asks</p>
<h1>${esc(action.summary)}</h1>
<p class="muted">${esc(action.kind)} · action ${action.index + 1} of ${view.actions.length}</p>
${decided}
${money ? `<div class="card"><p class="label" style="margin:0">Amount, read from the sealed input</p><p class="money">${esc(money)}</p>
<p class="faint" style="margin:0;font-size:13px">amount ${esc((action.input as { amount: number }).amount)} in minor units</p></div>` : ''}
<div class="card"><p class="label" style="margin-bottom:6px">Exact input</p><pre>${pretty(action.input)}</pre>
<p class="faint" style="margin:8px 0 0">Bound by <code>${esc(action.input_hash)}</code></p></div>
${form}
<h2>Why</h2><div class="card"><p style="margin:0">${esc(view.run.intent)}</p>
${view.run.plan.length ? `<ol class="steps">${view.run.plan.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
${view.run.stop_conditions.length ? `<p class="muted" style="margin:10px 0 0">Stops when: ${view.run.stop_conditions.map(esc).join(' · ')}</p>` : ''}</div>
<h2>The whole run</h2>${actionsBlock(view, action.index)}
<h2>Ledger</h2>${ledgerBlock(view)}`, true);
}

export function runPage(view: View): Response {
  return page('Run', `
<p class="label">${esc(view.run.agent)} · ${when(view.run.created_at)}</p>
<h1>${esc(view.run.intent)}</h1>
<p>${tag(view.run.status)}${view.run.stop_reason ? ` <span class="muted">${esc(view.run.stop_reason)}</span>` : ''}</p>
${view.approvals.filter(a => a.status === 'waiting').map(a => `<p><a href="/seal/${esc(a.id)}">Open the waiting seal request</a></p>`).join('')}
<h2>Actions</h2>${actionsBlock(view, view.run.status === 'completed' ? null : view.run.cursor)}
<h2>Ledger</h2>${ledgerBlock(view)}`, true);
}

export function messagePage(title: string, message: string, status = 200, signedIn = false): Response {
  const res = page(title, `<h1>${esc(title)}</h1><div class="card"><p style="margin:0">${esc(message)}</p></div><p><a href="/">Back to the inbox</a></p>`, signedIn);
  return new Response(res.body, { status, headers: res.headers });
}
