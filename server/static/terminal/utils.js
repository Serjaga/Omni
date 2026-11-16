import { st, dom } from './state.js';

export const $ = (id) => document.getElementById(id);
export const sleep = ms => new Promise(r => setTimeout(r, ms));
export const escapeHtml = s => String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');

export function addLine(html, isErr) {
  const d = document.createElement('div');
  d.className = 'line' + (isErr ? ' err' : '');
  d.innerHTML = html || '';
  const target = (st.consoleOutput && st.consoleOutput.isConnected) ? st.consoleOutput : dom.terminal;
  target.appendChild(d);
  dom.terminal.scrollTop = dom.terminal.scrollHeight;
  return d;
}

export async function progressBar(label, ms, prefix) {
  const width = 22;
  const start = Date.now();
  const d = document.createElement('div');
  d.className = 'line';
  const target = (st.consoleOutput && st.consoleOutput.isConnected) ? st.consoleOutput : dom.terminal;
  target.appendChild(d);
  const pfx = prefix || '[*]';
  while (true) {
    const t = Math.min(1, (Date.now() - start) / ms);
    const filled = Math.floor(t * width);
    const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
    d.innerHTML = `<span style="color:#006633">${escapeHtml(pfx)}</span> ${escapeHtml(label)} `
                + `[<span style="color:#009944">${bar}</span>] `
                + `<span style="color:#006633">${String(Math.floor(t*100)).padStart(3)}%</span>`;
    dom.terminal.scrollTop = dom.terminal.scrollHeight;
    if (t >= 1) break;
    await sleep(55);
  }
}

export function docSection(title, bodyHtml) {
  const s = document.createElement('div');
  s.className = 'doc-section';
  s.innerHTML = `<h3>${title}</h3>${bodyHtml}`;
  dom.terminal.appendChild(s);
}

export function docPageTitle(icon, name, subtitle) {
  const t = document.createElement('div');
  t.style.cssText = 'text-align:center;margin:4px 0 16px;';
  t.innerHTML =
    `<div style="font-size:clamp(20px,5vw,26px);font-weight:bold;color:#009944;text-shadow:0 0 12px rgba(0,153,68,0.35);">${icon} ${escapeHtml(name)}</div>` +
    (subtitle ? `<div style="font-size:11px;color:#666;margin-top:4px;letter-spacing:0.6px;">${escapeHtml(subtitle)}</div>` : '');
  dom.terminal.appendChild(t);
}