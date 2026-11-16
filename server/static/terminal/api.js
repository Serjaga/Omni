const API = '/terminal/api/';

export async function apiGet(path) {
  const r = await fetch(API + path, { credentials: 'same-origin' });
  let j = null; try { j = await r.json(); } catch(_) {}
  if (!r.ok) throw new Error((j && j.error) || r.statusText || ('HTTP ' + r.status));
  return j;
}

export async function apiPost(path, body) {
  const r = await fetch(API + path, {
    method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  let j = null; try { j = await r.json(); } catch(_) {}
  if (!r.ok) throw new Error((j && j.error) || r.statusText || ('HTTP ' + r.status));
  return j;
}

export async function doLogin(token) {
  const r = await fetch('/api/auth/login', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'token=' + encodeURIComponent(token),
  });
  if (!r.ok) {
    let msg = 'HTTP ' + r.status;
    const text = await r.text();
    try { const j = JSON.parse(text); msg = j.error || msg; }
    catch(_) { msg = text || msg; }
    throw new Error(msg);
  }
}

export async function fetchVisitorIP() {
  try {
    const r = await fetch('/api/auth/whoami', { credentials: 'same-origin' });
    if (r.ok) {
      const j = await r.json();
      if (j && j.ip && j.ip !== 'unknown') return j.ip;
    }
  } catch(_) {}
  return 'unknown';
}