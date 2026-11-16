import { st, dom } from './state.js';
import { escapeHtml, addLine } from './utils.js';
import { apiPost, doLogin } from './api.js';
import {
  renderMap, renderHttpDoc, renderDnsDoc, renderDbDoc,
  renderVpnDoc, renderProxyDoc, renderSecurityDoc,
} from './views.js';
import { renderConsole, startPasswordMode } from './console.js';
import {
  cmdHelp, cmdAbout, cmdWhoami, cmdStatus, cmdHistory,
  cmdScan, cmdConnect, cmdExploit, cmdCrack, cmdDump,
  cmdTrace, cmdLs, cmdCat, cmdSudo, cmdMatrix, cmdPhone,
} from './hack.js';
import { cmdLeak } from './leak.js';
import { positionWeb, startRain, startClock, syncViewport, preventZoom } from './ui.js';

const BANNER = [
  ' ██████╗ ███╗   ███╗███╗   ██╗██╗',
  '██╔═══██╗████╗ ████║████╗  ██║██║',
  '██║   ██║██╔████╔██║██╔██╗ ██║██║',
  '██║   ██║██║╚██╔╝██║██║╚██╗██║██║',
  '╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║',
  ' ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝',
];
const ASCII_BORDER = '╔════════════════════════════════════════════════════════════╗';

// ═══════════════ DISPATCHER ═══════════════
export function renderTab(tab) {
  if (st.leakRunning) { st.leakCancelled = true; }

  st.activeTab = tab;
  dom.terminal.innerHTML = '';
  dom.terminal.classList.remove('leak-mode', 'leak-ending');
  dom.terminalContainer.classList.remove('leak-shake', 'leak-intense');
  st.consoleOutput = null;

  dom.inputLineEl.classList.toggle('visible', tab === 'console');

  switch (tab) {
    case 'map':      renderMap();         break;
    case 'http':     renderHttpDoc();     break;
    case 'dns':      renderDnsDoc();      break;
    case 'db':       renderDbDoc();       break;
    case 'vpn':      renderVpnDoc();      break;
    case 'proxy':    renderProxyDoc();    break;
    case 'security': renderSecurityDoc(); break;
    case 'console':  renderConsole();     break;
  }
  updateNav();
  dom.terminal.scrollTop = 0;
  if (tab === 'console') setTimeout(() => dom.inputEl.focus(), 100);
}

// expose for views.js map cards
window.__renderTab = renderTab;

function updateNav() {
  dom.navDock.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === st.activeTab);
  });
}

// ═══════════════ EXEC DISPATCH ═══════════════
async function execCommand(cmd) {
  if (!cmd.trim()) return;
  const parts = cmd.trim().split(/\s+/);
  const c = parts[0].toLowerCase();
  const args = parts.slice(1);

  if (c === 'clear') {
    dom.terminal.innerHTML = '';
    dom.terminal.classList.remove('leak-mode','leak-ending');
    dom.terminalContainer.classList.remove('leak-shake','leak-intense');
    if (st.activeTab === 'console') renderConsole();
    return;
  }
  if (c === 'reset') {
    dom.terminal.innerHTML = '';
    dom.terminal.classList.remove('leak-mode','leak-ending');
    dom.terminalContainer.classList.remove('leak-shake','leak-intense');
    if (st.activeTab === 'console') renderConsole();
    addLine('<span style="color:#009944">[+]</span> терминал сброшен');
    addLine('');
    return;
  }
  if (c === 'check') {
    const tk = args.join('').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    addLine('Проверяем токен (hex): ' + escapeHtml(tk));
    try {
      const r = await apiPost('check_token', { token: tk });
      addLine('Результат: ' + escapeHtml(JSON.stringify(r, null, 2)));
    } catch(e) {
      addLine('<span style="color:#cc0000">✖ ' + escapeHtml(e.message) + '</span>', true);
    }
    addLine('');
    return;
  }

  switch (c) {
    case 'help': case '?':        cmdHelp();          return;
    case 'about': case 'info':    cmdAbout();         return;
    case 'whoami':                cmdWhoami();        return;
    case 'status':                cmdStatus();        return;
    case 'history':               cmdHistory();       return;
    case 'scan':                  await cmdScan();    return;
    case 'connect':               await cmdConnect(); return;
    case 'exploit':               await cmdExploit(); return;
    case 'crack':                 await cmdCrack();   return;
    case 'dump':                  await cmdDump(args);return;
    case 'trace': case 'traceroute': await cmdTrace();return;
    case 'ls':                    cmdLs();            return;
    case 'cat':                   await cmdCat(args); return;
    case 'sudo':                  await cmdSudo(args);return;
    case 'matrix':                await cmdMatrix();  return;
    case 'phone': case 'contact': cmdPhone();         return;
    case 'leak': case 'panic': case 'terror':
    case 'steal': case 'kaspi': case 'whatsapp':
                                  await cmdLeak(renderTab); return;
  }

  try {
    const r = await apiPost('exec', { cmd });
    for (const line of (r.output || [])) addLine(escapeHtml(line));
    addLine('');
  } catch(e) {
    addLine('<span style="color:#cc0000">omni: command not found: ' + escapeHtml(c) + '</span>', true);
    addLine('<span style="color:#666">нажми на кнопку в консоли или введи</span> <span style="color:#009944">help</span>');
    addLine('');
  }
}

window.__execCommand = execCommand;

// ═══════════════ INPUT ═══════════════
async function onEnter() {
  const val = dom.inputEl.value.replace(/[\r\n\t]+/g, ' ').replace(/ +/g, ' ').trim();
  dom.inputEl.value = '';

  if (st.leakRunning) return;

  if (st.mode === 'password') {
    if (!val || val.toLowerCase() === 'отмена' || val.toLowerCase() === 'cancel') {
      st.mode = 'shell';
      dom.promptEl.textContent = 'root@omni:~#';
      dom.inputEl.type = 'text';
      addLine('<span style="color:#666">вход отменён</span>');
      addLine('');
      return;
    }
    addLine('<span class="prompt">пароль:</span> <span style="color:#666">[' + val.length + ' символов]</span>');
    try {
      await doLogin(val);
      addLine('<span style="color:#009944">✓ access granted</span>');
      addLine('');
      setTimeout(() => { window.location.href = '/'; }, 500);
    } catch(e) {
      addLine('<span style="color:#cc0000">✖ ' + escapeHtml(e.message) + '</span> <span style="color:#666">(Enter на пустом — отмена)</span>', true);
      addLine('');
    }
    return;
  }

  addLine('<span class="prompt">' + escapeHtml(dom.promptEl.textContent) + '</span> ' + escapeHtml(val));
  if (!val) return;
  st.history.push(val);
  if (st.history.length > 200) st.history.shift();

  if (val.toLowerCase() === 'вход' || val.toLowerCase() === 'login') {
    startPasswordMode();
    return;
  }

  await execCommand(val);
}

function onKey(e) {
  if (e.key === 'Enter') { e.preventDefault(); onEnter(); }
}

// ═══════════════ INIT ═══════════════
function init() {
  document.addEventListener('contextmenu', e => e.preventDefault());
  ['copy','cut','paste','selectstart','dragstart'].forEach(ev =>
    document.addEventListener(ev, e => e.preventDefault()));
  document.addEventListener('keydown', e => {
    if (e.key === 'F12') { e.preventDefault(); return false; }
    if (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key)) { e.preventDefault(); return false; }
    if (e.ctrlKey && ['u','U','s','S'].includes(e.key)) { e.preventDefault(); return false; }
  });

  dom.borderEl.textContent = ASCII_BORDER;
  dom.banner.textContent = BANNER.join('\n');
  preventZoom();
  startClock();
  startRain();
  syncViewport();
  positionWeb();

  dom.inputEl.addEventListener('keydown', onKey);
  dom.navDock.querySelectorAll('.nav-btn').forEach(b => {
    b.onclick = () => renderTab(b.dataset.tab);
  });

  document.addEventListener('click', (e) => {
    if (st.activeTab === 'console' && e.target !== dom.inputEl &&
        !e.target.closest('.console-btn') && !e.target.closest('.nav-btn')) {
      dom.inputEl.focus();
    }
  });

  window.addEventListener('resize', () => { syncViewport(); positionWeb(); });
  window.addEventListener('orientationchange', () => setTimeout(() => { syncViewport(); positionWeb(); }, 250));
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', () => { syncViewport(); positionWeb(); });
    window.visualViewport.addEventListener('scroll', syncViewport);
  }
  dom.inputEl.addEventListener('focus', () => { setTimeout(syncViewport, 50); setTimeout(syncViewport, 300); });
  dom.inputEl.addEventListener('blur', () => setTimeout(syncViewport, 100));

  renderTab('map');
  dom.inputEl.focus();
}

init();