import { st, dom } from './state.js';
import { escapeHtml, addLine } from './utils.js';

export function renderConsole() {
  dom.terminal.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'console-title';
  header.innerHTML =
    '<h1>⚡ Консоль</h1>' +
    '<p>нажми на кнопку или введи команду ниже</p>';
  dom.terminal.appendChild(header);

  const buttons = [
    { cmd:'scan',      icon:'🎯', label:'scan',      desc:'сканировать цель' },
    { cmd:'connect',   icon:'🔌', label:'connect',   desc:'защищённый канал' },
    { cmd:'exploit',   icon:'💥', label:'exploit',   desc:'эксплуатация CVE' },
    { cmd:'crack',     icon:'🔓', label:'crack',     desc:'взлом хешей' },
    { cmd:'dump admin',icon:'🗄️', label:'dump',      desc:'выгрузить БД' },
    { cmd:'leak',      icon:'☠️', label:'leak',      desc:'screamer' },
    { cmd:'status',    icon:'📊', label:'status',    desc:'прогресс' },
    { cmd:'trace',     icon:'🛣️', label:'trace',     desc:'маршрут' },
    { cmd:'ls',        icon:'📁', label:'ls',        desc:'файлы' },
    { cmd:'matrix',    icon:'🟢', label:'matrix',    desc:'цифровой дождь' },
    { cmd:'history',   icon:'📜', label:'history',   desc:'история' },
    { cmd:'about',     icon:'ℹ️', label:'about',     desc:'о сервере' },
    { cmd:'help',      icon:'❓', label:'help',      desc:'справка' },
    { cmd:'reset',     icon:'🔄', label:'reset',     desc:'сброс' },
    { cmd:'вход',      icon:'🚪', label:'вход',      desc:'админ-панель' },
  ];

  const grid = document.createElement('div');
  grid.className = 'console-grid';
  grid.innerHTML = buttons.map(b => `
    <button class="console-btn" data-cmd="${escapeHtml(b.cmd)}">
      <div class="console-btn-icon">${b.icon}</div>
      <div class="console-btn-label">${escapeHtml(b.label)}</div>
      <div class="console-btn-desc">${escapeHtml(b.desc)}</div>
    </button>
  `).join('');
  dom.terminal.appendChild(grid);

  const sep = document.createElement('div');
  sep.className = 'console-sep';
  dom.terminal.appendChild(sep);

  st.consoleOutput = document.createElement('div');
  st.consoleOutput.id = 'consoleOutput';
  dom.terminal.appendChild(st.consoleOutput);

  grid.querySelectorAll('[data-cmd]').forEach(el => {
    el.onclick = () => {
      const cmd = el.dataset.cmd;
      addLine('<span class="prompt">root@omni:~#</span> ' + escapeHtml(cmd));
      if (cmd === 'вход') {
        startPasswordMode();
      } else {
        window.__execCommand && window.__execCommand(cmd);
      }
    };
  });

  addLine('<span style="color:#666">готов. выбери команду выше или введи в поле ввода.</span>');
  addLine('');
}

export function startPasswordMode() {
  st.mode = 'password';
  dom.promptEl.textContent = 'пароль:';
  dom.inputEl.type = 'password';
  dom.inputEl.setAttribute('autocapitalize', 'none');
  dom.inputEl.setAttribute('autocorrect', 'off');
  dom.inputEl.setAttribute('spellcheck', 'false');
  addLine('<span style="color:#666">введите пароль администратора (Enter на пустом — отмена)</span>');
  addLine('');
  dom.inputEl.focus();
}