import {
  S, $, $$, esc, get, post, postJ, api, del, dl,
  toast, confirmDlg, showModal, closeModal, spinner, errBox,
  renderTable, renderKV, renderKVGrid, badge, fmtSize, fmtTs,
  saveSubtabs, saveScrollAndRerender, scrollTabIntoView
} from './app';

const SUBS = [
  ['ikev2', '🔐 IKEv2/IPSec'],
  ['miraj', '📱 NekoBox/SingBox/Hiddify'],
  ['tunnel', '🚇 ProxyWGTunnel'],
  ['wireguard', '🛡️ Wireguard/AmneziaWG']
];

export async function mount(c) {
  if (!S.vpn) S.vpn = { sub: 'miraj' };
  if (!SUBS.some(([id]) => id === S.vpn.sub)) S.vpn.sub = 'miraj';

  c.innerHTML = `<div class="subtabs" id="vpnSubtabs">${SUBS.map(([id, l]) => `<button class="subtab ${S.vpn.sub === id ? 'active' : ''}" data-vpnsub="${id}">${l}</button>`).join('')}</div><div id="vpnTabBody"></div>`;
  
  $$('[data-vpnsub]').forEach(b => b.onclick = () => {
    S.vpn.sub = b.dataset.vpnsub; 
    saveSubtabs();
    saveScrollAndRerender('#vpnSubtabs', () => mount(c));
  });

  const box = $('#vpnTabBody');
  const dispatch = { ikev2: vpnIkev2Tab, miraj: vpnMirajTab, tunnel: vpnTunnelTab, wireguard: vpnWireguardTab };
  await dispatch[S.vpn.sub](box, c);
  setTimeout(() => scrollTabIntoView('#vpnSubtabs', '#vpnSubtabs .subtab.active'), 0);
}

/* ══════════════════ MIRAJ ══════════════════ */
async function vpnMirajTab(box) {
  await renderMirajSection(box);
}

export async function renderMirajSection(box) {
  if (!box) return;
  
  box.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">🌪️ Miraj — прокси (Hysteria2)</div>
          <div class="card-sub">QUIC-прокси на UDP · клик по строке — действия</div>
        </div>
        <div class="card-actions">
          <button class="button small" id="mjReload" title="Обновить">🔄</button>
          <button class="button small" id="mjConfig">⚙️ Настройки</button>
          <button class="button small primary" id="mjNew">+ Пользователь</button>
        </div>
      </div>
      <div id="mjMetrics" style="margin-bottom:14px">${spinner()}</div>
      <div id="mjBody">${spinner()}</div>
    </div>
  `;

  const loadMetrics = async () => {
    try {
      const m = await get('miraj/metrics');
      document.getElementById('mjMetrics').innerHTML = renderKVGrid(m, 3);
    } catch (e) {
      document.getElementById('mjMetrics').innerHTML = `<div class="info-box">Miraj-эндпоинт не отвечает. Проверьте <code>miraj.enabled</code> в БД и перезапустите сервис. <span style="color:var(--muted)">${esc(e.message)}</span></div>`;
    }
  };
  
  const loadClients = async () => {
    try {
      const list = await get('miraj/clients');
      const rows = Array.isArray(list) ? list : [];
      if (!rows.length) {
        document.getElementById('mjBody').innerHTML = `
          <div class="empty-state">
            <div class="icon">🌪️</div>
            <div class="title">Пользователей нет</div>
            <div class="sub">Добавьте первого — он получит <code>hysteria2://</code> URI для NekoBox / Hiddify / sing-box</div>
            <div class="actions"><button class="button small primary" id="mjNewEmpty">+ Создать</button></div>
          </div>
        `;
        const b = document.getElementById('mjNewEmpty');
        if (b) b.onclick = () => mirajNewClient(() => { loadClients(); loadMetrics(); });
        return;
      }
      
      document.getElementById('mjBody').innerHTML = renderTable([
        { label: 'ID', key: 'id' },
        { label: 'Имя', render: r => `<strong>${esc(r.name || '—')}</strong>` },
        { label: 'Статус', render: r => r.enabled ? badge('активен') : badge('отключён', 'neutral') },
        { label: 'Создан', render: r => r.created_at ? fmtTs(r.created_at) : '—' },
        { label: 'Байт ↓/↑', render: r => `${fmtSize(r.bytes_in || 0)} / ${fmtSize(r.bytes_out || 0)}` },
        { label: '', render: () => `<div class="row-actions"><button class="button small" title="Действия">›</button></div>` }
      ], rows);
      
      $$('#mjBody tbody tr').forEach((tr, i) => {
        if (rows[i]) {
          tr.classList.add('vpn-row-clickable');
          tr.onclick = () => openMirajUserPanel(rows[i]);
        }
      });
    } catch (e) {
      document.getElementById('mjBody').innerHTML = errBox(e);
    }
  };

  document.getElementById('mjReload').onclick = () => { loadMetrics(); loadClients(); };
  document.getElementById('mjConfig').onclick = () => mirajConfigDialog(() => loadMetrics());
  document.getElementById('mjNew').onclick = () => mirajNewClient(() => { loadClients(); loadMetrics(); });

  await loadMetrics();
  await loadClients();
}

export function openMirajUserPanel(user) {
  const panel = $('#toolPanel');
  const backdrop = $('#toolPanelBackdrop');
  panel.dataset.owner = 'miraj';
  backdrop.classList.add('open');
  
  const render = () => {
    if (S.toolPanelCollapsed) {
      panel.classList.add('collapsed');
      panel.innerHTML = `<button class="tool-panel-toggle" title="Развернуть" onclick="toggleToolPanelCollapse()">▴</button>`;
    } else {
      panel.classList.remove('collapsed');
      panel.innerHTML = `
        <button class="tool-panel-top-toggle" title="Свернуть" onclick="toggleToolPanelCollapse()">▾</button>
        <div class="tool-panel-title" title="${esc(user.name || ('#' + user.id))}">${esc(user.name || ('#' + user.id))}</div>
        <button class="tool-panel-btn" title="URI" onclick="closeToolPanel(); mirajShowUri('${user.id}')">🔗</button>
        <button class="tool-panel-btn" title="${user.enabled ? 'Отключить' : 'Включить'}" onclick="mirajToggle('${user.id}', ${user.enabled})">${user.enabled ? '⏸' : '▶'}</button>
        <button class="tool-panel-btn danger" title="Удалить" onclick="mirajDelete('${user.id}', '${esc(user.name || '')}')">×</button>
      `;
    }
    if (!panel.classList.contains('open')) requestAnimationFrame(() => panel.classList.add('open'));
  };
  
  render();
  panel._renderer = render;
}

export async function mirajShowUri(id) {
  try {
    const d = await get('miraj/clients/' + encodeURIComponent(id) + '/uri');
    const uri = d.uri || '';
    showModal('Hysteria2 URI',
      `<div class="field"><label>URI</label><input value="${esc(uri)}" readonly onclick="this.select()"></div>
       <div class="info-box">Вставьте в NekoBox / Hiddify / sing-box / официальный клиент Hysteria. Внутри — пароль пользователя и адрес сервера.</div>`,
      `<div class="modal-foot"><button class="button" onclick="closeModal()">Закрыть</button><button class="button primary" id="mjCopy">📋 Копировать</button></div>`);
    document.getElementById('mjCopy').onclick = () => {
      navigator.clipboard.writeText(uri).then(() => toast.ok('Скопировано')).catch(() => toast.err('Не удалось'));
    };
  } catch (e) { toast.err(e.message); }
}

export async function mirajToggle(id, enable) {
  closeToolPanel();
  try {
    await post('miraj/clients/' + encodeURIComponent(id) + (enable ? '/disable' : '/enable'));
    toast.ok('OK');
    mount(document.getElementById('viewContent'));
  } catch (e) { toast.err(e.message); }
}

export async function mirajDelete(id, name) {
  closeToolPanel();
  if (!await confirmDlg('Удалить пользователя?', name || String(id))) return;
  try {
    await api('miraj/clients/' + encodeURIComponent(id), { method: 'DELETE' });
    toast.ok('Удалён');
    mount(document.getElementById('viewContent'));
  } catch (e) { toast.err(e.message); }
}

export function mirajNewClient(onDone) {
  showModal('Новый Miraj-пользователь',
    `<div class="field"><label>Имя</label><input id="mjNewName" placeholder="my-phone" autofocus></div>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="mjNewSave">Создать</button></div>`);
  setTimeout(() => document.getElementById('mjNewName')?.focus(), 50);
  document.getElementById('mjNewSave').onclick = async () => {
    const name = document.getElementById('mjNewName').value.trim();
    if (!name) return toast.err('Введите имя');
    try {
      const r = await postJ('miraj/clients', { name });
      toast.ok('Создан');
      closeModal();
      if (onDone) onDone();
      if (r && r.id) mirajShowUri(r.id);
    } catch (e) { toast.err(e.message); }
  };
}

export function mirajConfigDialog(onDone) {
  (async () => {
    try {
      const cfg = await get('miraj/config');
      showModal('Настройки Miraj',
        `<div class="form-grid">
           <div class="field"><label>Listen</label><input id="mjCfgListen" value="${esc(cfg.listen || '0.0.0.0:808')}"></div>
           <div class="field"><label>Masquerade URL</label><input id="mjCfgMasq" value="${esc(cfg.masquerade_url || '')}"></div>
         </div>
         <div class="form-grid">
           <div class="field"><label>Auth token</label><input id="mjCfgAuth" value="${esc(cfg.auth_token || '')}"></div>
           <div class="field"><label>Obfs password</label><input id="mjCfgObfs" value="${esc(cfg.obfs_password || '')}"></div>
         </div>
         <div class="form-grid">
           <div class="field"><label>Brutal TX (B/s, 0 = BBR)</label><input id="mjCfgBrutal" type="number" value="${cfg.brutal_tx || 0}"></div>
           <div class="field"><label>Idle timeout (s)</label><input id="mjCfgIdle" type="number" value="${cfg.idle_timeout_secs || 30}"></div>
         </div>
         <div class="switch-row"><div><strong>UDP relay</strong><small>Разрешить UDP через QUIC-datagrams</small></div><input type="checkbox" class="switch" id="mjCfgUdp" ${cfg.udp_enabled !== false ? 'checked' : ''}></div>
         <div class="switch-row"><div><strong>Gecko</strong><small>Фрагментация QUIC-пакетов</small></div><input type="checkbox" class="switch" id="mjCfgGecko" ${cfg.gecko_enabled ? 'checked' : ''}></div>`,
        `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="mjCfgSave">Сохранить</button></div>`,
        true);
      
      document.getElementById('mjCfgSave').onclick = async () => {
        const body = {
          listen: document.getElementById('mjCfgListen').value.trim(),
          masquerade_url: document.getElementById('mjCfgMasq').value.trim(),
          auth_token: document.getElementById('mjCfgAuth').value.trim(),
          obfs_password: document.getElementById('mjCfgObfs').value.trim(),
          brutal_tx: +document.getElementById('mjCfgBrutal').value || 0,
          idle_timeout_secs: +document.getElementById('mjCfgIdle').value || 30,
          udp_enabled: document.getElementById('mjCfgUdp').checked,
          gecko_enabled: document.getElementById('mjCfgGecko').checked
        };
        try {
          await postJ('miraj/config', body);
          toast.ok('Сохранено. Для применения — перезапустите сервис.');
          closeModal();
          if (onDone) onDone();
        } catch (e) { toast.err(e.message); }
      };
    } catch (e) { toast.err(e.message); }
  })();
}

/* ══════════════════ TUNNEL ══════════════════ */
async function vpnTunnelTab(box) {
  await renderTunnelSection(box);
}

export async function renderTunnelSection(box) {
  if (!box) return;
  
  box.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">🚇 Tunnel клиенты</div>
          <div class="card-sub">Пользователи обратного туннеля (WS на :443 / WebTransport на :808) · клик по строке — действия</div>
        </div>
        <div class="card-actions">
          <button class="button small" id="tnReload" title="Обновить">🔄</button>
          <button class="button small primary" id="tnNew">+ Клиент</button>
        </div>
      </div>
      <div id="tnBody">${spinner()}</div>
    </div>
  `;
  
  const load = async () => {
    try {
      const list = await get('tunnel/clients');
      const rows = Array.isArray(list) ? list : [];
      if (!rows.length) {
        document.getElementById('tnBody').innerHTML = `
          <div class="empty-state">
            <div class="icon">🚇</div>
            <div class="title">Tunnel-клиентов нет</div>
            <div class="sub">Создайте первого — он получит уникальный path_prefix и пароль</div>
            <div class="actions"><button class="button small primary" id="tnNewEmpty">+ Создать</button></div>
          </div>
        `;
        const b = document.getElementById('tnNewEmpty');
        if (b) b.onclick = () => tunnelNewClient(() => load());
        return;
      }
      
      document.getElementById('tnBody').innerHTML = renderTable([
        { label: 'ID', key: 'id' },
        { label: 'Имя', render: r => `<strong>${esc(r.name)}</strong>` },
        { label: 'Path prefix', render: r => `<code class="mono">${esc(r.path_prefix)}</code>` },
        { label: 'Targets', render: r => {
            const t = Array.isArray(r.allow_targets) ? r.allow_targets : [];
            return t.length ? t.map(x => `<span class="tag">${esc(x)}</span>`).join(' ') : '—';
          }
        },
        { label: 'Статус', render: r => r.enabled ? badge('активен') : badge('отключён', 'neutral') },
        { label: 'Трафик ↓/↑', render: r => `${fmtSize(r.bytes_in || 0)} / ${fmtSize(r.bytes_out || 0)}` },
        { label: '', render: () => `<div class="row-actions"><button class="button small" title="Действия">›</button></div>` }
      ], rows);
      
      $$('#tnBody tbody tr').forEach((tr, i) => {
        if (rows[i]) { tr.classList.add('vpn-row-clickable'); tr.onclick = () => openTunnelClientPanel(rows[i]); }
      });
    } catch (e) {
      document.getElementById('tnBody').innerHTML = errBox(e);
    }
  };
  
  document.getElementById('tnReload').onclick = load;
  document.getElementById('tnNew').onclick = () => tunnelNewClient(() => load());
  await load();
}

export function openTunnelClientPanel(client) {
  const panel = $('#toolPanel'); 
  const backdrop = $('#toolPanelBackdrop');
  panel.dataset.owner = 'tunnel'; 
  backdrop.classList.add('open');
  
  const render = () => {
    if (S.toolPanelCollapsed) {
      panel.classList.add('collapsed');
      panel.innerHTML = `<button class="tool-panel-toggle" title="Развернуть" onclick="toggleToolPanelCollapse()">▴</button>`;
    } else {
      panel.classList.remove('collapsed');
      panel.innerHTML = `
        <button class="tool-panel-top-toggle" title="Свернуть" onclick="toggleToolPanelCollapse()">▾</button>
        <div class="tool-panel-title" title="${esc(client.name || ('#' + client.id))}">${esc(client.name || ('#' + client.id))}</div>
        <button class="tool-panel-btn" title="URI" onclick="closeToolPanel(); tunnelShowUri('${client.id}')">🔗</button>
        <button class="tool-panel-btn" title="Сбросить пароль" onclick="tunnelResetPassword('${client.id}')">🔑</button>
        <button class="tool-panel-btn" title="${client.enabled ? 'Отключить' : 'Включить'}" onclick="tunnelToggle('${client.id}', ${client.enabled})">${client.enabled ? '⏸' : '▶'}</button>
        <button class="tool-panel-btn danger" title="Удалить" onclick="tunnelDelete('${client.id}', '${esc(client.name || '')}')">×</button>
      `;
    }
    if (!panel.classList.contains('open')) requestAnimationFrame(() => panel.classList.add('open'));
  };
  
  render();
  panel._renderer = render;
}

export async function tunnelShowUri(id) {
  try {
    const d = await get('tunnel/clients/' + encodeURIComponent(id) + '/uri');
    const uri = d.uri || '';
    showModal('Tunnel URI',
      `<div class="field"><label>URI</label><input value="${esc(uri)}" readonly onclick="this.select()"></div>
       <div class="info-box">Вставьте URI в клиент OmniTunnel. Хост взят из <code>acme_ip</code> / <code>acme_domains</code>.</div>`,
      `<div class="modal-foot"><button class="button" onclick="closeModal()">Закрыть</button><button class="button primary" id="tnCopy">📋 Копировать</button></div>`);
    document.getElementById('tnCopy').onclick = () => {
      navigator.clipboard.writeText(uri).then(() => toast.ok('Скопировано')).catch(() => toast.err('Не удалось'));
    };
  } catch (e) { toast.err(e.message); }
}

export async function tunnelToggle(id, enable) {
  closeToolPanel();
  try { 
    await post('tunnel/clients/' + encodeURIComponent(id) + (enable ? '/disable' : '/enable')); 
    toast.ok('OK'); 
    mount(document.getElementById('viewContent')); 
  } catch (e) { toast.err(e.message); }
}

export async function tunnelResetPassword(id) {
  if (!await confirmDlg('Сбросить пароль?', 'Старый URI перестанет работать.')) return;
  closeToolPanel();
  try { 
    const r = await post('tunnel/clients/' + encodeURIComponent(id) + '/reset'); 
    toast.ok('Новый пароль: ' + r.password); 
    mount(document.getElementById('viewContent')); 
  } catch (e) { toast.err(e.message); }
}

export async function tunnelDelete(id, name) {
  closeToolPanel();
  if (!await confirmDlg('Удалить tunnel-клиента?', name || String(id))) return;
  try { 
    await del('tunnel/clients/' + encodeURIComponent(id)); 
    toast.ok('Удалён'); 
    mount(document.getElementById('viewContent')); 
  } catch (e) { toast.err(e.message); }
}

export function tunnelNewClient(onDone) {
  showModal('Новый tunnel-клиент',
    `<div class="field"><label>Имя</label><input id="tnNewName" placeholder="my-client" autofocus></div>
     <div class="field"><label>Path prefix <span style="color:var(--muted);font-weight:400">(пусто = имя)</span></label><input id="tnNewPrefix" placeholder="v1"></div>
     <div class="field"><label>Allow targets <span style="color:var(--muted);font-weight:400">(через запятую host:port)</span></label><input id="tnNewTargets" placeholder="127.0.0.1:443, 127.0.0.1:888"></div>
     <div class="field"><label>Пароль <span style="color:var(--muted);font-weight:400">(пусто = сгенерировать)</span></label><input id="tnNewPass" placeholder=""></div>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="tnNewSave">Создать</button></div>`);
  setTimeout(() => document.getElementById('tnNewName')?.focus(), 50);
  
  document.getElementById('tnNewSave').onclick = async () => {
    const name = document.getElementById('tnNewName').value.trim();
    if (!name) return toast.err('Введите имя');
    const path_prefix = document.getElementById('tnNewPrefix').value.trim() || name;
    const targets_raw = document.getElementById('tnNewTargets').value.trim();
    const allow_targets = targets_raw ? targets_raw.split(',').map(s => s.trim()).filter(Boolean) : [];
    const password = document.getElementById('tnNewPass').value.trim();
    try {
      const r = await postJ('tunnel/clients', { name, path_prefix, allow_targets, password });
      toast.ok('Создан · пароль: ' + (r.password || '—'));
      closeModal(); 
      if (onDone) onDone();
    } catch (e) { toast.err(e.message); }
  };
}

/* ══════════════════ IKEv2 ══════════════════ */
async function vpnIkev2Tab(box, c) {
  await renderIkev2Section(box, c);
}

export async function renderIkev2Section(box, c) {
  if (!box) return;
  
  box.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">🔐 IKEv2/IPSec Сервер</div>
          <div class="card-sub">Настройки встроенного сервера (RFC 7296)</div>
        </div>
        <div class="card-actions">
          <button class="button small" id="ikev2Reload" title="Обновить">🔄</button>
        </div>
      </div>
      <div id="ikev2Body">${spinner()}</div>
    </div>
    
    <div class="card" style="margin-top:14px">
      <div class="card-head">
        <div><div class="card-title">📱 Настройка Android</div></div>
      </div>
      <div class="info-box">
        <p style="margin:0 0 10px 0"><strong>1.</strong> В настройках телефона выберите <b>VPN → Добавить VPN → IKEv2/IPSec PSK</b>.</p>
        <p style="margin:0 0 10px 0"><strong>2.</strong> <b>Адрес сервера:</b> <code>${location.hostname}</code></p>
        <p style="margin:0 0 10px 0"><strong>3.</strong> <b>Идентификатор IPSec:</b> <code id="ikeHelpId">загрузка...</code></p>
        <p style="margin:0 0 10px 0"><strong>4.</strong> <b>Предварительный ключ (PSK):</b> Ваш пароль администратора</p>
      </div>
    </div>
  `;

  const load = async () => {
    try {
      const cfg = await get('ikev2/config');
      const sys = await get('system/config'); // Получаем настройки системы, чтобы взять acme_ip
      const fallbackIp = sys.acme_ip || location.hostname;
      
      // Если local_id пустой или "omnirs", показываем fallbackIp
      const currentId = (cfg.local_id && cfg.local_id !== 'omnirs') ? cfg.local_id : fallbackIp;

      // Обновляем текст в инструкции
      const helpId = document.getElementById('ikeHelpId');
      if (helpId) helpId.textContent = currentId;

      document.getElementById('ikev2Body').innerHTML = `
        <div class="form-grid">
          <div class="field">
            <label>Listen Address (UDP)</label>
            <input id="ikeListen" value="${esc(cfg.listen || '0.0.0.0:500')}" readonly style="opacity: 0.7">
          </div>
          <div class="field">
            <label>IPSec ID (Local ID)</label>
            <input id="ikeLocalId" value="${esc(currentId)}" placeholder="${esc(fallbackIp)}">
            <small>Должен совпадать с IP-адресом сервера (acme_ip)</small>
          </div>
        </div>
        
        <div class="switch-row">
          <div>
            <strong>Сервер включен</strong>
            <small>Включен по умолчанию. Требуется перезагрузка сервиса.</small>
          </div>
          <input type="checkbox" class="switch" id="ikeEnabled" ${cfg.enabled ? 'checked' : ''}>
        </div>

        <div style="margin-top:16px; display:flex; gap:8px;">
          <button class="button primary" id="ikeSave">💾 Сохранить настройки</button>
        </div>
      `;

      document.getElementById('ikeSave').onclick = async () => {
        const body = {
          listen: '0.0.0.0:500',
          local_id: document.getElementById('ikeLocalId').value.trim() || fallbackIp,
          remote_id: '%any',
          enabled: document.getElementById('ikeEnabled').checked
        };
        
        try {
          await postJ('ikev2/config', body);
          toast.ok('Сохранено. Перезапустите сервис (ritual -> 2).');
        } catch (e) {
          toast.err(e.message);
        }
      };
    } catch (e) {
      document.getElementById('ikev2Body').innerHTML = errBox(e);
    }
  };

  document.getElementById('ikev2Reload').onclick = load;
  await load();
}


/* ══════════════════ WIREGUARD ══════════════════ */
async function vpnWireguardTab(box, c) { 
  await renderVPNSection(box, c); 
}

export async function renderVPNSection(box, c) {
  box.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">🛡️ VPN клиенты</div>
          <div class="card-sub">Два интерфейса: vpn0 (QR) и obfs0 (обфускация)</div>
        </div>
        <div class="card-actions">
          <input id="vpnSearch" placeholder="Поиск…" style="max-width:180px">
          <button class="button small" id="vpnRefresh" title="Обновить">🔄</button>
          <button class="button small primary" id="vpnNew">+ Клиент</button>
        </div>
      </div>
      <div id="vpnBody">${spinner()}</div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-head">
        <div>
          <div class="card-title">⚙️ Интерфейсы</div>
          <div class="card-sub">vpn0 — VPN (QR :888), obfs0 — обфускация (:880)</div>
        </div>
        <div class="card-actions">
          <button class="button small" id="vpnIfaceEdit">✎ Редактировать</button>
          <button class="button small" id="vpnCidr">CIDR</button>
          <button class="button small danger" id="vpnRestart">🔁 Restart</button>
        </div>
      </div>
      <div id="vpnIface">${spinner()}</div>
    </div>
  `;

  const load = async () => {
    const search = (document.getElementById('vpnSearch').value || '').toLowerCase();
    try {
      const clients = await get('vpn/clients' + (search ? '?filter=' + encodeURIComponent(search) : ''));
      S.vpnClients = clients;
      document.getElementById('vpnBody').innerHTML = renderVPNTable(clients);
      bindVPNActions();
    } catch (e) { 
      document.getElementById('vpnBody').innerHTML = errBox(e); 
    }
    
    try {
      const iface = await get('vpn/interface');
      const vpnState = iface.vpn.running ? '✓ запущен' : '✗ остановлен';
      const obfsState = iface.vpn.running ? '✓ запущен' : (iface.obfs.running ? (iface.obfs.obfs_active ? '✓ запущен (обфускация)' : '⚠ запущен без обфускации') : '✗ остановлен');
      
      document.getElementById('vpnIface').innerHTML = `
        <div class="grid two-col" style="gap:14px">
          <div class="card" style="background:var(--panel2);padding:14px">
            <div class="card-title">🌐 ${esc(iface.vpn.name)} — VPN</div>
            <div class="card-sub" style="margin-bottom:10px">QR-конфиг подключается сюда</div>
            ${renderKVGrid({ port: iface.vpn.port, listen_port: iface.vpn.listen_port || '—', state: vpnState, peers: iface.vpn.peers, ipv4_cidr: iface.vpn.ipv4_cidr, ipv6_cidr: iface.vpn.ipv6_cidr }, 2)}
          </div>
          <div class="card" style="background:var(--panel2);padding:14px">
            <div class="card-title">🛡️ ${esc(iface.obfs.name)} — обфускация</div>
            <div class="card-sub" style="margin-bottom:10px">Скачиваемый конфиг подключается сюда</div>
            ${renderKVGrid({ port: iface.obfs.port, listen_port: iface.obfs.listen_port || '—', state: obfsState, peers: iface.obfs.peers, ipv4_cidr: iface.obfs.ipv4_cidr, ipv6_cidr: iface.obfs.ipv6_cidr }, 2)}
          </div>
        </div>
        <div class="card" style="background:var(--panel2);padding:14px;margin-top:14px">
          <div class="card-title">Общие настройки</div>
          ${renderKVGrid({
            device: iface.device, mtu: iface.mtu, routing_table: iface.routing_table,
            enabled: iface.enabled == 1 ? '✓' : '✗',
            firewall: iface.firewall_enabled == 1 ? 'включён' : 'выключен',
            public_key: iface.public_key
          }, 3)}
        </div>
      `;
    } catch (e) { 
      document.getElementById('vpnIface').innerHTML = errBox(e); 
    }
  };

  document.getElementById('vpnRefresh').onclick = load;
  document.getElementById('vpnSearch').oninput = () => { clearTimeout(window.__vpnT); window.__vpnT = setTimeout(load, 300); };
  document.getElementById('vpnNew').onclick = () => vpnNewClient(load);
  document.getElementById('vpnIfaceEdit').onclick = () => vpnEditInterface(load);
  document.getElementById('vpnCidr').onclick = () => vpnEditCidr(load);
  document.getElementById('vpnRestart').onclick = async () => {
    if (!await confirmDlg('Перезапустить интерфейсы?', 'Клиенты отключатся на ~2 секунды')) return;
    try { await post('vpn/interface/restart'); toast.ok('OK'); load(); }
    catch (e) { toast.err(e.message); }
  };
  
  await load();
}

export function renderVPNTable(clients) {
  if (!clients || !clients.length) {
    return `
      <div class="empty-state">
        <div class="icon">🛡️</div>
        <div class="title">Клиентов нет</div>
        <div class="sub">Создайте первого клиента</div>
        <div class="actions"><button class="button small primary" id="vpnNewEmpty">+ Создать</button></div>
      </div>
    `;
  }
  
  const rows = clients.map(x => {
    const hs = x.latestHandshakeAt ? new Date(x.latestHandshakeAt).toLocaleString('ru-RU') : '—';
    const connected = x.latestHandshakeAt && (Date.now() - new Date(x.latestHandshakeAt).getTime() < 600000);
    const enabled = x.enabled === 1;
    
    return `
      <tr class="vpn-row-clickable" data-vpn-row="${x.id}">
        <td>${x.id}</td>
        <td><strong>${esc(x.name)}</strong>${connected ? ' <span class="status">online</span>' : ''}</td>
        <td>
          <div style="font-size:10px;color:var(--muted);margin-bottom:2px">VPN :888</div>
          <code class="mono-sm">${esc(x.vpnIpv4Address || '—')}</code><br>
          <code class="mono-sm" style="color:var(--muted)">${esc(x.vpnIpv6Address || '—')}</code>
        </td>
        <td>
          <div style="font-size:10px;color:var(--muted);margin-bottom:2px">Obfs :880</div>
          <code class="mono-sm">${esc(x.ipv4Address || '—')}</code><br>
          <code class="mono-sm" style="color:var(--muted)">${esc(x.ipv6Address || '—')}</code>
        </td>
        <td>${enabled ? badge('активен') : badge('отключён', 'neutral')}</td>
        <td>${hs}</td>
        <td>${x.transferRx != null ? `↓${fmtSize(x.transferRx)} ↑${fmtSize(x.transferTx)}` : '—'}</td>
        <td style="text-align:center;color:var(--muted);font-size:20px;line-height:1">›</td>
      </tr>
    `;
  }).join('');
  
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>ID</th><th>Имя</th><th>IP (VPN)</th><th>IP (Obfs)</th><th>Статус</th><th>Handshake</th><th>Трафик</th><th></th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

export function bindVPNActions() {
  $$('[data-vpn-row]').forEach(el => {
    el.onclick = () => {
      const id = el.dataset.vpnRow;
      const client = (S.vpnClients || []).find(c => String(c.id) === String(id));
      if (client) openVPNClientPanel(client);
    };
  });
}

export function openVPNClientPanel(client) {
  S.toolPanelVpnClient = client;
  const panel = $('#toolPanel');
  const backdrop = $('#toolPanelBackdrop');
  panel.dataset.owner = 'vpn';
  backdrop.classList.add('open');
  
  const render = () => {
    const isDefault = client.name === 'OmniVPN';
    const enabled = client.enabled === 1;
    
    if (S.toolPanelCollapsed) {
      panel.classList.add('collapsed');
      panel.innerHTML = `<button class="tool-panel-toggle" title="Развернуть" onclick="toggleToolPanelCollapse()">▴</button>`;
    } else {
      panel.classList.remove('collapsed');
      panel.innerHTML = `
        <button class="tool-panel-top-toggle" title="Свернуть" onclick="toggleToolPanelCollapse()">▾</button>
        <div class="tool-panel-title" title="${esc(client.name)}">${esc(client.name)}</div>
        <button class="tool-panel-btn" title="QR-код" onclick="vpnShowQR('${client.id}')">📱</button>
        <button class="tool-panel-btn" title="Скачать" onclick="vpnDownloadCfg('${client.id}', '${esc(client.name)}')">⬇</button>
        <button class="tool-panel-btn" title="One-time-link" onclick="vpnCreateOTL('${client.id}')">🔗</button>
        <button class="tool-panel-btn" title="${enabled ? 'Отключить' : 'Включить'}" onclick="vpnToggle('${client.id}', ${enabled})">${enabled ? '⏸' : '▶'}</button>
        <button class="tool-panel-btn" title="Редактировать" onclick="closeToolPanel(); vpnEditClient(${client.id})">✎</button>
        ${isDefault ? '' : `<button class="tool-panel-btn danger" title="Удалить" onclick="vpnDelete('${client.id}', '${esc(client.name)}')">×</button>`}
      `;
    }
    if (!panel.classList.contains('open')) requestAnimationFrame(() => panel.classList.add('open'));
  };
  
  render();
  panel._renderer = render;
}

export function vpnShowQR(id) {
  closeToolPanel();
  showModal('QR-код',
    `<div style="text-align:center"><img src="/api/vpn/client/${id}/qrcode" style="max-width:100%;background:#fff;padding:10px;border-radius:12px"></div>
     <p style="color:var(--muted);font-size:12px;margin:12px 0 0"></p>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Закрыть</button></div>`);
}

export async function vpnDownloadCfg(id, name) {
  closeToolPanel();
  const safeName = name.replace(/[^a-zA-Z0-9_-]+/g, '_') || ('client-' + id);
  try {
    const r = await fetch('/api/vpn/client/' + id + '/configuration', { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const b = await r.blob();
    const url = URL.createObjectURL(b);
    const a = document.createElement('a');
    a.href = url; 
    a.download = safeName + '.conf';
    document.body.appendChild(a); 
    a.click(); 
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  } catch (e) { toast.err('Config: ' + e.message); }
}

export async function vpnCreateOTL(id) {
  closeToolPanel();
  try {
    const d = await post('vpn/client/' + id + '/one-time-link');
    const extOrigin = location.protocol + '//' + location.hostname;
    const link = extOrigin + '/cnf/' + d.oneTimeLink;
    showModal('One-time-link',
      `<div class="field"><label>Ссылка (действует 5 минут)</label><input value="${esc(link)}" readonly onclick="this.select()"></div>`,
      `<div class="modal-foot"><button class="button" onclick="closeModal()">Закрыть</button><button class="button primary" id="otlCopy">📋 Копировать</button></div>`);
    document.getElementById('otlCopy').onclick = () => {
      navigator.clipboard.writeText(link).then(() => toast.ok('Скопировано')).catch(() => toast.err('Не удалось'));
    };
  } catch (e) { toast.err(e.message); }
}

export async function vpnToggle(id, isEnabled) {
  closeToolPanel();
  try { 
    await post('vpn/client/' + id + (isEnabled ? '/disable' : '/enable')); 
    toast.ok('OK'); 
    document.getElementById('vpnRefresh').click(); 
  } catch (e) { toast.err(e.message); }
}

export async function vpnDelete(id, name) {
  closeToolPanel();
  if (!await confirmDlg('Удалить клиента?', name)) return;
  try { 
    await api('vpn/client/' + id, { method: 'DELETE' }); 
    toast.ok('Удалён'); 
    document.getElementById('vpnRefresh').click(); 
  } catch (e) { toast.err(e.message); }
}

export function vpnEditClient(id) {
  (async () => {
    try {
      const c = await get('vpn/client/' + id);
      const allowed = (c.allowedIps || []).join(', ');
      const serverAllowed = (c.serverAllowedIps || []).join(', ');
      const firewallIps = (c.firewallIps || []).join(', ');
      const expires = c.expiresAt || '';
      
      showModal('Редактировать: ' + c.name,
        `<div class="form-grid">
           <div class="field"><label>Имя</label><input id="wcName" value="${esc(c.name)}"></div>
           <div class="field"><label>MTU</label><input id="wcMtu" type="number" value="${c.mtu}"></div>
         </div>
         <div class="section-label">VPN (:888, QR)</div>
         <div class="form-grid">
           <div class="field"><label>IPv4</label><input id="wcVpnV4" value="${esc(c.vpnIpv4Address || '')}"></div>
           <div class="field"><label>IPv6</label><input id="wcVpnV6" value="${esc(c.vpnIpv6Address || '')}"></div>
         </div>
         <div class="section-label">Obfs (:880, конфиг)</div>
         <div class="form-grid">
           <div class="field"><label>IPv4</label><input id="wcV4" value="${esc(c.ipv4Address || '')}"></div>
           <div class="field"><label>IPv6</label><input id="wcV6" value="${esc(c.ipv6Address || '')}"></div>
         </div>
         <div class="form-grid">
           <div class="field"><label>Keepalive</label><input id="wcPk" type="number" value="${c.persistentKeepalive || 0}"></div>
           <div class="field"><label>Expires at (RFC3339)</label><input id="wcExp" value="${esc(expires)}" placeholder="2027-01-01T00:00:00Z"></div>
         </div>
         <div class="field"><label>DNS (через запятую)</label><input id="wcDns" value="${esc((c.dns || []).join(', '))}"></div>
         <div class="field"><label>AllowedIps (клиента, через запятую)</label><input id="wcAllowed" value="${esc(allowed)}" placeholder="0.0.0.0/0, ::/0"></div>
         <div class="field"><label>ServerAllowedIps (через запятую)</label><input id="wcSrv" value="${esc(serverAllowed)}"></div>
         <div class="field"><label>FirewallIps (через запятую)</label><input id="wcFw" value="${esc(firewallIps)}" placeholder="10.0.0.0/24, 8.8.8.8:53/udp"></div>`,
        `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="wcSave">Сохранить</button></div>`,
        true);
        
      document.getElementById('wcSave').onclick = async () => {
        const v = {
          name: document.getElementById('wcName').value.trim(),
          mtu: +document.getElementById('wcMtu').value,
          vpnIpv4Address: document.getElementById('wcVpnV4').value.trim(),
          vpnIpv6Address: document.getElementById('wcVpnV6').value.trim(),
          ipv4Address: document.getElementById('wcV4').value.trim(),
          ipv6Address: document.getElementById('wcV6').value.trim(),
          persistentKeepalive: +document.getElementById('wcPk').value,
          expiresAt: document.getElementById('wcExp').value.trim() || null,
          dns: document.getElementById('wcDns').value.split(',').map(s => s.trim()).filter(Boolean),
          allowedIps: document.getElementById('wcAllowed').value.split(',').map(s => s.trim()).filter(Boolean),
          serverAllowedIps: document.getElementById('wcSrv').value.split(',').map(s => s.trim()).filter(Boolean),
          firewallIps: document.getElementById('wcFw').value.split(',').map(s => s.trim()).filter(Boolean)
        };
        try { 
          await postJ('vpn/client/' + id, v); 
          toast.ok('Сохранено'); 
          closeModal(); 
          document.getElementById('vpnRefresh').click(); 
        } catch (e) { toast.err(e.message); }
      };
    } catch (e) { toast.err(e.message); }
  })();
}

export function vpnEditInterface(onDone) {
  (async () => {
    try {
      const i = await get('vpn/interface');
      showModal('Настройки интерфейсов',
        `<div class="form-grid">
           <div class="field"><label>Device</label><input id="wiDev" value="${esc(i.device)}"></div>
           <div class="field"><label>MTU</label><input id="wiMtu" type="number" value="${i.mtu}"></div>
         </div>
         <div class="form-grid">
           <div class="field"><label>VPN port (QR, :888)</label><input id="wiVpnPort" type="number" value="${i.vpn.port}"></div>
           <div class="field"><label>Obfs port (конфиг, :880)</label><input id="wiPort" type="number" value="${i.obfs.port}"></div>
         </div>
         <div class="field"><label>Routing Table</label><input id="wiRt" value="${esc(i.routing_table)}"></div>
         <div class="switch-row">
           <div><strong>Per-client firewall</strong><small>iptables chain WG_CLIENTS_*</small></div>
           <input type="checkbox" class="switch" id="wiFw" ${i.firewall_enabled == 1 ? 'checked' : ''}>
         </div>`,
        `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="wiSave">Сохранить</button></div>`);
        
      document.getElementById('wiSave').onclick = async () => {
        try {
          await postJ('vpn/interface', {
            device: document.getElementById('wiDev').value.trim(),
            port: +document.getElementById('wiPort').value,
            vpnPort: +document.getElementById('wiVpnPort').value,
            mtu: +document.getElementById('wiMtu').value,
            routingTable: document.getElementById('wiRt').value.trim(),
            firewallEnabled: document.getElementById('wiFw').checked
          });
          toast.ok('Сохранено'); 
          closeModal(); 
          if (onDone) onDone();
        } catch (e) { toast.err(e.message); }
      };
    } catch (e) { toast.err(e.message); }
  })();
}

export function vpnEditCidr(onDone) {
  (async () => {
    try {
      const i = await get('vpn/interface');
      showModal('CIDR подсети',
        `<div class="section-label">VPN (:888, QR)</div>
         <div class="form-grid">
           <div class="field"><label>IPv4 CIDR</label><input id="wcVpnV4C" value="${esc(i.vpn.ipv4_cidr)}"></div>
           <div class="field"><label>IPv6 CIDR</label><input id="wcVpnV6C" value="${esc(i.vpn.ipv6_cidr)}"></div>
         </div>
         <div class="section-label">Obfs (:880, конфиг)</div>
         <div class="form-grid">
           <div class="field"><label>IPv4 CIDR</label><input id="wcV4C" value="${esc(i.obfs.ipv4_cidr)}"></div>
           <div class="field"><label>IPv6 CIDR</label><input id="wcV6C" value="${esc(i.obfs.ipv6_cidr)}"></div>
         </div>
         <p style="color:var(--muted);font-size:12px;margin:10px 0 0">⚠️ Клиентские IP пересчитаются. Старые конфиги перестанут работать — надо пере-скачать.</p>`,
        `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="wcCidrSave">Применить</button></div>`);
        
      document.getElementById('wcCidrSave').onclick = async () => {
        try {
          await postJ('vpn/interface/cidr', {
            ipv4Cidr: document.getElementById('wcV4C').value.trim(),
            ipv6Cidr: document.getElementById('wcV6C').value.trim(),
            vpnIpv4Cidr: document.getElementById('wcVpnV4C').value.trim(),
            vpnIpv6Cidr: document.getElementById('wcVpnV6C').value.trim()
          });
          toast.ok('CIDR обновлён'); 
          closeModal(); 
          if (onDone) onDone();
        } catch (e) { toast.err(e.message); }
      };
    } catch (e) { toast.err(e.message); }
  })();
}

export function vpnNewClient(onDone) {
  showModal('Новый VPN клиент',
    `<div class="field"><label>Имя клиента</label><input id="vpnNewName" placeholder="my-device" autofocus></div>
     <div class="field"><label>Пароль <span style="color:var(--muted);font-weight:400">(опционально, для учёта)</span></label><input id="vpnNewPass" placeholder="Можно оставить пустым"></div>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="vpnNewSave">Создать</button></div>`);
  setTimeout(() => $('#vpnNewName')?.focus(), 50);
  
  $('#vpnNewSave').onclick = async () => {
    const name = $('#vpnNewName').value.trim();
    const password = $('#vpnNewPass').value.trim();
    if (!name) return toast.err('Введите имя клиента');
    try {
      const r = await postJ('vpn/clients', { name, password });
      toast.ok('Клиент создан #' + r.clientId);
      closeModal();
      if (onDone) onDone();
    } catch (e) { toast.err(e.message); }
  };
}

/* ── Экспорт всех функций в window для inline onclick ── */
Object.assign(window, {
  renderMirajSection, openMirajUserPanel, mirajShowUri, mirajToggle, mirajDelete, mirajNewClient, mirajConfigDialog,
  renderTunnelSection, openTunnelClientPanel, tunnelShowUri, tunnelToggle, tunnelResetPassword, tunnelDelete, tunnelNewClient,
  renderVPNSection, openVPNClientPanel, vpnShowQR, vpnDownloadCfg, vpnCreateOTL, vpnToggle, vpnDelete,
  vpnEditClient, vpnEditInterface, vpnEditCidr, vpnNewClient,
  renderIkev2Section
});