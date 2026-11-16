import {
  S, $, $$, esc, get, post, postJ, toast, confirmDlg,
  spinner, errBox, renderKV, renderKVGrid, renderTable, THEMES, setTheme,
  saveSubtabs, saveScrollAndRerender, scrollTabIntoView
} from './app.js';

const SUBS = [
  ['info','📄 Информация'],
  ['settings','⚙️ Настройки']
];

export async function mount(c){
  if(!SUBS.some(([id])=>id===S.sys.sub)) S.sys.sub = 'info';
  c.innerHTML = `<div class="subtabs" id="sysSubtabs">${SUBS.map(([id,l])=>`<button class="subtab ${S.sys.sub===id?'active':''}" data-syssub="${id}">${l}</button>`).join('')}</div><div id="sysBody"></div>`;
  $$('[data-syssub]').forEach(b=>b.onclick=()=>{
    S.sys.sub = b.dataset.syssub;
    saveSubtabs();
    saveScrollAndRerender('#sysSubtabs', ()=>mount(c));
  });
  const box = $('#sysBody');
  const dispatch = { info: systemInfo, settings: systemSettings };
  await dispatch[S.sys.sub](box, c);
  setTimeout(()=>scrollTabIntoView('#sysSubtabs','#sysSubtabs .subtab.active'), 0);
}

async function systemInfo(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">Порты</div></div></div>
    <div id="sysPorts">${spinner()}</div>
  </div>
  <div class="card" style="margin-top:14px">
    <div class="card-head">
      <div><div class="card-title">Действия</div></div>
      <div class="card-actions">
        <button class="button small" id="sysReload">🔄 Hot-reload</button>
        <button class="button small" id="sysReloadDns">🔄 Reload DNS</button>
        <button class="button small" id="sysGC">🧹 GC</button>
        <button class="button small danger" id="sysRestart">🔁 Restart</button>
      </div>
    </div>
  </div>`;

  try {
    const ports = await get('system/ports');
    $('#sysPorts').innerHTML = renderTable(['proto','port','state'], ports);
  } catch(e) {
    $('#sysPorts').innerHTML = errBox(e);
  }

  $('#sysReload').onclick = async ()=>{
    try{ await post('system/config_reload'); toast.ok('OK'); }
    catch(e){ toast.err(e.message); }
  };
  $('#sysReloadDns').onclick = async ()=>{
    try{ const d = await post('system/reload_dns'); toast.ok('Зон: '+d.loaded); }
    catch(e){ toast.err(e.message); }
  };
  $('#sysGC').onclick = async ()=>{
    try{ await post('system/gc'); toast.ok('OK'); }
    catch(e){ toast.err(e.message); }
  };
  $('#sysRestart').onclick = async ()=>{
    if(!await confirmDlg('Перезапустить?','systemctl restart omnirs')) return;
    try{ await post('system/restart'); toast.warn('Перезапуск…'); }
    catch(e){ toast.err(e.message); }
  };
}

async function systemSettings(box, c){
  box.innerHTML = `<div class="card" style="margin-bottom:14px">
    <div class="card-head"><div><div class="card-title">Цветовая тема</div></div></div>
    <div class="theme-palette" id="themePalette"></div>
  </div>
  <div class="grid two-col">
    <div class="card">
      <div class="card-head"><div><div class="card-title">Логирование</div></div></div>
      <label class="switch-row" style="border:0;padding:0 0 12px;cursor:pointer">
        <strong>Включено</strong>
        <input type="checkbox" class="switch" id="setLogging" ${S.settings.logging_enabled!==false?'checked':''}>
      </label>
      <button class="button primary" id="setLoggingBtn">Применить</button>
    </div>
  </div>`;

  const palette = $('#themePalette');
  palette.innerHTML = THEMES.map(t=>`<button class="theme-swatch ${S.theme===t.id?'active':''}" data-theme-pick="${t.id}">
    <div class="theme-swatch-preview" style="background:${t.bg};border-color:${t.line}"><span style="background:${t.accent}"></span></div>
    <div class="theme-swatch-name">${esc(t.name)}</div>
  </button>`).join('');
  $$('[data-theme-pick]').forEach(el=>el.onclick=()=>{
    setTheme(el.dataset.themePick);
    systemSettings(box, c);
  });

  try{
    const s = await get('settings');
    S.settings = s;
    $('#setLogging').checked = !!s.logging_enabled;
  }catch(e){}

  $('#setLoggingBtn').onclick = async ()=>{
    try{
      const d = await post('settings/logging_toggle', {enabled: $('#setLogging').checked?'true':'false'});
      S.settings.logging_enabled = d.enabled;
      toast.ok(d.enabled ? 'Вкл' : 'Выкл');
    }catch(e){ toast.err(e.message); }
  };
}

Object.assign(window, {
  renderSystem: mount,
  systemInfo, systemSettings
});