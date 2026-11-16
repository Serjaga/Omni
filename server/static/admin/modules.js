// Единый интерфейс системных и устанавливаемых Rust-модулей OmniRS.
import { $, get, post, toast, spinner, errBox } from './app.js';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let poll=null;
export async function mount(c){
  if(poll){clearInterval(poll);poll=null;}
  c.innerHTML=spinner();
  try{
    const d=await get('modules'); const mods=d.modules||[];
    c.innerHTML=`<div class="card"><div class="card-head"><div><div class="card-title">Модули OmniRS (${mods.length})</div><p style="opacity:.7;font-size:13px">Системные и установленные модули. Rust-модули собираются непосредственно в основной бинарник OmniRS.</p></div>
    <div class="card-actions"><input id="moduleZip" type="file" accept=".zip,application/zip" style="display:none"><button class="button primary" id="moduleUpload">⬆ Установить / обновить ZIP</button></div></div>
    <div class="table-wrap"><table><thead><tr><th>Модуль</th><th>Версия</th><th>Тип</th><th>Состояние</th><th>Интерфейс</th><th></th></tr></thead><tbody>${mods.map(m=>{
      const builtIn=m.source==='system'; const hasAdmin=!!m.admin_entry;
      return `<tr><td><b>${esc(m.name||m.label||m.module_id||m.key)}</b><br><code style="opacity:.6">${esc(m.module_id||m.key)}</code><div style="opacity:.65;font-size:12px">${esc(m.description||m.desc||'')}</div></td><td>${esc(m.version||'—')}</td><td>${builtIn?'Системный':'Rust source'}</td><td>${esc(m.status|| (m.enabled===false?'отключён':'встроен'))}</td><td>${hasAdmin?`<button class="button small" data-open-admin="${esc(m.module_id)}">Открыть</button>`:'—'}</td><td>${builtIn?'':`<button class="button small danger" data-delete="${esc(m.module_id)}">Удалить</button>`}</td></tr>`;
    }).join('')||'<tr><td colspan="6">Модули пока не зарегистрированы</td></tr>'}</tbody></table></div><div id="moduleAdminHost"></div></div>`;
    const input=$('#moduleZip',c); $('#moduleUpload',c).onclick=()=>input.click();
    input.onchange=async()=>{const f=input.files?.[0];if(!f)return;try{const id=prompt('ID модуля (должен совпадать с module.toml):',f.name.replace(/\.zip$/i,'').replace(/[^a-zA-Z0-9_-]/g,'_'));if(!id)return;if(!/^[a-zA-Z0-9_-]{1,64}$/.test(id))throw new Error('Недопустимый ID');const r=await fetch(`api/modules/upload/${encodeURIComponent(id)}`,{method:'POST',headers:{'content-type':'application/zip'},body:await f.arrayBuffer()});const x=await r.json();if(!r.ok||!x.ok)throw new Error(x.error||`HTTP ${r.status}`);toast(x.updated?'Модуль обновлён. Началась пересборка OmniRS':'Модуль установлен. Началась пересборка OmniRS','ok');await mount(c);poll=setInterval(async()=>{try{const s=await get(`modules/status/${encodeURIComponent(id)}`);if(['installed','build_failed'].includes(s.status)){clearInterval(poll);poll=null;s.status==='installed'?toast.ok('Сборка завершена; сервер перезапускается'):toast.err('Ошибка сборки: '+s.build_log);await mount(c);}}catch(_){}},4000);}catch(e){toast.err('Ошибка установки: '+e.message);}finally{input.value='';}};
    c.querySelectorAll('[data-open-admin]').forEach(b=>b.onclick=async()=>{const m=mods.find(x=>x.module_id===b.dataset.openAdmin);if(!m?.admin_entry)return;const host=$('#moduleAdminHost',c);host.innerHTML='<div class="card"><h3>'+esc(m.name)+'</h3><div id="moduleAdminMount"></div></div>';try{const mod=await import(`/module-assets/${encodeURIComponent(m.module_id)}/${m.admin_entry.split('/').map(encodeURIComponent).join('/')}`);if(typeof mod.mount!=='function')throw new Error('admin entry должен экспортировать mount(container)');await mod.mount($('#moduleAdminMount',host));}catch(e){host.innerHTML=`<div class="card">Не удалось открыть интерфейс модуля: ${esc(e.message)}</div>`;}});
    c.querySelectorAll('[data-delete]').forEach(b=>b.onclick=async()=>{const id=b.dataset.delete;if(!confirm(`Удалить модуль ${id}? Для удаления его кода из текущего бинарника потребуется пересборка.`))return;try{await post(`modules/delete/${encodeURIComponent(id)}`,{});toast('Исходники модуля удалены','ok');await mount(c);}catch(e){toast.err('Ошибка: '+e);}});
  }catch(e){c.innerHTML=errBox(e);}
}
