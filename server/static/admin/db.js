import {
  S, $, $$, esc, get, post, api, toast, confirmDlg,
  showModal, closeModal, spinner, errBox, renderTable,
  badge, invalidateGetCache, del
} from './app.js';

export async function mount(c){
  c.innerHTML=`<div class="card">
    <div class="card-head">
      <div><div class="card-title" id="dbTitle">🗄️ Базы данных</div>
           <div class="card-sub" id="dbPath"></div></div>
    </div>
    <div id="dbBulkBar"></div>
    <div id="dbContent">${spinner()}</div>
  </div>`;
  await loadDbContent(c);
}

export async function loadDbContent(c){
  const box=$('#dbContent'), title=$('#dbTitle'), pathInfo=$('#dbPath');
  box.innerHTML=spinner();
  try{
    if(!S.db.dbName){
      title.textContent='🗄️ Базы данных';
      const d=await get('db/connections',true);
      pathInfo.textContent='Папка: '+(d.db_dir||'./db');
      if(!d.connections||!d.connections.length){
        box.innerHTML=`<div class="empty-state">
          <div class="icon">🗄️</div>
          <div class="title">Баз данных нет</div>
          <div class="sub">Нажмите «+» в боковом меню, чтобы создать первую</div>
        </div>`;
        $('#dbBulkBar').innerHTML=''; renderDbToolPanel(); return;
      }
      const allChecked = d.connections.every(r=>S.db.selectedDbs.has(r.id));
      const rows = d.connections.map(r=>{
        const checked = S.db.selectedDbs.has(r.id);
        return {
          _check: `<input type="checkbox" class="db-check" data-db-check="${esc(r.id)}" ${checked?'checked':''}>`,
          _name: `<a data-dbopen="${esc(r.id)}" style="cursor:pointer;font-weight:600;color:var(--accent)">📁 ${esc(r.id)}</a>`,
          _kind: `<span class="tag">${esc(r.kind)}</span>`,
          _status: badge(r.healthy?'OK':'down',r.healthy?'':'error'),
          _q: r.queries_total,
          _sys: (r.id==='OmniDB'||r.id==='OmniVPN')
        };
      });
      box.innerHTML = renderTable([
        {label:`<input type="checkbox" class="db-check" id="dbCheckAll" ${allChecked?'checked':''}>`, render:r=>r._check},
        {label:'Имя', render:r=>r._name},
        {label:'Тип', render:r=>r._kind},
        {label:'Статус', render:r=>r._status},
        {label:'Запросов', key:'queries_total'}
      ], rows);
      $('#dbBulkBar').innerHTML = dbBulkBarHtml('db', S.db.selectedDbs.size);
      $('#dbCheckAll').onchange = (e)=>{
        if(e.target.checked) d.connections.forEach(r=>{
          if(r.id!=='OmniDB' && r.id!=='OmniVPN') S.db.selectedDbs.add(r.id);
        });
        else S.db.selectedDbs.clear();
        loadDbContent(c);
      };
      $$('[data-db-check]').forEach(el=>{
        el.onchange = (e)=>{
          const id = el.dataset.dbCheck;
          if(id==='OmniDB'||id==='OmniVPN'){e.target.checked=false;toast.warn('Системные БД нельзя удалять');return;}
          if(e.target.checked) S.db.selectedDbs.add(id); else S.db.selectedDbs.delete(id);
          loadDbContent(c);
        };
      });
      $$('[data-dbopen]').forEach(el=>el.onclick=()=>{
        S.db.dbName=el.dataset.dbopen; S.db.tableName=''; S.db.page=0; S.db.search='';
        S.db.activeRowPk=null; S.db.selectedDbs.clear();
        loadDbContent(c);
      });
      const bd=$('#dbBulkDel'), bc=$('#dbBulkClear');
      if(bd) bd.onclick = ()=>dbBulkDeleteSelectedDbs(c);
      if(bc) bc.onclick = ()=>{ S.db.selectedDbs.clear(); loadDbContent(c); };
    }
    else if(!S.db.tableName){
      title.textContent='📁 '+S.db.dbName;
      pathInfo.textContent='Выберите таблицу';
      const d=await get('db/connections/'+encodeURIComponent(S.db.dbName)+'/tables');
      if(!d.tables||!d.tables.length){
        box.innerHTML=`<div class="empty-state"><div class="icon">📋</div><div class="title">Таблиц нет</div><div class="sub">База данных пуста или не содержит таблиц</div></div>`;
        $('#dbBulkBar').innerHTML=''; renderDbToolPanel(); return;
      }
      const allChecked = d.tables.every(r=>S.db.selectedTables.has(r.name));
      const rows = d.tables.map(r=>({
        _check: `<input type="checkbox" class="db-check" data-tbl-check="${esc(r.name)}" ${S.db.selectedTables.has(r.name)?'checked':''}>`,
        _name: `<a data-tblopen="${esc(r.name)}" style="cursor:pointer;font-weight:600;color:var(--accent)">📄 ${esc(r.name)}</a>`,
        kind: r.kind,
        _fields: (r.schema||'').split(',').length-1
      }));
      box.innerHTML = renderTable([
        {label:`<input type="checkbox" class="db-check" id="dbCheckAll" ${allChecked?'checked':''}>`, render:r=>r._check},
        {label:'Имя таблицы', render:r=>r._name},
        {label:'Тип', key:'kind'},
        {label:'Поля', render:r=>r._fields}
      ], rows);
      $('#dbBulkBar').innerHTML = dbBulkBarHtml('table', S.db.selectedTables.size);
      $('#dbCheckAll').onchange = (e)=>{
        if(e.target.checked) d.tables.forEach(r=>S.db.selectedTables.add(r.name));
        else S.db.selectedTables.clear();
        loadDbContent(c);
      };
      $$('[data-tbl-check]').forEach(el=>el.onchange=(e)=>{
        const n = el.dataset.tblCheck;
        if(e.target.checked) S.db.selectedTables.add(n); else S.db.selectedTables.delete(n);
        loadDbContent(c);
      });
      $$('[data-tblopen]').forEach(el=>el.onclick=()=>{
        S.db.tableName=el.dataset.tblopen; S.db.page=0; S.db.search='';
        S.db.activeRowPk=null; S.db.selectedTables.clear();
        loadDbContent(c);
      });
      const bd=$('#dbBulkDel'), bc=$('#dbBulkClear');
      if(bd) bd.onclick = ()=>dbBulkDropSelectedTables(c);
      if(bc) bc.onclick = ()=>{ S.db.selectedTables.clear(); loadDbContent(c); };
    }
    else {
      title.textContent='📄 '+S.db.dbName+' / '+S.db.tableName;
      pathInfo.textContent='Записи таблицы';
      const limit = 50;
      const offset = S.db.page * limit;
      const [schemaRes, rowsRes] = await Promise.all([
        get('db/connections/'+encodeURIComponent(S.db.dbName)+'/tables/'+encodeURIComponent(S.db.tableName)+'/schema'),
        get('db/connections/'+encodeURIComponent(S.db.dbName)+'/tables/'+encodeURIComponent(S.db.tableName)+'/rows?limit='+limit+'&offset='+offset+'&search='+encodeURIComponent(S.db.search||''))
      ]);
      const columns = (rowsRes.columns || []).filter(col=>col!=='__rowid__');
      const rows = rowsRes.rows || [];
      const total = rowsRes.total || 0;
      S.db.schema = schemaRes.columns || [];
      S.db.rows = rows || [];
      const toolbar = `<div style="padding:12px 16px;border-bottom:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <input id="dbSearch" placeholder="Поиск..." value="${esc(S.db.search||'')}" style="width:200px;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text)">
        <span style="color:var(--muted);font-size:12px;margin-left:auto">Записей: <strong>${total}</strong></span>
      </div>`;
      if(!rows.length){
        box.innerHTML = toolbar + `<div class="empty" style="padding:40px">Записей нет</div>`;
        $('#dbBulkBar').innerHTML='';
        $('#dbSearch').oninput = (e)=>{
          S.db.search = e.target.value; S.db.page = 0;
          clearTimeout(window.__dbT); window.__dbT = setTimeout(()=>loadDbContent(c),300);
        };
        renderDbToolPanel(); return;
      }
      if(S.db.activeRowPk){
        const row = rows.find(r=>String(r.__rowid__)===String(S.db.activeRowPk)) || rows[0];
        S.db.activeRowPk = row.__rowid__;
        const pk = row.__rowid__;
        const fieldsHtml = Object.entries(row).filter(([k])=>k!=='__rowid__').map(([k,v])=>{
          let display;
          if(v===null||v===undefined) display = '<span style="color:var(--muted)">NULL</span>';
          else if(typeof v==='object') display = `<code class="mono" style="font-size:11px">${esc(JSON.stringify(v))}</code>`;
          else if(typeof v==='string'&&v.length>80) display = `<code class="mono" style="font-size:11px;word-break:break-all">${esc(v)}</code>`;
          else display = `<span class="mono" style="font-size:12px">${esc(String(v))}</span>`;
          return `<div style="display:grid;grid-template-columns:200px 1fr;gap:12px;padding:10px 14px;border-bottom:1px solid var(--line);align-items:start">
            <div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.4px;font-weight:700;padding-top:2px">${esc(k)}</div>
            <div style="min-width:0">${display}</div>
          </div>`;
        }).join('');
        const body = `<div class="card" style="padding:0;overflow:hidden;margin-top:14px">
          <div class="card-head" style="padding:12px 16px;margin:0;background:var(--panel2);border-bottom:1px solid var(--line)">
            <div><div class="card-title">📋 Запись</div><div class="card-sub mono">${esc(S.db.tableName)} · id=${esc(String(pk))}</div></div>
          </div>
          ${fieldsHtml}
        </div>`;
        box.innerHTML = toolbar + body;
        $('#dbBulkBar').innerHTML='';
        $('#dbSearch').oninput = (e)=>{
          S.db.search = e.target.value; S.db.page = 0;
          clearTimeout(window.__dbT); window.__dbT = setTimeout(()=>loadDbContent(c),300);
        };
      } else {
        const allChecked = rows.every(r=>S.db.selectedRows.has(String(r.__rowid__)));
        let tableCols = [{
          label:`<input type="checkbox" class="db-check" id="dbCheckAll" ${allChecked?'checked':''}>`,
          render:r=>`<input type="checkbox" class="db-check" data-row-check="${r.__rowid__}" ${S.db.selectedRows.has(String(r.__rowid__))?'checked':''}>`
        }];
        columns.forEach(col=>{
          tableCols.push({label:col, render:r=>{
            const v = r[col];
            if(v===null||v===undefined) return '<span style="color:var(--muted)">NULL</span>';
            if(typeof v==='string'&&v.length>40) return `<span class="mono" style="font-size:11px" title="${esc(v)}">${esc(v.slice(0,40))}…</span>`;
            return `<span class="mono" style="font-size:11px">${esc(String(v))}</span>`;
          }});
        });
        tableCols.push({label:'', render:r=>`<div class="row-actions"><button class="button small" data-rowview="${r.__rowid__}">👁</button></div>`});
        const totalPages = Math.max(1, Math.ceil(total / limit));
        const pager = `<div style="padding:12px;display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--line)">
          <span>Стр. ${S.db.page + 1} из ${totalPages}</span>
          <div>
            <button class="button small" id="pgPrev" ${S.db.page===0?'disabled':''}>‹</button>
            <button class="button small" id="pgNext" ${S.db.page>=totalPages-1?'disabled':''}>›</button>
          </div>
        </div>`;
        box.innerHTML = toolbar + `<div style="padding:16px">${renderTable(tableCols, rows, 'Записей нет')}</div>` + pager;
        $('#dbBulkBar').innerHTML = dbBulkBarHtml('row', S.db.selectedRows.size);
        $('#dbSearch').oninput = (e)=>{
          S.db.search = e.target.value; S.db.page = 0;
          clearTimeout(window.__dbT); window.__dbT = setTimeout(()=>loadDbContent(c),300);
        };
        $('#pgPrev').onclick = ()=>{ if(S.db.page>0){ S.db.page--; loadDbContent(c); } };
        $('#pgNext').onclick = ()=>{ if(S.db.page<totalPages-1){ S.db.page++; loadDbContent(c); } };
        $('#dbCheckAll').onchange = (e)=>{
          if(e.target.checked) rows.forEach(r=>S.db.selectedRows.add(String(r.__rowid__)));
          else S.db.selectedRows.clear();
          loadDbContent(c);
        };
        $$('[data-row-check]').forEach(el=>el.onchange=(e)=>{
          const pk = el.dataset.rowCheck;
          if(e.target.checked) S.db.selectedRows.add(pk); else S.db.selectedRows.delete(pk);
          loadDbContent(c);
        });
        $$('[data-rowview]').forEach(el=>el.onclick=()=>{
          S.db.activeRowPk = el.dataset.rowview; loadDbContent(c);
        });
        const bd=$('#dbBulkDel'), bc=$('#dbBulkClear');
        if(bd) bd.onclick = ()=>dbBulkDeleteSelectedRows(c);
        if(bc) bc.onclick = ()=>{ S.db.selectedRows.clear(); loadDbContent(c); };
      }
    }
    renderDbToolPanel();
  } catch(e){
    box.innerHTML = errBox(e);
    $('#dbBulkBar').innerHTML='';
    renderDbToolPanel();
  }
}

function dbBulkBarHtml(kind, n){
  if(!n) return '';
  const labels = { db:'БД', table:'таблиц', row:'записей' };
  return `<div class="db-bulk-bar">
    <span>Выбрано: <strong>${n}</strong> ${labels[kind]}</span>
    <button class="button small danger" id="dbBulkDel">🗑 Удалить</button>
    <button class="button small" id="dbBulkClear">✖ Снять</button>
  </div>`;
}

export function renderDbToolPanel(){
  const panel = $('#toolPanel');
  const backdrop = $('#toolPanelBackdrop');
  if(!panel) return;
  if(S.tab !== 'db'){
    if(panel.dataset.owner === 'db') closeToolPanel();
    return;
  }
  panel.dataset.owner = 'db';
  backdrop.classList.remove('open');
  backdrop.style.display = 'none';

  if(S.toolPanelCollapsed){
    panel.classList.add('collapsed');
    panel.innerHTML = `<button class="tool-panel-toggle" title="Развернуть" onclick="toggleToolPanelCollapse()">▴</button>`;
    if(!panel.classList.contains('open')) requestAnimationFrame(()=>panel.classList.add('open'));
    return;
  }
  panel.classList.remove('collapsed');

  let html = `<button class="tool-panel-top-toggle" title="Свернуть" onclick="toggleToolPanelCollapse()">▾</button>`;
  html += `<div class="tool-panel-title" title="Действия БД">БД</div>`;

  if(!S.db.dbName){
    if(S.db.selectedDbs.size>0) html += `<button class="tool-panel-btn danger" title="Удалить выбранные БД (${S.db.selectedDbs.size})" onclick="dbBulkDeleteSelectedDbs(document.getElementById('viewContent'))">🗑</button>`;
    html += `<button class="tool-panel-btn" title="Создать БД" onclick="dbCreateDatabase(document.getElementById('viewContent'))">+</button>`;
    html += `<button class="tool-panel-btn" title="Обновить" onclick="loadDbContent(document.getElementById('viewContent'))">🔄</button>`;
    html += `<button class="tool-panel-btn" title="Импорт БД (файл)" onclick="dbImportPrompt()">⬆</button>`;
  } else if(!S.db.tableName){
    if(S.db.selectedTables.size>0) html += `<button class="tool-panel-btn danger" title="Удалить выбранные таблицы (${S.db.selectedTables.size})" onclick="dbBulkDropSelectedTables(document.getElementById('viewContent'))">🗑</button>`;
    html += `<button class="tool-panel-btn" title="Создать таблицу" onclick="dbCreateTableModal(document.getElementById('viewContent'))">+</button>`;
    html += `<button class="tool-panel-btn" title="Обновить" onclick="loadDbContent(document.getElementById('viewContent'))">🔄</button>`;
    html += `<button class="tool-panel-btn" title="Скачать БД" onclick="dbExport('${esc(S.db.dbName)}')">⬇</button>`;
    html += `<button class="tool-panel-btn" title="Импорт в БД (файл)" onclick="dbImportPrompt('${esc(S.db.dbName)}')">⬆</button>`;
    html += `<button class="tool-panel-btn" title="Назад" onclick="dbGoBack()">←</button>`;
  } else if(!S.db.activeRowPk){
    if(S.db.selectedRows.size>0) html += `<button class="tool-panel-btn danger" title="Удалить выбранные записи (${S.db.selectedRows.size})" onclick="dbBulkDeleteSelectedRows(document.getElementById('viewContent'))">🗑</button>`;
    html += `<button class="tool-panel-btn" title="Добавить запись" onclick="dbRowModal(document.getElementById('viewContent'), 'add')">+</button>`;
    html += `<button class="tool-panel-btn" title="Обновить" onclick="loadDbContent(document.getElementById('viewContent'))">🔄</button>`;
    html += `<button class="tool-panel-btn" title="Назад" onclick="dbGoBack()">←</button>`;
  } else {
    html += `<button class="tool-panel-btn" title="Редактировать" onclick="dbRowModal(document.getElementById('viewContent'), 'edit', '${S.db.activeRowPk}')">✎</button>`;
    html += `<button class="tool-panel-btn danger" title="Удалить запись" onclick="dbRowDelete(document.getElementById('viewContent'), '${S.db.activeRowPk}')">×</button>`;
    html += `<button class="tool-panel-btn" title="Назад" onclick="dbClearActiveRow()">←</button>`;
  }
  panel.innerHTML = html;
  if(!panel.classList.contains('open')) requestAnimationFrame(()=>panel.classList.add('open'));
}

export async function dbBulkDeleteSelectedDbs(c){
  const ids = [...S.db.selectedDbs].filter(id=>id!=='OmniDB' && id!=='OmniVPN');
  if(!ids.length) return;
  if(!await confirmDlg('Удалить выбранные БД?', ids.join(', ')+' — будут удалены безвозвратно')) return;
  let ok=0, fail=0;
  for(const id of ids){
    try{ await api('db/delete_database/'+encodeURIComponent(id), {method:'POST'}); ok++; S.db.selectedDbs.delete(id); }
    catch(e){ fail++; toast.err(id+': '+e.message); }
  }
  invalidateGetCache();
  toast[fail?'warn':'ok'](`Удалено: ${ok}${fail?`, ошибок: ${fail}`:''}`);
  loadDbContent(c);
}

export async function dbBulkDropSelectedTables(c){
  const names = [...S.db.selectedTables];
  if(!names.length) return;
  if(!await confirmDlg('Удалить выбранные таблицы?', names.join(', '))) return;
  let ok=0, fail=0;
  for(const t of names){
    try{ await api('db/drop_table/'+encodeURIComponent(S.db.dbName)+'/'+encodeURIComponent(t), {method:'POST'}); ok++; S.db.selectedTables.delete(t); }
    catch(e){ fail++; toast.err(t+': '+e.message); }
  }
  invalidateGetCache();
  toast[fail?'warn':'ok'](`Удалено: ${ok}${fail?`, ошибок: ${fail}`:''}`);
  loadDbContent(c);
}

export async function dbBulkDeleteSelectedRows(c){
  const pks = [...S.db.selectedRows];
  if(!pks.length) return;
  if(!await confirmDlg('Удалить выбранные записи?', `${pks.length} шт.`)) return;
  let ok=0, fail=0;
  for(const pk of pks){
    try{
      await api('db/connections/'+encodeURIComponent(S.db.dbName)+'/tables/'+encodeURIComponent(S.db.tableName)+'/row?pk='+encodeURIComponent(pk), {method:'DELETE'});
      ok++; S.db.selectedRows.delete(pk);
    }catch(e){ fail++; toast.err('pk '+pk+': '+e.message); }
  }
  invalidateGetCache();
  toast[fail?'warn':'ok'](`Удалено: ${ok}${fail?`, ошибок: ${fail}`:''}`);
  loadDbContent(c);
}

export function dbCreateTableModal(c){
  showModal('Создать таблицу',
    `<div class="field"><label>Имя таблицы</label><input id="dbTblName" placeholder="users"></div>
     <div id="dbTblCols"></div>
     <button class="button small" id="dbAddColBtn">+ Колонка</button>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="dbTblSave">Создать</button></div>`);
  const addCol = ()=>{
    const div = document.createElement('div');
    div.className = 'form-row';
    div.innerHTML = `<div class="field"><label>Имя</label><input class="db-col-name"></div>
      <div class="field"><label>Тип</label><select class="db-col-type"><option>TEXT</option><option>INTEGER</option><option>REAL</option><option>BLOB</option></select></div>
      <div class="field shrink"><label>PK</label><input type="checkbox" class="db-col-pk"></div>`;
    $('#dbTblCols').appendChild(div);
  };
  $('#dbAddColBtn').onclick = addCol;
  addCol();
  $('#dbTblSave').onclick = async ()=>{
    const name = $('#dbTblName').value.trim();
    if(!name) return toast.err('Введите имя');
    const cols = $$('#dbTblCols .form-row').map(r=>({
      name: $('.db-col-name', r).value.trim(),
      type: $('.db-col-type', r).value,
      primary_key: $('.db-col-pk', r).checked
    })).filter(c=>c.name);
    if(!cols.length) return toast.err('Добавьте хотя бы одну колонку');
    try{
      await api(`db/create_table/${encodeURIComponent(S.db.dbName)}`, {method:'POST', json:{name, columns: cols}});
      toast.ok('Таблица создана');
      closeModal();
      loadDbContent(c);
    }catch(e){ toast.err(e.message); }
  };
}

export function dbExport(name){
  const a = document.createElement('a');
  a.href = `/api/db/export/${encodeURIComponent(name)}`;
  a.download = name + '.db';
  a.click();
}

export function dbImportPrompt(targetDb){
  const existing = targetDb ? `<input type="hidden" id="dbImportTarget" value="${esc(targetDb)}">` : '';
  showModal('Импорт БД из файла',
    `${existing}
     <div class="field"><label>Имя БД (если новой)</label><input id="dbImportName" placeholder="myapp" ${targetDb?'readonly value="'+esc(targetDb)+'"':''}></div>
     <div class="field"><label>Файл *.db / *.sqlite</label><input id="dbImportFile" type="file" accept=".db,.sqlite,.sqlite3"></div>
     <p style="color:var(--muted);font-size:12px;margin:8px 0 0">Содержимое файла заменит текущие таблицы в выбранной БД.</p>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="dbImportOk">Импортировать</button></div>`);
  $('#dbImportOk').onclick = async ()=>{
    const f = $('#dbImportFile').files[0];
    if(!f) return toast.err('Выберите файл');
    let name = (targetDb || $('#dbImportName').value || '').trim();
    if(!name){ return toast.err('Введите имя БД'); }
    try {
      try { await api('db/create_database', {method:'POST', json:{name}}); } catch(_){}
      const buf = await f.arrayBuffer();
      const r = await fetch(`/api/db/import/${encodeURIComponent(name)}`, {method:'POST', body: buf, credentials:'same-origin'});
      if(!r.ok) throw new Error('HTTP '+r.status);
      toast.ok('Импортировано');
      closeModal();
      invalidateGetCache();
      S.db.selectedDbs.clear();
      S.db.dbName = name; S.db.tableName = ''; S.db.activeRowPk = null;
      loadDbContent(document.getElementById('viewContent'));
    }catch(e){ toast.err(e.message); }
  };
}

export function dbCreateDatabase(c){
  showModal('Новая база данных',
    `<div class="field"><label>Имя базы данных (без расширения)</label><input id="dbCreateName" placeholder="myapp" autofocus><small style="color:var(--muted)">Файл будет создан в папке <code>db</code></small></div>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="dbCreateOk">Создать</button></div>`);
  setTimeout(()=>$('#dbCreateName')?.focus(), 50);
  $('#dbCreateOk').onclick = async ()=>{
    const name = $('#dbCreateName').value.trim();
    if(!name) return toast.err('Введите имя');
    try{
      await api('db/create_database', {method:'POST', json:{name}});
      toast.ok('База данных создана');
      closeModal();
      invalidateGetCache();
      loadDbContent(c);
    }catch(e){ toast.err(e.message); }
  };
}

export async function dbDeleteDatabase(name, c){
  if(!await confirmDlg('Удалить базу данных?', 'Файл '+name+' будет удалён безвозвратно!')) return;
  try{
    await api('db/delete_database/'+encodeURIComponent(name), {method:'POST'});
    toast.ok('База данных удалена');
    invalidateGetCache();
    if(S.db.dbName === name){ S.db.dbName=''; S.db.tableName=''; S.db.activeRowPk=null; }
    S.db.selectedDbs.delete(name);
    loadDbContent(c);
  }catch(e){ toast.err(e.message); }
}

export function dbRowModal(c, mode, pk = null){
  const isEdit = mode === 'edit';
  const cols = S.db.schema.filter(col => !col.primary_key || isEdit);
  let fieldsHtml = '';
  const existingRow = isEdit ? (S.db.rows || []).find(r => String(r.__rowid__) === String(pk)) : {};
  cols.forEach(col => {
    const val = existingRow[col.column] !== undefined && existingRow[col.column] !== null ? esc(existingRow[col.column]) : '';
    fieldsHtml += `<div class="field"><label>${esc(col.column)} <span style="color:var(--muted);font-size:10px">(${esc(col.type)})</span></label><input id="dbField_${esc(col.column)}" value="${val}" placeholder="${col.nullable?'NULL':''}"></div>`;
  });
  showModal(isEdit ? 'Редактировать запись' : 'Новая запись',
    `<div id="dbRowForm">${fieldsHtml}</div>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="dbRowSave">${isEdit?'Сохранить':'Добавить'}</button></div>`);
  $('#dbRowSave').onclick = async () => {
    const values = {};
    cols.forEach(col => {
      const el = $(`#dbField_${esc(col.column)}`);
      if (el) {
        let v = el.value;
        if (v === '' && col.nullable) values[col.column] = null;
        else if (v === '') values[col.column] = '';
        else if (/^-?\d+(\.\d+)?$/.test(v)) values[col.column] = parseFloat(v);
        else values[col.column] = v;
      }
    });
    try {
      if (isEdit) {
        await api('db/connections/'+encodeURIComponent(S.db.dbName)+'/tables/'+encodeURIComponent(S.db.tableName)+'/row', {method:'PUT', json:{values, pk}});
        toast.ok('Обновлено');
      } else {
        await api('db/connections/'+encodeURIComponent(S.db.dbName)+'/tables/'+encodeURIComponent(S.db.tableName)+'/row', {method:'POST', json:{values}});
        toast.ok('Добавлено');
      }
      closeModal(); invalidateGetCache(); loadDbContent(c);
    } catch(e) { toast.err(e.message); }
  };
}

export async function dbRowDelete(c, pk){
  if (!await confirmDlg('Удалить запись?', 'Строка будет удалена.')) return;
  try {
    await api('db/connections/'+encodeURIComponent(S.db.dbName)+'/tables/'+encodeURIComponent(S.db.tableName)+'/row?pk='+encodeURIComponent(pk), {method:'DELETE'});
    toast.ok('Удалено');
    invalidateGetCache();
    if (String(S.db.activeRowPk) === String(pk)) S.db.activeRowPk = null;
    S.db.selectedRows.delete(String(pk));
    loadDbContent(c);
  } catch(e) { toast.err(e.message); }
}

export function dbGoBack() {
  if (S.db.activeRowPk) { S.db.activeRowPk = null; }
  else if (S.db.tableName) { S.db.selectedRows.clear(); S.db.tableName = ''; }
  else if (S.db.dbName) { S.db.selectedTables.clear(); S.db.dbName = ''; }
  loadDbContent(document.getElementById('viewContent'));
}

export function dbClearActiveRow() {
  S.db.activeRowPk = null;
  loadDbContent(document.getElementById('viewContent'));
}

Object.assign(window, {
  loadDbContent, renderDbToolPanel,
  dbBulkDeleteSelectedDbs, dbBulkDropSelectedTables, dbBulkDeleteSelectedRows,
  dbCreateTableModal, dbExport, dbImportPrompt, dbCreateDatabase, dbDeleteDatabase,
  dbRowModal, dbRowDelete, dbGoBack, dbClearActiveRow
});