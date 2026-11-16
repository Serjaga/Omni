import {
  S, $, $$, esc, join, fmtSize, get, post, dl,
  toast, confirmDlg, showModal, closeModal,
  spinner, errBox, renderTable, renderKV,
  navigate
} from './app.js';

/* ── state helpers ── */
function renderBreadcrumbs(path){
  const parts=String(path||'/').split('/').filter(Boolean);
  const crumbs=[`<a data-bcpath="/" title="В корень">🏠</a>`];
  let accum='';
  for(const p of parts){
    accum+='/'+p;
    crumbs.push(`<span class="sep">/</span>`);
    crumbs.push(`<a data-bcpath="${esc(accum)}">${esc(p)}</a>`);
  }
  return crumbs.join('');
}

/* ── main mount (порт renderFiles) ── */
export async function mount(c){
  c.innerHTML=`<div class="card table-card">
    <div class="table-tools">
      <button class="button small" id="filesMkdir" title="Создать папку">📁+ Папка</button>
      <button class="button small" id="filesMkfile" title="Создать файл">📝+ Файл</button>
      <label class="button small" title="Загрузить файлы">⬆ Upload
        <input type="file" multiple id="filesUpload" style="display:none">
      </label>
    </div>
    <div id="filesBulk"></div>
    <div id="filesBody">${spinner()}</div>
    <div id="filesPager"></div>
  </div>
  <div id="filesEditorPanel" style="margin-top:14px"></div>`;

  $('#filesMkdir').onclick = () => createDir(c);
  $('#filesMkfile').onclick = () => createFile(c);
  $('#filesUpload').onchange = async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    let ok = 0, fail = 0;
    for (const f of files) {
      const fd = new FormData();
      fd.append('file', f, f.name);
      try {
        const r = await fetch('/api/files/upload?path=' + encodeURIComponent(S.files.path), {
          method: 'POST', body: fd, headers: { 'x-admin-token': S.token }, credentials: 'same-origin'
        });
        if (r.ok) ok++;
        else { fail++; const txt = await r.text(); toast.err(`Upload ${f.name}: ${txt || r.status}`); }
      } catch (err) { fail++; toast.err(`Upload ${f.name}: ${err.message}`); }
    }
    e.target.value = '';
    if (ok) toast.ok(`Загружено: ${ok}${fail ? `, ошибок: ${fail}` : ''}`);
    loadFilesList(c);
  };
  await loadFilesList(c);
  if (S.files.editor.open) renderInlineEditor(c);
  else $('#filesEditorPanel').innerHTML = '';
}

/* ── loadFilesList — порт из оригинала ── */
async function loadFilesList(c){
  const body = $('#filesBody'); if (!body) return;
  body.innerHTML = spinner();
  try{
    const [listR, usageR] = await Promise.all([
      get('files/list?path=' + encodeURIComponent(S.files.path)),
      get('files/disk_usage?path=' + encodeURIComponent(S.files.path)).catch(() => null)
    ]);
    const items = Array.isArray(listR.items) ? listR.items : [];
    S.files.items = items;
    const usage = usageR;
    const totalPages = Math.max(1, Math.ceil(items.length / S.files.pageSize));
    if (S.files.page >= totalPages) S.files.page = totalPages - 1;
    const start = S.files.page * S.files.pageSize;
    const pageItems = items.slice(start, start + S.files.pageSize);

    const header = `<div class="files-head">
      <div class="files-bc">${renderBreadcrumbs(S.files.path)}</div>
      <div class="files-stats">
        <span>${usage ? 'Размер: <strong>' + esc(usage.human) + '</strong> · ' : ''}Элементов: <strong>${items.length}</strong></span>
        <button class="button small" id="filesSearchBtn" title="Поиск">🔍</button>
        <span id="filesSearchInline"></span>
      </div>
    </div>`;

    if (!items.length) {
      body.innerHTML = header + `<div class="empty-state">
        <div class="icon">📂</div>
        <div class="title">Директория пуста</div>
        <div class="sub">В <code>${esc(S.files.path)}</code> нет файлов или папок</div>
        <div class="actions">
          <button class="button small" id="emptyReload">⟳ Обновить</button>
          <button class="button small" id="emptyMkdir">📁+ Папка</button>
          <button class="button small" id="emptyMkfile">📝+ Файл</button>
          <button class="button small primary" id="emptyUpload">⬆ Загрузить</button>
        </div>
      </div>`;
      $('#emptyReload').onclick = () => loadFilesList(c);
      $('#emptyMkdir').onclick = () => createDir(c);
      $('#emptyMkfile').onclick = () => createFile(c);
      $('#emptyUpload').onclick = () => $('#filesUpload')?.click();
      bindBreadcrumbs(body, c); bindSearchBtn(c);
      $('#filesPager').innerHTML = ''; $('#filesBulk').innerHTML = '';
      return;
    }

    const allChecked = pageItems.every(it => S.files.selected.has(it.name));
    const rows = pageItems.map(it => {
      const checked = S.files.selected.has(it.name) ? 'checked' : '';
      const acts = [];
      if (it.kind === 'file') acts.push(`<button class="button small" data-view="${esc(it.name)}" title="Скачать">⬇</button>`);
      acts.push(`<button class="button small" data-rename="${esc(it.name)}" title="Переименовать">✎</button>`);
      acts.push(`<button class="button small" data-copy="${esc(it.name)}" title="Копировать">📋</button>`);
      if (it.kind === 'dir') acts.push(`<button class="button small" data-archive="${esc(it.name)}" title="Архивировать">📦</button>`);
      acts.push(`<button class="button small danger" data-rm="${esc(it.name)}" title="Удалить">×</button>`);
      return {
        name: it.name, kind: it.kind, size: it.size,
        _check: `<input type="checkbox" class="file-check" data-check="${esc(it.name)}" ${checked}>`,
        _actions: `<div class="row-actions">${acts.join('')}</div>`
      };
    });

    body.innerHTML = header + renderTable([
      { label: `<input type="checkbox" class="file-check" id="checkAll" ${allChecked ? 'checked' : ''}>`, render: r => r._check },
      { label: 'Имя', render: r => `<a data-open="${esc(r.name)}">${r.kind === 'dir' ? '📂' : '📄'} ${esc(r.name)}</a>` },
      { label: 'Тип', key: 'kind' },
      { label: 'Размер', render: r => r.kind === 'file' ? fmtSize(r.size) : '—' },
      { label: '', render: r => r._actions }
    ], rows);

    $$('tbody tr', body).forEach((tr, i) => {
      if (rows[i] && S.files.selected.has(rows[i].name)) tr.classList.add('selected');
    });

    $('#checkAll').onchange = (e) => {
      pageItems.forEach(it => {
        if (e.target.checked) S.files.selected.add(it.name);
        else S.files.selected.delete(it.name);
      });
      loadFilesList(c);
    };
    $$('[data-check]', body).forEach(el => el.onchange = (e) => {
      const n = el.dataset.check;
      if (e.target.checked) S.files.selected.add(n); else S.files.selected.delete(n);
      renderBulk(c);
    });
    $$('[data-open]', body).forEach(el => el.onclick = () => openFileItem(el.dataset.open, c));
    $$('[data-view]', body).forEach(el => el.onclick = () => dl('files/download?path=' + encodeURIComponent(join(S.files.path, el.dataset.view))));
    $$('[data-rename]', body).forEach(el => el.onclick = () => renameItem(el.dataset.rename, c));
    $$('[data-copy]', body).forEach(el => el.onclick = () => copyItem(el.dataset.copy, c));
    $$('[data-archive]', body).forEach(el => el.onclick = () => archiveItem(el.dataset.archive, c));
    $$('[data-rm]', body).forEach(el => el.onclick = () => {
      const n = el.dataset.rm;
      const it = items.find(x => x.name === n);
      deleteItem(n, it ? it.kind : 'file', c);
    });

    renderBulk(c);
    bindBreadcrumbs(body, c);
    bindSearchBtn(c);

    if (totalPages > 1) {
      $('#filesPager').innerHTML = `<div class="files-pager">
        <button class="button small" id="pgFirst" ${S.files.page === 0 ? 'disabled' : ''}>«</button>
        <button class="button small" id="pgPrev" ${S.files.page === 0 ? 'disabled' : ''}>‹</button>
        <span class="pg-info">Стр. <strong>${S.files.page + 1}</strong> из ${totalPages}</span>
        <button class="button small" id="pgNext" ${S.files.page >= totalPages - 1 ? 'disabled' : ''}>›</button>
        <button class="button small" id="pgLast" ${S.files.page >= totalPages - 1 ? 'disabled' : ''}>»</button>
      </div>`;
      $('#pgFirst').onclick = () => { S.files.page = 0; loadFilesList(c); };
      $('#pgPrev').onclick = () => { S.files.page = Math.max(0, S.files.page - 1); loadFilesList(c); };
      $('#pgNext').onclick = () => { S.files.page = Math.min(totalPages - 1, S.files.page + 1); loadFilesList(c); };
      $('#pgLast').onclick = () => { S.files.page = totalPages - 1; loadFilesList(c); };
    } else {
      $('#filesPager').innerHTML = '';
    }
  } catch (e) {
    body.innerHTML = `<div class="empty-state">
      <div class="icon">⚠</div>
      <div class="title">Не удалось прочитать директорию</div>
      <div class="sub">${esc(e.message)}</div>
      <div class="actions">
        <button class="button small" id="emptyRetry">⟳ Повторить</button>
        <button class="button small" id="emptyRoot">🏠 В корень</button>
      </div>
    </div>`;
    $('#emptyRetry')?.addEventListener('click', () => loadFilesList(c));
    $('#emptyRoot')?.addEventListener('click', () => { S.files.path = '/'; loadFilesList(c); });
  }
}

/* ── bind helpers ── */
function bindBreadcrumbs(scope, c){
  $$('[data-bcpath]', scope).forEach(el => el.onclick = () => {
    const p = el.dataset.bcpath;
    if (p === S.files.path) return;
    S.files.path = p; S.files.selected.clear(); S.files.page = 0; S.files.editor.open = false;
    mount(c);
  });
}
function bindSearchBtn(c){
  const btn = $('#filesSearchBtn'); if (!btn) return;
  btn.onclick = () => {
    const w = $('#filesSearchInline');
    if (w && w.innerHTML.trim()) { w.innerHTML = ''; return; }
    w.innerHTML = `<input id="filesSearchInput" placeholder="Поиск файла…" style="padding:6px 10px;font-size:12px;border:1px solid var(--line);background:var(--bg);color:var(--text);border-radius:8px;width:200px"><button class="button small" id="filesSearchGo" title="Найти">🔎</button>`;
    const inp = $('#filesSearchInput'); inp.focus();
    inp.onkeydown = (e) => { if (e.key === 'Enter') doFileSearch(c); };
    $('#filesSearchGo').onclick = () => doFileSearch(c);
  };
}
async function doFileSearch(c){
  const q = ($('#filesSearchInput')?.value || '').trim(); if (!q) return;
  try {
    const d = await get('files/search?q=' + encodeURIComponent(q) + '&path=' + encodeURIComponent(S.files.path));
    showModal('Поиск: ' + q, renderTable([
      { label: 'Имя', render: r => `<a data-sres="${esc(r.path)}" style="cursor:pointer">${esc(r.name)}</a>` },
      { label: 'Путь', key: 'path' },
      { label: 'Тип', key: 'kind' },
      { label: 'Размер', render: r => fmtSize(r.size) }
    ], d.results || [], 'Ничего не найдено'), undefined, true);
    $$('[data-sres]').forEach(el => el.onclick = () => {
      closeModal();
      const full = el.dataset.sres; const parts = full.split('/'); const name = parts.pop();
      S.files.path = '/' + parts.filter(Boolean).join('/');
      if (!S.files.path) S.files.path = '/';
      openFileItem(name, c);
    });
  } catch (e) { toast.err(e.message); }
}

/* ── bulk / open / editor / rename / copy / archive / delete ── */
function renderBulk(c){
  const box = $('#filesBulk'); if (!box) return;
  const n = S.files.selected.size;
  if (!n) { box.innerHTML = ''; return; }
  box.innerHTML = `<div class="files-bulk"><span>Выбрано: <strong>${n}</strong></span><button class="button small danger" id="bulkDel">🗑 Удалить</button><button class="button small" id="bulkClear">✖ Снять</button></div>`;
  $('#bulkDel').onclick = async () => {
    if (!await confirmDlg('Удалить выбранные?', `${n} элемент(ов)`)) return;
    let ok = 0, fail = 0;
    const names = [...S.files.selected];
    for (const name of names) {
      const it = (S.files.items || []).find(x => x.name === name);
      try { await post('files/delete', { path: join(S.files.path, name) }); ok++; }
      catch (e) {
        if (it && it.kind === 'dir') {
          try { await post('files/delete_recursive', { path: join(S.files.path, name), confirm: 'yes' }); ok++; }
          catch (e2) { fail++; }
        } else { fail++; }
      }
    }
    S.files.selected.clear();
    toast[fail ? 'warn' : 'ok'](`Удалено: ${ok}${fail ? `, ошибок: ${fail}` : ''}`);
    loadFilesList(c);
  };
  $('#bulkClear').onclick = () => { S.files.selected.clear(); loadFilesList(c); };
}

async function openFileItem(name, c){
  const found = (S.files.items || []).find(it => it.name === name);
  if (!found) return;
  if (found.kind === 'dir') {
    S.files.path = join(S.files.path, name);
    S.files.selected.clear(); S.files.page = 0; S.files.editor.open = false;
    return mount(c);
  }
  try {
    const d = await get('files/read?path=' + encodeURIComponent(join(S.files.path, name)));
    S.files.editor = { open: true, path: join(S.files.path, name), content: d.content, collapsed: false };
    renderInlineEditor(c);
    setTimeout(() => $('#filesEditorPanel')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80);
  } catch (e) { toast.err('Не удалось открыть: ' + e.message); }
}
function renderInlineEditor(c){
  const panel = $('#filesEditorPanel'); if (!panel) return;
  const ed = S.files.editor;
  if (!ed.open) { panel.innerHTML = ''; return; }
  const lang = detectLang(ed.path);
  const fileName = ed.path.split('/').pop() || ed.path;
  panel.innerHTML = `<div class="card" style="padding:0;overflow:hidden">
    <div class="card-head" style="padding:12px 16px;margin:0;border-bottom:${ed.collapsed ? '0' : '1px solid var(--line)'};background:var(--panel2)">
      <div style="min-width:0;flex:1">
        <div class="card-title">📝 ${esc(fileName)}</div>
        <div class="card-sub mono" style="word-break:break-all">${esc(ed.path)}</div>
      </div>
      <div class="card-actions" style="flex-shrink:0">
        ${ed.collapsed ? '' : '<input id="editorSearch" placeholder="Найти в файле…" style="max-width:160px"><span id="editorSearchInfo" style="font-size:11px;color:var(--muted)"></span>'}
        <button class="button small" id="fileToggle" title="${ed.collapsed ? 'Развернуть' : 'Свернуть'}">${ed.collapsed ? '▼ Развернуть' : '▲ Свернуть'}</button>
        <button class="button small danger" id="fileClose" title="Закрыть">✖ Закрыть</button>
        ${ed.collapsed ? '' : '<button class="button primary" id="fileSave">💾 Сохранить</button>'}
      </div>
    </div>
    ${ed.collapsed ? '' : `<div class="editor-wrap inline" id="editorWrap">
      <div class="editor-gutter" id="editorGutter"></div>
      <div class="editor-inner">
        <pre class="editor-highlight" id="editorHighlight"></pre>
        <textarea class="editor-textarea" id="fileContent" spellcheck="false"></textarea>
      </div>
    </div>
    <div style="font-size:11px;color:var(--muted);padding:8px 16px;border-top:1px solid var(--line)">Язык: <code>${lang}</code> · Строк: <span id="editorLines">0</span> · Ctrl+S — сохранить</div>`}
  </div>`;
  $('#fileToggle').onclick = () => { S.files.editor.collapsed = !S.files.editor.collapsed; renderInlineEditor(c); };
  $('#fileClose').onclick = () => { S.files.editor.open = false; S.files.editor.content = ''; renderInlineEditor(c); };
  if (!ed.collapsed) bindEditorInput(panel, lang, c);
}
function bindEditorInput(panel, lang, c){
  const ta = $('#fileContent', panel);
  const hl = $('#editorHighlight', panel);
  const gut = $('#editorGutter', panel);
  ta.value = S.files.editor.content;
  const update = () => {
    const txt = ta.value;
    hl.innerHTML = highlightCode(txt, lang);
    const lines = txt.split('\n').length;
    let g = ''; for (let k = 1; k <= lines; k++) g += `<div>${k}</div>`;
    gut.innerHTML = g;
    $('#editorLines', panel).textContent = lines;
    hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; gut.scrollTop = ta.scrollTop;
  };
  update();
  ta.addEventListener('input', update);
  ta.addEventListener('scroll', () => { hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; gut.scrollTop = ta.scrollTop; });
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const s = ta.selectionStart, en = ta.selectionEnd;
      ta.value = ta.value.slice(0, s) + '  ' + ta.value.slice(en);
      ta.selectionStart = ta.selectionEnd = s + 2; update();
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); saveInlineEditor(c); }
  });
  const searchInp = $('#editorSearch', panel);
  if (searchInp) searchInp.addEventListener('input', () => {
    const q = searchInp.value; const info = $('#editorSearchInfo', panel);
    if (!q) { info.textContent = ''; return; }
    const idx = ta.value.toLowerCase().indexOf(q.toLowerCase());
    if (idx < 0) { info.textContent = 'не найдено'; return; }
    ta.focus(); ta.setSelectionRange(idx, idx + q.length);
    const linesBefore = ta.value.slice(0, idx).split('\n').length;
    ta.scrollTop = Math.max(0, (linesBefore - 3) * 18.75);
    hl.scrollTop = ta.scrollTop; gut.scrollTop = ta.scrollTop;
    const count = (ta.value.toLowerCase().match(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
    info.textContent = `${count} совпад.`;
  });
  const saveBtn = $('#fileSave', panel);
  if (saveBtn) saveBtn.onclick = () => saveInlineEditor(c);
}
async function saveInlineEditor(c){
  const ta = $('#fileContent'); if (!ta) return;
  try { await post('files/save', { path: S.files.editor.path, content: ta.value }); S.files.editor.content = ta.value; toast.ok('Сохранено'); }
  catch (e) { toast.err(e.message); }
}
function createDir(c){
  showModal('Новая папка', `<div class="field"><label>Имя папки в <code class="mono">${esc(S.files.path)}</code></label><input id="newDirName" placeholder="new-folder" autofocus></div>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="mkdirOk">Создать</button></div>`);
  setTimeout(() => $('#newDirName')?.focus(), 50);
  $('#mkdirOk').onclick = async () => {
    const n = $('#newDirName').value.trim(); if (!n) return toast.err('Имя не может быть пустым');
    try { await post('files/mkdir', { path: join(S.files.path, n) }); toast.ok('Папка создана'); closeModal(); loadFilesList(c); }
    catch (e) { toast.err(e.message); }
  };
}
function createFile(c){
  showModal('Новый файл', `<div class="field"><label>Имя файла в <code class="mono">${esc(S.files.path)}</code></label><input id="newFileName" placeholder="new-file.txt" autofocus></div><div class="field"><label>Содержимое (опционально)</label><textarea id="newFileContent" rows="6" class="filter-input mono"></textarea></div>`,
    `<div class="modal-foot"><button class="button" onclick="closeModal()">Отмена</button><button class="button primary" id="mkfileOk">Создать</button></div>`);
  setTimeout(() => $('#newFileName')?.focus(), 50);
  $('#mkfileOk').onclick = async () => {
    const n = $('#newFileName').value.trim(); if (!n) return toast.err('Имя не может быть пустым');
    try { await post('files/save', { path: join(S.files.path, n), content: $('#newFileContent').value }); toast.ok('Файл создан'); closeModal(); loadFilesList(c); }
    catch (e) { toast.err(e.message); }
  };
}
async function renameItem(name, c){
  const to = prompt('Новое имя:', name);
  if (!to || to === name) return;
  try { await post('files/rename', { from: join(S.files.path, name), to: join(S.files.path, to) }); toast.ok('Переименовано'); loadFilesList(c); }
  catch (e) { toast.err(e.message); }
}
async function copyItem(name, c){
  const to = prompt('Куда скопировать (полный путь):', join(S.files.path, name + '.copy'));
  if (!to) return;
  try { await post('files/copy', { from: join(S.files.path, name), to }); toast.ok('Скопировано'); loadFilesList(c); }
  catch (e) { toast.err(e.message); }
}
async function archiveItem(name, c){
  const out = prompt('Имя архива:', join(S.files.path, name + '.tar.gz'));
  if (!out) return;
  try { await post('files/archive', { path: join(S.files.path, name), out }); toast.ok('Архивировано'); loadFilesList(c); }
  catch (e) { toast.err(e.message); }
}
async function deleteItem(name, kind, c){
  const path = join(S.files.path, name);
  if (!await confirmDlg('Удалить?', name)) return;
  try { await post('files/delete', { path }); S.files.selected.delete(name); toast.ok('Удалено'); loadFilesList(c); }
  catch (e) {
    if (kind === 'dir' && /not empty|directory|не пуст/i.test(e.message)) {
      if (await confirmDlg('Папка не пуста. Удалить рекурсивно?', name)) {
        try { await post('files/delete_recursive', { path, confirm: 'yes' }); S.files.selected.delete(name); toast.ok('Удалено рекурсивно'); loadFilesList(c); }
        catch (e2) { toast.err(e2.message); }
      }
    } else { toast.err(e.message); }
  }
}

/* ── detectLang / highlightCode — перенесены из оригинала ── */
function detectLang(path){
  const ext = (path.split('.').pop() || '').toLowerCase();
  if (['js','mjs','cjs','jsx','ts','tsx'].includes(ext)) return 'js';
  if (ext === 'rs') return 'rust';
  if (ext === 'json') return 'json';
  if (['toml','yaml','yml','conf','ini'].includes(ext)) return 'conf';
  if (['html','htm','xml','svg'].includes(ext)) return 'html';
  if (['css','scss','sass','less'].includes(ext)) return 'css';
  if (['md','markdown'].includes(ext)) return 'md';
  if (ext === 'php') return 'php';
  if (ext === 'py') return 'py';
  return 'text';
}
function highlightCode(src, lang){
  const esc0 = (s) => s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  const kw = {
    js: /^(?:const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|class|extends|new|this|super|import|from|export|default|async|await|try|catch|finally|throw|typeof|instanceof|in|of|null|undefined|true|false|void|delete|yield|static|get|set)\b/,
    rust: /^(?:fn|let|mut|const|static|struct|enum|impl|trait|use|mod|pub|crate|self|Self|super|match|if|else|while|for|loop|return|break|continue|as|where|move|ref|dyn|unsafe|async|await|true|false|None|Some|Ok|Err)\b/,
    php: /^(?:function|return|if|else|elseif|for|foreach|while|do|switch|case|break|continue|class|extends|implements|new|this|self|parent|public|private|protected|static|const|namespace|use|require|include|require_once|include_once|try|catch|finally|throw|echo|print|true|false|null|as|instanceof|array|int|string|bool|float|void)\b/,
    py: /^(?:def|return|if|elif|else|for|while|break|continue|class|import|from|as|try|except|finally|raise|with|lambda|yield|True|False|None|and|or|not|in|is|pass|global|nonlocal|async|await)\b/
  };
  let out = ''; let i = 0; const n = src.length; const langKw = kw[lang];
  const push = (txt, cls) => { if (cls) out += `<span class="${cls}">${esc0(txt)}</span>`; else out += esc0(txt); };
  while (i < n) {
    const c = src[i];
    if ((lang === 'js' && c === '/' && src[i + 1] === '/') || (lang === 'rust' && c === '/' && src[i + 1] === '/') || (lang === 'php' && c === '/' && src[i + 1] === '/') || (lang === 'py' && c === '#')) {
      let j = i; while (j < n && src[j] !== '\n') j++; push(src.slice(i, j), 'code-com'); i = j; continue;
    }
    if ((lang === 'js' && c === '/' && src[i + 1] === '*') || (lang === 'rust' && c === '/' && src[i + 1] === '*') || (lang === 'php' && c === '/' && src[i + 1] === '*') || (lang === 'css' && c === '/' && src[i + 1] === '*')) {
      let j = i + 2; while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++; j = Math.min(n, j + 2); push(src.slice(i, j), 'code-com'); i = j; continue;
    }
    if (lang === 'php' && c === '<' && src[i + 1] === '?') {
      let j = i; while (j < n && src[j] !== '\n') j++; push(src.slice(i, j), 'code-tag'); i = j; continue;
    }
    if (c === '"' || c === "'" || (lang === 'js' && c === '`')) {
      const quote = c; let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') j += 2;
        else if (src[j] === quote) { j++; break; }
        else if (src[j] === '\n' && quote !== '`') break;
        else j++;
      }
      push(src.slice(i, j), 'code-str'); i = j; continue;
    }
    if (lang === 'html' && c === '<') {
      let j = i + 1; if (src[j] === '/') j++;
      if (/[a-zA-Z!]/.test(src[j] || '')) {
        let s = i; while (j < n && src[j] !== '>') j++; j = Math.min(n, j + 1);
        push(src.slice(s, j), 'code-tag'); i = j; continue;
      }
    }
    if (/[a-zA-Z_$]/.test(c) && langKw) {
      let j = i; while (j < n && /[a-zA-Z0-9_$]/.test(src[j])) j++;
      const word = src.slice(i, j);
      if (langKw.test(word)) {
        if (word === 'true' || word === 'false' || word === 'null' || word === 'None' || word === 'True' || word === 'False') push(word, 'code-bool');
        else push(word, 'code-kw');
      } else if (src[j] === '(' && (lang === 'js' || lang === 'py' || lang === 'php')) push(word, 'code-fn');
      else push(word);
      i = j; continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i; while (j < n && /[0-9.]/.test(src[j])) j++;
      push(src.slice(i, j), 'code-num'); i = j; continue;
    }
    out += esc0(c); i++;
  }
  return out;
}

/* ── Экспорт инлайн-функций ── */
Object.assign(window, { renderFiles: mount, loadFilesList, createDir, createFile, saveInlineEditor });