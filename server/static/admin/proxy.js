import {
  S, $, $$, esc, get, post, del, dl, toast, confirmDlg,
  spinner, errBox, renderTable, renderKV
} from './app.js';

export async function mount(c){
  c.innerHTML = `<div id="proxyBody"></div>`;
  await proxyConfig($('#proxyBody'), c);
}

async function proxyConfig(box){
  box.innerHTML = `
    <div id="pcBackends"></div>
    <div id="pcVhosts" style="margin-top:14px"></div>
    <div id="pcRedirects" style="margin-top:14px"></div>
    <div id="pcCache" style="margin-top:14px"></div>
    <div id="pcRl" style="margin-top:14px"></div>`;
  await proxyBackendsSection($('#pcBackends'));
  await proxyVhostsSection($('#pcVhosts'));
  await proxyRedirectsSection($('#pcRedirects'));
  await proxyCacheSection($('#pcCache'));
  await proxyRlSection($('#pcRl'));
}

async function proxyBackendsSection(box){
  box.innerHTML = `<div class="card">
    <div class="card-head">
      <div><div class="card-title">Backends</div><div class="card-sub">Пул upstream-серверов</div></div>
    </div>
    <div class="form-row">
      <div class="field"><label>URL</label><input id="pbUrl" placeholder="http://127.0.0.1:8080"></div>
      <button class="button primary" id="pbAdd">+ Добавить</button>
    </div>
    <div id="pbBody">${spinner()}</div>
  </div>`;
  $('#pbAdd').onclick = async ()=>{
    try{ await post('proxy/backends/add', {url: $('#pbUrl').value}); toast.ok('OK'); proxyBackendsSection(box); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('proxy/backends');
    $('#pbBody').innerHTML = renderTable([
      {label:'URL', key:'url'},
      {label:'Healthy', render:r=>r.healthy?'✓':'✖'},
      {label:'Conns', key:'connections'},
      {label:'Circuit', render:r=>r.circuit_open?'●':'○'},
      {label:'', render:r=>`<div class="row-actions">
        <button class="button small" data-ptg="${esc(r.url)}">Toggle</button>
        <button class="button small" data-prs="${esc(r.url)}">Reset</button>
      </div>`}
    ], d);
    $$('[data-ptg]').forEach(el=>el.onclick=async()=>{
      try{ await post('proxy/backends/'+encodeURIComponent(el.dataset.ptg)+'/toggle'); proxyBackendsSection(box); }
      catch(e){ toast.err(e.message); }
    });
    $$('[data-prs]').forEach(el=>el.onclick=async()=>{
      try{ await post('proxy/backends/'+encodeURIComponent(el.dataset.prs)+'/reset_circuit'); proxyBackendsSection(box); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#pbBody').innerHTML = errBox(e); }
}

async function proxyVhostsSection(box){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">VHosts</div><div class="card-sub">Виртуальные хосты</div></div></div>
    <div class="form-row">
      <div class="field"><label>Host</label><input id="pvHost" placeholder="example.com"></div>
      <div class="field"><label>Path</label><input id="pvPath" placeholder="/var/www/example"></div>
      <button class="button primary" id="pvSet">+ Добавить</button>
    </div>
    <div id="pvBody">${spinner()}</div>
  </div>`;
  $('#pvSet').onclick = async ()=>{
    try{ await post('proxy/vhosts/set', {host:$('#pvHost').value, path:$('#pvPath').value}); toast.ok('OK'); proxyVhostsSection(box); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('proxy/vhosts');
    const rows = Object.entries(d).map(([h,p])=>({host:h, path:p}));
    $('#pvBody').innerHTML = renderTable([
      {label:'Host', key:'host'},
      {label:'Path', key:'path'},
      {label:'', render:r=>`<button class="button small danger" data-pvd="${esc(r.host)}">×</button>`}
    ], rows);
    $$('[data-pvd]').forEach(el=>el.onclick=async()=>{
      if(!await confirmDlg('Удалить vhost?', el.dataset.pvd)) return;
      try{ await post('proxy/vhosts/'+encodeURIComponent(el.dataset.pvd)+'/delete'); proxyVhostsSection(box); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#pvBody').innerHTML = errBox(e); }
}

async function proxyRedirectsSection(box){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">Redirects</div><div class="card-sub">Редиректы путей</div></div></div>
    <div class="form-row">
      <div class="field"><label>From</label><input id="prFrom" placeholder="/old"></div>
      <div class="field"><label>To</label><input id="prTo" placeholder="/new"></div>
      <button class="button primary" id="prSet">+ Добавить</button>
    </div>
    <div id="prBody">${spinner()}</div>
  </div>`;
  $('#prSet').onclick = async ()=>{
    try{ await post('proxy/redirects/set', {from:$('#prFrom').value, to:$('#prTo').value}); toast.ok('OK'); proxyRedirectsSection(box); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('proxy/redirects');
    const rows = Object.entries(d).map(([f,t])=>({from:f,to:t}));
    $('#prBody').innerHTML = renderTable([
      {label:'From', key:'from'},
      {label:'To', key:'to'},
      {label:'', render:r=>`<button class="button small danger" data-prd="${esc(r.from)}">×</button>`}
    ], rows);
    $$('[data-prd]').forEach(el=>el.onclick=async()=>{
      if(!await confirmDlg('Удалить?', el.dataset.prd)) return;
      try{ await post('proxy/redirects/'+encodeURIComponent(el.dataset.prd)+'/delete'); proxyRedirectsSection(box); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#prBody').innerHTML = errBox(e); }
}

async function proxyCacheSection(box){
  box.innerHTML = `<div class="grid two-col">
    <div class="card">
      <div class="card-head"><div><div class="card-title">Кэш — статистика</div></div>
      <div class="card-actions">
        <button class="button small" id="cacheReload">🔄</button>
        <button class="button small" id="cacheInv">Inv. Prefix</button>
        <button class="button small danger" id="cacheClear">🗑️</button>
      </div></div>
      <div id="cacheStats">${spinner()}</div>
    </div>
    <div class="card">
      <div class="card-head"><div><div class="card-title">Кэш — ключи</div></div></div>
      <div class="form-row">
        <div class="field"><label>Поиск</label><input id="cachePattern" placeholder="…" value="${esc(S.cache.pattern)}"></div>
        <button class="button primary" id="cacheSearch">🔍</button>
      </div>
      <div id="cacheKeys">${spinner()}</div>
    </div>
  </div>
  <div class="card" id="cacheDetail" style="display:none;margin-top:14px"></div>`;

  try{
    const s = await get('cache/stats');
    $('#cacheStats').innerHTML = renderKV(s);
  }catch(e){ $('#cacheStats').innerHTML = errBox(e); }

  const loadKeys = async ()=>{
    try{
      const d = await get('cache/keys?limit=500' + (S.cache.pattern ? '&pattern='+encodeURIComponent(S.cache.pattern) : ''));
      $('#cacheKeys').innerHTML = renderTable([
        {label:'Key', render:r=>`<a data-ckey="${esc(r)}">${esc(r)}</a>`},
        {label:'', render:r=>`<button class="button small danger" data-cdel="${esc(r)}">×</button>`}
      ], d.keys||[]);
      $$('[data-ckey]').forEach(el=>el.onclick=async()=>{
        try{
          const d = await get('cache/key/'+encodeURIComponent(el.dataset.ckey));
          const bx = $('#cacheDetail');
          bx.style.display = '';
          bx.innerHTML = `<div class="card-head"><div class="card-title">${esc(el.dataset.ckey)}</div></div>
            ${renderKV(d.entry)}
            <h4 style="margin-top:12px">Body</h4>
            <pre class="kv-pre">${esc(d.entry.body||'(binary)')}</pre>`;
        }catch(e){ toast.err(e.message); }
      });
      $$('[data-cdel]').forEach(el=>el.onclick=async()=>{
        try{ await del('cache/key/'+encodeURIComponent(el.dataset.cdel)); toast.ok('Удалено'); loadKeys(); }
        catch(e){ toast.err(e.message); }
      });
    }catch(e){ $('#cacheKeys').innerHTML = errBox(e); }
  };
  $('#cacheReload').onclick = loadKeys;
  $('#cacheSearch').onclick = ()=>{ S.cache.pattern = $('#cachePattern').value; loadKeys(); };
  $('#cacheInv').onclick = async ()=>{
    const p = prompt('Префикс:'); if(!p) return;
    try{ const d = await post('cache/invalidate_prefix', {prefix:p}); toast.ok('Invalidated: '+d.invalidated); loadKeys(); }
    catch(e){ toast.err(e.message); }
  };
  $('#cacheClear').onclick = async ()=>{
    if(!await confirmDlg('Clear cache?','')) return;
    try{ await post('cache/clear'); toast.ok('OK'); loadKeys(); }
    catch(e){ toast.err(e.message); }
  };
  loadKeys();
}

async function proxyRlSection(box){
  box.innerHTML = `<div class="card">
    <div class="card-head">
      <div><div class="card-title">Rate limits</div></div>
      <div class="card-actions"><button class="button small danger" id="prlR">🗑️ Reset All</button></div>
    </div>
    <div id="prlBody">${spinner()}</div>
  </div>`;
  $('#prlR').onclick = async ()=>{
    try{ await post('proxy/rate_limits/reset'); toast.ok('OK'); proxyRlSection(box); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const [d, grpc, ws] = await Promise.all([
      get('proxy/rate_limits'),
      get('proxy/grpc'),
      get('proxy/websocket/active')
    ]);
    $('#prlBody').innerHTML = renderTable(['ip','count','window_start_secs_ago'], d)
      + `<p style="color:var(--muted);font-size:12px;margin-top:10px">gRPC: ${grpc.enabled?'✓':'—'} · WS: ${ws.active_connections}/${ws.total_connections}</p>`;
  }catch(e){ $('#prlBody').innerHTML = errBox(e); }
}