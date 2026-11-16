import {
  S, $, $$, esc, get, post, toast, confirmDlg, dl,
  spinner, errBox, renderTable, renderKV, renderKVGrid,
  saveSubtabs, saveScrollAndRerender, scrollTabIntoView
} from './app.js';

const SUBS = [
  ['zones','🌐 Зоны'],
  ['protection','🛡️ Защита'],
  ['routing','🧭 Маршрутизация'],
  ['access','🔑 Доступ']
];

export async function mount(c){
  if(!SUBS.some(([id])=>id===S.dns.sub)) S.dns.sub = 'zones';
  c.innerHTML = `<div class="subtabs" id="dnsSubtabs">${SUBS.map(([id,l])=>`<button class="subtab ${S.dns.sub===id?'active':''}" data-dnssub="${id}">${l}</button>`).join('')}</div><div id="dnsBody"></div>`;
  $$('[data-dnssub]').forEach(b=>b.onclick=()=>{
    S.dns.sub = b.dataset.dnssub;
    saveSubtabs();
    saveScrollAndRerender('#dnsSubtabs', ()=>mount(c));
  });
  const box = $('#dnsBody');
  const dispatch = { zones: dnsZonesCombined, protection: dnsProtection, routing: dnsRouting, access: dnsAccess };
  await dispatch[S.dns.sub](box, c);
  setTimeout(()=>scrollTabIntoView('#dnsSubtabs','#dnsSubtabs .subtab.active'), 0);
}

/* ── Zones + Views ── */
async function dnsZonesCombined(box, c){
  box.innerHTML = `<div id="dzMain"></div><div id="dzViews" style="margin-top:14px"></div>`;
  await dnsZonesSection($('#dzMain'), c);
  await dnsViewsSection($('#dzViews'), c);
}

async function dnsZonesSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head">
      <div><div class="card-title">DNS-зоны</div><div class="card-sub">Записи · DNSSEC — из строки зоны</div></div>
    </div>
    <div class="form-row">
      <div class="field"><label>Origin</label><input id="dnsNewOrigin" placeholder="example.com."></div>
      <div class="field shrink"><label>TTL</label><input id="dnsNewTtl" type="number" value="3600"></div>
      <button class="button primary" id="dnsCreate">+ Создать</button>
    </div>
    <div id="dnsZonesBody">${spinner()}</div>
  </div>`;
  $('#dnsCreate').onclick = async ()=>{
    try{
      await post('dns/zones/create', {origin: $('#dnsNewOrigin').value, ttl: $('#dnsNewTtl').value});
      toast.ok('OK'); dnsZonesSection(box, c);
    }catch(e){ toast.err(e.message); }
  };
  try{
    const zones = await get('dns/zones');
    $('#dnsZonesBody').innerHTML = renderTable([
      {label:'Origin', key:'origin'},
      {label:'Serial', key:'serial'},
      {label:'Records', key:'records'},
      {label:'', render:r=>`<div class="row-actions">
        <button class="button small" data-zrec="${esc(r.origin)}">📝</button>
        <button class="button small" data-zdnssec="${esc(r.origin)}">🔐</button>
        <button class="button small" data-zbump="${esc(r.origin)}">±1</button>
        <button class="button small" data-zexp="${esc(r.origin)}">⬇</button>
        <button class="button small danger" data-zdel="${esc(r.origin)}">×</button>
      </div>`}
    ], zones);
    $$('[data-zrec]').forEach(el=>el.onclick=()=>showDnsZoneRecords(el.dataset.zrec));
    $$('[data-zdnssec]').forEach(el=>el.onclick=()=>showDnssecModal(el.dataset.zdnssec, c));
    $$('[data-zbump]').forEach(el=>el.onclick=async()=>{
      try{ await post('dns/zones/'+encodeURIComponent(el.dataset.zbump)+'/serial_bump'); toast.ok('OK'); dnsZonesSection(box, c); }
      catch(e){ toast.err(e.message); }
    });
    $$('[data-zexp]').forEach(el=>el.onclick=()=>dl('dns/export?origin='+encodeURIComponent(el.dataset.zexp)));
    $$('[data-zdel]').forEach(el=>el.onclick=async()=>{
      if(!await confirmDlg('Удалить зону?', el.dataset.zdel)) return;
      try{ await post('dns/zones/'+encodeURIComponent(el.dataset.zdel)+'/delete', {confirm:'yes'}); toast.ok('OK'); dnsZonesSection(box, c); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#dnsZonesBody').innerHTML = errBox(e); }
}

async function showDnsZoneRecords(origin){
  try{
    const z = await get('dns/zones/'+encodeURIComponent(origin));
    showModal('Зона '+origin,
      `<div style="margin-bottom:14px">
        <div class="section-label">Записи</div>
        ${renderTable(['name','type','ttl','rdata'], z.records)}
      </div>
      <div>
        <div class="section-label">Добавить запись</div>
        <div class="form-row" style="border:0;padding-bottom:0;margin-bottom:0">
          <div class="field"><label>Name</label><input id="recName" value="@"></div>
          <div class="field shrink"><label>Type</label><select id="recType">${['A','AAAA','CNAME','MX','TXT','SRV','CAA'].map(t=>`<option>${t}</option>`).join('')}</select></div>
          <div class="field shrink"><label>TTL</label><input id="recTtl" type="number" value="3600"></div>
          <div class="field"><label>Value</label><input id="recValue"></div>
          <button class="button primary" id="recAdd">+ Добавить</button>
        </div>
      </div>`,
      undefined, true);
    $('#recAdd').onclick = async ()=>{
      try{
        await post('dns/add', {origin, name:$('#recName').value, type:$('#recType').value, value:$('#recValue').value, ttl:$('#recTtl').value});
        toast.ok('OK'); closeModal(); showDnsZoneRecords(origin);
      }catch(e){ toast.err(e.message); }
    };
  }catch(e){ toast.err(e.message); }
}

async function showDnssecModal(origin, c){
  showModal('DNSSEC · '+origin, `<div id="dnssecBody">${spinner()}</div>`, undefined, true);
  const load = async ()=>{
    try{
      const keys = await get('dns/dnssec/keys?zone='+encodeURIComponent(origin));
      $('#dnssecBody').innerHTML = `
        <div class="card-head" style="padding:0;border:0">
          <div><div class="section-label">Ключи</div></div>
          <div class="card-actions">
            <button class="button small primary" id="dsGenKsk">+ KSK</button>
            <button class="button small" id="dsGenZsk">+ ZSK</button>
          </div>
        </div>
        ${renderTable([
          {label:'Tag', key:'key_tag'},
          {label:'Alg', key:'algorithm'},
          {label:'KSK', render:r=>r.is_ksk?'✓':'—'},
          {label:'', render:r=>`<button class="button small danger" data-dsdel="${r.key_tag}">×</button>`}
        ], keys.keys||[])}
        <h4 class="section-label" style="margin-top:16px">Операции</h4>
        <div class="form-row" style="border:0;padding-bottom:0;margin-bottom:0">
          <div class="field shrink"><label>Действие</label><select id="dsOp">${['sign','unsign','ds','dnskey'].map(o=>`<option>${o}</option>`).join('')}</select></div>
          <button class="button" id="dsRun">Выполнить</button>
        </div>
        <div id="dsRes" style="margin-top:10px"></div>`;
      $$('[data-dsdel]').forEach(el=>el.onclick=async()=>{
        try{ await post('dns/dnssec/keys/'+el.dataset.dsdel+'/delete?zone='+encodeURIComponent(origin)); toast.ok('OK'); load(); }
        catch(e){ toast.err(e.message); }
      });
      $('#dsGenKsk').onclick = async ()=>{
        try{ await post('dns/dnssec/keys/generate', {zone: origin, is_ksk:'true'}); toast.ok('OK'); load(); }
        catch(e){ toast.err(e.message); }
      };
      $('#dsGenZsk').onclick = async ()=>{
        try{ await post('dns/dnssec/keys/generate', {zone: origin, is_ksk:'false'}); toast.ok('OK'); load(); }
        catch(e){ toast.err(e.message); }
      };
      $('#dsRun').onclick = async ()=>{
        const op = $('#dsOp').value;
        try{
          const d = await get('dns/dnssec/zones/'+encodeURIComponent(origin)+'/'+op);
          $('#dsRes').innerHTML = renderKV(d);
        }catch(_){
          try{
            const d = await post('dns/dnssec/zones/'+encodeURIComponent(origin)+'/'+op);
            $('#dsRes').innerHTML = renderKV(d);
          }catch(e){ toast.err(e.message); }
        }
      };
    }catch(e){ $('#dnssecBody').innerHTML = errBox(e); }
  };
  await load();
}

async function dnsViewsSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">Views</div><div class="card-sub">Разделение ответов по клиентам</div></div></div>
    <div class="form-row">
      <div class="field"><label>Name</label><input id="dvName" placeholder="internal"></div>
      <div class="field"><label>CIDRs</label><input id="dvCidrs" placeholder="10.0.0.0/8, 192.168.0.0/16"></div>
      <button class="button primary" id="dvCreate">+ Создать</button>
    </div>
    <div id="dvBody">${spinner()}</div>
  </div>`;
  $('#dvCreate').onclick = async ()=>{
    try{ await post('dns/views/create', {name:$('#dvName').value, cidrs:$('#dvCidrs').value}); toast.ok('OK'); dnsViewsSection(box, c); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('dns/views');
    $('#dvBody').innerHTML = renderTable([
      {label:'Name', key:'name'},
      {label:'CIDRs', render:r=>(r.match_cidrs||[]).join(', ')},
      {label:'', render:r=>`<button class="button small danger" data-vdel="${esc(r.name)}">×</button>`}
    ], d.views);
    $$('[data-vdel]').forEach(el=>el.onclick=async()=>{
      try{ await post('dns/views/'+encodeURIComponent(el.dataset.vdel)+'/delete'); dnsViewsSection(box, c); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#dvBody').innerHTML = errBox(e); }
}

/* ── Protection ── */
async function dnsProtection(box, c){
  box.innerHTML = `<div id="dpCache"></div>
    <div id="dpRrl" style="margin-top:14px"></div>
    <div id="dpRpz" style="margin-top:14px"></div>
    <div id="dpLocal" style="margin-top:14px"></div>`;
  await dnsCacheSection($('#dpCache'), c);
  await dnsRrlSection($('#dpRrl'), c);
  await dnsRpzSection($('#dpRpz'), c);
  await dnsLocalSection($('#dpLocal'), c);
}

async function dnsCacheSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head">
      <div><div class="card-title">DNS-кэш</div><div class="card-sub">Ключи и очистка</div></div>
      <div class="card-actions">
        <button class="button small" id="dcKeys">🔄</button>
        <button class="button small danger" id="dcClear">🗑️ Clear</button>
      </div>
    </div>
    <div id="dcStats">${spinner()}</div>
    <div id="dcList" style="margin-top:10px">${spinner()}</div>
  </div>`;
  try{ const s = await get('dns/cache/stats'); $('#dcStats').innerHTML = renderKV(s); }
  catch(e){ $('#dcStats').innerHTML = errBox(e); }
  const load = async ()=>{
    try{
      const d = await get('dns/cache/keys?limit=500');
      $('#dcList').innerHTML = renderTable(['key'], (d.keys||[]).map(k=>({key:k})));
    }catch(e){ $('#dcList').innerHTML = errBox(e); }
  };
  $('#dcKeys').onclick = load;
  $('#dcClear').onclick = async ()=>{
    if(!await confirmDlg('Очистить DNS-кэш?','')) return;
    try{ await post('dns/cache/clear'); toast.ok('OK'); load(); }
    catch(e){ toast.err(e.message); }
  };
  load();
}

async function dnsRrlSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head">
      <div><div class="card-title">RRL (Response Rate Limiting)</div></div>
      <div class="card-actions"><button class="button small" id="drrSweep">🧹 Sweep</button></div>
    </div>
    <div id="drrBody">${spinner()}</div>
  </div>`;
  $('#drrSweep').onclick = async ()=>{
    try{ await post('dns/rrl/sweep'); toast.ok('OK'); dnsRrlSection(box, c); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('dns/rrl/buckets');
    $('#drrBody').innerHTML = renderTable(['key','count','slipped'], d);
  }catch(e){ $('#drrBody').innerHTML = errBox(e); }
}

async function dnsRpzSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">RPZ (блок-лист)</div></div></div>
    <div class="form-row">
      <div class="field"><label>Name</label><input id="drpzName" placeholder="zone-name"></div>
      <div class="field"><label>Path</label><input id="drpzPath" placeholder="/path/to/hosts"></div>
      <button class="button primary" id="drpzLoad">Загрузить</button>
    </div>
    <div id="drpzBody">${spinner()}</div>
    <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--line)">
      <div class="section-label">Проверка домена</div>
      <div class="form-row" style="border:0;padding:0;margin:0">
        <div class="field"><label>Домен</label><input id="drpzChk" placeholder="example.com"></div>
        <button class="button" id="drpzChkBtn">Проверить</button>
      </div>
      <div id="drpzChkRes"></div>
    </div>
  </div>`;
  $('#drpzLoad').onclick = async ()=>{
    try{ await post('dns/rpz/load', {name:$('#drpzName').value, path:$('#drpzPath').value}); toast.ok('OK'); dnsRpzSection(box, c); }
    catch(e){ toast.err(e.message); }
  };
  $('#drpzChkBtn').onclick = async ()=>{
    try{
      const d = await get('dns/rpz/check?name='+encodeURIComponent($('#drpzChk').value));
      $('#drpzChkRes').innerHTML = renderKV(d);
    }catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('dns/rpz/list');
    $('#drpzBody').innerHTML = renderTable([
      {label:'Zone', key:'name'},
      {label:'Exact', key:'exact'},
      {label:'Wild', key:'wildcards'},
      {label:'', render:r=>`<button class="button small danger" data-rpz="${esc(r.name)}">×</button>`}
    ], d.zones);
    $$('[data-rpz]').forEach(el=>el.onclick=async()=>{
      try{ await post('dns/rpz/unload', {name:el.dataset.rpz}); dnsRpzSection(box, c); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#drpzBody').innerHTML = errBox(e); }
}

async function dnsLocalSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">Local Names</div><div class="card-sub">Локальные переопределения</div></div></div>
    <div class="form-row">
      <div class="field"><label>Host</label><input id="dlHost" placeholder="hostname"></div>
      <div class="field"><label>IP</label><input id="dlIp" placeholder="1.2.3.4"></div>
      <button class="button primary" id="dlSet">+ Добавить</button>
    </div>
    <div id="dlBody">${spinner()}</div>
  </div>`;
  $('#dlSet').onclick = async ()=>{
    try{ await post('dns/local_names/set', {host:$('#dlHost').value, ip:$('#dlIp').value}); toast.ok('OK'); dnsLocalSection(box, c); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('dns/local_names');
    const rows = Object.entries(d).map(([h,ip])=>({host:h, ip}));
    $('#dlBody').innerHTML = renderTable([
      {label:'Host', key:'host'},
      {label:'IP', key:'ip'},
      {label:'', render:r=>`<button class="button small danger" data-dlh="${esc(r.host)}">×</button>`}
    ], rows);
    $$('[data-dlh]').forEach(el=>el.onclick=async()=>{
      try{ await post('dns/local_names/del?host='+encodeURIComponent(el.dataset.dlh)); dnsLocalSection(box, c); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#dlBody').innerHTML = errBox(e); }
}

/* ── Routing ── */
async function dnsRouting(box, c){
  box.innerHTML = `<div id="drWeighted"></div><div id="drGeo" style="margin-top:14px"></div>`;
  await dnsWeightedSection($('#drWeighted'), c);
  await dnsGeoSection($('#drGeo'), c);
}

async function dnsWeightedSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head">
      <div><div class="card-title">Weighted</div><div class="card-sub">Взвешенные A/AAAA · сперва выберите зону в «Зоны»</div></div>
      <div class="card-actions"><button class="button small" id="dwLoad">Загрузить</button></div>
    </div>
    <div class="form-row">
      <div class="field"><label>Origin</label><input id="dwOrigin" placeholder="example.com." list="dwZonesList"></div>
      <datalist id="dwZonesList"></datalist>
    </div>
    <div class="form-row">
      <div class="field"><label>Name</label><input id="dwName" value="@"></div>
      <div class="field shrink"><label>Type</label><select id="dwType"><option>A</option><option>AAAA</option></select></div>
      <div class="field"><label>Weights (10,20,70)</label><input id="dwWeights" placeholder="10,20,70"></div>
      <button class="button primary" id="dwSet">Set</button>
      <button class="button danger" id="dwDel">Del</button>
    </div>
    <div id="dwList"><div class="empty">Укажите Origin и нажмите «Загрузить»</div></div>
  </div>`;
  try{
    const zones = await get('dns/zones');
    const znames = (zones||[]).map(z=>z.origin);
    const dl = $('#dwZonesList');
    if(dl) dl.innerHTML = znames.map(z=>`<option value="${esc(z)}">`).join('');
    if(!$('#dwOrigin').value && znames.length) $('#dwOrigin').value = znames[0];
  }catch(e){}
  const load = async ()=>{
    const origin = ($('#dwOrigin').value || '').trim();
    if(!origin){ toast.warn('Укажите Origin (например, example.com.)'); return; }
    try{
      const d = await get('dns/weighted?origin='+encodeURIComponent(origin));
      const rows = Array.isArray(d) ? d : [];
      if(!rows.length){ $('#dwList').innerHTML = `<div class="empty">Правил пока нет — добавьте первое через «Set»</div>`; return; }
      $('#dwList').innerHTML = renderTable([
        {label:'Name', key:'name'},
        {label:'Type', key:'type'},
        {label:'W', render:r=>(r.weights||[]).join(',')}
      ], rows);
    }catch(e){ $('#dwList').innerHTML = errBox(e); }
  };
  const gather = ()=>({
    origin: ($('#dwOrigin').value || '').trim(),
    name: $('#dwName').value || '@',
    type: $('#dwType').value,
    weights: $('#dwWeights').value || ''
  });
  $('#dwLoad').onclick = load;
  $('#dwSet').onclick = async ()=>{
    const g = gather();
    if(!g.origin){ toast.warn('Укажите Origin'); return; }
    if(!g.weights){ toast.warn('Укажите Weights (10,20,70)'); return; }
    try{ await post('dns/weighted/set', g); toast.ok('Сохранено'); load(); }
    catch(e){ toast.err(e.message); }
  };
  $('#dwDel').onclick = async ()=>{
    const g = gather();
    if(!g.origin){ toast.warn('Укажите Origin'); return; }
    try{ await post('dns/weighted/delete', g); toast.ok('Удалено'); load(); }
    catch(e){ toast.err(e.message); }
  };
  if($('#dwOrigin').value) load();
}

async function dnsGeoSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head">
      <div><div class="card-title">GeoDNS</div><div class="card-sub">Ответы по стране клиента · сперва выберите зону в «Зоны»</div></div>
      <div class="card-actions"><button class="button small" id="dgLoad">Загрузить</button></div>
    </div>
    <div id="dgInfo">${spinner()}</div>
    <div class="form-row" style="margin-top:14px">
      <div class="field"><label>Origin</label><input id="dgOrigin" placeholder="example.com." list="dgZonesList"></div>
      <datalist id="dgZonesList"></datalist>
    </div>
    <div class="form-row">
      <div class="field"><label>Name</label><input id="dgName" value="@"></div>
      <div class="field shrink"><label>Type</label><select id="dgType"><option>A</option><option>AAAA</option></select></div>
      <div class="field shrink"><label>Country</label><input id="dgCountry" value="US" placeholder="US"></div>
      <button class="button primary" id="dgSet">Set</button>
    </div>
    <div id="dgList"><div class="empty">Укажите Origin и нажмите «Загрузить»</div></div>
  </div>`;
  try{ const info = await get('dns/geo/db_info'); $('#dgInfo').innerHTML = renderKV(info); }
  catch(e){ $('#dgInfo').innerHTML = errBox(e); }
  try{
    const zones = await get('dns/zones');
    const znames = (zones||[]).map(z=>z.origin);
    const dl = $('#dgZonesList');
    if(dl) dl.innerHTML = znames.map(z=>`<option value="${esc(z)}">`).join('');
    if(!$('#dgOrigin').value && znames.length) $('#dgOrigin').value = znames[0];
  }catch(e){}
  const load = async ()=>{
    const origin = ($('#dgOrigin').value || '').trim();
    if(!origin){ toast.warn('Укажите Origin (например, example.com.)'); return; }
    try{
      const d = await get('dns/geo?origin='+encodeURIComponent(origin));
      const rows = Array.isArray(d) ? d : [];
      if(!rows.length){ $('#dgList').innerHTML = `<div class="empty">Правил пока нет — добавьте первое через «Set»</div>`; return; }
      $('#dgList').innerHTML = renderTable([
        {label:'Name', key:'name'},
        {label:'Type', key:'type'},
        {label:'Countries', render:r=>(r.countries||[]).join(', ')}
      ], rows);
    }catch(e){ $('#dgList').innerHTML = errBox(e); }
  };
  $('#dgLoad').onclick = load;
  $('#dgSet').onclick = async ()=>{
    const origin = ($('#dgOrigin').value || '').trim();
    const country = ($('#dgCountry').value || '').trim();
    if(!origin){ toast.warn('Укажите Origin'); return; }
    if(!country){ toast.warn('Укажите Country (US, RU, DE…)'); return; }
    try{ await post('dns/geo/set', {origin, name:$('#dgName').value||'@', type:$('#dgType').value, country}); toast.ok('Сохранено'); load(); }
    catch(e){ toast.err(e.message); }
  };
  if($('#dgOrigin').value) load();
}

/* ── Access ── */
async function dnsAccess(box, c){
  box.innerHTML = `<div id="daTsig"></div><div id="daTenants" style="margin-top:14px"></div>`;
  await dnsTsigSection($('#daTsig'), c);
  await dnsTenantsSection($('#daTenants'), c);
}

async function dnsTsigSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">TSIG</div><div class="card-sub">Ключи аутентификации</div></div></div>
    <div class="form-row">
      <div class="field"><label>Name</label><input id="dtsName" placeholder="key-name"></div>
      <div class="field"><label>Secret (base64)</label><input id="dtsSecret" placeholder="base64..."></div>
      <button class="button primary" id="dtsAdd">+ Добавить</button>
    </div>
    <div id="dtsBody">${spinner()}</div>
  </div>`;
  $('#dtsAdd').onclick = async ()=>{
    try{ await post('dns/tsig/keys/add', {name:$('#dtsName').value, algorithm:'hmac-sha256', secret_b64:$('#dtsSecret').value}); toast.ok('OK'); dnsTsigSection(box, c); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('dns/tsig/keys');
    const rows = (d && Array.isArray(d.keys)) ? d.keys : [];
    if(!rows.length){ $('#dtsBody').innerHTML = `<div class="empty">Ключей нет — добавьте первый</div>`; return; }
    $('#dtsBody').innerHTML = renderTable([
      {label:'Name', key:'name'},
      {label:'Alg', key:'algorithm'},
      {label:'Len', key:'secret_len'},
      {label:'', render:r=>`<button class="button small danger" data-tdel="${esc(r.name)}">×</button>`}
    ], rows);
    $$('[data-tdel]').forEach(el=>el.onclick=async()=>{
      try{ await post('dns/tsig/keys/'+encodeURIComponent(el.dataset.tdel)+'/delete'); dnsTsigSection(box, c); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#dtsBody').innerHTML = errBox(e); }
}

async function dnsTenantsSection(box, c){
  box.innerHTML = `<div class="card">
    <div class="card-head"><div><div class="card-title">Tenants</div><div class="card-sub">Мульти-тенантность (требует <code>[dns.tenants]</code> в config.toml)</div></div></div>
    <div class="form-row">
      <div class="field shrink"><label>ID</label><input id="dtnId" placeholder="acme"></div>
      <div class="field"><label>Name</label><input id="dtnNm" placeholder="ACME Corp"></div>
      <div class="field"><label>CIDRs</label><input id="dtnCidrs" placeholder="10.0.0.0/8"></div>
      <button class="button primary" id="dtnCreate">+ Добавить</button>
    </div>
    <div id="dtnBody">${spinner()}</div>
  </div>`;
  $('#dtnCreate').onclick = async ()=>{
    try{ await post('dns/tenants/create', {id:$('#dtnId').value, display_name:$('#dtnNm').value, allowed_cidrs:$('#dtnCidrs').value}); toast.ok('OK'); dnsTenantsSection(box, c); }
    catch(e){ toast.err(e.message); }
  };
  try{
    const d = await get('dns/tenants');
    const rows = (d && Array.isArray(d.tenants)) ? d.tenants : [];
    if(!rows.length){
      $('#dtnBody').innerHTML = `<div class="empty-state">
        <div class="icon">👥</div>
        <div class="title">Тенантов нет</div>
        <div class="sub">Создайте первого через форму выше. Если сервер вернул ошибку 503 — задайте секцию <code>[dns.tenants]</code> в config.toml.</div>
      </div>`;
      return;
    }
    $('#dtnBody').innerHTML = renderTable([
      {label:'ID', key:'id'},
      {label:'Name', key:'display_name'},
      {label:'CIDRs', render:r=>(r.allowed_cidrs||[]).join(', ')},
      {label:'', render:r=>`<button class="button small danger" data-tn="${esc(r.id)}">×</button>`}
    ], rows);
    $$('[data-tn]').forEach(el=>el.onclick=async()=>{
      try{ await post('dns/tenants/'+encodeURIComponent(el.dataset.tn)+'/delete'); dnsTenantsSection(box, c); }
      catch(e){ toast.err(e.message); }
    });
  }catch(e){ $('#dtnBody').innerHTML = errBox(e); }
}

Object.assign(window, {
  renderDNS: mount,
  dnsZonesCombined, dnsZonesSection, showDnsZoneRecords, showDnssecModal, dnsViewsSection,
  dnsProtection, dnsCacheSection, dnsRrlSection, dnsRpzSection, dnsLocalSection,
  dnsRouting, dnsWeightedSection, dnsGeoSection,
  dnsAccess, dnsTsigSection, dnsTenantsSection
});