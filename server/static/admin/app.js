// app — ядро SPA.

/* ══════════════ Service worker ══════════════ */
const SW_SRC="const C='omnirs-v12';self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;const u=new URL(e.request.url);if(u.pathname.startsWith('/api/'))return;e.respondWith(fetch(e.request).then(r=>{if(!r.ok)return r;const c=r.clone();caches.open(C).then(cc=>cc.put(e.request,c)).catch(()=>{});return r}).catch(()=>caches.match(e.request)))});";
if('serviceWorker' in navigator && location.protocol.startsWith('http')){
  try{const b=new Blob([SW_SRC],{type:'application/javascript'});
    navigator.serviceWorker.register(URL.createObjectURL(b)).catch(()=>{});}catch(_){}
}

/* ══════════════ Константы ══════════════ */
const THEME_KEY='omnirs.theme', NAV_KEY='omnirs.nav.collapsed',
      TAB_KEY='omnirs.tab', SUBTAB_KEY='omnirs.subtabs';

export const THEMES=[
  {id:'dark',name:'Тёмная',bg:'#0e1118',accent:'#8b7cff',line:'#293141'},
  {id:'light',name:'Светлая',bg:'#f4f6fb',accent:'#6555e8',line:'#e2e6ef'},
  {id:'ocean',name:'Океан',bg:'#0a1628',accent:'#06b6d4',line:'#1e3a5c'},
  {id:'forest',name:'Лес',bg:'#0f1a14',accent:'#4ade80',line:'#294d36'},
  {id:'sunset',name:'Закат',bg:'#1a0f1f',accent:'#f472b6',line:'#472c52'},
  {id:'amber',name:'Янтарь',bg:'#1a1410',accent:'#f59e0b',line:'#4d3822'},
  {id:'neon',name:'Неон',bg:'#0d0418',accent:'#e879f9',line:'#3d1f66'},
  {id:'matrix',name:'Матрица',bg:'#000a00',accent:'#22c55e',line:'#0f3d0f'},
  {id:'monokai',name:'Monokai',bg:'#1e1f1c',accent:'#f92672',line:'#49483e'},
  {id:'dracula',name:'Dracula',bg:'#1e1f29',accent:'#bd93f9',line:'#44475a'},
  {id:'nord',name:'Nord',bg:'#2e3440',accent:'#81a1c1',line:'#4c566a'},
  {id:'rose',name:'Роза',bg:'#1a0e14',accent:'#fb7185',line:'#4c2933'}
];

export const TABS={
  dashboard:{icon:'🏠',label:'Обзор'},
  files:{icon:'📁',label:'Файлы'},
  dns:{icon:'🌐',label:'DNS'},
  certs:{icon:'🔐',label:'Сертификаты'},
  proxy:{icon:'🔀',label:'Proxy'},
  system:{icon:'⚙️',label:'Система'},
  db:{icon:'🗄️',label:'Базы данных'},
  vpn:{icon:'🛡️',label:'VPN'},
  modules:{icon:'🧩',label:'Модули'}
};

const TAB_TO_PAGE={
  dashboard:'dashboard', files:'files', dns:'dns', certs:'ssl',
  proxy:'proxy', system:'settings', db:'db', vpn:'vpn', modules:'modules'
};

const PRIMARY_ORDER=['files','db','dns','certs','vpn','proxy','modules'];
const ADMIN_ORDER=['dashboard','system'];

/* ══════════════ State ══════════════ */
function readStoredTab(){
  try{let t=localStorage.getItem(TAB_KEY);if(t==='wg')t='vpn';
    if(t&&TABS[t])return t;}catch(_){}
  return 'dashboard';
}
function readStoredSubtabs(){
  try{return JSON.parse(localStorage.getItem(SUBTAB_KEY)||'{}');}catch(_){return {};}
}
const ST_SUB=readStoredSubtabs();

export const S={
  token:'', authed:false, who:null, loading:true,
  tab:readStoredTab(),
  theme:localStorage.getItem(THEME_KEY)||'dark',
  navCollapsed:localStorage.getItem(NAV_KEY)==='1',
  files:{path:'/',items:null,selected:new Set(),page:0,pageSize:50,
    editor:{open:false,path:'',content:'',collapsed:false}},
  cache:{pattern:''},
  db:{sub:'connections',conn:'',dbName:'',tableName:'',search:'',page:0,
    schema:[],rows:[],filter:'',sql:'SELECT 1;',result:null,activeRowPk:null,
    selectedDbs:new Set(),selectedTables:new Set(),selectedRows:new Set()},
  dns:{sub:ST_SUB.dns||'zones'},
  proxy:{sub:ST_SUB.proxy||'config'},
  vpn:{sub:ST_SUB.vpn||'miraj'},
  monitor:{sub:ST_SUB.monitor||'traffic'},
  sys:{sub:ST_SUB.sys||'info'},
  logs:{sel:null,n:200,showAdmin:false,journal:null},
  settings:{}, vpnClients:[],
  toolPanelCollapsed:false, toolPanelVpnClient:null
};
window.S=S;

/* ══════════════ Utils ══════════════ */
export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
export const esc = (v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const join = (a,b)=>(a.endsWith('/')?a:a+'/')+String(b||'').replace(/^\/+/,'');
export const fmtSize = (n)=>!n?'0 B':n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(2)+' MB':(n/1073741824).toFixed(2)+' GB';
export const fmtTs = (ts)=>ts?new Date(ts*1000).toLocaleString('ru-RU'):'—';

export function saveSubtabs(){
  ST_SUB.dns=S.dns.sub; ST_SUB.proxy=S.proxy.sub;
  ST_SUB.monitor=S.monitor.sub; ST_SUB.sys=S.sys.sub;
  if(S.vpn)ST_SUB.vpn=S.vpn.sub;
  try{localStorage.setItem(SUBTAB_KEY,JSON.stringify(ST_SUB));}catch(_){}
}

/* ══════════════ API ══════════════ */
export async function api(path,opts={}){
  const h={...(opts.headers||{})};let body=opts.body;
  if(opts.json!==undefined){h['content-type']='application/json';body=JSON.stringify(opts.json);}
  else if(opts.form!==undefined){h['content-type']='application/x-www-form-urlencoded';body=new URLSearchParams(opts.form).toString();}
  const r=await fetch('/api/'+path,{method:opts.method||'GET',headers:h,body,credentials:'same-origin'});
  const ct=r.headers.get('content-type')||'';let d;
  try{d=ct.includes('json')?await r.json():await r.text();}catch(_){d=null;}
  if(typeof d==='string'){const t=d.trim();
    if((t.startsWith('{')&&t.endsWith('}'))||(t.startsWith('[')&&t.endsWith(']'))){
      try{d=JSON.parse(t);}catch(_){}}}
  if(!r.ok){if(r.status===401){window.location.href='/';throw new Error('unauthorized');}
    const msg=typeof d==='string'?d:((d&&d.error)||r.statusText||('HTTP '+r.status));
    throw new Error(msg);}
  return d;
}
const GET_CACHE=new Map(); const GET_TTL=5000;
export async function get(p,force){
  if(!force){const e=GET_CACHE.get(p);if(e&&Date.now()-e.ts<GET_TTL)return e.data;}
  const d=await api(p);GET_CACHE.set(p,{data:d,ts:Date.now()});return d;
}
export function invalidateGetCache(){GET_CACHE.clear();}
export async function post(p,form){const r=await api(p,{method:'POST',form:form||{}});invalidateGetCache();return r;}
export async function postJ(p,json){const r=await api(p,{method:'POST',json});invalidateGetCache();return r;}
export async function del(p){const r=await api(p,{method:'DELETE'});invalidateGetCache();return r;}
export const dl = async(path)=>{try{
  const r=await fetch('/api/'+path,{credentials:'same-origin'});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const blob=await r.blob();const cd=r.headers.get('content-disposition')||'';
  let name='download';const m=cd.match(/filename="?([^";]+)"?/);if(m)name=m[1];
  const url=URL.createObjectURL(blob);const a=document.createElement('a');
  a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),30000);
}catch(e){toast.err('Download: '+e.message);}};

/* ══════════════ Toast / Modal ══════════════ */
export function toast(msg,level='info'){
  const el=document.createElement('div');
  el.className='toast '+(level==='error'?'error':level==='warn'?'warn':level==='ok'?'success':'');
  el.innerHTML=`<div>${level==='error'?'⚠':level==='warn'?'!':level==='ok'?'✓':'ℹ'}</div><div>${esc(msg)}</div>`;
  $('#toastArea').appendChild(el);setTimeout(()=>el.remove(),4500);
}
toast.ok=(m)=>toast(m,'ok');toast.err=(m)=>toast(m,'error');toast.warn=(m)=>toast(m,'warn');

export function showModal(title,bodyHtml,footHtml,wide){
  const bd=$('#modalBackdrop');
  bd.innerHTML=`<div class="modal ${wide?'modal-wide':''}"><div class="modal-head"><h2>${esc(title)}</h2><button onclick="closeModal()">×</button></div><div class="modal-body">${bodyHtml}</div>${footHtml||'<div class="modal-foot"><button class="button" onclick="closeModal()">Закрыть</button></div>'}</div>`;
  bd.classList.add('open');return bd;
}
export function closeModal(){const bd=$('#modalBackdrop');bd.classList.remove('open');bd.innerHTML='';}
export function confirmDlg(title,body){
  return new Promise(resolve=>{
    showModal(title,`<p style="margin:0">${esc(body)}</p>`,
      `<div class="modal-foot"><button class="button" id="cfNo">Отмена</button><button class="button danger" id="cfYes">Подтвердить</button></div>`);
    $('#cfNo').onclick=()=>{closeModal();resolve(false);};
    $('#cfYes').onclick=()=>{closeModal();resolve(true);};
  });
}

/* ══════════════ Render primitives ══════════════ */
function isPlainObj(v){return v&&typeof v==='object'&&!Array.isArray(v);}
function renderNestedArray(arr){
  if(!arr.length)return '<div class="empty" style="padding:12px">Пустой список</div>';
  if(isPlainObj(arr[0])){
    const cols=[...new Set(arr.flatMap(o=>Object.keys(o)))];
    return renderTable(cols.map(k=>({label:k,render:r=>formatVal(r[k],k)})),arr);
  }
  return `<pre class="kv-pre">${esc(JSON.stringify(arr,null,2))}</pre>`;
}
function formatVal(v,key){
  if(v==null)return '—';
  if(typeof v==='boolean')return v?'<span class="status">да</span>':'<span class="status neutral">нет</span>';
  if(typeof v==='number'){
    if((key==='ts'||key==='time'||key==='started_at'||key==='created_at'||key==='expires_at'||key==='not_before'||key==='not_after')&&v>1000000000)return fmtTs(v);
    if(key==='uptime_secs'||key==='uptime')return `${v} s`;
    if(key==='latency_ms'||key==='threshold_ms')return `${v} ms`;
    if(key==='latency_us')return `${(v/1000).toFixed(1)} ms`;
    if(v>1000000&&/mem|bytes|size|free|total|available/i.test(key))return `${fmtSize(v)} <span style="color:var(--muted)">(${v})</span>`;
  }
  if(Array.isArray(v)&&v.length&&isPlainObj(v[0]))return `<div class="kv-nested">${renderNestedArray(v)}</div>`;
  if(Array.isArray(v))return `<pre class="kv-pre">${esc(JSON.stringify(v,null,2))}</pre>`;
  if(isPlainObj(v))return `<div class="kv-nested">${renderKV(v)}</div>`;
  return esc(v);
}
export function renderKV(data){
  if(data==null)return '';
  if(typeof data!=='object')return `<pre class="kv-pre">${esc(data)}</pre>`;
  if(Array.isArray(data))return renderNestedArray(data);
  return `<dl class="kv">${Object.entries(data).map(([k,v])=>`<dt>${esc(k)}</dt><dd>${formatVal(v,k)}</dd>`).join('')}</dl>`;
}
export function renderKVGrid(data,cols=2){
  if(!data||typeof data!=='object'||Array.isArray(data))return renderKV(data);
  return `<div style="display:grid;grid-template-columns:repeat(${cols},minmax(0,1fr));gap:8px">${Object.entries(data).map(([k,v])=>`<div style="background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 10px;min-width:0"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;font-weight:600">${esc(k)}</div><div style="font-family:ui-monospace,monospace;font-size:12px;margin-top:3px;word-break:break-word">${formatVal(v,k)}</div></div>`).join('')}</div>`;
}
export function renderTable(cols,rows,empty='Нет данных'){
  if(!rows||!rows.length)return `<div class="empty">${esc(empty)}</div>`;
  const headerCells=cols.map(c=>{
    const label=c.label??c;const s=String(label);
    const isHtml=s.trimStart().startsWith('<');
    return `<th>${isHtml?s:esc(s)}</th>`;
  }).join('');
  return `<div class="table-wrap"><table><thead><tr>${headerCells}</tr></thead><tbody>${rows.map((r,i)=>`<tr>${cols.map(c=>{
    const v=c.render?c.render(r,i):(c.key?r[c.key]:r[c]);
    return `<td>${v==null?'':v}</td>`;
  }).join('')}</tr>`).join('')}</tbody></table></div>`;
}
export function spinner(){return `<div class="spinner"></div>`;}
export function errBox(e){return `<div class="err">${esc(e?.message||e||'error')}</div>`;}
export function badge(text,kind){
  const k=kind||(/ошиб|отключ|приостанов|fail|✖|error/i.test(text)?'error':
    /ожидан|предупреж|warn|demo|демо/i.test(text)?'warning':
    /локальн|neutral/i.test(text)?'neutral':'');
  return `<span class="status ${k}">${esc(text)}</span>`;
}
export function renderRawLog(raw,filterAdmin){
  let lines=String(raw||'').split('\n').filter(l=>l.trim());
  if(!lines.length)return '<div class="empty">Пусто</div>';
  if(filterAdmin===false){
    lines=lines.filter(l=>{try{const e=JSON.parse(l);const p=String(e.path||e.endpoint||'');return !p.startsWith('/__admin/');}catch{return true;}});
    if(!lines.length)return '<div class="empty">Пусто (все записи — обращения к админ-панели скрыты тумблером)</div>';
  }
  const events=[];let nonJson=0;
  for(const l of lines){try{events.push(JSON.parse(l));}catch{nonJson++;}}
  if(nonJson>lines.length/2)return `<pre class="kv-pre" style="max-height:500px">${esc(lines.join('\n'))}</pre>`;
  const cols=[...new Set(events.flatMap(e=>isPlainObj(e)?Object.keys(e):[]))];
  if(!cols.length)return `<pre class="kv-pre" style="max-height:500px">${esc(lines.join('\n'))}</pre>`;
  return renderTable(cols.map(k=>({label:k,render:r=>formatVal(r[k],k)})),events);
}

// ── journalctl-рендер: превращает journal -o json в читаемый текст ──
export function renderJournal(raw){
  // Нормализуем вход: строка | массив строк | массив объектов
  let lines;
  if(Array.isArray(raw)){
    lines=raw.map(l=>(typeof l==='string'?l:JSON.stringify(l)));
  }else{
    lines=String(raw||'').split('\n').filter(l=>l.trim());
  }
  if(!lines.length)return '<div class="empty">Пусто</div>';

  // Пробуем распарсить как journalctl -o json
  const parsed=[];let nonJson=0;
  for(const l of lines){try{parsed.push(JSON.parse(l));}catch(_){nonJson++;}}

  // Больше половины не-JSON → journalctl -o cat/short, показываем как есть
  if(nonJson>lines.length/2){
    return `<pre class="kv-pre" style="max-height:500px">${esc(lines.join('\n'))}</pre>`;
  }

  // journalctl -o json → собираем строки вида: [ts] host unit[pid]: msg
  const out=parsed.map(e=>{
    let ts='';
    const tsMicro=e.__REALTIME_TIMESTAMP;
    if(tsMicro){
      try{
        const d=new Date(parseInt(tsMicro,10)/1000);
        ts=d.toLocaleString('ru-RU',{hour12:false});
      }catch(_){}
    }
    const host=e._HOSTNAME||'';
    const unit=e.SYSLOG_IDENTIFIER||e._SYSTEMD_UNIT||e.SYSLOG_TAG||'';
    const pid=e._PID||e.SYSLOG_PID||'';
    const msg=e.MESSAGE||'';

    let s='';
    if(ts)s+='['+ts+'] ';
    if(host)s+=host+' ';
    if(unit)s+=unit+(pid?`[${pid}]`:'')+': ';
    s+=msg;
    return s.trim();
  });

  return `<pre class="kv-pre" style="max-height:500px">${esc(out.join('\n'))}</pre>`;
}

export function renderChart(history){
  if(!history||!history.length)return `<div class="empty">Нет данных для графика</div>`;
  const vals=history.map(h=>h.requests||0);const max=Math.max(1,...vals);
  const W=640,H=220,L=32,R=10,T=12,B=28;
  const x=i=>L+i*(W-L-R)/Math.max(1,vals.length-1);
  const y=v=>T+(max-v)*(H-T-B)/max;
  const path=vals.map((v,i)=>`${i?'L':'M'} ${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ');
  const grid=[0,25,50,75,100].map(pct=>{
    const v=max*pct/100;
    return `<line x1="${L}" y1="${y(v)}" x2="${W-R}" y2="${y(v)}" stroke="var(--line)" stroke-dasharray="3 5"/><text x="0" y="${y(v)+4}" fill="var(--muted)" font-size="10">${Math.round(v)}</text>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="График"><defs><linearGradient id="grad" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="var(--accent)" stop-opacity=".28"/><stop offset="1" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>${grid}<path d="${path} L ${x(vals.length-1)} ${H-B} L ${x(0)} ${H-B} Z" fill="url(#grad)"/><path d="${path}" fill="none" stroke="var(--accent)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

/* ══════════════ Theme / nav ══════════════ */
export function setTheme(t){
  const found=THEMES.find(x=>x.id===t)||THEMES[0];
  S.theme=found.id;document.documentElement.dataset.theme=found.id;
  localStorage.setItem(THEME_KEY,found.id);
  const b=$('#themeBtn');if(b)b.textContent=found.id==='light'?'☾':'☼';
}
export function toggleTheme(){setTheme(S.theme==='light'?'dark':'light');}
document.documentElement.dataset.theme=S.theme;
function applyNavState(){
  document.body.classList.toggle('nav-collapsed',S.navCollapsed);
  const t=$('#navToggle');
  if(t){t.textContent=S.navCollapsed?'▴':'▾';t.title=S.navCollapsed?'Развернуть меню':'Свернуть меню';}
}
function toggleNav(){
  S.navCollapsed=!S.navCollapsed;
  localStorage.setItem(NAV_KEY,S.navCollapsed?'1':'0');
  applyNavState();
}

/* ══════════════ Auth ══════════════ */
async function checkAuth(){
  try{
    const w=await get('auth/whoami');
    if(!w||!w.id){window.location.href='/';return;}
    S.who=w;S.authed=true;S.loading=false;renderApp();
  }catch(_){window.location.href='/';}
}
async function doLogout(){try{await post('auth/logout',{});}catch(_){}S.authed=false;S.who=null;window.location.href='/';}

/* ══════════════ Shell + Router ══════════════ */
function renderApp(){
  const app=$('#app');
  if(S.loading){app.innerHTML=`<div class="spinner" style="padding:80px 20px;text-align:center"></div>`;return;}
  if(!S.authed){window.location.href='/';return;}
  const current=TABS[S.tab]||{label:'OmniRS',icon:'🏠'};

  const bottomBtns=PRIMARY_ORDER.map(id=>{
    const t=TABS[id];const active=S.tab===id?'active':'';
    return `<button class="bottom-nav-btn ${active}" data-nav="${id}" title="${esc(t.label)}" aria-label="${esc(t.label)}">${t.icon}</button>`;
  }).join('');

  const adminBtns=ADMIN_ORDER.map(id=>{
    const t=TABS[id];const active=S.tab===id?'active':'';
    return `<button class="admin-tab ${active}" data-nav="${id}" title="${esc(t.label)}"><span class="admin-tab-icon">${t.icon}</span><span class="admin-tab-label">${esc(t.label)}</span></button>`;
  }).join('');

  app.innerHTML=`<div class="app">
    <main class="main">
      <header class="topbar">
        <div class="topbar-title">
          <div class="breadcrumb">OmniRS / <span>${esc(current.label)}</span></div>
          <h1 class="page-title">${esc(current.label)}</h1>
        </div>
        <div class="topbar-center">
          <nav class="admin-tabs" aria-label="Навигация верхнего уровня">${adminBtns}</nav>
        </div>
        <div class="topbar-actions">
          <button class="icon-btn" id="themeBtn" title="Сменить тему">${S.theme==='light'?'☾':'☼'}</button>
          <button class="icon-btn" id="logoutBtn" title="Выйти из аккаунта" aria-label="Выйти">⎋</button>
        </div>
      </header>
      <div id="viewContent"></div>
    </main>
    <nav class="bottom-nav" id="bottomNav" aria-label="Разделы сервера">
      <div class="bottom-nav-row">${bottomBtns}</div>
      <div class="bottom-nav-toggle-row">
        <button class="bottom-nav-toggle" id="navToggle" aria-label="Свернуть/развернуть меню"></button>
      </div>
    </nav>
  </div>
  <div class="tool-panel-backdrop" id="toolPanelBackdrop" onclick="onToolPanelBackdrop()"></div>
  <div class="tool-panel" id="toolPanel"></div>`;

  $$('[data-nav]').forEach(b=>b.onclick=()=>navigate(b.dataset.nav));
  $('#logoutBtn').onclick=doLogout;
  $('#themeBtn').onclick=toggleTheme;
  $('#navToggle').onclick=toggleNav;
  applyNavState();
  renderView();
}

export function navigate(tab){
  if(!TABS[tab])return;
  S.tab=tab;
  try{localStorage.setItem(TAB_KEY,tab);}catch(_){}
  closeToolPanel();
  renderApp();
  window.scrollTo({top:0,behavior:'smooth'});
}

async function renderView(){
  const c=$('#viewContent');
  c.innerHTML=spinner();
  const page=TAB_TO_PAGE[S.tab]||'dashboard';
  try{
    const mod = await import(`./${page}.js`);
    c.innerHTML='';
    await mod.mount(c);
  }catch(e){
    console.error('[renderView]',e);
    c.innerHTML=errBox(e);
  }
}

export function saveScrollAndRerender(subtabsSel,fn){
  const el=$(subtabsSel);const sl=el?el.scrollLeft:0;fn();
  setTimeout(()=>{const el2=$(subtabsSel);if(el2)el2.scrollLeft=sl;},0);
}
export function scrollTabIntoView(containerSel,activeSel){
  const cont=$(containerSel);const tab=$(activeSel);
  if(!cont||!tab)return;
  const cr=cont.getBoundingClientRect();const tr=tab.getBoundingClientRect();
  if(tr.left<cr.left+4||tr.right>cr.right-4){
    const target=tab.offsetLeft-(cont.clientWidth-tab.clientWidth)/2;
    cont.scrollLeft=Math.max(0,target);
  }
}

/* ══════════════ Tool panel (shared) ══════════════ */
function onToolPanelBackdrop(){
  if(S.tab==='db')return;
  closeToolPanel();
}
function closeToolPanel(){
  const panel=$('#toolPanel');
  if(!panel) return;
  panel.classList.remove('open');panel.classList.remove('collapsed');
  panel.dataset.owner='';panel._renderer=null;
  S.toolPanelVpnClient=null;S.toolPanelCollapsed=false;
  const backdrop=$('#toolPanelBackdrop');
  if(backdrop){backdrop.classList.remove('open');backdrop.style.display='';}
}
function toggleToolPanelCollapse(){
  S.toolPanelCollapsed=!S.toolPanelCollapsed;
  const panel=$('#toolPanel');
  if(S.tab==='db'){ if(window.renderDbToolPanel) window.renderDbToolPanel(); return; }
  if(panel._renderer)panel._renderer();
}

/* ══════════════ Экспорт в window (для inline onclick) ══════════════ */
Object.assign(window,{
  S, THEMES, TABS,
  api, get, post, postJ, del, dl, toast,
  showModal, closeModal, confirmDlg,
  renderTable, renderKV, renderKVGrid, renderNestedArray, formatVal,
  renderChart, renderRawLog, renderJournal, badge, spinner, errBox,
  setTheme, toggleTheme, toggleNav, navigate,
  closeToolPanel, toggleToolPanelCollapse, onToolPanelBackdrop,
  invalidateGetCache, saveScrollAndRerender, scrollTabIntoView,
  saveSubtabs
});

/* ══════════════ Start ══════════════ */
setTheme(S.theme);
applyNavState();
checkAuth();