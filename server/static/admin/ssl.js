import {
  S, $, $$, esc, get, post, dl, toast, confirmDlg,
  spinner, errBox, renderKV, renderTable, fmtSize
} from './app.js';

export async function mount(c){
  const [sumR, acmeR, listR] = await Promise.allSettled([
    get('certs'),
    get('certs/acme_account'),
    get('certs/list')
  ]);
  const sum = sumR.status === 'fulfilled' ? sumR.value : null;
  const acme = acmeR.status === 'fulfilled' ? acmeR.value : null;
  const list = listR.status === 'fulfilled' ? (Array.isArray(listR.value) ? listR.value : []) : [];

  if(!S.certsExpanded) S.certsExpanded = {};

  const fmtSans = (sans)=>{
    if(!sans) return '—';
    if(Array.isArray(sans)){
      if(!sans.length) return '—';
      return sans.map(s=>{
        if(typeof s === 'string') return s;
        if(s && typeof s === 'object') return s.value || s.name || s.dns || s.ip || s.common_name || JSON.stringify(s);
        return String(s);
      }).join(', ');
    }
    if(typeof sans === 'string') return sans;
    return String(sans);
  };

  let listHtml;
  if(!list.length){
    listHtml = `<div class="empty-state">
      <div class="icon">🔐</div>
      <div class="title">Сертификатов нет</div>
      <div class="sub">Выпустите первый через плитки ниже</div>
    </div>`;
  } else {
    const rowsHtml = list.map(r=>{
      const open = !!S.certsExpanded[r.file];
      const sansStr = fmtSans(r.sans);
      const main = `<tr data-certrow="${esc(r.file)}" style="cursor:pointer">
        <td style="width:24px;color:var(--muted);text-align:center">${open?'▼':'▶'}</td>
        <td><code class="mono-sm">${esc(r.file)}</code></td>
        <td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(sansStr)}">${esc(sansStr)}</td>
        <td>${esc(r.not_after||'—')}</td>
        <td>${r.days_left != null ? `<span class="status ${r.days_left<7?'error':r.days_left<30?'warning':''}">${r.days_left} дн.</span>` : '—'}</td>
        <td>${fmtSize(r.size)}</td>
      </tr>`;
      let detail = '';
      if(open){
        detail = `<tr data-certdetail="${esc(r.file)}">
          <td colspan="6" style="padding:0;background:color-mix(in srgb,var(--accent) 5%,transparent);white-space:normal">
            <div style="padding:16px 18px;border-top:1px solid var(--line)">
              <div class="grid two-col" style="gap:14px">
                <div>
                  <div class="section-label">📄 Сертификат</div>
                  ${renderKV({file:r.file, size:fmtSize(r.size), sans:sansStr, not_before:r.not_before, not_after:r.not_after, days_left:r.days_left})}
                </div>
                <div>
                  <div class="section-label">✅ Активный</div>
                  ${sum ? renderKV(sum) : '<div class="empty">Нет данных</div>'}
                  ${acme ? `<div class="section-label" style="margin-top:14px">🔑 ACME аккаунт</div>${renderKV(acme)}` : ''}
                </div>
              </div>
              <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
                <button class="button small" data-certdl="${esc(r.file)}">⬇ Скачать</button>
                <button class="button small" data-certrn="${esc(r.file.replace(/\.cer$/,''))}">🔄 Renew</button>
                <button class="button small danger" data-certdel="${esc(r.file.replace(/\.cer$/,''))}">× Удалить</button>
              </div>
            </div>
          </td>
        </tr>`;
      }
      return main + detail;
    }).join('');
    listHtml = `<div class="table-wrap"><table>
      <thead><tr><th></th><th>Файл</th><th>SANs</th><th>Not after</th><th>Days</th><th>Размер</th></tr></thead>
      <tbody>${rowsHtml}</tbody></table></div>`;
  }

  c.innerHTML = `<div class="card table-card">
    <div class="card-head" style="padding:12px 16px">
      <div>
        <div class="card-title">🔐 Сертификаты</div>
        <div class="card-sub">Клик по строке — детали</div>
      </div>
      <div class="card-actions"><button class="button small" id="certReload">🔄 Reload</button></div>
    </div>
    <div id="certList">${listHtml}</div>
  </div>
  <div class="grid three-col" style="margin-top:14px">
    <div class="card">
      <div class="card-head"><div><div class="card-title">Issue Domain</div><div class="card-sub">HTTP-01</div></div></div>
      <div class="field"><label>Domain</label><input id="certDomain" placeholder="example.com"></div>
      <button class="button primary" id="certIssueD" style="width:100%">Выпустить</button>
    </div>
    <div class="card">
      <div class="card-head"><div><div class="card-title">DNS-01</div><div class="card-sub">TXT challenge</div></div></div>
      <div class="field"><label>Domain</label><input id="certDns01" placeholder="example.com"></div>
      <button class="button" id="certDns01Btn" style="width:100%">Опубликовать TXT</button>
    </div>
    <div class="card">
      <div class="card-head"><div><div class="card-title">Issue IP</div><div class="card-sub">IP из config.toml</div></div></div>
      <div class="field"><label>IP</label><input value="${sum && sum.ip ? esc(sum.ip) : '—'}" readonly style="opacity:.7"></div>
      <button class="button primary" id="certIssueI" style="width:100%">Выпустить IP</button>
    </div>
  </div>`;

  $$('[data-certrow]').forEach(el=>el.onclick=()=>{
    const f = el.dataset.certrow; S.certsExpanded[f] = !S.certsExpanded[f]; mount(c);
  });
  $$('[data-certdl]').forEach(el=>el.onclick=(e)=>{ e.stopPropagation(); dl('certs/download?name='+encodeURIComponent(el.dataset.certdl)); });
  $$('[data-certrn]').forEach(el=>el.onclick=async(e)=>{
    e.stopPropagation();
    try{
      await post('certs/renew?name='+encodeURIComponent(el.dataset.certrn));
      toast.ok('Обновление запущено');
      ['certs','certs/list','certs/acme_account'].forEach(k=>{ try{ get.__invalidate?.(k);}catch(_){} });
      mount(c);
    }catch(err){ toast.err(err.message); }
  });
  $$('[data-certdel]').forEach(el=>el.onclick=async(e)=>{
    e.stopPropagation();
    if(!await confirmDlg('Удалить сертификат?', el.dataset.certdel)) return;
    try{
      await post('certs/delete?name='+encodeURIComponent(el.dataset.certdel));
      toast.ok('Удалено');
      delete S.certsExpanded[el.dataset.certdel+'.cer'];
      mount(c);
    }catch(err){ toast.err(err.message); }
  });
  $('#certReload').onclick = async ()=>{
    try{ await post('certs/reload'); toast.ok('OK'); mount(c); }
    catch(e){ toast.err(e.message); }
  };
  $('#certIssueD').onclick = async ()=>{
    const domain = $('#certDomain').value.trim();
    if(!domain) return toast.err('Введите домен');
    try{
      const d = await post('certs/issue_domain', {domain});
      toast.ok(d.message||'Started');
      setTimeout(()=>mount(c), 1500);
    }catch(e){ toast.err(e.message); }
  };
  $('#certIssueI').onclick = async ()=>{
    try{
      const d = await post('certs/issue_ip');
      toast.ok(d.message||'Started');
      setTimeout(()=>mount(c), 1500);
    }catch(e){ toast.err(e.message); }
  };
  $('#certDns01Btn').onclick = async ()=>{
    try{
      const d = await post('certs/issue_dns01', {domain: $('#certDns01').value});
      toast.ok('TXT: '+d.value);
    }catch(e){ toast.err(e.message); }
  };
}

Object.assign(window, { renderCerts: mount });