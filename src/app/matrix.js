/* ================= MATRIX ================= */
function renderMatrix(){
 const q=(document.getElementById('gq').value||'').toLowerCase();
 const host=document.getElementById('matrix');
 host.innerHTML=TACTICS.map(([tac,slug,techs])=>{
  let covered=0;
  const cells=techs.filter(id=>{
   if(!q)return true;const t=T(id);
   return id.toLowerCase().includes(q)||t.name.toLowerCase().includes(q);
  }).map(id=>{
   const t=T(id);
   let evs=eventsForTech(id);if(plat!=='all')evs=evs.filter(e=>e.plat===plat);
   const n=evs.length;if(n)covered++;
   const cov=n>=3?'cov-hi':n===2?'cov-md':n===1?'cov-lo':'cov-no';
   const inS=studio.has(id)?' in-studio':'';
   const rf=t.ref?' is-ref':'';
   return`<div class="tcell ${cov}${inS}${rf}" onclick="togStudio('${id}')" onmouseenter="showPeek(event,'${id}')" onmouseleave="hidePeek()" data-tip="Click to ${studio.has(id)?'unstage':'stage'} · ⓘ for full strategy">
     <div class="tcell-id">${id}${t.subs?`<span class="tcell-sub">${t.subs}</span>`:''}</div>
     <div class="tcell-name">${t.name}</div>
     <div class="tcell-meta">
       <span class="cov-pip">${t.ref&&!n?'reference':n+' evt'+(n===1?'':'s')}</span>
       <span class="tcell-info" onclick="event.stopPropagation();openDrawer('${id}')" data-tip="Full strategy, fields & mitigations">ⓘ</span>
     </div>
   </div>`;
  }).join('');
  if(!cells)return'';
  return`<div class="tac-col"><div class="tac-head"><b>${tac}</b><span class="cvr">${covered}</span>/${techs.length} covered</div>${cells}</div>`;
 }).join('')||'<div class="no-match">No techniques match.</div>';
 updateStats();
}

/* ================= PEEK ================= */
let peekTimer=null;
function showPeek(ev,id){
 if(document.body.classList.contains('no-tips'))return;
 clearTimeout(peekTimer);
 const cell=ev.currentTarget.getBoundingClientRect();
 peekTimer=setTimeout(()=>{
  const t=T(id);
  let evs=eventsForTech(id);if(plat!=='all')evs=evs.filter(e=>e.plat===plat);
  const p=document.getElementById('peek');
  p.innerHTML=`
   <div class="peek-id">${id} · ${t.tactic}</div>
   <div class="peek-name">${t.name}</div>
   <div class="peek-sum">${(t.summary||'').length>150?t.summary.slice(0,150)+'…':(t.summary||'')}</div>
   ${evs.length?`<div class="peek-evs">${evs.slice(0,6).map(e=>`<span class="peek-ev">${e.id}</span>`).join('')}</div>`:'<div class="peek-evs"><span class="peek-ev" style="color:var(--amber);border-color:var(--amber-line)">coverage gap</span></div>'}
   <div class="peek-cta"><span><b>click</b> to ${studio.has(id)?'unstage':'stage'}</span><span><b>ⓘ</b> full strategy</span></div>`;
  const pw=290,ph=p.offsetHeight||170;
  let x=cell.right+12,y=cell.top;
  if(x+pw>window.innerWidth-10)x=cell.left-pw-12;
  if(x<10)x=Math.min(cell.left,window.innerWidth-pw-10);
  y=Math.min(y,window.innerHeight-ph-14);
  p.style.left=x+'px';p.style.top=Math.max(10,y)+'px';
  p.classList.add('show');
 },240);
}
function hidePeek(){clearTimeout(peekTimer);document.getElementById('peek').classList.remove('show');}

/* ================= DRAWER ================= */
let _dwTech=null;
function openDrawer(id,keepScroll){
 hidePeek();
 _dwTech=id;
 const _body=document.getElementById('dw-body');
 const _sc=keepScroll&&_body?_body.scrollTop:0;
 const t=T(id);const evs=eventsForTech(id);
 document.getElementById('dw-head').innerHTML=`
  <div class="dw-top">
    <span class="dw-id">${id}</span>
    <span class="dw-tactic">${t.tactic}</span>
    <button class="dw-close" onclick="closeDrawer()" data-tip="Close (esc)">×</button>
  </div>
  <div class="dw-name">${t.name}</div>
  <div class="dw-summary">${t.summary}</div>
  ${t.note?`<div class="dw-note">⚠ ${t.note}</div>`:''}
  <div class="dw-actions">
    <button class="btn ${studio.has(id)?'mint':'violet'}" id="dw-stage-btn" onclick="togStudio('${id}');refreshDrawerStage('${id}')" data-tip="${studio.has(id)?'Click to remove from the Studio':'Adds this technique + all its detections to the dashboard & report'}">${studio.has(id)?'✓ Staged — click to remove':'+ Stage in Detection Studio'}</button>
    <button class="btn ghost-violet" onclick="askAboutTech('${id}')" data-tip="Opens the AI Analyst pre-loaded with a deep-dive prompt for this technique">Ask AI Analyst</button>
    ${t.unverified?'':`<a class="btn" href="https://attack.mitre.org/techniques/${id.replace('.','/')}/" target="_blank" rel="noopener" data-tip="Open the official MITRE page in a new tab">MITRE ↗</a>`}
  </div>`;
 document.getElementById('dw-body').innerHTML=`
  ${t.ref?`<div class="dw-refnote"><b>Reference technique.</b> AEGIS has no hand-written detection strategy for this one yet — it is here so the matrix reflects the full ATT&CK surface and your coverage percentages are honest. Staging it marks it as a known gap.${t.unverified?'<br><span class="dw-unver">The identifier for this recently-added technique could not be verified against the published matrix, so no MITRE deep-link is shown.</span>':''}</div>`:''}
  ${t.detect&&t.detect.length?`<div class="dw-sec"><div class="sec-t">Detection signals</div>${t.detect.map(d=>`<div class="sig">${d}</div>`).join('')}</div>`:''}
  ${t.pivots&&t.pivots.length?`<div class="dw-sec"><div class="sec-t">Pivot keys</div><div class="pivots">${t.pivots.map(p=>`<span class="pivot">${p}</span>`).join('')}</div></div>`:''}
  ${t.subs?`<div class="dw-sec"><div class="sec-t">Sub-techniques · ${t.subs}</div><div class="dw-subs">This technique has <b>${t.subs}</b> sub-technique${t.subs===1?'':'s'} in ATT&CK.${SUBS[id]?'':' AEGIS tracks it at the parent level; open MITRE for the full breakdown.'}</div>${(SUBS[id]||[]).map(s=>`<div class="dw-sub"><span class="dw-sub-id">${s[0]}</span><span class="dw-sub-name">${s[1]}</span></div>`).join('')}</div>`:''}
  ${(t.mits&&t.mits.length)?`<div class="dw-sec"><div class="sec-t">Mitigations · auto-mapped</div>${t.mits.map(m=>MITS[m]?`
    <div class="mit"><span class="mit-code">${m}</span><div class="mit-body"><div class="mit-name">${MITS[m].name}</div><div class="mit-act">${MITS[m].act}</div></div></div>`:'').join('')}</div>`:''}
  ${evs.length?`<div class="dw-sec"><div class="sec-t">Mapped telemetry · ${evs.length}</div><div class="dw-events">${evs.map(e=>eventCardHTML(e,'drawer')).join('')}</div></div>`:''}
  ${t.start&&(t.start.win||t.start.aws)?`<div class="dw-sec"><div class="sec-t">Best starting point</div><div class="start-box">
    ${t.start.win?`<div class="start-row"><span class="start-plat">WIN</span><span class="start-txt">${t.start.win}</span></div>`:''}
    ${t.start.aws?`<div class="start-row"><span class="start-plat">AWS</span><span class="start-txt">${t.start.aws}</span></div>`:''}
  </div></div>`:''}`;
 document.getElementById('drawer').classList.add('open');
 document.getElementById('dw-veil').classList.add('open');
 if(keepScroll&&_body)_body.scrollTop=_sc;
}
function closeDrawer(){document.getElementById('drawer').classList.remove('open');document.getElementById('dw-veil').classList.remove('open');}
function refreshDrawerStage(id){
 const b=document.getElementById('dw-stage-btn');if(!b)return;
 const on=studio.has(id);
 b.className='btn '+(on?'mint':'violet');
 b.innerHTML=on?'✓ Staged — click to remove':'+ Stage in Detection Studio';
 b.setAttribute('data-tip',on?'Click to remove from the Studio':'Adds this technique + all its detections to the dashboard & report');
}

/* ================= EVENTS ================= */
const CATS={all:'All',auth:'Authentication',process:'Process',registry:'Registry',object:'Object Access',privilege:'Privilege',persistence:'Persistence',defense:'Defense Evasion',network:'Network',account:'Accounts',iam:'IAM',credential:'Credentials',discovery:'Discovery',collection:'Collection'};
function currentEvents(){let evs=ALL();if(plat!=='all')evs=evs.filter(e=>e.plat===plat);return evs;}
function renderCats(){
 if(!document.getElementById('cat-list'))return;
 const evs=currentEvents();const counts={all:evs.length};
 evs.forEach(e=>counts[e.cat]=(counts[e.cat]||0)+1);
 document.getElementById('cat-list').innerHTML=Object.entries(CATS).filter(([k])=>counts[k]).map(([k,v])=>`
  <div class="fchip${cat===k?' on':''}" onclick="cat='${k}';renderCats();renderEvents()">${v}<span class="n">${counts[k]||0}</span></div>`).join('');
}
function togRisk(r){
 risks.has(r)?risks.delete(r):risks.add(r);
 document.getElementById('rf-hi').classList.toggle('on',risks.has('high'));
 document.getElementById('rf-md').classList.toggle('on',risks.has('med'));
 document.getElementById('rf-lo').classList.toggle('on',risks.has('low'));
 renderEvents();
}
function clearEvFilters(){
 if(!document.getElementById('cat-list'))return;
 risks.clear();cat='all';
 const gq=document.getElementById('gq');if(gq)gq.value='';
 ['rf-hi','rf-md','rf-lo'].forEach(id=>document.getElementById(id)?.classList.remove('on'));
 renderCats();renderEvents();toast('Filters cleared');
}
function filteredEvents(){
 const q=(document.getElementById('gq').value||'').toLowerCase().trim();
 return currentEvents().filter(e=>{
  if(cat!=='all'&&e.cat!==cat)return false;
  if(risks.size&&!risks.has(e.risk))return false;
  if(!q)return true;
  return e.id.toLowerCase().includes(q)||e.title.toLowerCase().includes(q)||e.desc.toLowerCase().includes(q)
   ||e.mitre.some(m=>m.toLowerCase().includes(q)||T(m).name.toLowerCase().includes(q))
   ||e.fields.some(f=>f[0].toLowerCase().includes(q))||e.iocs.some(i=>i[1].toLowerCase().includes(q));
 });
}
function eventCardHTML(e,ctx){
 const key=e.plat+'::'+e.id;const open=xp.has(key);
 const riskCls=e.risk==='high'?'hi':e.risk==='med'?'md':'lo';
 const hasNote=(notes[key]||'').trim();const tb=tabState[key]||'fields';
 return`<div class="ecard${open?' xp':''}" id="ec-${e.plat}-${e.id}">
   <div class="ec-head" onclick="togCard('${key}')">
     <span class="eid ${e.plat==='windows'?'w':'a'}">${e.id}</span>
     <div class="ec-info">
       <div class="ec-title">${e.title}${hasNote?' <span style="color:var(--amber);font-size:9px" title="Has analyst note">●</span>':''}</div>
       <div class="ec-desc">${e.desc}</div>
     </div>
     <div class="ec-right">
       <span class="risk ${riskCls}">${e.risk.toUpperCase()}</span>
       ${ctx==='drawer'?'':e.mitre.slice(0,2).map(m=>`<span class="mtag" data-tip="Open the ${m} detection strategy" onclick="event.stopPropagation();openDrawer('${m}')">${m}</span>`).join('')}
     </div>
     <svg class="chev${open?' open':''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
   </div>
   <div class="ec-body${open?' open':''}">
     <div class="tabs">
       ${['fields','iocs','query','correlate','notes'].map(x=>`<button class="tab${tb===x?' on':''}" onclick="setTab('${key}','${x}')">${x.toUpperCase()}</button>`).join('')}
     </div>
     <div class="pane${tb==='fields'?' on':''}">${e.fields.map(f=>`<div class="frow"><span class="fname">${f[0]}</span><span class="fnote">${f[1]}</span></div>`).join('')}</div>
     <div class="pane${tb==='iocs'?' on':''}">
       ${e.iocs.map(i=>`<div class="ioc ${i[0]}"><i></i><span>${i[1]}</span></div>`).join('')}
       <div class="sec-t" style="margin-top:12px;">Likely benign</div>
       ${e.benign.map(b=>`<div class="ben">${b}</div>`).join('')}
     </div>
     <div class="pane${tb==='query'?' on':''}">
       ${e.setup?`<div class="setup-note">\u2699 <b style="color:var(--amber)">Telemetry setup:</b>&nbsp;${esc(e.setup)}</div>`:''}
       <div class="qwrap"><div class="qblock">${hl(e.query)}</div>
       <button class="cpy" data-tip="Copy the raw SPL to clipboard" onclick="copyText(this,${JSON.stringify(e.query).replace(/"/g,'&quot;')})">COPY</button></div>
     </div>
     <div class="pane${tb==='correlate'?' on':''}">${e.corr.map(c=>`<div class="crow"><span class="ceid" data-tip="Jump to this event" onclick="jumpById('${c[0]}')">${c[0]}</span><span class="cdesc">${c[1]}</span></div>`).join('')}</div>
     <div class="pane${tb==='notes'?' on':''}">
       <textarea class="narea" id="na-${e.plat}-${e.id}" placeholder="FP patterns, environment context, escalation criteria\u2026">${esc(notes[key]||'')}</textarea>
       <button class="btn violet" style="margin-top:8px;" onclick="saveCardNote('${key}')">Save note</button>
     </div>
   </div>
  </div>`;
}
function renderEvents(){
 const host=document.getElementById('ev-list');if(!host)return;
 const evs=filteredEvents();
 if(!evs.length){host.innerHTML='<div class="no-match">Nothing matches these filters.</div>';return;}
 host.innerHTML=evs.map(e=>eventCardHTML(e)).join('');
}
function togCard(key){xp.has(key)?xp.delete(key):xp.add(key);refreshCards();}
function setTab(key,t){tabState[key]=t;refreshCards();}
/* re-render event cards wherever they currently live (events view or drawer) */
function refreshCards(){
 if(document.getElementById('drawer')&&document.getElementById('drawer').classList.contains('open')&&_dwTech){openDrawer(_dwTech,true);return;}
 renderEvents();
}
function copyText(btn,text){navigator.clipboard.writeText(text).then(()=>{btn.textContent='COPIED';btn.classList.add('ok');setTimeout(()=>{btn.textContent='COPY';btn.classList.remove('ok')},1800);});}
function jump(p,id){
 // Event Intel is merged into the Matrix drawer: open the technique that maps this event
 const e=ALL().find(x=>x.plat===p&&x.id===id);
 if(!e){toast(id+' \u2014 not found');return;}
 const tid=(e.mitre||[]).find(m=>MITRE[m]);
 xp.add(p+'::'+id);
 if(tid){go('matrix');openDrawer(tid);setTimeout(()=>{const el=document.getElementById(`ec-${p}-${id}`);if(el)el.scrollIntoView({behavior:'smooth',block:'center'});},120);}
 else toast(id+' \u2014 no mapped technique');
}
function jumpById(id){const e=ALL().find(x=>x.id===id);if(e)jump(e.plat,e.id);else toast(id+' — reference event');}
