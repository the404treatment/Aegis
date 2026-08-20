/* ================= MATRIX ================= */
/* The matrix is a wide row of tactic columns. On a smaller screen (VMs
   especially) the right-hand tactics sit off-screen and a horizontal scrollbar
   is easy to miss or hard to reach. This lets the normal mouse wheel pan the
   matrix sideways whenever there is horizontal overflow and nothing to scroll
   vertically - so the wheel reaches those right-hand columns without shift or
   hunting for the scrollbar. When a column IS tall enough to scroll vertically,
   the wheel behaves normally. Shift+wheel always pans horizontally too. */
function mxWheel(e){
 const sc=e.currentTarget; if(!sc) return;
 const hasHoriz=sc.scrollWidth>sc.clientWidth+2;
 if(!hasHoriz) return;
 const noVert=sc.scrollHeight<=sc.clientHeight+2;
 if(e.shiftKey || noVert){
  if(e.deltaY!==0){sc.scrollLeft+=e.deltaY;e.preventDefault();}
 }
}
/* Live hits per technique, built from real telemetry. The matrix's static
   colour already says "can I detect this" (how many catalog events map here);
   this is the orthogonal signal "is this happening right now". Two deliberate
   choices keep it readable when a noisy host floods events:
     - we key on the DISTINCT HOST, not the event count, so ten 4104s from one
       box read as "1 host", not "10 hits". That is the delineation the busy
       case needs.
     - a cell takes the worst severity seen, and the overlay is a separate
       visual channel (a glow + a small pill) layered over the coverage colour,
       so the two never fight for the same border.
   A live event maps to a technique two ways: its own `technique` tag if the
   agent set one, and every technique the catalog links to its event ID. Agent
   self-telemetry (scheduled collector runs) is excluded - that is not an
   attacker doing something. */
let _evIdToTechs=null;
function evIdToTechs(){
 if(_evIdToTechs)return _evIdToTechs;
 _evIdToTechs=new Map();
 ALL().forEach(e=>_evIdToTechs.set(String(e.id),e.mitre||[]));
 return _evIdToTechs;
}
const SEV_RANK={info:1,suspicious:2,malicious:3};
/* Fold any technique id onto the cell the matrix actually draws. Sub-technique
   tags like T1003.001 have no cell of their own - AEGIS tracks at the parent
   level (T1003) - so a hit on a sub-technique must light its parent, or it
   lights nothing and the overlay looks broken exactly when telemetry is richest. */
function matrixCellFor(tid){
 if(!tid)return null;
 if(MITRE[tid])return tid;
 const parent=String(tid).split('.')[0];
 return MITRE[parent]?parent:null;
}
function liveHitsByTech(){
 const map=new Map();  // tid -> {hosts:Set, sev, n}
 if(!(typeof LIVE!=='undefined'&&LIVE&&LIVE.connected))return map;
 const idx=evIdToTechs();
 (LIVE.events||[]).forEach(e=>{
  if(e.self)return;
  const techs=new Set();
  const own=matrixCellFor(e.technique);if(own)techs.add(own);
  (idx.get(String(e.eventId))||[]).forEach(t=>{const c=matrixCellFor(t);if(c)techs.add(c);});
  if(!techs.size)return;
  const host=e.host||'unknown';
  const sev=e.severity||'info';
  techs.forEach(tid=>{
   const rec=map.get(tid)||{hosts:new Set(),sev:'info',n:0};
   rec.hosts.add(host);rec.n++;
   if((SEV_RANK[sev]||0)>(SEV_RANK[rec.sev]||0))rec.sev=sev;
   map.set(tid,rec);
  });
 });
 return map;
}
function renderMatrix(){
 const q=(document.getElementById('gq').value||'').toLowerCase();
 const host=document.getElementById('matrix');
 const hits=liveHitsByTech();
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
   const h=hits.get(id);
   const hitCls=h?` hit hit-${h.sev}`:'';
   const nh=h?h.hosts.size:0;
   const hitPill=h?`<span class="tcell-hit ${h.sev}" onclick="event.stopPropagation();openDrawer('${id}')"
       data-tip="Live: ${h.n} event${h.n===1?'':'s'} on ${nh} host${nh===1?'':'s'} (${[...h.hosts].slice(0,6).map(esc).join(', ')}${nh>6?'…':''}) · worst severity ${h.sev}. Click for detail.">● ${nh}</span>`:'';
   return`<div class="tcell ${cov}${inS}${rf}${hitCls}" onclick="togStudio('${id}')" onmouseenter="showPeek(event,'${id}')" onmouseleave="hidePeek()" data-tip="Click to ${studio.has(id)?'unstage':'stage'} · ⓘ for full strategy">
     <div class="tcell-id">${id}${t.subs?`<span class="tcell-sub">${t.subs}</span>`:''}</div>
     <div class="tcell-name">${t.name}</div>
     <div class="tcell-meta">
       ${hitPill||`<span class="cov-pip">${t.ref&&!n?'reference':n+' evt'+(n===1?'':'s')}</span>`}
       <span class="tcell-info" onclick="event.stopPropagation();openDrawer('${id}')" data-tip="Full strategy, fields & mitigations">ⓘ</span>
     </div>
   </div>`;
  }).join('');
  if(!cells)return'';
  return`<div class="tac-col"><div class="tac-head"><b>${tac}</b><span class="cvr">${covered}</span>/${techs.length} covered</div>${cells}</div>`;
 }).join('')||'<div class="no-match">No techniques match.</div>';
 // Live banner: when telemetry is lighting cells, say so above the matrix so it
 // reads as a live threat surface, not a static reference. Its own container
 // (not inside the horizontally-scrolling flex row), so it spans the full width
 // and clears itself when nothing is live.
 const bh=document.getElementById('mx-live-host');
 if(bh)bh.innerHTML=matrixLiveBanner(hits);
 updateStats();
}
function matrixLiveBanner(hits){
 if(!hits||!hits.size)return'';
 const allHosts=new Set();let worst='info';
 hits.forEach(h=>{h.hosts.forEach(x=>allHosts.add(x));if((SEV_RANK[h.sev]||0)>(SEV_RANK[worst]||0))worst=h.sev;});
 const nt=hits.size,nh=allHosts.size;
 return`<div class="mx-live ${worst}">
   <span class="mx-live-dot"></span>
   <b>${nt} technique${nt===1?'':'s'} active</b> across ${nh} host${nh===1?'':'s'} right now
   <span class="mx-live-sub">worst severity ${worst} · cells with a ● are lit by live telemetry, not just detection coverage</span>
 </div>`;
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
    <button class="btn ${studio.has(id)?'mint':'violet'}" id="dw-stage-btn" onclick="togStudio('${id}');refreshDrawerStage('${id}')" data-tip="${studio.has(id)?'Click to remove from the Studio':'Adds this technique + all its detections to the dashboard & report'}">${studio.has(id)?'✓ Staged - click to remove':'+ Stage in Detection Studio'}</button>
    <button class="btn ghost-violet" onclick="askAboutTech('${id}')" data-tip="Opens the AI Analyst pre-loaded with a deep-dive prompt for this technique">Ask AI Analyst</button>
    <button class="btn ghost-violet" onclick="openAdvisor('${id}')" data-tip="Offline, deterministic containment/eradication/recovery commands for this technique - no network, no LLM">Response playbook</button>
    ${t.unverified?'':`<a class="btn" href="https://attack.mitre.org/techniques/${id.replace('.','/')}/" target="_blank" rel="noopener" data-tip="Open the official MITRE page in a new tab">MITRE ↗</a>`}
  </div>`;
 document.getElementById('dw-body').innerHTML=`
  ${t.ref?`<div class="dw-refnote"><b>Reference technique.</b> AEGIS has no hand-written detection strategy for this one yet - it is here so the matrix reflects the full ATT&CK surface and your coverage percentages are honest. Staging it marks it as a known gap.${t.unverified?'<br><span class="dw-unver">The identifier for this recently-added technique could not be verified against the published matrix, so no MITRE deep-link is shown.</span>':''}</div>`:''}
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
 b.innerHTML=on?'✓ Staged - click to remove':'+ Stage in Detection Studio';
 b.setAttribute('data-tip',on?'Click to remove from the Studio':'Adds this technique + all its detections to the dashboard & report');
}

/* ================= EVENT CARDS =================
   These render inside the matrix drawer (the standalone Event Intel view was
   merged into it - its render/filter shell is gone; jump() below is the
   surviving entry point). */
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
function togCard(key){xp.has(key)?xp.delete(key):xp.add(key);refreshCards();}
function setTab(key,t){tabState[key]=t;refreshCards();}
/* re-render event cards where they live: the matrix drawer */
function refreshCards(){
 if(document.getElementById('drawer')&&document.getElementById('drawer').classList.contains('open')&&_dwTech)openDrawer(_dwTech,true);
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
function jumpById(id){const e=ALL().find(x=>x.id===id);if(e)jump(e.plat,e.id);else toast(id+' - reference event');}
