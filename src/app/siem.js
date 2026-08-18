/* ================= EVENT SEARCH (SIEM) ================= */
/* Field-aware search across the telemetry the server holds. The query language
   lives server-side in server/lake.mjs (GET /api/lake); this is the console
   for it. Server-backed only — like Tickets, it degrades to a connect CTA
   when offline rather than pretending to have data. */

let siemQ='', siemRows=[], siemTotal=0, siemTop=null, siemChannels={}, siemBusy=false, siemErr='', siemRan=false;

const SIEM_EXAMPLES=[
 ['severity:malicious','only the events the agent flagged as malicious'],
 ['technique:T1059','everything mapped to a technique'],
 ['host:DC01 severity:suspicious','narrow to one host'],
 ['channel:Security -eventid:4624','a channel, minus the noisy ID'],
 ['lsass or mimikatz','free text, either term'],
];

function renderSiem(){
 const el=document.getElementById('sq-main');if(!el)return;
 if(!LIVE.connected){
  el.innerHTML=`<div class="ls-empty">
    <div class="ls-empty-ic">⌕</div>
    <h3>Event Search needs a server</h3>
    <p>Agents report telemetry to an AEGIS server; this searches across it. Everything else in AEGIS keeps working offline — this view is the one that needs the live feed.</p>
    <div class="ls-empty-acts"><button class="btn violet" onclick="openLiveSetup()">Connect to a server</button></div>
  </div>`;
  return;
 }
 el.innerHTML=`
  <div class="sq-bar">
    <input class="sq-input" id="sq-q" value="${esc(siemQ)}" placeholder="severity:malicious · host:DC01 · technique:T1059 · -eventid:4624 · free text"
      onkeydown="if(event.key==='Enter')siemRun()">
    <button class="btn violet" onclick="siemRun()" ${siemBusy?'disabled':''}>${siemBusy?'Searching…':'Search'}</button>
  </div>
  ${siemErr?`<div class="lint err">${esc(siemErr)}</div>`:''}
  ${!siemRan?`<div class="sq-hint">
    <div class="sq-hint-h">Query syntax</div>
    <div class="sq-hint-b">Terms are ANDed. <code>field:value</code> matches a field, <code>field:"two words"</code> quotes a phrase, <code>-</code> negates, and a bare <code>or</code> starts an alternative. Anything without a field matches the whole event.</div>
    ${SIEM_EXAMPLES.map(([q,why])=>`<button class="sq-ex" onclick="siemQ=${JSON.stringify(q).replace(/"/g,'&quot;')};siemRun()"><code>${esc(q)}</code><small>${esc(why)}</small></button>`).join('')}
  </div>`:''}
  ${siemRan?siemResultsHTML():''}`;
}
function siemResultsHTML(){
 const top=siemTop||{hosts:[],techniques:[]};
 return `
  <div class="sq-sum">
    <span><b>${siemTotal}</b> match${siemTotal===1?'':'es'}${siemRows.length<siemTotal?` · showing ${siemRows.length}`:''}</span>
    ${top.hosts.length?`<span class="sq-facet">Top hosts: ${top.hosts.slice(0,4).map(h=>`<button onclick="siemAdd('host:${esc(h.k)}')">${esc(h.k)} <i>${h.v}</i></button>`).join('')}</span>`:''}
    ${top.techniques.length?`<span class="sq-facet">Techniques: ${top.techniques.slice(0,5).map(t=>`<button onclick="siemAdd('technique:${esc(t.k)}')">${esc(t.k)} <i>${t.v}</i></button>`).join('')}</span>`:''}
  </div>
  ${siemRows.length?`<div class="sq-rows">${siemRows.map((e,i)=>`
    <div class="sq-row inc-${esc(e.severity||'info')}" onclick="siemOpen(${i})">
      <span class="sq-t">${new Date(e.ts).toLocaleString()}</span>
      <span class="sq-host">${esc(e.host||'—')}</span>
      <span class="sq-eid">${esc(e.eventId||'')}</span>
      ${e.technique?`<span class="sq-tech">${esc(e.technique)}</span>`:''}
      <span class="sq-msg">${highlightIocs(e.message||'')}</span>
    </div>`).join('')}</div>`
   :'<div class="ls-det-sub" style="padding:16px 2px">No events match that query.</div>'}`;
}
async function siemRun(){
 const inp=document.getElementById('sq-q');
 if(inp)siemQ=inp.value;
 siemBusy=true;siemErr='';renderSiem();
 try{
  const r=await liveApi('/api/lake?limit=200&q='+encodeURIComponent(siemQ));
  siemRows=r.events||[];siemTotal=r.total||0;siemTop=r.top||null;siemChannels=r.channels||{};
 }catch(e){siemErr='Search failed: '+e.message;siemRows=[];siemTotal=0;}
 siemBusy=false;siemRan=true;renderSiem();
}
function siemAdd(term){
 siemQ=(siemQ+' '+term).trim();
 siemRun();
}
function siemOpen(i){
 const e=siemRows[i];if(!e)return;
 let v=document.getElementById('sq-veil');
 if(!v){v=document.createElement('div');v.id='sq-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const f=e.fields||{};
 v.innerHTML=`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="siemClose()"></div>
  <div class="ls-det-head">${esc(e.eventId||'event')} · ${esc(e.host||'unknown host')}</div>
  <div class="ls-det-sub">${new Date(e.ts).toLocaleString()} · ${esc(e.channel||'')} · <span class="ls-ne-obs-sev inc-${esc(e.severity||'info')}">${esc(e.severity||'info')}</span>${e.technique?` · <span class="ls-ne-obs-tech">${esc(e.technique)}</span>`:''}</div>
  <div class="sq-raw">${highlightIocs(e.message||'')}</div>
  ${Object.keys(f).length?`<div class="ls-mm-sec">Fields</div>${Object.keys(f).map(k=>`<div class="ls-det-row"><span class="ls-det-tid">${esc(k)}</span><span style="flex:1;min-width:0;word-break:break-word">${highlightIocs(String(f[k]))}</span></div>`).join('')}`:''}
  ${siemAdvisable(e.technique)?`<button class="btn ghost-violet" style="width:100%;justify-content:center;margin-top:10px" onclick="siemClose();openAdvisor('${esc(e.technique)}')">▤ Response playbook for ${esc(e.technique)}</button>`:''}
  ${LIVE.connected?`<button class="btn violet" style="width:100%;justify-content:center;margin-top:8px" onclick="siemTicket(${i})">⚑ Raise a ticket from this event</button>`:''}
 </div>`;
 v.classList.add('open');v.onclick=(ev)=>{if(ev.target===v)siemClose();};
}
function siemClose(){const v=document.getElementById('sq-veil');if(v)v.classList.remove('open');}
/* An agent can tag a sub-technique (T1003.001) that AEGIS tracks only at the
   parent level (T1003) — and that is exactly where the advisor has its most
   specific playbook. Gate on either, or the button hides when it matters most. */
function siemAdvisable(tech){
 if(!tech)return false;
 return !!(MITRE[tech]||MITRE[tech.split('.')[0]]||RA_TECH[tech]||RA_TECH[tech.split('.')[0]]);
}
async function siemTicket(i){
 const e=siemRows[i];if(!e)return;
 try{
  await liveApi('/api/tickets',{method:'POST',body:JSON.stringify({
   title:`${e.eventId||'Event'} on ${e.host||'unknown host'}`,
   body:e.message||'',
   severity:e.severity==='malicious'?'high':e.severity==='suspicious'?'medium':'low',
   host:e.host||'',technique:e.technique||'',
  })});
  siemClose();toast('Ticket raised');
 }catch(err){toast('Could not raise a ticket: '+err.message);}
}
