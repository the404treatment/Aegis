/* ================= EVENT SEARCH (SIEM) ================= */
/* Field-aware search across the telemetry the server holds. The query language
   lives server-side in server/lake.mjs (GET /api/lake); this is the console
   for it. Server-backed only — like Tickets, it degrades to a connect CTA
   when offline rather than pretending to have data. */

let siemQ='', siemRows=[], siemTotal=0, siemTop=null, siemChannels={}, siemBusy=false, siemErr='', siemRan=false;
let siemLive=false, _siemLiveTimer=null;
/* The collector reports its own scheduled runs, flagged self:true, so they can
   be recognised rather than chased. Hidden by default because that is what an
   analyst wants almost always; the toggle brings them back when you are
   specifically checking the agent is alive. */
let siemHideSelf=true;

function siemLiveToggle(on){siemLive=on;renderSiem();}
function siemHideSelfToggle(on){siemHideSelf=on;siemRun();}
/* Fold the hide-self preference into the query sent to the server, unless the
   analyst has typed an explicit self: term, in which case they mean it. */
function siemEffectiveQuery(){
 const q=siemQ.trim();
 if(!siemHideSelf||/\bself:/i.test(q))return q;
 return (q+' -self:true').trim();
}
/* Called from the SSE events handler: when live-tail is on and a search is on
   screen, re-run it. Debounced — an agent batch can be hundreds of events, and
   one refresh at the end beats two hundred re-renders. */
function siemLivePing(){
 if(!siemLive||!siemRan||view!=='siem')return;
 clearTimeout(_siemLiveTimer);
 _siemLiveTimer=setTimeout(()=>{if(siemLive&&view==='siem'&&!siemBusy)siemRun(true);},800);
}

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
/* Same day → just the time; the full stamp lives in the row's title and the
   detail sheet. A column of "18/08/2026, 23:32:25" repeated 200 times is noise
   that pushes the message — the thing you actually scan — off the right edge. */
function siemTime(ts){
 const d=new Date(ts);
 const sameDay=new Date().toDateString()===d.toDateString();
 return sameDay?d.toLocaleTimeString():d.toLocaleDateString(undefined,{day:'2-digit',month:'short'})+' '+d.toLocaleTimeString();
}
function siemEmptyHTML(){
 // "No matches" means two very different things: a filter that excluded
 // everything, or a server that has never received an event. Say which.
 if(!siemQ.trim()&&!siemTotal)return `<div class="ls-det-sub" style="padding:16px 2px">
   No telemetry on this server yet. Deploy an agent (<code>INSTALL.md</code> — two commands),
   or seed a demo incident with <code>npm run demo</code> to explore with data.</div>`;
 return '<div class="ls-det-sub" style="padding:16px 2px">No events match that query.</div>';
}
function siemResultsHTML(){
 const top=siemTop||{hosts:[],techniques:[]};
 const chans=Object.entries(siemChannels||{}).sort((a,b)=>b[1]-a[1]);
 return `
  <div class="sq-sum">
    <span><b>${siemTotal}</b> match${siemTotal===1?'':'es'}${siemRows.length<siemTotal?` · showing ${siemRows.length}`:''}</span>
    <label class="sq-live${siemLive?' on':''}" data-tip="Re-run this search automatically as new events arrive">
      <input type="checkbox" ${siemLive?'checked':''} onchange="siemLiveToggle(this.checked)">Live</label>
    <label class="sq-live${siemHideSelf?' on':''}" data-tip="The collector reports its own scheduled runs. Hidden by default; untick to confirm the agent is alive.">
      <input type="checkbox" ${siemHideSelf?'checked':''} onchange="siemHideSelfToggle(this.checked)">Hide agent activity</label>
    ${top.hosts.length?`<span class="sq-facet">Top hosts: ${top.hosts.slice(0,4).map(h=>`<button onclick="siemAdd('host:${jsq(h.k)}')">${esc(h.k)} <i>${h.v}</i></button>`).join('')}</span>`:''}
    ${top.techniques.length?`<span class="sq-facet">Techniques: ${top.techniques.slice(0,5).map(t=>`<button onclick="siemAdd('technique:${jsq(t.k)}')">${esc(t.k)} <i>${t.v}</i></button>`).join('')}</span>`:''}
    ${chans.length?`<span class="sq-facet">Channels: ${chans.slice(0,4).map(([k,v])=>`<button onclick="siemAdd('channel:${esc(k.includes(' ')?'&quot;'+k+'&quot;':k)}')">${esc(k.split('/').pop()||k)} <i>${v}</i></button>`).join('')}</span>`:''}
  </div>
  ${siemRows.length?`<div class="sq-rows">${siemRows.map((e,i)=>`
    <div class="sq-row inc-${esc(e.severity||'info')}${e.self?' sq-self':''}" onclick="siemOpen(${i})">
      <span class="sq-t" title="${new Date(e.ts).toLocaleString()}">${siemTime(e.ts)}</span>
      <span class="sq-host">${esc(e.host||'—')}</span>
      <span class="sq-eid" title="${esc(e.eventId||'')}">${esc(e.eventId||'—')}</span>
      <span class="sq-tech">${e.self?'<span class="sq-selftag" title="AEGIS collector self-activity">AEGIS</span>':(e.technique?esc(e.technique):'')}</span>
      <span class="sq-msg">${highlightIocs(e.message||'')}</span>
    </div>`).join('')}</div>`
   :siemEmptyHTML()}`;
}
async function siemRun(quiet){
 const inp=document.getElementById('sq-q');
 if(inp)siemQ=inp.value;
 siemBusy=true;siemErr='';
 if(quiet!==true)renderSiem();   // live refresh: no spinner flash, keep the page still
 try{
  const r=await liveApi('/api/lake?limit=200&q='+encodeURIComponent(siemEffectiveQuery()));
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
  ${e.self?`<div class="sq-selfnote">This is the AEGIS collector's own scheduled run, not activity on the host. Safe to ignore.</div>`:''}
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
