/* ================= LIVE MODE =================
   Connects to an AEGIS server: agents populate the map, events land as
   observations, and tickets sync in real time over SSE. Fully optional -
   with no server configured the app stays exactly as it was, local-only. */
let LIVE={url:'',token:'',connected:false,es:null,agents:[],tickets:[],cases:[],chat:[],events:[],lastError:''};
function liveLoad(){
 try{const c=JSON.parse(read('aegis-live','{}'));LIVE.url=c.url||'';LIVE.token=c.token||'';}catch{}
}
function liveSave(){try{store('aegis-live',JSON.stringify({url:LIVE.url,token:LIVE.token}))}catch{}}
function liveHeaders(){return{'Content-Type':'application/json','Authorization':'Bearer '+LIVE.token};}
async function liveApi(path,opts){
 const r=await fetch(LIVE.url.replace(/\/$/,'')+path,{...(opts||{}),headers:liveHeaders()});
 if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||('HTTP '+r.status));
 return r.json();
}
/* Reconnect on load when we already hold credentials. Without this a refresh
   silently drops the analyst into offline mode with a stored token sitting
   right there - the data looks gone rather than disconnected. Quiet by
   design: failure just leaves the console offline, which is a supported
   state, not an error worth interrupting anyone over. */
async function liveAutoConnect(){
 // Which server should this console talk to? An explicitly saved one, or - for
 // a stock npm start / start.sh / Docker install that serves the console from
 // the same origin as its own API - this origin, if it answers /api/health.
 // Same-origin detection removes a step first-time analysts have no reason to
 // expect: pasting the address of the page they are already looking at into a
 // dialog. Never fires against the static offline build or a file:// open,
 // since neither serves that endpoint.
 const freshlyDetected=!LIVE.url;
 if(!LIVE.url && location.protocol!=='file:'){
  let health=null;
  try{const r=await fetch(location.origin+'/api/health');if(r.ok)health=await r.json();}catch{}
  if(health&&health.ok){LIVE.url=location.origin;liveSave();liveBadge();}
 }
 if(!LIVE.url)return; // nothing to connect to: offline build, file://, or an unreachable origin
 // Hold a token? Try it. A refresh with a live session must land straight back
 // in, not drop silently to offline mode with the token sitting right there.
 if(LIVE.token){try{await liveConnect({quiet:true});}catch{}}
 if(LIVE.connected)return;
 // Not connected. What the server wants decides how hard we prompt. This is the
 // point the old code skipped when a URL was saved but its token was empty or
 // stale: on a login-required server that left the console usable offline with
 // no sign-in, which read as "the login can just be dismissed". A required
 // login is now a hard, non-dismissable gate whenever there is no live session.
 const mode=await authMode(LIVE.url);
 if(mode.requireLogin){_authNeedsSetup=!!mode.needsSetup;_authDefaults=mode.defaults||[];_authMandatory=true;openLogin();return;}
 // Accounts are off: the console is legitimately usable local-only, so never
 // force anything. Only nudge with the token dialog the first time we detect a
 // server on this origin - never nag a saved-but-idle one on every reload.
 if(freshlyDetected)openLiveSetup();
}
async function liveConnect(opts){
 if(!LIVE.url){toast('Set the server URL first');return;}
 // A server with accounts on should ask for one rather than failing with a
 // bare 401 the analyst can't act on.
 if(!LIVE.token){
  const mode=await authMode(LIVE.url);
  if(mode.requireLogin){_authNeedsSetup=!!mode.needsSetup;_authDefaults=mode.defaults||[];_authMandatory=true;openLogin();return;}
  toast('Set the analyst token first');return;
 }
 try{
  const st=await liveApi('/api/state');
  LIVE.agents=st.agents||[];LIVE.tickets=st.tickets||[];LIVE.cases=st.cases||[];LIVE.chat=st.chat||[];LIVE.events=st.events||[];
  LIVE.connected=true;LIVE.lastError='';
  liveSave();liveApplyAgents();liveApplyLinks(st.links);liveOpenStream();
  // The dashboard is rendered at boot, before this resolves, so it starts out
  // showing the offline state. Without this it would sit there claiming to be
  // disconnected while live telemetry streamed in behind it.
  renderLogSrc();renderTickets();renderCases();renderDash();if(view==='matrix')renderMatrix();liveBadge();updateBadges();
  await authFetchMe();authRenderWho();renderChat();renderActivity();activityLoad();coStatus();
  if(!(opts&&opts.quiet))toast(`Connected \u00b7 ${LIVE.agents.length} agent${LIVE.agents.length===1?'':'s'}`);
 }catch(e){
  LIVE.connected=false;LIVE.lastError=e.message;liveBadge();
  // A stale/rejected credential against an accounts server means sign in
  // again, not "your server is broken".
  if(/HTTP 401|unauthorized/i.test(e.message)){
   const mode=await authMode(LIVE.url);
   if(mode.requireLogin){
    LIVE.token='';liveSave();_authNeedsSetup=!!mode.needsSetup;_authDefaults=mode.defaults||[];_authMandatory=true;
    // On a silent reconnect don't ambush someone with a login box they
    // didn't ask for; the connect button is right there when they want it.
    if(!(opts&&opts.quiet))openLogin('That session has expired. Sign in again.');
    return;
   }
  }
  if(!(opts&&opts.quiet))toast('Connection failed: '+e.message);
 }
}
function liveDisconnect(){
 if(LIVE.es){try{LIVE.es.close()}catch{}LIVE.es=null;}
 LIVE.connected=false;chatOpen=false;activityOpen=false;coOpen=false;PRESENCE=[];
 CO={available:false,name:'',model:'',watch:false};
 liveBadge();authRenderWho();renderChat();renderPresence();renderActivity();renderCompanion();renderLogSrc();renderDash();if(view==='matrix')renderMatrix();
 toast('Disconnected \u2014 back to local mode');
}
function liveOpenStream(){
 if(LIVE.es){try{LIVE.es.close()}catch{}}
 const u=LIVE.url.replace(/\/$/,'')+'/api/stream?token='+encodeURIComponent(LIVE.token);
 const es=new EventSource(u);LIVE.es=es;
 es.addEventListener('agent',e=>{
  const a=JSON.parse(e.data);
  const i=LIVE.agents.findIndex(x=>x.id===a.id);
  if(i>=0)LIVE.agents[i]=a;else LIVE.agents.push(a);
  liveApplyAgents();if(view==='logsrc')renderLogSrc();liveBadge();
 });
 es.addEventListener('agentRemoved',e=>{
  const {id}=JSON.parse(e.data);
  LIVE.agents=LIVE.agents.filter(a=>a.id!==id);
  lsNodes=lsNodes.filter(n=>n.agentId!==id);
  if(view==='logsrc')renderLogSrc();
 });
 es.addEventListener('events',e=>{
  const evs=JSON.parse(e.data);
  LIVE.events.push(...evs);if(LIVE.events.length>500)LIVE.events.splice(0,LIVE.events.length-500);
  evs.forEach(liveIngestEvent);
  if(view==='logsrc')renderLogSrc();
  if(view==='dash')renderDash();
  if(view==='matrix')renderMatrix();   // light up techniques as their telemetry lands
  if(typeof siemLivePing==='function')siemLivePing();
  updateBadges();
  const bad=evs.filter(x=>x.severity==='malicious');
  if(bad.length)toast(`\u26a0 ${bad.length} malicious event${bad.length===1?'':'s'} on ${bad[0].host}`);
 });
 es.addEventListener('links',e=>{liveApplyLinks(JSON.parse(e.data));if(view==='logsrc')renderLogSrc();});
 es.addEventListener('ticket',e=>{
  const tk=JSON.parse(e.data);
  const i=LIVE.tickets.findIndex(x=>x.id===tk.id);
  if(i>=0)LIVE.tickets[i]=tk;else LIVE.tickets.push(tk);
  if(view==='tickets')renderTickets();
  if(view==='cases')renderCases();
  if(view==='dash')renderDash();
  liveBadge();updateBadges();activityPing();
 });
 es.addEventListener('case',e=>{
  csUpsert(JSON.parse(e.data));
  if(view==='cases')csRefresh();
  updateBadges();activityPing();
 });
 es.addEventListener('chat',e=>chatIngest(JSON.parse(e.data)));
 es.addEventListener('presence',e=>presenceIngest(JSON.parse(e.data)));
 es.addEventListener('companion',e=>coIngest(JSON.parse(e.data)));
 es.onerror=()=>{LIVE.connected=false;PRESENCE=[];renderPresence();liveBadge();};
 es.onopen=()=>{LIVE.connected=true;liveBadge();};
}
/* agents become nodes on the map, laid out in their zone, never duplicated */
function liveApplyAgents(){
 LIVE.agents.forEach(a=>{
  let n=lsNodes.find(x=>x.agentId===a.id);
  if(!n){
   const type=NODE_TYPES[a.nodeType]?a.nodeType:'wks';
   n=lsAddNode(type,0,0,false);
   n.agentId=a.id;n.live=true;
   const r=lsZoneRect(a.zone)||{x:80,y:80,w:600,h:200};
   const peers=lsNodes.filter(x=>x.live&&nodeZone(x)===a.zone).length;
   n.x=r.x+80+((peers-1)%7)*140;
   n.y=r.y+60+Math.floor(Math.max(0,peers-1)/7)*80;
  }
  n.label=a.hostname;n.os=a.os||n.os;n.zone=a.zone;n.stale=a.stale;n.ip=a.ip;
 });
 persistAll();
}
/* a live event with a known Event ID becomes an observation on that host */
function liveIngestEvent(ev){
 // The collector's own scheduled runs are not activity on the host. Keep them
 // out of the map's observation log; they are still searchable in Event Search
 // for when you want to confirm the agent is alive.
 if(ev.self)return;
 const n=lsNodes.find(x=>x.agentId===ev.agentId)||lsNodes.find(x=>x.label===ev.host);
 if(!n)return;
 if(!n.obs)n.obs=[];
 if(n.obs.some(o=>o.liveId===ev.id))return;
 const known=LOGSRC.some(e=>e.id===ev.eventId);
 n.obs.push({id:'o'+Date.now()+Math.floor(Math.random()*99),liveId:ev.id,
   evId:known?ev.eventId:'',note:(known?'':ev.eventId+' \u2014 ')+(ev.message||''),
   sev:ev.severity,t:ev.ts||Date.now(),tech:ev.technique||''});
 if(n.obs.length>200)n.obs.splice(0,n.obs.length-200);
}
function liveBadge(){
 const el=document.getElementById('live-ind');if(!el)return;
 const open=LIVE.tickets.filter(t=>t.status==='open').length;
 el.className='live-ind '+(LIVE.connected?'on':(LIVE.url?'off':''));
 el.innerHTML=LIVE.connected
  ? `<i></i>LIVE \u00b7 ${LIVE.agents.filter(a=>!a.stale).length}/${LIVE.agents.length} agents${open?` \u00b7 ${open} open`:''}`
  : (LIVE.url?'<i></i>offline':'');
 el.title=LIVE.lastError||'';
}
function openLiveSetup(){
 let v=document.getElementById('live-veil');
 if(!v){v=document.createElement('div');v.id='live-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="closeLiveSetup()"></div>
  <div class="ls-det-head">Connect to an AEGIS server</div>
  <div class="ls-det-sub">Agents report in to a server; this console reads from it. Without a server AEGIS keeps working exactly as it does now, entirely local. Both values are printed by the server on startup.</div>
  <label class="live-l">Server URL</label>
  <input class="ui-dlg-input" id="live-url" value="${esc(LIVE.url)}" placeholder="https://aegis.internal:8787">
  <label class="live-l">Analyst token</label>
  <input class="ui-dlg-input" id="live-tok" type="password" value="${esc(LIVE.token)}" placeholder="paste the analyst token">
  <div style="display:flex;gap:8px">
   <button class="btn violet" style="flex:1;justify-content:center" onclick="LIVE.url=document.getElementById('live-url').value.trim();LIVE.token=document.getElementById('live-tok').value.trim();closeLiveSetup();liveConnect()">Connect</button>
   ${LIVE.connected?`<button class="btn" onclick="closeLiveSetup();liveDisconnect()">Disconnect</button>`:''}
  </div>
  ${LIVE.lastError?`<div class="lint err" style="margin-top:10px"><b>Error</b> ${esc(LIVE.lastError)}</div>`:''}
  <div class="ls-mm-sec">Deploying agents</div>
  <div class="ls-det-sub">On each Windows host, as admin:<br>
   <code>.\\aegis-agent.ps1 -Server &lt;url&gt; -EnrollmentToken &lt;token&gt; -Install</code><br>
   Linux/macOS: <code>sudo python3 agents/aegis-agent.py --server &lt;url&gt; --token &lt;token&gt; --once</code> from a systemd timer or cron.
   The enrollment token is separate from the analyst token above and is printed alongside it.</div>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeLiveSetup();};
}
function closeLiveSetup(){const v=document.getElementById('live-veil');if(v)v.classList.remove('open');}


/* --- discovered links: real adjacency from what hosts actually talk to --- */
function liveApplyLinks(links){
 if(!Array.isArray(links))return;
 // drop previously auto-discovered edges, keep anything the analyst drew
 lsEdges=lsEdges.filter(e=>!e.discovered);
 links.forEach(l=>{
  const a=lsNodes.find(n=>n.agentId===l.a), b=lsNodes.find(n=>n.agentId===l.b);
  if(!a||!b)return;
  if(lsEdges.some(e=>(e.a===a.uid&&e.b===b.uid)||(e.a===b.uid&&e.b===a.uid)))return;
  lsEdges.push({a:a.uid,b:b.uid,discovered:true,label:l.port?String(l.port):''});
 });
 persistAll();
}
/* --- logging posture across the estate: find blind spots before an incident --- */
function openLoggingGaps(){
 let v=document.getElementById('gap-veil');
 if(!v){v=document.createElement('div');v.id='gap-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const agents=LIVE.agents||[];
 const withGaps=agents.filter(a=>(a.gaps||[]).length);
 const tally={};
 agents.forEach(a=>(a.gaps||[]).forEach(g=>{(tally[g.id]=tally[g.id]||{label:g.label,impact:g.impact,hosts:[]}).hosts.push(a.hostname);}));
 v.innerHTML=`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="closeLoggingGaps()"></div>
  <div class="ls-det-head">Logging posture</div>
  <div class="ls-det-sub">Reported by the agents themselves \u2014 what each host is actually configured to log. ${agents.length?`${withGaps.length} of ${agents.length} hosts have a gap.`:'Connect to a server to populate this.'}</div>
  ${Object.entries(tally).map(([id,g])=>`<div class="gap-row">
    <div class="gap-h">${esc(g.label)}<span>${g.hosts.length} host${g.hosts.length===1?'':'s'}</span></div>
    <div class="gap-i">${esc(g.impact)}</div>
    <div class="gap-hosts">${g.hosts.slice(0,12).map(h=>`<span>${esc(h)}</span>`).join('')}${g.hosts.length>12?` +${g.hosts.length-12}`:''}</div>
  </div>`).join('')||(agents.length?'<div class="lint ok">\u2713 No logging gaps reported across any host.</div>':'')}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeLoggingGaps();};
}
function closeLoggingGaps(){const v=document.getElementById('gap-veil');if(v)v.classList.remove('open');}
/* ---------------- ticketing UI ---------------- */
let tkFilter='open';
function renderTickets(){
 const host=document.getElementById('tk-main');if(!host)return;
 if(!LIVE.connected){
  host.innerHTML=`<div class="ls-empty"><div class="ls-empty-ic">\u25f3</div><h3>Ticketing needs a server</h3>
   <p>Tickets are shared across everyone working the incident, so they live on the AEGIS server rather than in your browser.</p>
   <div class="ls-empty-acts"><button class="btn violet" onclick="openLiveSetup()">Connect to a server</button></div></div>`;
  return;
 }
 const all=LIVE.tickets.slice().reverse();
 const shown=tkFilter==='all'?all:all.filter(t=>tkFilter==='open'?t.status!=='closed':t.status===tkFilter);
 const count=s=>all.filter(t=>s==='all'?1:s==='open'?t.status!=='closed':t.status===s).length;
 host.innerHTML=`
  <div class="tk-head">
    <div class="tk-tabs">
      ${['open','contained','closed','all'].map(s=>`<button class="${tkFilter===s?'on':''}" onclick="tkFilter='${s}';renderTickets()">${s[0].toUpperCase()+s.slice(1)} <span>${count(s)}</span></button>`).join('')}
    </div>
    <button class="btn violet" onclick="tkNew()">\uff0b New ticket</button>
  </div>
  ${shown.length?shown.map(t=>`<div class="tk-card sev-${t.severity}" onclick="tkOpen('${t.id}')">
    <div class="tk-num">#${t.num}</div>
    <div class="tk-main">
      <div class="tk-title">${esc(t.title)}</div>
      <div class="tk-meta">
        <span class="tk-sev ${t.severity}">${t.severity}</span>
        <span class="tk-status ${t.status}">${t.status}</span>
        ${t.host?`<span>\u25a3 ${esc(t.host)}</span>`:''}
        ${t.technique?`<span>${esc(t.technique)}</span>`:''}
        ${t.assignee?`<span>\u25cf ${esc(t.assignee)}</span>`:''}
        ${t.comments&&t.comments.length?`<span>\u25cb ${t.comments.length}</span>`:''}
        <span class="tk-when">${new Date(t.updatedAt).toLocaleString()}</span>
      </div>
    </div>
  </div>`).join(''):'<div class="ls-det-sub" style="padding:30px;text-align:center">No tickets in this view.</div>'}`;
}
/* Facts about one machine, pulled from its enrolled agent. Drives the auto-
   populated info block on the ticket form and detail view: an analyst raising a
   ticket should not have to remember what OS a box is or whether it is even
   reporting. Falls back gracefully for a hostname with no agent - which is
   exactly the "the machine is down, I typed it in by hand" case. */
function tkAgentFor(host){
 const h=String(host||'').trim().toLowerCase();
 if(!h)return null;
 return (LIVE.agents||[]).find(a=>(a.hostname||'').toLowerCase()===h)||null;
}
function tkHostFacts(host){
 const a=tkAgentFor(host);
 if(!host||!host.trim())return '';
 if(!a)return `<div class="tk-facts down"><b>▣ ${esc(host)}</b> · not an enrolled agent.
   Either it has no AEGIS agent, or it is down. The ticket still records the name; fill in details by hand.</div>`;
 const seen=a.lastSeen?new Date(a.lastSeen).toLocaleString():'unknown';
 const gaps=(a.gaps||[]);
 return `<div class="tk-facts ${a.stale?'stale':'ok'}">
   <div class="tk-facts-h"><b>▣ ${esc(a.hostname)}</b>
     <span class="tk-facts-badge ${a.stale?'stale':'ok'}">${a.stale?'gone quiet':'reporting'}</span></div>
   <div class="tk-facts-grid">
     ${a.os?`<span>OS</span><span>${esc(a.os)}</span>`:''}
     ${a.ip?`<span>IP</span><span>${esc(a.ip)}</span>`:''}
     ${a.nodeType?`<span>Type</span><span>${esc(a.nodeType)}</span>`:''}
     ${a.zone?`<span>Zone</span><span>${esc(a.zone)}</span>`:''}
     <span>Events</span><span>${a.eventCount||0}</span>
     <span>Last seen</span><span>${esc(seen)}</span>
     ${a.version?`<span>Agent</span><span>v${esc(a.version)}</span>`:''}
   </div>
   ${gaps.length?`<div class="tk-facts-gaps">⚠ ${gaps.length} logging gap${gaps.length===1?'':'s'}: ${gaps.map(g=>esc(g.label)).join(', ')}</div>`:''}
 </div>`;
}
/* Live-refresh the info block on the new-ticket form as the host field changes. */
function tkNewHostInfo(host){const el=document.getElementById('tk-new-info');if(el)el.innerHTML=tkHostFacts(host);}
/* Dropdown -> hidden text field: picking a known host fills it and refreshes the
   facts; "Other" reveals the field to type an unenrolled/down host by hand. The
   text field is always the value tkCreate reads, so both paths converge. */
function tkNewHostPick(val){
 const other=document.getElementById('tk-new-host');if(!other)return;
 if(val==='__other'){other.style.display='block';other.value='';other.focus();tkNewHostInfo('');}
 else{other.style.display='none';other.value=val;tkNewHostInfo(val);}
}
async function tkNew(prefill){
 prefill=prefill||{};
 const hosts=(LIVE.agents||[]).slice().sort((a,b)=>(a.hostname||'').localeCompare(b.hostname||''));
 let v=document.getElementById('tk-veil');
 if(!v){v=document.createElement('div');v.id='tk-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet" style="width:min(480px,100vw)">
  <div class="ls-ne-grip" onclick="tkClose()"></div>
  <div class="ls-det-head">New ticket</div>
  <label class="ls-ne-label">What is it about?</label>
  <input class="ui-dlg-input" id="tk-new-title" placeholder="e.g. Encoded PowerShell on DC01" value="${esc(prefill.title||'')}">
  <label class="ls-ne-label">Machine</label>
  ${hosts.length?(()=>{
    // A real dropdown of every enrolled host - online and gone-quiet alike, so
    // a box that dropped offline is still one click away and never has to be
    // retyped. "Other" reveals a free-text field for a host with no agent.
    const known=hosts.some(a=>a.hostname===prefill.host);
    return `<select class="ui-dlg-input" id="tk-new-host-sel" onchange="tkNewHostPick(this.value)">
      <option value="">— select a host —</option>
      ${hosts.map(a=>`<option value="${esc(a.hostname)}" ${prefill.host===a.hostname?'selected':''}>${esc(a.hostname)}${a.stale?' · offline':''}${a.os?' · '+esc(a.os):''}</option>`).join('')}
      <option value="__other" ${(prefill.host&&!known)?'selected':''}>Other / not enrolled (type it)…</option>
    </select>
    <input class="ui-dlg-input" id="tk-new-host" style="margin-top:6px;display:${(prefill.host&&!known)?'block':'none'}" placeholder="hostname of a machine with no agent, or one that's down"
      value="${esc(prefill.host||'')}" oninput="tkNewHostInfo(this.value)">`;
  })():`<input class="ui-dlg-input" id="tk-new-host" placeholder="hostname of the affected host" value="${esc(prefill.host||'')}" oninput="tkNewHostInfo(this.value)">`}
  <div id="tk-new-info">${tkHostFacts(prefill.host||'')}</div>
  <label class="ls-ne-label">Severity</label>
  <select class="ui-dlg-input" id="tk-new-sev">${['low','medium','high','critical'].map(s=>`<option ${((prefill.severity||'medium')===s)?'selected':''}>${s}</option>`).join('')}</select>
  <button class="btn violet" style="width:100%;justify-content:center;margin-top:12px" onclick="tkCreate()">Create ticket</button>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)tkClose();};
 setTimeout(()=>{const t=document.getElementById('tk-new-title');if(t&&t.focus)t.focus();},60);
}
async function tkCreate(){
 const title=(document.getElementById('tk-new-title')||{}).value||'';
 const host=(document.getElementById('tk-new-host')||{}).value||'';
 const severity=(document.getElementById('tk-new-sev')||{}).value||'medium';
 if(!title.trim()){toast('Give the ticket a title');return;}
 try{
  await liveApi('/api/tickets',{method:'POST',body:JSON.stringify({title:title.trim(),host:host.trim()||undefined,severity})});
  tkClose();toast('Ticket created');
 }catch(e){toast('Failed: '+e.message);}
}
/* raise a ticket straight from a host on the map */
async function tkFromNode(uid){
 if(!LIVE.connected){toast('Connect to a server to raise tickets');return;}
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 const worst=lsNodeStatus(n)||'info';
 const obs=lsNodeObs(n).slice(-8).map(o=>`${o.evId||''} ${o.note||''} (${o.sev})`).join('\n');
 try{
  await liveApi('/api/tickets',{method:'POST',body:JSON.stringify({
   title:`${worst==='malicious'?'Compromise':'Suspicious activity'} on ${n.label}`,
   body:obs||'Raised from the AEGIS hunt map.',
   severity:worst==='malicious'?'critical':worst==='suspicious'?'high':'medium',
   host:n.label,createdBy:'analyst'})});
  toast('Ticket raised for '+n.label);go('tickets');
 }catch(e){toast('Failed: '+e.message);}
}
async function tkOpen(id){
 const t=LIVE.tickets.find(x=>x.id===id);if(!t)return;
 let v=document.getElementById('tk-veil');
 if(!v){v=document.createElement('div');v.id='tk-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="tkClose()"></div>
  <div class="tk-d-head">#${t.num} \u00b7 ${esc(t.title)}</div>
  <div class="tk-d-row">
   ${(() => {
     // Only a lead may close. For everyone else, drop 'closed' from the choices
     // (unless it is already closed, which we still want to display) and let the
     // server be the real gate - see the PATCH handler.
     const canClose=authCan('ticket.editAny');
     const opts=['open','contained'].concat((canClose||t.status==='closed')?['closed']:[]);
     return `<select onchange="tkPatch('${t.id}',{status:this.value})">${opts.map(s=>`<option ${t.status===s?'selected':''}>${s}</option>`).join('')}</select>`;
   })()}
   <select onchange="tkPatch('${t.id}',{severity:this.value})">${['low','medium','high','critical'].map(s=>`<option ${t.severity===s?'selected':''}>${s}</option>`).join('')}</select>
   <input placeholder="assignee" value="${esc(t.assignee||'')}" onchange="tkPatch('${t.id}',{assignee:this.value})">
  </div>
  ${authCan('ticket.editAny')?'':'<div class="ls-det-sub" style="margin:-2px 0 6px">Set it to <b>Contained</b> when handled - a lead signs off the close.</div>'}
  ${t.host?tkHostFacts(t.host):''}
  ${t.technique?`<div class="tk-d-tags"><span>${esc(t.technique)}</span></div>`:''}
  ${csTicketSelectHTML(t)}
  ${t.body?`<div class="tk-d-body">${highlightIocs(t.body).replace(/\n/g,'<br>')}</div>`:''}
  <div class="ls-mm-sec">Activity</div>
  ${(t.comments||[]).map(c=>`<div class="tk-c"><span class="tk-c-a">${esc(c.author)}</span><span class="tk-c-t">${new Date(c.at).toLocaleString()}</span><div>${esc(c.text).replace(/\n/g,'<br>')}</div></div>`).join('')||'<div class="ls-det-sub">No comments yet.</div>'}
  <textarea id="tk-c-in" class="art-ta" style="min-height:70px;margin-top:8px" placeholder="Add an update\u2026"></textarea>
  <button class="btn violet" style="width:100%;justify-content:center;margin-top:8px" onclick="tkComment('${t.id}')">Post update</button>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)tkClose();};
}
function tkClose(){const v=document.getElementById('tk-veil');if(v)v.classList.remove('open');}
async function tkPatch(id,patch){
 try{await liveApi('/api/tickets/'+id,{method:'PATCH',body:JSON.stringify(patch)});renderTickets();}
 catch(e){toast(e.message);const v=document.getElementById('tk-veil');if(v&&v.classList.contains('open'))tkOpen(id);}
}
async function tkComment(id){
 const ta=document.getElementById('tk-c-in');if(!ta||!ta.value.trim())return;
 try{
  await liveApi('/api/tickets/'+id+'/comments',{method:'POST',body:JSON.stringify({author:'analyst',text:ta.value.trim()})});
  ta.value='';setTimeout(()=>tkOpen(id),150);
 }catch(e){toast('Failed: '+e.message);}
}
