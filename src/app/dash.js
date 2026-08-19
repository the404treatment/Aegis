/* ================= DASHBOARD ================= */
/* The first thing you see, and the answer to "what is happening right now".
 *
 * Everything on it is live. Nothing on it is a static reference — the ATT&CK
 * matrix, the log-source catalogue and the technique library are all reference
 * material and belong behind a click, not in front of someone walking up to a
 * screen mid-incident.
 *
 * Cards are chosen by the analyst and remembered per browser. That is not a
 * feature for its own sake: a triage analyst and a detection engineer want
 * genuinely different first screens, and forcing one layout on both means it is
 * wrong for at least one of them. */

const DASH_CARDS = {
 threat:    {label:'Threat level',       hint:'One line: how bad is it right now'},
 malicious: {label:'Malicious events',   hint:'Everything the agents flagged as malicious'},
 hosts:     {label:'Noisiest hosts',     hint:'Which machines are generating the most'},
 techniques:{label:'Techniques seen',    hint:'ATT&CK techniques observed in live telemetry'},
 tickets:   {label:'Open tickets',       hint:'The shared queue, newest first'},
 cases:     {label:'Active cases',       hint:'Incidents currently open'},
 agents:    {label:'Agent health',       hint:'Who is reporting, and who has gone quiet'},
 companion: {label:'Companion notes',    hint:'What the local model has flagged unasked'},
 activity:  {label:'Team activity',      hint:'What your colleagues have been doing'},
};
const DASH_DEFAULT = ['threat','malicious','techniques','hosts','agents','tickets'];

let dashCards = DASH_DEFAULT.slice();
let _dashTimer = null;

function dashLoad(){
 try{
  const s=JSON.parse(read('aegis-dash','null'));
  if(Array.isArray(s)&&s.length)dashCards=s.filter(k=>DASH_CARDS[k]);
 }catch{}
 if(!dashCards.length)dashCards=DASH_DEFAULT.slice();
}
function dashSave(){try{store('aegis-dash',JSON.stringify(dashCards));}catch{}}

/* ------------------------------------------------------------ the data */
/** Events from the last N minutes. The dashboard is about now, not history.
    The collector's own scheduled runs (self) are excluded everywhere on the
    dashboard: they are expected, so they are noise on a "what is happening"
    screen. */
function dashRecent(mins){
 const cut=Date.now()-(mins||60)*60000;
 return (LIVE.events||[]).filter(e=>(e.ts||0)>=cut&&!e.self);
}

/** One honest sentence about the current state. */
function dashThreat(){
 const rec=dashRecent(60);
 const mal=rec.filter(e=>e.severity==='malicious');
 const sus=rec.filter(e=>e.severity==='suspicious');
 const hosts=new Set(mal.map(e=>e.host).filter(Boolean));
 if(!LIVE.connected)return {level:'offline',line:'Not connected to a server.',sub:'The console is running local-only. Connect to see live telemetry.'};
 if(!(LIVE.agents||[]).length)return {level:'quiet',line:'No agents are reporting.',sub:'Deploy an agent and telemetry appears here. See INSTALL.md.'};
 if(mal.length)return {level:'malicious',
  line:`${mal.length} malicious event${mal.length===1?'':'s'} in the last hour`,
  sub:hosts.size?`Across ${hosts.size} host${hosts.size===1?'':'s'}: ${[...hosts].slice(0,4).join(', ')}${hosts.size>4?'…':''}`:''};
 if(sus.length)return {level:'suspicious',
  line:`${sus.length} suspicious event${sus.length===1?'':'s'} in the last hour`,
  sub:'Nothing confirmed malicious. Worth a look.'};
 return {level:'clear',line:'Nothing flagged in the last hour.',
  sub:`${(LIVE.agents||[]).length} agent${(LIVE.agents||[]).length===1?'':'s'} reporting normally.`};
}

const dashAgo=t=>{const s=Math.max(0,Math.round((Date.now()-t)/1000));
 return s<60?s+'s':s<3600?Math.floor(s/60)+'m':s<86400?Math.floor(s/3600)+'h':Math.floor(s/86400)+'d';};

/* ------------------------------------------------------------- render */
function renderDash(){
 const host=document.getElementById('dash-grid');if(!host)return;
 host.innerHTML=dashCards.map(k=>dashCard(k)).join('')||
  '<div class="no-match">No cards selected. Click <b>Customise</b> to pick some.</div>';
}

function dashCard(key){
 const meta=DASH_CARDS[key];if(!meta)return '';
 const body=({
  threat:dashCardThreat, malicious:dashCardMalicious, hosts:dashCardHosts,
  techniques:dashCardTechniques, tickets:dashCardTickets, cases:dashCardCases,
  agents:dashCardAgents, companion:dashCardCompanion, activity:dashCardActivity,
 }[key]||(()=>''))();
 return`<div class="dcard dcard-${key}">
   <div class="dcard-h"><span>${esc(meta.label)}</span></div>
   <div class="dcard-b">${body}</div>
 </div>`;
}

const dashEmpty=t=>`<div class="dash-empty">${esc(t)}</div>`;

function dashCardThreat(){
 const t=dashThreat();
 return`<div class="threat threat-${t.level}">
   <div class="threat-dot"></div>
   <div><div class="threat-line">${esc(t.line)}</div>
   ${t.sub?`<div class="threat-sub">${esc(t.sub)}</div>`:''}</div>
 </div>`;
}

function dashCardMalicious(){
 const rows=(LIVE.events||[]).filter(e=>e.severity==='malicious').slice(-8).reverse();
 if(!rows.length)return dashEmpty('Nothing malicious reported.');
 return rows.map(e=>`<div class="drow" onclick="dashOpenEvent('${jsq(e.host||'')}')">
   <span class="drow-k sev-malicious">${esc(String(e.eventId||'—'))}</span>
   <span class="drow-m">${esc((e.message||'').slice(0,60))}</span>
   ${e.technique?`<span class="drow-t">${esc(e.technique)}</span>`:''}
   <span class="drow-a">${esc(e.host||'')} · ${dashAgo(e.ts||0)}</span>
 </div>`).join('');
}

function dashCardHosts(){
 const rec=dashRecent(60);
 if(!rec.length)return dashEmpty('No telemetry in the last hour.');
 const by={};
 for(const e of rec){const h=e.host||'unknown';
  by[h]=by[h]||{n:0,bad:0};by[h].n++;
  if(e.severity==='malicious')by[h].bad++;}
 const max=Math.max(...Object.values(by).map(v=>v.n));
 return Object.entries(by).sort((a,b)=>b[1].n-a[1].n).slice(0,6).map(([h,v])=>`
  <div class="dbar" onclick="dashOpenEvent('${jsq(h)}')">
    <span class="dbar-n">${esc(h)}</span>
    <span class="dbar-t"><i style="width:${Math.round(v.n/max*100)}%" class="${v.bad?'bad':''}"></i></span>
    <span class="dbar-v">${v.n}${v.bad?` <b>${v.bad}</b>`:''}</span>
  </div>`).join('');
}

/* The live answer to "what is actually happening", which is what the static
   matrix could never give you: techniques the agents have genuinely observed. */
function dashCardTechniques(){
 const rec=(LIVE.events||[]).filter(e=>e.technique);
 if(!rec.length)return dashEmpty('No technique-tagged telemetry yet. The Windows agent tags what it can.');
 const by={};
 for(const e of rec){const t=e.technique;by[t]=by[t]||{n:0,hosts:new Set(),worst:'info'};
  by[t].n++;by[t].hosts.add(e.host);
  if(e.severity==='malicious')by[t].worst='malicious';
  else if(e.severity==='suspicious'&&by[t].worst!=='malicious')by[t].worst='suspicious';}
 return Object.entries(by).sort((a,b)=>b[1].n-a[1].n).slice(0,7).map(([t,v])=>{
  const name=(MITRE[t]||MITRE[t.split('.')[0]]||{}).name||'';
  return`<div class="drow" onclick="dashOpenTech('${jsq(t)}')">
    <span class="drow-k sev-${esc(v.worst)}">${esc(t)}</span>
    <span class="drow-m">${esc(name)}</span>
    <span class="drow-a">${v.n} · ${v.hosts.size} host${v.hosts.size===1?'':'s'}</span>
  </div>`;}).join('');
}

function dashCardTickets(){
 const rows=(LIVE.tickets||[]).filter(t=>t.status!=='closed').slice(-7).reverse();
 if(!rows.length)return dashEmpty(LIVE.connected?'No open tickets.':'Connect to a server to see the shared queue.');
 return rows.map(t=>`<div class="drow" onclick="go('tickets')">
   <span class="drow-k sev-${esc(t.severity||'info')}">${esc((t.severity||'').slice(0,4).toUpperCase()||'—')}</span>
   <span class="drow-m">${esc(t.title||'untitled')}</span>
   <span class="drow-a">${esc(t.status||'')}</span>
 </div>`).join('');
}

function dashCardCases(){
 const rows=(LIVE.cases||[]).filter(c=>c.status!=='closed').slice(-6).reverse();
 if(!rows.length)return dashEmpty(LIVE.connected?'No open cases.':'Connect to a server to see cases.');
 return rows.map(c=>`<div class="drow" onclick="go('cases')">
   <span class="drow-k sev-${esc(c.severity||'info')}">#${esc(String(c.num||''))}</span>
   <span class="drow-m">${esc(c.title||'untitled')}</span>
   <span class="drow-a">${esc(c.status||'')}</span>
 </div>`).join('');
}

function dashCardAgents(){
 const ags=LIVE.agents||[];
 if(!ags.length)return dashEmpty('No agents enrolled. See INSTALL.md to deploy one.');
 const stale=ags.filter(a=>a.stale);
 const head=stale.length
  ? `<div class="dash-warn">${stale.length} agent${stale.length===1?'':'s'} gone quiet — silence is a signal, not calm.</div>`
  : '';
 return head+ags.slice(0,7).map(a=>`<div class="drow" onclick="go('logsrc')">
   <span class="drow-k ${a.stale?'sev-suspicious':'sev-ok'}">${a.stale?'quiet':'live'}</span>
   <span class="drow-m">${esc(a.hostname||a.id)}</span>
   <span class="drow-a">${a.lastSeen?dashAgo(a.lastSeen):'never'}</span>
 </div>`).join('');
}

function dashCardCompanion(){
 if(!CO.available)return dashEmpty('No local model running. See LOCAL-AI.md — it is optional.');
 const rows=coItems.filter(i=>i.kind==='watch').slice(-4).reverse();
 if(!rows.length)return dashEmpty('Nothing flagged yet. It speaks when telemetry warrants it.');
 return rows.map(i=>`<div class="dnote dnote-${esc(i.worst||'suspicious')}" onclick="coToggle()">
   <div class="dnote-t">${i.events} event${i.events===1?'':'s'}${i.hosts&&i.hosts.length?' · '+esc(i.hosts.join(', ')):''} · ${dashAgo(i.at)} ago</div>
   <div class="dnote-b">${esc(i.text)}</div>
 </div>`).join('');
}

function dashCardActivity(){
 if(!LIVE.connected)return dashEmpty('Connect to a server to see what the team is doing.');
 if(!activityItems.length)return dashEmpty('Nothing yet.');
 return activityItems.slice(0,6).map(a=>`<div class="drow" onclick="activityToggle()">
   <span class="who-dot sm" style="--who:${whoColor(a.actor)}">${esc(initialsOf(a.actor))}</span>
   <span class="drow-m"><b>${esc(a.actor)}</b> ${esc(a.verb)}${a.noun?' '+esc(a.noun):''} ${esc(a.target||'')}</span>
   <span class="drow-a">${dashAgo(a.at)}</span>
 </div>`).join('');
}

/* ------------------------------------------------------------ actions */
function dashOpenEvent(host){go('siem');const q=document.getElementById('siem-q');
 if(q&&host){q.value='host:'+host;if(typeof siemRun==='function')siemRun();}}
function dashOpenTech(t){const id=MITRE[t]?t:t.split('.')[0];
 if(MITRE[id]){go('matrix');openDrawer(id);}else toast(t+' — no strategy page for this one');}

/** Pick which cards you want. Per browser, because it is a personal choice. */
async function dashCustomise(){
 let v=document.getElementById('dash-veil');
 if(!v){v=document.createElement('div');v.id='dash-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet" style="width:min(460px,100vw)">
   <div class="ls-ne-grip" onclick="dashCloseCustomise()"></div>
   <div class="ls-det-head">Your dashboard</div>
   <div class="ls-det-sub">Pick what you want to see first. A triage shift and a detection-engineering afternoon want different screens; this is remembered in this browser.</div>
   ${Object.entries(DASH_CARDS).map(([k,m])=>`
     <label class="dash-pick">
       <input type="checkbox" ${dashCards.includes(k)?'checked':''} onchange="dashToggleCard('${k}',this.checked)">
       <span><b>${esc(m.label)}</b><i>${esc(m.hint)}</i></span>
     </label>`).join('')}
   <button class="btn violet" style="width:100%;justify-content:center;margin-top:12px" onclick="dashCloseCustomise()">Done</button>
   <div class="ls-det-sub" style="margin-top:10px"><a href="#" onclick="dashReset();return false">Reset to defaults</a></div>
 </div>`;
 v.classList.add('open');v.onclick=e=>{if(e.target===v)dashCloseCustomise();};
}
function dashCloseCustomise(){const v=document.getElementById('dash-veil');if(v)v.classList.remove('open');}
function dashToggleCard(k,on){
 // Keep DASH_CARDS order rather than click order, so the layout stays stable
 // as you tick things on and off.
 const want=new Set(dashCards);on?want.add(k):want.delete(k);
 dashCards=Object.keys(DASH_CARDS).filter(x=>want.has(x));
 dashSave();renderDash();
}
function dashReset(){dashCards=DASH_DEFAULT.slice();dashSave();renderDash();dashCustomise();}

/** Keep relative times honest without re-rendering constantly. */
function dashTick(){
 clearInterval(_dashTimer);
 _dashTimer=setInterval(()=>{if(view==='dash')renderDash();},30000);
}
