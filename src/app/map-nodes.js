/* ---- observed events (incident mapping) ---- */
const SEV_META={info:{label:'Info',color:'var(--sky)',rank:1},suspicious:{label:'Suspicious',color:'var(--amber)',rank:2},malicious:{label:'Malicious',color:'var(--magenta)',rank:3}};
function lsAddObs(uid,evId,note,sev){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 if(!n.obs)n.obs=[];
 n.obs.push({id:'o'+Date.now()+Math.floor(Math.random()*99),evId:evId||'',note:note||'',sev:sev||'suspicious',t:Date.now()});
 persistAll();lsSnapshot();
 // offer to stage the technique this event maps to (closes hunt→coverage loop)
 if(evId){
  const ev=LOGSRC.find(e=>e.id===evId);
  if(ev&&ev.linked){
   const evObj=ALL().find(x=>x.id===ev.linked);
   if(evObj&&evObj.mitre&&evObj.mitre.length){
    const tid=evObj.mitre[0];
    if(MITRE[tid]&&!studio.has(tid)){lsPendingStage={tid,name:T(tid).name};}
   }
  }
 }
 renderLogSrc();
}
let lsPendingStage=null;
function lsAcceptStage(){
 if(!lsPendingStage)return;
 studio.add(lsPendingStage.tid);persistAll();updateBadges();
 toast(`${lsPendingStage.tid} staged in the Studio`);
 lsPendingStage=null;renderLogSrc();
}
function lsDismissStage(){lsPendingStage=null;renderLogSrc();}
function lsDelObs(uid,oid){const n=lsNodes.find(x=>x.uid===uid);if(!n)return;n.obs=(n.obs||[]).filter(o=>o.id!==oid);persistAll();lsSnapshot();renderLogSrc();}
/* observations on a node, respecting the timeline scrubber */
function lsNodeObs(n){
 const obs=n.obs||[];
 if(lsScrubT==null)return obs;
 return obs.filter(o=>o.t<=lsScrubT);
}
/* node incident status derived from its worst observation */
function lsNodeStatus(n){
 const obs=lsNodeObs(n);
 if(!obs.length)return null;
 const worst=Math.max(...obs.map(o=>SEV_META[o.sev]?SEV_META[o.sev].rank:1));
 return worst>=3?'malicious':worst===2?'suspicious':'info';
}
function lsHasIncident(){return lsNodes.some(n=>n.obs&&n.obs.length);}
/* min/max observation timestamps across the map */
function lsObsTimeRange(){
 const ts=lsNodes.flatMap(n=>(n.obs||[]).map(o=>o.t));
 if(!ts.length)return null;
 return{min:Math.min(...ts),max:Math.max(...ts)};
}
/* all observations across the map, ordered by kill-chain stage of the tagged event then time */
function lsAllObs(){
 const rows=[];
 lsNodes.forEach(n=>(n.obs||[]).forEach(o=>{
  const ev=LOGSRC.find(e=>e.id===o.evId);
  const stage=ev&&ev.linked?primaryStage((ALL().find(x=>x.id===ev.linked)||{mitre:['']}).mitre[0]):99;
  rows.push({node:n,obs:o,ev,stage:isNaN(stage)?99:stage});
 }));
 rows.sort((a,b)=>(a.stage-b.stage)||(a.obs.t-b.obs.t));
 return rows;
}
function lsScrubSet(v){
 const r=lsObsTimeRange();if(!r)return;
 lsScrubT=parseInt(v);
 // update just the canvas + label without full re-render for smoothness
 const cv=document.getElementById('ls-canvas');if(cv){const cap=cv.querySelector('#ls-anim-cap');cv.innerHTML=lsCanvasSVG()+(cap?cap.outerHTML:'<div class="ls-anim-cap" id="ls-anim-cap" style="display:none"></div>');lsBindCanvas();}
 const lbl=document.getElementById('ls-scrub-lbl');if(lbl)lbl.textContent=lsScrubT>=r.max?'now (all observations)':new Date(lsScrubT).toLocaleTimeString();
 const cnt=document.getElementById('ls-scrub-cnt');if(cnt){const shown=lsNodes.reduce((a,n)=>a+lsNodeObs(n).length,0);cnt.textContent=shown;}
}
function lsScrubReset(){lsScrubT=null;renderLogSrc();}

/* Which LOGSRC events does a node of this type emit, in hunt scope? */
function lsEventsForNode(node){
 const t=NODE_TYPES[node.type];
 if(!t.win)return []; // non-windows: handled via data-source mapping instead
 // linux servers/workstations don't emit Windows Event IDs
 if(/linux|macos/i.test(node.os))return [];
 return LOGSRC.filter(ev=>{
  if(!ev.roles.includes(t.role))return false;
  if(ev.sysmon && lsAnswers.sysmon!=='yes')return false;
  if(ev.ch.startsWith('PowerShell') && lsAnswers.pwsh!=='yes')return false;
  return ev.phase==='hunt'||ev.phase==='both';
 });
}
/* Which nodes emit a given event id? */
function lsNodesForEvent(evId){
 return lsNodes.filter(n=>lsEventsForNode(n).some(e=>e.id===evId));
}
/* All unique events across the current topology */
function lsTopoEvents(){
 const set=new Map();
 lsNodes.forEach(n=>lsEventsForNode(n).forEach(e=>set.set(e.id,e)));
 return [...set.values()];
}
/* ---- node risk heat: exposure vs telemetry coverage ----
   A blind spot = exposed position with little/no monitoring. Score 0..1 (hot). */
function lsNodeHeat(n){
 const t=NODE_TYPES[n.type];
 // exposure by the node's EFFECTIVE zone (respects per-node overrides)
 const zoneExp={external:1,dmz:0.9,edge:0.75,cloud:0.55,internal:0.4,core:0.65}[nodeZone(n)]??0.5;
 // extra exposure for known pivot/foothold types
 const typeExp={iot:0.2,vpn:0.15,nas:0.1,dmz:0.1}[n.type]||0;
 const exposure=Math.min(1,zoneExp+typeExp);
 // telemetry coverage 0..1 - 18 event IDs is treated as thorough monitoring
 let cover;
 if(t.win&&!/linux|macos/i.test(n.os)){
  cover=Math.min(1,lsEventsForNode(n).length/18);
 } else {
  cover=t.win?0.15:0.35; // linux on a windows-typed host = thin; infra w/ syslog = modest
 }
 // even a well-monitored host keeps residual risk from its position, so coverage
 // damps exposure rather than cancelling it (max 80% reduction).
 const heat=exposure*(1-0.8*cover);
 return Math.max(0,Math.min(1,heat));
}
function lsHeatColor(h){
 // green→amber→red
 if(h<0.25)return'#3ddc97';
 if(h<0.5)return'#ffb547';
 if(h<0.72)return'#ff8a5c';
 return'#ff4d8f';
}
function lsToggleHeat(){lsHeatOn=!lsHeatOn;renderLogSrc();}
/* #13 collapse / expand a zone group */
function lsExpandZone(z){lsCollapsed.delete(z);renderLogSrc();}
function lsCollapseZone(z){lsCollapsed.add(z);renderLogSrc();}
function lsToggleZoneCollapse(z){lsCollapsed.has(z)?lsCollapsed.delete(z):lsCollapsed.add(z);renderLogSrc();}
function lsZonesPresent(){const s=new Set();lsNodes.forEach(n=>s.add(nodeZone(n)));return [...s];}
function openLsGroups(){
 let v=document.getElementById('ls-grp-veil');
 if(!v){v=document.createElement('div');v.id='ls-grp-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const zs=lsZonesPresent();
 v.innerHTML=`<div class="ls-det-sheet">
   <div class="ls-ne-grip" onclick="lsCloseGroups()"></div>
   <div class="ls-det-head">Collapse zone groups</div>
   <div class="ls-det-sub">Collapse a segment into a single icon to simplify a large map. Tap a collapsed cluster on the map to expand it again.</div>
   ${zs.map(z=>{const members=lsNodes.filter(n=>nodeZone(n)===z);const col=zoneColor(z),label=zoneLabel(z);const on=lsCollapsed.has(z);
     return`<div class="ls-grp-row"><span class="ls-grp-dot" style="background:${col}"></span><span class="ls-grp-name">${label}</span><span class="ls-grp-count">${members.length} host${members.length===1?'':'s'}</span><button class="ls-snap-btn ${on?'on':''}" onclick="lsToggleZoneCollapse('${z}');openLsGroups()">${on?'expand':'collapse'}</button></div>`;
   }).join('')}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseGroups();};
}
function lsCloseGroups(){const v=document.getElementById('ls-grp-veil');if(v)v.classList.remove('open');}
/* ---- #14 auto-suggest observations on adjacent nodes ---- */
/* the events you'd expect to confirm lateral movement TO a neighbour */
const LATMOVE_EVENTS={
 dc:['4768','4769','4624','4672'],srv:['4624','5140','5145','4688','7045'],
 wks:['4624','4688','5140','7045'],nas:['5140','5145'],dmz:['4624','4688'],
 cloud:['ConsoleLogin','AssumeRole'],vpn:['4624'],default:['4624','4688']
};
function lsAdjacent(uid){
 const adj=new Set();
 lsEdges.forEach(e=>{if(e.a===uid)adj.add(e.b);if(e.b===uid)adj.add(e.a);});
 return [...adj].map(id=>lsNodes.find(n=>n.uid===id)).filter(Boolean);
}
function lsAdjacentSuggestHTML(n){
 const adj=lsAdjacent(n.uid).filter(x=>lsNodeStatus(x)!=='malicious');
 if(!adj.length)return `<div class="ls-adj-sugg"><div class="ls-adj-h">Spread check</div><div class="ls-adj-none">No links from this host yet. Use <b>Connect</b> to draw its real adjacencies, then AEGIS will suggest where to hunt next.</div></div>`;
 return `<div class="ls-adj-sugg">
   <div class="ls-adj-h">Where to hunt next - ${adj.length} adjacent host${adj.length===1?'':'s'}</div>
   <div class="ls-adj-sub">If this host is compromised, check these neighbours for the same actor:</div>
   ${adj.map(a=>{const evs=(LATMOVE_EVENTS[a.type]||LATMOVE_EVENTS.default).slice(0,4);
     return `<div class="ls-adj-row"><span class="ls-adj-node">${NODE_TYPES[a.type].glyph} ${esc(a.label)}</span><span class="ls-adj-evs">${evs.join(' · ')}</span><button class="ls-adj-jump" onclick="lsQuickObs('${a.uid}')" data-tip="Log an observation on this neighbour">log</button></div>`;
   }).join('')}
 </div>`;
}
/* ---- named map templates ---- */
const LS_TEMPLATES={
 smb:{name:'Small business',blurb:'Flat network - one DC, a few workstations, a NAS behind a firewall.',
   nodes:[['internet',600,50],['fw',600,150],['dc',200,180],['nas',420,180],['wks',150,320],['wks',300,320],['wks',450,320]]},
 adcloud:{name:'AD + Cloud',blurb:'Hybrid identity - on-prem AD with a cloud tenant and DMZ web tier.',
   nodes:[['internet',610,50],['fw',610,150],['dmz',610,260],['router',440,150],['switch',300,270],['dc',140,180],['srv',300,400],['wks',140,340],['wks',140,440],['cloud',610,390]]},
 ot:{name:'OT / ICS network',blurb:'Segmented plant - IT hosts up top, an OT cell with PLCs behind a firewall.',
   nodes:[['internet',600,50],['fw',600,150],['dc',180,150],['wks',180,270],['switch',420,270],['router',420,150],['iot',330,410],['iot',480,410],['srv',600,300]]},
 remote:{name:'Remote workforce',blurb:'VPN-centric - remote endpoints landing through a VPN gateway to core.',
   nodes:[['internet',600,50],['vpn',600,160],['fw',430,160],['dc',180,180],['srv',330,320],['wks',150,320],['wks',150,430],['cloud',600,320]]}
};
async function lsLoadTemplate(key){
 const tpl=LS_TEMPLATES[key];if(!tpl)return;
 if(lsNodes.length&&!await uiConfirm(`Replace the current map with the "${tpl.name}" template? Your current nodes and links will be cleared (export the case first if you want to keep them).`))return;
 lsNodes=[];lsEdges=[];lsNodeSeq=1;lsScrubT=null;lsPendingChain=null;lsAnim=null;
 tpl.nodes.forEach(([type,x,y])=>lsAddNode(type,x,y,false));
 lsAutoEdges();
 // reset undo baseline to the loaded template
 lsHist=[JSON.stringify({nodes:lsNodes,edges:lsEdges,seq:lsNodeSeq})];lsHistIdx=0;
 closeLsTemplates();renderLogSrc();toast(`Loaded the "${tpl.name}" template`);
}
function openLsTemplates(){
 let v=document.getElementById('ls-tpl-veil');
 if(!v){v=document.createElement('div');v.id='ls-tpl-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-tpl-sheet">
   <div class="ls-ne-grip" onclick="closeLsTemplates()"></div>
   <div class="ls-tpl-head">Start from a template</div>
   <div class="ls-tpl-list">
   ${Object.entries(LS_TEMPLATES).map(([k,t])=>`<button class="ls-tpl-card" onclick="lsLoadTemplate('${k}')">
     <div class="ls-tpl-name">${t.name}</div>
     <div class="ls-tpl-blurb">${t.blurb}</div>
     <div class="ls-tpl-meta">${t.nodes.length} nodes</div>
   </button>`).join('')}
   </div>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeLsTemplates();};
}
function closeLsTemplates(){const v=document.getElementById('ls-tpl-veil');if(v)v.classList.remove('open');}
/* Attack-flow: for a selected event, describe the movement it represents between zones */
const LS_FLOW={
 '4624':{from:['wks','srv','dmz'],to:['dc','srv'],label:"logon / authentication"},
 '4625':{from:['wks','srv','dmz'],to:['dc'],label:"failed auth (spray/brute)"},
 '4648':{from:['wks','srv'],to:['srv','dc'],label:"explicit-cred lateral use"},
 '4688':{self:true,label:"process execution on host"},
 '4104':{self:true,label:"PowerShell execution on host"},
 '4769':{from:['wks','srv'],to:['dc'],label:"Kerberos service-ticket (roasting)"},
 '4662':{from:['srv','wks'],to:['dc'],label:"DCSync replication pull"},
 '5140':{from:['wks','srv'],to:['srv'],label:"admin-share access (lateral)"},
 '5145':{from:['wks','srv'],to:['srv'],label:"file collection over share"},
 '5156':{self:true,to:['fw','cloud'],label:"outbound connection / C2"},
 '7045':{self:true,label:"service install (persistence/PsExec)"},
 '4732':{self:true,label:"privileged group change"},
 'Sysmon 10':{self:true,label:"LSASS access (cred dump)"}
};

function lsTopologyHTML(){
 const events=lsTopoEvents();
 const sel=lsSelEvent;
 // group events for the picker
 const byCat={};events.forEach(e=>{(byCat[e.cat]=byCat[e.cat]||[]).push(e);});
 const cats=Object.keys(byCat).sort();
 return`<div class="ls-topo">
   <div class="ls-quiz-head">
     <div class="ls-topo-title"><span class="ls-topo-titletag">Network Map</span> - drag to build your environment, click a node to log what you're seeing, then let the AI trace the attack across it</div>
   </div>
   <div class="ls-topo-grid">
     <div class="ls-topo-canvaswrap">
       <div class="ls-topo-toolbar">
         <button class="ls-toolbtn primary" onclick="openLsAddMenu()" data-tip="Add a host to the map">\uff0b Add host</button>
         <button class="ls-toolbtn" onclick="openLsTemplates()" data-tip="Start from a named template">\u29c9 Templates</button>
         <span class="ls-tb-div"></span>
         <div class="ls-toolgrp" data-tip="Pointer selects and drags. Hand pans the map \u2014 or hold Space with the pointer.">
           <button class="${lsTool==='select'?'on':''}" onclick="lsSetTool('select')">\u2196</button>
           <button class="${lsTool==='pan'?'on':''}" onclick="lsSetTool('pan')">\u270b</button>
         </div>
         <button class="ls-toolbtn ${lsConnectMode?'on':''}" onclick="lsToggleConnect()" data-tip="Connect two hosts with a link">\u234c Link</button>
         <button class="ls-toolbtn ${lsChainMode?'on':''}" onclick="lsToggleChainMode()" data-tip="Click hosts in attack order, then play the path">\u21b3 Trace</button>
         <span class="ls-tb-div"></span>
         <button class="ls-toolbtn" onclick="lsUndo()" ${lsCanUndo()?'':'disabled'} data-tip="Undo">\u21b6</button>
         <button class="ls-toolbtn" onclick="lsRedo()" ${lsCanRedo()?'':'disabled'} data-tip="Redo">\u21b7</button>
         <div class="ls-find"><input id="ls-find" placeholder="Find host\u2026" value="${esc(lsQuery||'')}" oninput="lsSearch(this.value)"><span id="ls-findcount"></span></div>
         <span class="ls-tb-sep"></span>
         <button class="ls-toolbtn" onclick="openLsMapMenu()" data-tip="View options, zones, snapshots, export and more">\u22ef More</button>
         <button class="ls-toolbtn danger" onclick="lsClearMap()" data-tip="Remove everything from the map">\u2715 Clear</button>
       </div>
       <div class="ls-canvas" id="ls-canvas">${lsCanvasSVG()}<div class="ls-anim-cap" id="ls-anim-cap" style="display:none"></div>
         <div class="ls-zoomctl">
           <button onclick="lsZoomBy(1.2)" data-tip="Zoom in">+</button>
           <button onclick="lsZoomBy(0.83)" data-tip="Zoom out">−</button>
           <button onclick="lsZoomReset()" data-tip="Reset zoom">⊙</button>
           <button onclick="lsZoomFit()" data-tip="Zoom to fit everything">⛶</button>
           <span class="ls-zoompct" id="ls-zoompct">${lsZoomPct()}%</span>
         </div>
         <div class="ls-fab-wrap">
           <div class="ls-fab-menu" id="ls-fab-menu">
             ${Object.entries(NODE_TYPES).map(([k,t])=>`<button onclick="lsFabAdd('${k}')">${t.glyph} ${t.label.split(' ')[0]}</button>`).join('')}
           </div>
           <button class="ls-fab" onclick="document.getElementById('ls-fab-menu').classList.toggle('open')" data-tip="Add a node">+</button>
         </div>
       </div>
       ${lsNodes.length?'':lsEmptyStateHTML()}
       ${lsSel.size?`<div class="ls-bulkbar"><b>${lsSel.size}</b> selected
         <select onchange="if(this.value)lsBulkZone(this.value)"><option value="">Move to zone\u2026</option>${Object.keys(ZONES).map(z=>`<option value="${z}">${esc(zoneLabel(z))}</option>`).join('')}</select>
         ${lsSel.size===1?`<button onclick="lsDuplicate('${[...lsSel][0]}')">Duplicate</button>`:''}
         <button class="del" onclick="lsBulkDelete()">Delete</button>
         <button onclick="lsSelClear()">Clear</button></div>`:''}
       ${lsIncidentStrip()}
       <div class="ls-canvas-hint">${
         lsConnectMode?`<b style="color:var(--sky)">Connect mode</b> - click a node, then another, to link them.${lsConnectFrom?' Source selected - pick the destination.':''} Click <b>Connect</b> again to exit.`
         :lsChainMode?`<b style="color:var(--magenta)">Trace mode</b> - click nodes in attack order (${lsManualChain.length} selected)${lsManualChain.length>=2?' - then ▶ Play path below':''}. Click the last node again to undo.`
         :`<b>Click</b> a host to triage \u00b7 <b>double-click</b> to rename \u00b7 <b>drag between lanes</b> to change its zone${lsSelEvent?` \u00b7 showing <b>${lsSelEvent}</b>`:''}`
       }</div>
       ${(()=>{const r=lsObsTimeRange();if(!r||r.min===r.max)return'';const cur=lsScrubT==null?r.max:lsScrubT;const shown=lsNodes.reduce((a,n)=>a+lsNodeObs(n).length,0);return`<div class="ls-scrubber">
         <span class="ls-scrub-icon" data-tip="Scrub through the incident - drag to replay how observations appeared over time">◷</span>
         <input type="range" id="ls-scrub" min="${r.min}" max="${r.max}" value="${cur}" step="1000" oninput="lsScrubSet(this.value)">
         <span class="ls-scrub-meta"><b id="ls-scrub-cnt">${shown}</b> obs · <span id="ls-scrub-lbl">${lsScrubT==null||lsScrubT>=r.max?'now (all observations)':new Date(cur).toLocaleTimeString()}</span></span>
         ${lsScrubT!=null?`<button class="ls-scrub-reset" onclick="lsScrubReset()">reset</button>`:''}
       </div>`;})()}
     </div>
     <aside class="ls-topo-side">
       ${sel?lsEventDetailHTML(sel):`<div class="ls-side-intro"><h3>Which logs cover this map</h3><p>These are the <b>${events.length} Event IDs your hosts can actually produce</b>. Click one to light up the hosts it comes from \u2014 use it to check a technique is visible before you rely on it, or to spot which segments log nothing.</p></div>`}
       <div class="ls-evpicker">
         ${cats.map(c=>`<div class="ls-evcat"><div class="ls-evcat-h">${c}</div>${byCat[c].map(e=>`<button class="ls-evchip${sel===e.id?' on':''}" onclick="lsSelectEvent('${e.id}')" data-tip="${esc(e.why)}">${e.id}<span class="ls-evchip-noise" style="color:${lsNoiseColor(e.noise)}">${'●'.repeat(e.noise)}</span></button>`).join('')}</div>`).join('')}
       </div>
     </aside>
   </div>
   <div class="ls-topo-foot">
     <div class="ls-topo-stats">
       <span class="chain-sum-pill"><b>${lsNodes.length}</b> nodes</span>
       <span class="chain-sum-pill"><b>${events.length}</b> Event IDs available</span>
       ${lsHasIncident()?`<span class="chain-sum-pill inc"><b>${lsNodes.filter(n=>n.obs&&n.obs.length).length}</b> hosts with observations</span>`:''}
     </div>
     ${lsHasIncident()?`<button class="btn magenta" onclick="analyzeIncident()" data-tip="Ask the AI to correlate everything observed across the map into a likely attack chain, then watch it trace across the map">◎ Analyse &amp; trace hunt map</button>`:''}
     ${lsChainMode&&lsManualChain.length>=2?`<button class="btn magenta" onclick="lsPlayManualChain()" data-tip="Animate the attack path you just mapped">▶ Play path (${lsManualChain.length})</button>`:''}
     ${lsPendingChain&&!lsAnim&&!lsChainMode?`<button class="btn ghost-violet" onclick="lsTracePending()" data-tip="Replay the last AI-reconstructed attack chain on the map">▶ Replay trace</button>`:''}
     <button class="btn ghost-violet" onclick="lsBuildFromTopo()" data-tip="Generate a prioritised logging checklist for this exact network - which Event IDs to turn on first and the inputs.conf to do it">\u2699 Logging plan</button>
     ${studio.size?`<button class="btn ghost-violet" onclick="lsOpenDetCoverage()" data-tip="Which of your staged detections would actually fire on the hosts in this map?">◈ Detection coverage</button>`:''}
     <button class="btn ghost-violet" onclick="if(!studio.size){toast('Stage techniques in the Matrix first to include them in the report');}else{openReport();}" data-tip="Open the full report - this live network map and any observations are included. Refresh anytime.">Add to report ↗</button>
   </div>
 </div>`;
}

function lsNodesSVG(){
 const sel=lsSelEvent;
 const isCollapsed=n=>lsCollapsed.has(nodeZone(n));
 const visibleNodes=lsNodes.filter(n=>!isCollapsed(n));
 const compromised=new Set(lsNodes.filter(n=>lsNodeStatus(n)==='malicious').map(n=>n.uid));
 const reachable=new Set();
 lsEdges.forEach(e=>{if(compromised.has(e.a)&&!compromised.has(e.b))reachable.add(e.b);if(compromised.has(e.b)&&!compromised.has(e.a))reachable.add(e.a);});
 return visibleNodes.map(n=>{
  const t=NODE_TYPES[n.type];
  const emits=t.win?lsEventsForNode(n):[];
  const lit = sel ? (t.win ? emits.some(e=>e.id===sel) : false) : false;
  const dim = (sel && !lit) || (lsAnim && lsAnim.active && !lsAnimNodeActive(n.uid));
  const isLinux=/linux|macos/i.test(n.os);
  const status=lsNodeStatus(n);
  const obsN=lsNodeObs(n).length;
  const animHit=lsAnim&&lsAnim.active&&lsAnimNodeActive(n.uid);
  const connFrom=lsConnectMode&&lsConnectFrom===n.uid;
  const inChain=lsChainMode&&lsManualChain.includes(n.uid);
  const chainIdx=inChain?lsManualChain.indexOf(n.uid)+1:0;
  const isReachable=reachable.has(n.uid);
  const cls=`ls-node ${nodeZone(n)} ${n.live?'live':''} ${n.stale?'stale':''} ${lsSel.has(n.uid)?'multi-sel':''} ${lit?'lit':''} ${dim?'dim':''} ${status?('inc-'+status):''} ${animHit?'anim-hit':''} ${connFrom?'conn-from':''} ${isReachable?'reachable':''}`;
  const count=t.win?emits.length:0;
  const statusRing=status?`<rect x="-55" y="-33" width="110" height="66" rx="13" class="ls-node-ring inc-${status}"/>`:'';
  const animRing=animHit?`<rect x="-58" y="-36" width="116" height="72" rx="15" class="ls-anim-ring"/>`:'';
  const reachRing=isReachable&&!status?`<rect x="-56" y="-34" width="112" height="68" rx="14" class="ls-reach-ring"/>`:'';
  const heat=lsHeatOn?lsNodeHeat(n):null;
  const heatFill=lsHeatOn?`fill="${lsHeatColor(heat)}" fill-opacity="0.16" stroke="${lsHeatColor(heat)}" stroke-opacity="0.85" stroke-width="2"`:'';
  const heatBadge=lsHeatOn?`<g class="ls-heat-badge" transform="translate(40,30)"><circle r="9" fill="${lsHeatColor(heat)}"/><text y="3" text-anchor="middle" style="fill:#0a0a12;font-size:8px;font-weight:700;font-family:'IBM Plex Mono',monospace">${Math.round(heat*100)}</text></g>`:'';
  return`<g class="${cls}" transform="translate(${n.x},${n.y}) scale(${(n.scale||1)*lsNodeScale})" data-uid="${n.uid}" style="cursor:${lsConnectMode||lsChainMode?'pointer':'grab'}">
    ${animRing}${reachRing}${statusRing}
    <rect x="-52" y="-30" width="104" height="60" rx="11" class="ls-node-box" ${heatFill}/>
    <text x="0" y="-9" text-anchor="middle" class="ls-node-glyph">${t.glyph}</text>
    <text x="0" y="9" text-anchor="middle" class="ls-node-label">${esc(n.label.length>15?n.label.slice(0,14)+'…':n.label)}</text>
    <text x="0" y="21" text-anchor="middle" class="ls-node-os">${esc((n.os||'').length>16?n.os.slice(0,15)+'…':n.os)}</text>
    ${t.win&&!isLinux?`<g class="ls-node-badge" transform="translate(40,-30)"><circle r="11" class="ls-badge-c"/><text y="3.5" text-anchor="middle" class="ls-badge-t">${count}</text></g>`:''}
    ${!t.win||isLinux?`<g class="ls-node-badge alt" transform="translate(40,-30)"><circle r="11" class="ls-badge-c"/><text y="3.5" text-anchor="middle" class="ls-badge-t">⇄</text></g>`:''}
    ${obsN?`<g class="ls-node-obs inc-${status}" transform="translate(-40,-30)"><circle r="11"/><text y="3.5" text-anchor="middle">${obsN}</text></g>`:''}
    ${chainIdx?`<g class="ls-chain-num" transform="translate(-40,30)"><circle r="10"/><text y="3.5" text-anchor="middle">${chainIdx}</text></g>`:''}
    ${heatBadge}
    <g class="ls-node-rs" data-uid="${n.uid}">
      <rect x="42" y="20" width="18" height="18" fill="transparent"/>
      <path d="M 46 36 L 56 26 M 51 36 L 56 31" class="ls-nrs-p"/>
    </g>
    <g class="ls-node-x" data-uid="${n.uid}">
      <circle cx="52" cy="-30" r="10" class="ls-nx-c"/>
      <path d="M 48 -34 L 56 -26 M 56 -34 L 48 -26" class="ls-nx-p"/>
    </g>
  </g>`;
 }).join('');
}
function lsCanvasSVG(){
 const W=LS_W,H=LS_H;
 const sel=lsSelEvent;
 const flow=sel?LS_FLOW[sel]:null;
 const nodeById=id=>lsNodes.find(n=>n.uid===id);
 // zone overlay behind everything
 const zones=lsZoneRegions();
 // edges: custom if the user has drawn any, else inferred backbone
 let edges='';
 const hidden=uid=>{const n=lsNodes.find(x=>x.uid===uid);return n&&lsCollapsed.has(nodeZone(n));};
 if(lsEdges.length){
  lsEdges.forEach(e=>{if(hidden(e.a)||hidden(e.b))return;const a=nodeById(e.a),b=nodeById(e.b);if(a&&b)edges+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="ls-edge${e.discovered?' discovered':''}"/>`+lsEdgeLabel(e);});
 }else{
  const byType=t=>lsNodes.filter(n=>n.type===t);
  function link(a,b){if(!a||!b)return;edges+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="ls-edge"/>`;}
  const fw=byType('fw')[0], dc=byType('dc')[0], rtr=byType('router')[0], sw=byType('switch')[0], net=byType('internet')[0];
  byType('vpn').forEach(v=>link(net,v));
  if(net&&fw)link(net,fw);
  if(fw&&rtr)link(fw,rtr);
  byType('dmz').forEach(d=>link(fw||net,d));
  byType('cloud').forEach(c=>link(fw||net,c));
  if(rtr&&sw)link(rtr,sw);
  if(rtr&&dc)link(rtr,dc);
  const fabric=sw||dc||rtr;
  lsNodes.filter(n=>['srv','wks','nas','iot'].includes(n.type)).forEach(n=>link(fabric,n));
  if(dc&&sw)link(sw,dc);
 }
 // connect-mode: highlight the pending source
 // attack-flow overlay (per-event, manual)
 let flowPaths='';
 if(sel && lsFlowView==='attack' && flow){
  const srcNodes = flow.self ? lsNodesForEvent(sel) : lsNodes.filter(n=>flow.from&&flow.from.includes(n.type));
  const dstNodes = flow.to ? lsNodes.filter(n=>flow.to.includes(n.type)) : (flow.self?[]:lsNodesForEvent(sel));
  srcNodes.forEach(s=>{(dstNodes.length?dstNodes:[s]).forEach(d=>{
   if(s.uid===d.uid){flowPaths+=`<circle cx="${s.x}" cy="${s.y-42}" r="10" class="ls-flow-self"/>`;return;}
   const mx=(s.x+d.x)/2,my=(s.y+d.y)/2-40;
   flowPaths+=`<path d="M ${s.x} ${s.y} Q ${mx} ${my} ${d.x} ${d.y}" class="ls-flow-path" marker-end="url(#ls-flowarrow)"/>`;
  });});
 }
 // manual chain overlay
 let manualPaths='';
 if(lsChainMode&&lsManualChain.length){
  for(let i=0;i<lsManualChain.length-1;i++){
   const a=nodeById(lsManualChain[i]),b=nodeById(lsManualChain[i+1]);if(!a||!b)continue;
   const mx=(a.x+b.x)/2,my=(a.y+b.y)/2-40;
   manualPaths+=`<path d="M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}" class="ls-manual-path" marker-end="url(#ls-animarrow)"/>`;
  }
 }
 // telemetry overlay: highlight source nodes only (no external sink)
 // (highlight handled per-node below via the 'lit' class)
 // AI attack-chain animation overlay
 let animLayer=lsAnimSVG();
 // reachable-target hint: nodes adjacent to a compromised node (compromise-flow)
 const compromised=new Set(lsNodes.filter(n=>lsNodeStatus(n)==='malicious').map(n=>n.uid));
 const reachable=new Set();
 if(compromised.size&&lsEdges.length){
  lsEdges.forEach(e=>{if(compromised.has(e.a)&&!compromised.has(e.b))reachable.add(e.b);if(compromised.has(e.b)&&!compromised.has(e.a))reachable.add(e.a);});
 }
 // #13 collapsed zone groups: hide members, draw one cluster puck per collapsed zone
 const isCollapsed=n=>lsCollapsed.has(nodeZone(n));
 const visibleNodes=lsNodes.filter(n=>!isCollapsed(n));
 let clusters='';
 lsCollapsed.forEach(z=>{
  const members=lsNodes.filter(n=>nodeZone(n)===z);
  if(!members.length)return;
  const cx=members.reduce((a,n)=>a+n.x,0)/members.length;
  const cy=members.reduce((a,n)=>a+n.y,0)/members.length;
  const obs=members.reduce((a,n)=>a+lsNodeObs(n).length,0);
  const worst=members.map(n=>lsNodeStatus(n)).filter(Boolean);
  const st=worst.includes('malicious')?'malicious':worst.includes('suspicious')?'suspicious':worst.length?'info':null;
  const col=zoneColor(z),label=zoneLabel(z);
  clusters+=`<g class="ls-cluster ${st?'inc-'+st:''}" transform="translate(${cx},${cy})" onclick="lsExpandZone('${z}')" style="cursor:pointer">
    <rect x="-66" y="-34" width="132" height="68" rx="14" fill="${col}" fill-opacity="0.14" stroke="${col}" stroke-width="2"/>
    <text x="0" y="-8" text-anchor="middle" style="fill:${col};font-size:11px;font-weight:700;font-family:'Sora',sans-serif">${label}</text>
    <text x="0" y="8" text-anchor="middle" style="fill:var(--t2);font-size:9px;font-family:'IBM Plex Mono',monospace">${members.length} hosts collapsed</text>
    <text x="0" y="23" text-anchor="middle" style="fill:var(--t3);font-size:8px;font-family:'IBM Plex Mono',monospace">${obs?obs+' obs · ':''}tap to expand</text>
  </g>`;
 });
 // nodes
 const nodesSVG=lsNodesSVG();
 return`<svg viewBox="0 0 ${W} ${H}" width="100%" height="100%" id="ls-svg" style="display:block">
   <defs>
     <marker id="ls-flowarrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--magenta)"/></marker>
     <marker id="ls-animarrow" markerWidth="10" markerHeight="10" refX="7" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#ff4d8f"/></marker>
   </defs>
   <g id="ls-zoomer" transform="translate(${lsPanX},${lsPanY}) scale(${lsZoom})">${lsGridSVG()}<g id="ls-zonelayer">${zones}</g>${edges}${flowPaths}${manualPaths}${animLayer}${clusters}<g id="ls-nodelayer">${nodesSVG}</g></g>
 </svg>`;
}
