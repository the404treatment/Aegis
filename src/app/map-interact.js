/* ---- manual chain builder (build an attack path without the AI) ---- */
function lsToggleChainMode(){lsChainMode=!lsChainMode;lsConnectMode=false;lsConnectFrom=null;lsManualChain=[];renderLogSrc();}
function lsChainAddNode(uid){
 // Click a host to add it as the next hop; click any host already in the path
 // to pull it back out (not just the last one), so re-pointing a hop at a
 // different computer is one click to remove and one to re-add - no need to
 // unwind the whole chain.
 const at=lsManualChain.indexOf(uid);
 if(at>=0){lsManualChain.splice(at,1);renderLogSrc();return;}
 lsManualChain.push(uid);renderLogSrc();
}
/* Remove one hop from the trace by its position (from the steps list). */
function lsChainRemoveAt(i){lsManualChain.splice(i,1);renderLogSrc();}
function lsChainClear(){lsManualChain=[];renderLogSrc();}
/* The ordered steps of the trace being built, as removable chips. */
function lsChainStepsHTML(){
 if(!lsChainMode)return'';
 if(!lsManualChain.length)return`<div class="ls-chain-steps empty">Trace: click hosts on the map in attack order - first host the attacker touched, then each hop. They number as you go.</div>`;
 const chips=lsManualChain.map((uid,i)=>{const n=lsNodes.find(x=>x.uid===uid);const label=n?n.label:'(deleted)';
  return`<span class="ls-chain-chip"><b>${i+1}</b> ${esc(label)}<button onclick="lsChainRemoveAt(${i})" data-tip="Remove this hop">×</button></span>`;}).join('<span class="ls-chain-arrow">→</span>');
 return`<div class="ls-chain-steps"><span class="ls-chain-lbl">Attack path</span>${chips}<button class="ls-chain-clear" onclick="lsChainClear()">clear</button></div>`;
}
/* Pick an OS from the list, or type a custom one. The advisor/response playbook
   classifies whatever free-text lands in n.os (network gear, Linux, Windows),
   so a typed "Palo Alto PAN-OS" drives network-device guidance with no extra
   wiring - the only thing missing before was a way to type it. */
async function lsPickNodeOS(uid,val){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 if(val==='__custom'){
  const v=await uiPrompt('OS / platform for this host:',NODE_TYPES[n.type].os.includes(n.os)?'':n.os,
    {title:'Custom OS / platform',ok:'Set',placeholder:'e.g. Palo Alto PAN-OS, MikroTik RouterOS, VMware ESXi'});
  if(v===null||!v.trim()){renderNodeEditor(n,NODE_TYPES[n.type]);return;}
  lsSetNodeOS(uid,v.trim());
 } else lsSetNodeOS(uid,val);
 renderNodeEditor(n,NODE_TYPES[n.type]);   // keep the editor open on the same host
}
function lsPlayManualChain(){
 if(lsManualChain.length<2){toast('Click at least two nodes to build a path');return;}
 const steps=[];
 for(let i=0;i<lsManualChain.length-1;i++)steps.push({from:lsManualChain[i],to:lsManualChain[i+1],detail:'analyst-mapped hop'});
 lsChainMode=false;lsManualChain=[];
 lsRunAnim(steps);
 toast('Playing your mapped attack path');
}
function renderNodeEditor(n,t){
 const host=document.getElementById('ls-node-editor');
 let box=document.getElementById('ls-node-editor');
 const wrap=document.querySelector('.ls-topo-canvaswrap');if(!wrap)return;
 if(!box){box=document.createElement('div');box.id='ls-node-editor';wrap.appendChild(box);}
 box.className='ls-node-editor';
 const isLinux=/linux|macos/i.test(n.os);
 const emit=(t.win&&!isLinux)?lsEventsForNode(n):[];
 const status=lsNodeStatus(n);
 const obs=n.obs||[];
 box.innerHTML=`
   <div class="ls-ne-grip" onclick="lsCloseNodeEdit()"></div>
   <div class="ls-ne-head"><span>${t.glyph} ${esc(n.label)}${status?` <span class="ls-ne-status inc-${status}">${SEV_META[status].label}</span>`:''}</span><button onclick="lsCloseNodeEdit()">×</button></div>
   <label class="ls-ne-label">Name</label>
   <input class="dash-input" style="width:100%" value="${esc(n.label)}" oninput="lsSetNodeLabel('${n.uid}',this.value)">
   <label class="ls-ne-label">OS / platform</label>
   <select class="nsel" style="width:100%" onchange="lsPickNodeOS('${n.uid}',this.value)">
     ${t.os.map(o=>`<option ${o===n.os?'selected':''}>${esc(o)}</option>`).join('')}
     ${t.os.includes(n.os)?'':`<option selected>${esc(n.os)}</option>`}
     <option value="__custom">✎ Other / not listed…</option>
   </select>
   <div class="ls-ne-hint">Not listed? Choose <b>Other</b> and type it - e.g. "Palo Alto PAN-OS", "MikroTik RouterOS", "VMware ESXi". The response playbook adapts to what you enter (network gear, Linux, Windows…).</div>
   <div class="ls-ne-zonerow">
     <span class="ls-ne-zlabel">Zone</span>
     <select class="nsel ls-ne-zsel" onchange="if(this.value==='__new'){const z=lsAddZone();if(z)lsSetNodeZone('${n.uid}',z);else renderLogSrc();}else lsSetNodeZone('${n.uid}',this.value)">
       ${Object.keys(ZONES).map(z=>`<option value="${z}" ${nodeZone(n)===z?'selected':''}>${esc(zoneLabel(z))}</option>`).join('')}
       <option value="__new">＋ New zone…</option>
     </select>
     <button class="ls-ne-zedit" onclick="openLsZoneMgr()" data-tip="Manage zones - rename, recolour, reorder">⚙</button>
   </div>
   ${(()=>{const d=lsNodeDetections(n);return studio.size&&d.covers.length?`<div class="ls-ne-det">✓ <b>${d.covers.length}</b> staged detection${d.covers.length===1?'':'s'} fire here: ${d.covers.slice(0,6).map(id=>`<span>${id}</span>`).join(' ')}${d.covers.length>6?' …':''}</div>`:'';})()}

   ${LIVE.connected?`<button class="ls-snap-btn" style="width:100%;margin-bottom:8px" onclick="tkFromNode('${n.uid}')">\u2691 Raise a ticket for this host</button>`:''}
   <div class="ls-ne-obs-head">Observed on this host <span>${obs.length?obs.length:''}</span></div>
   ${lsPendingStage?`<div class="ls-ne-stageoffer">Detected <b>${lsPendingStage.tid} ${esc(lsPendingStage.name)}</b> - stage it in the Studio?<div class="ls-ne-stageoffer-btns"><button class="btn mint" onclick="lsAcceptStage()">Stage it</button><button class="btn" onclick="lsDismissStage()">Not now</button></div></div>`:''}
   ${obs.length?`<div class="ls-ne-obs-list">${obs.map(o=>{const ev=LOGSRC.find(e=>e.id===o.evId);return`<div class="ls-ne-obs inc-${o.sev}">
      <div class="ls-ne-obs-top"><span class="ls-ne-obs-sev inc-${o.sev}">${SEV_META[o.sev].label}</span>${o.evId?`<span class="ls-ne-obs-ev">${o.evId}</span>`:''}${o.tech?`<span class="ls-ne-obs-tech">${esc(o.tech)}</span>`:''}<button class="ls-ne-obs-x" onclick="lsDelObs('${n.uid}','${o.id}')">×</button></div>
      ${ev?`<div class="ls-ne-obs-name">${ev.name}</div>`:''}
      ${o.note?`<div class="ls-ne-obs-note">${highlightIocs(o.note)}</div>`:''}
   </div>`;}).join('')}</div>`:`<div class="ls-ne-obs-empty">Nothing logged yet. Tag what you're seeing on this host below.</div>`}

   <div class="ls-ne-addobs">
     ${emit.length?`<label class="ls-ne-label">Event ID (quick pick)</label>
     <select class="nsel" id="ls-obs-ev" style="width:100%">
       <option value="">— none / other —</option>
       ${emit.map(e=>`<option value="${e.id}">${e.id} - ${e.name}</option>`).join('')}
     </select>`:''}
     <label class="ls-ne-label">Note (what did you see?)</label>
     <input class="dash-input" id="ls-obs-note" style="width:100%" placeholder="e.g. encoded PowerShell spawned by winword.exe">
     <label class="ls-ne-label">Severity</label>
     <div class="ls-sev-pick">
       <button class="ls-sev-btn info" data-sev="info" onclick="lsPickSev(this)">Info</button>
       <button class="ls-sev-btn suspicious on" data-sev="suspicious" onclick="lsPickSev(this)">Suspicious</button>
       <button class="ls-sev-btn malicious" data-sev="malicious" onclick="lsPickSev(this)">Malicious</button>
     </div>
     <button class="btn violet" style="width:100%;justify-content:center;margin-top:8px" onclick="lsSubmitObs('${n.uid}')">+ Log observation</button>
   </div>

   ${obs.length?`<button class="btn ghost-violet" style="width:100%;justify-content:center;margin-top:8px" onclick="lsTriageNode('${n.uid}')" data-tip="Ask the AI Analyst what this host's observations mean and what to check next">◎ AI: triage this host</button>`:''}
   <button class="btn ghost-violet" style="width:100%;justify-content:center;margin-top:8px" onclick="openAdvisor(null,'${n.uid}')" data-tip="Offline, deterministic containment/eradication/recovery commands for this host - no network, no LLM">▤ Response playbook</button>
   ${status==='malicious'?`<div class="ls-ne-contain">
     <div class="ls-ne-contain-h">⚠ Containment - ${esc(n.label)}</div>
     <label class="ls-contain-item"><input type="checkbox"> Isolate host from the network (EDR contain / switch ACL)</label>
     <label class="ls-contain-item"><input type="checkbox"> Disable / reset implicated account credentials</label>
     <label class="ls-contain-item"><input type="checkbox"> Capture volatile memory &amp; triage image before reboot</label>
     <label class="ls-contain-item"><input type="checkbox"> Preserve relevant logs off-host (they may be cleared)</label>
     <label class="ls-contain-item"><input type="checkbox"> Hunt the same IOCs on peer hosts in this zone</label>
     <label class="ls-contain-item"><input type="checkbox"> Notify IR lead &amp; open or update the incident ticket</label>
   </div>${lsAdjacentSuggestHTML(n)}`:''}

   <div class="ls-ne-note" style="margin-top:12px">${esc(t.note)}</div>
   ${!t.win?`<div class="ls-ne-src"><b>Data source:</b> ${t.src}<ul>${t.inputs.map(i=>`<li>${esc(i)}</li>`).join('')}</ul></div>`:(isLinux?`<div class="ls-ne-src"><b>Non-Windows OS:</b> emits no Windows Event IDs. Collect via syslog / auditd (Linux) or Unified Logging (macOS) with the relevant Splunk add-on.</div>`:'')}
   <button class="btn" style="width:100%;justify-content:center;margin-top:10px" onclick="lsDelNode('${n.uid}');lsCloseNodeEdit()">Remove node</button>
 `;
 box.style.display='block';
 box._sev='suspicious';
}
let _lsPendingSev='suspicious';
function lsPickSev(btn){
 document.querySelectorAll('.ls-sev-btn').forEach(b=>b.classList.remove('on'));
 btn.classList.add('on');_lsPendingSev=btn.getAttribute('data-sev');
}
function lsSubmitObs(uid){
 const evSel=document.getElementById('ls-obs-ev');
 const evId=evSel?evSel.value:'';
 const note=(document.getElementById('ls-obs-note')||{}).value||'';
 if(!evId&&!note.trim()){toast('Pick an Event ID or write a note first');return;}
 lsAddObs(uid,evId,note.trim(),_lsPendingSev);
 // re-open editor to show the new observation
 const n=lsNodes.find(x=>x.uid===uid);if(n)renderNodeEditor(n,NODE_TYPES[n.type]);
 toast('Observation logged');
}
function lsCloseNodeEdit(){lsEditNode=null;const b=document.getElementById('ls-node-editor');if(b)b.style.display='none';}
/* ---- long-press quick observation logger ---- */
let _lsQuickSev='suspicious';
function lsQuickObs(uid){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 _lsQuickSev='suspicious';
 let v=document.getElementById('ls-quick-veil');
 if(!v){v=document.createElement('div');v.id='ls-quick-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const t=NODE_TYPES[n.type];const isLinux=/linux|macos/i.test(n.os);
 const emit=(t.win&&!isLinux)?lsEventsForNode(n):[];
 v.innerHTML=`<div class="ls-quick-sheet">
   <div class="ls-ne-grip" onclick="lsCloseQuick()"></div>
   <div class="ls-quick-head">${t.glyph} ${esc(n.label)} <span>quick log</span></div>
   ${emit.length?`<select class="nsel" id="ls-quick-ev" style="width:100%;margin-bottom:8px">
     <option value="">— Event ID (optional) —</option>
     ${emit.map(e=>`<option value="${e.id}">${e.id} - ${e.name}</option>`).join('')}
   </select>`:''}
   <input class="dash-input" id="ls-quick-note" style="width:100%;margin-bottom:8px" placeholder="What did you see?">
   <div class="ls-sev-pick" style="margin-bottom:10px">
     <button class="ls-sev-btn info" data-sev="info" onclick="lsQuickSev(this)">Info</button>
     <button class="ls-sev-btn suspicious on" data-sev="suspicious" onclick="lsQuickSev(this)">Suspicious</button>
     <button class="ls-sev-btn malicious" data-sev="malicious" onclick="lsQuickSev(this)">Malicious</button>
   </div>
   <div style="display:flex;gap:8px">
     <button class="btn" style="flex:1;justify-content:center" onclick="lsCloseQuick()">Cancel</button>
     <button class="btn violet" style="flex:2;justify-content:center" onclick="lsQuickSubmit('${n.uid}')">Log observation</button>
   </div>
 </div>`;
 v.classList.add('open');
 v.onclick=(e)=>{if(e.target===v)lsCloseQuick();};
 setTimeout(()=>{const el=document.getElementById('ls-quick-note');if(el)el.focus();},60);
}
function lsQuickSev(btn){document.querySelectorAll('#ls-quick-veil .ls-sev-btn').forEach(b=>b.classList.remove('on'));btn.classList.add('on');_lsQuickSev=btn.getAttribute('data-sev');}
function lsQuickSubmit(uid){
 const evSel=document.getElementById('ls-quick-ev');const evId=evSel?evSel.value:'';
 const note=(document.getElementById('ls-quick-note')||{}).value||'';
 if(!evId&&!note.trim()){toast('Pick an Event ID or write a note');return;}
 lsAddObs(uid,evId,note.trim(),_lsQuickSev);lsCloseQuick();toast('Observation logged');
}
function lsCloseQuick(){const v=document.getElementById('ls-quick-veil');if(v)v.classList.remove('open');}
function lsFabAdd(type){document.getElementById('ls-fab-menu').classList.remove('open');lsAddNode(type);}


function lsResultHTML(){
 const picks=lsResult.picks;
 const included=picks.filter(p=>lsMode==='baseline'?true:true);
 const noisy=picks.filter(p=>p.flagged).length;
 const withDet=picks.filter(p=>p.ev.linked).length;
 const roles=lsResult.generic?'all host types':[...lsAnswers.roles].map(r=>LS_ROLES[r]).join(', ');
 // group by channel for readability
 const byCh={};picks.forEach(p=>{(byCh[p.ev.ch]=byCh[p.ev.ch]||[]).push(p);});
 const chOrder=['Security','System','PowerShell/Operational','Sysmon'];
 const chans=Object.keys(byCh).sort((a,b)=>{const ia=chOrder.indexOf(a),ib=chOrder.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib);});
 const tog=(k,v,label)=>`<button class="ls-plan-tog${lsAnswers[k]===v?' on':''}" onclick="lsAnswers.${k}='${v}';lsBuildFromTopo()">${label}</button>`;
 return`<div class="ls-result">
   <div class="ls-res-head">
     <div class="ls-res-title">
       <h2>Event-ID plan · ${picks.length} sources</h2>
       <span class="ls-res-sub">Derived from your ${lsNodes.filter(n=>NODE_TYPES[n.type].win).length} Windows host${lsNodes.filter(n=>NODE_TYPES[n.type].win).length===1?'':'s'} - ${esc(roles)}</span>
     </div>
     <div class="ls-res-actions">
       <button class="btn ghost-violet" onclick="lsCopyChecklist()" data-tip="Copy the audit-policy + inputs.conf enablement checklist">Copy checklist</button>
       <button class="btn" onclick="lsDownloadDash()" data-tip="Download a Splunk health dashboard: is each event ID actually flowing?">Health dashboard XML</button>
       <button class="btn mint" onclick="lsToStudio()" data-tip="Send the detection-backed events to the Detection Studio">Send to Studio →</button>
     </div>
   </div>
   <div class="ls-plan-settings">
     <span class="ls-plan-slabel">Sysmon</span>${tog('sysmon','yes','Deployed')}${tog('sysmon','no','No')}
     <span class="ls-plan-slabel">PowerShell logging</span>${tog('pwsh','yes','Yes')}${tog('pwsh','no','No')}
     <span class="ls-plan-slabel">Volume</span>${tog('noise','quiet','Quiet')}${tog('noise','balanced','Balanced')}${tog('noise','verbose','Verbose')}
   </div>
   <div class="ls-res-stats">
     <span class="chain-sum-pill"><b>${picks.length}</b> event IDs</span>
     <span class="chain-sum-pill"><b>${withDet}</b> with ready detections</span>
     ${noisy?`<span class="chain-sum-pill" style="border-color:var(--magenta-line);color:var(--magenta)"><b>${noisy}</b> high-volume - scope these</span>`:''}
   </div>
   ${(lsResult.fromTopo&&(lsResult.nonWin.cloud||lsResult.nonWin.fw))?`<div class="ls-nonwin-note"><div class="ls-nonwin-h">Your network also has non-Windows sources</div>${lsResult.nonWin.fw?`<div class="ls-nonwin-row"><b>${NODE_TYPES.fw.glyph} Firewall / Router / VPN →</b> ${NODE_TYPES.fw.src}. ${NODE_TYPES.fw.inputs[0]}.</div>`:''}${lsResult.nonWin.cloud?`<div class="ls-nonwin-row"><b>${NODE_TYPES.cloud.glyph} Cloud →</b> ${NODE_TYPES.cloud.src}. ${NODE_TYPES.cloud.inputs[0]}. AEGIS has full CloudTrail detections - open any cloud technique in the Matrix.</div>`:''}</div>`:''}
   ${chans.map(ch=>`
     <div class="ls-ch-group">
       <div class="ls-ch-head"><span>${ch}</span><span class="ls-ch-count">${byCh[ch].length}</span></div>
       ${byCh[ch].map(p=>lsEventRow(p)).join('')}
     </div>`).join('')}
 </div>`;
}
function lsEventRow(p){
 const ev=p.ev;
 const linked=ev.linked?`<span class="ls-ev-linked" onclick="event.stopPropagation();jumpById('${ev.linked}')" data-tip="Open the full detection in the technique drawer">detection ↗</span>`:'';
 return`<div class="ls-ev">
   <div class="ls-ev-id">${ev.id}</div>
   <div class="ls-ev-main">
     <div class="ls-ev-top">
       <span class="ls-ev-name">${ev.name}</span>
       <span class="ls-ev-cat">${ev.cat}</span>
       ${linked}
       <span class="ls-ev-noise" style="color:${lsNoiseColor(ev.noise)}" data-tip="Relative event volume / noise">${'●'.repeat(ev.noise)}${'○'.repeat(5-ev.noise)} ${lsNoiseLabel(ev.noise)}</span>
       ${p.flagged?'<span class="ls-ev-flag">scope this</span>':''}
     </div>
     <div class="ls-ev-why">${ev.why}</div>
     <div class="ls-ev-setup"><b>Enable:</b> ${esc(ev.setup)} <span class="ls-ev-tune"><b>Tune:</b> ${esc(ev.tune)}</span></div>
   </div>
   <div class="ls-ev-roles">${ev.roles.map(r=>`<span class="ls-role-pip" data-tip="${LS_ROLES[r]}">${r.toUpperCase()}</span>`).join('')}</div>
 </div>`;
}

/* Host-group map builder */
/* Enablement checklist (audit policy + inputs.conf) */
function lsCurrentPicks(){
 if(!lsResult)return[];
 return lsResult.picks;
}
function lsChannelSource(ch){
 const map={
  'Security':'WinEventLog:Security',
  'System':'WinEventLog:System',
  'Sysmon':'WinEventLog:Microsoft-Windows-Sysmon/Operational',
  'PowerShell/Operational':'WinEventLog:Microsoft-Windows-PowerShell/Operational',
  'Windows Defender/Operational':'WinEventLog:Microsoft-Windows-Windows Defender/Operational',
  'WMI-Activity/Operational':'WinEventLog:Microsoft-Windows-WMI-Activity/Operational',
  'AppLocker/WDAC':'WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL'
 };
 return map[ch]||('WinEventLog:'+ch);
}
function lsChecklistText(){
 const picks=lsCurrentPicks();
 const channels=[...new Set(picks.map(p=>p.ev.ch))];
 const lines=[];
 lines.push('===============================================================');
 lines.push(' HOST-BASED LOG SOURCE ENABLEMENT CHECKLIST - generated by AEGIS');
 lines.push(` Mode: ${lsMode.toUpperCase()} · ${picks.length} event IDs`);
 lines.push('===============================================================\n');
 lines.push('STEP 1 - ENABLE AUDIT POLICY / LOGGING (per event ID)\n');
 picks.forEach(p=>{lines.push(`[ ] ${p.ev.id}  ${p.ev.name}`);lines.push(`      why:   ${p.ev.why}`);lines.push(`      setup: ${p.ev.setup}`);lines.push(`      tune:  ${p.ev.tune}\n`);});
 lines.push('STEP 2 - FORWARD THE CHANNELS (inputs.conf on the Universal Forwarder)\n');
 const chMap={};[...new Set(picks.map(p=>p.ev.ch))].forEach(ch=>chMap[ch]=lsChannelSource(ch));
 channels.forEach(ch=>{const src=chMap[ch]||ch;lines.push(`[${src}]`);lines.push('disabled = 0');lines.push('index = win_host');
  if(ch==='Security'){const wl=picks.filter(p=>p.ev.ch==='Security'&&/^\d+$/.test(p.ev.id)).map(p=>p.ev.id);if(wl.length)lines.push('# optional whitelist to cut volume: whitelist = '+wl.join('|'));}
  lines.push('');});
 lines.push('STEP 3 - VERIFY IT IS FLOWING');
 lines.push('Import the AEGIS health dashboard (Health dashboard XML) - each panel shows whether that event ID has arrived in the last 24h, per host.');
 return lines.join('\n');
}
function lsCopyChecklist(){navigator.clipboard.writeText(lsChecklistText()).then(()=>toast('Enablement checklist copied'));}

/* Health dashboard - is each event flowing? */
function lsHealthDashXML(){
 const picks=lsCurrentPicks();
 const title=`AEGIS ${lsMode==='baseline'?'Baseline':'Hunt'} Log-Source Health`;
 const panel=(p)=>{
  const ev=p.ev;const numeric=/^\d+$/.test(ev.id);
  const src=lsChannelSource(ev.ch);
  let q;
  if(ev.ch==='Sysmon'){const eid=ev.id.split(' ')[1];q=`index=win_host source="${src}" EventCode=${eid}\n| stats count as events, dc(ComputerName) as hosts, max(_time) as last_seen\n| eval status=if(events>0,"✓ flowing","✗ MISSING"), last_seen=strftime(last_seen,"%F %T")`;}
  else if(!numeric){q=`index=win_host source="${src}"\n| stats count as events, dc(host) as hosts, max(_time) as last_seen\n| eval status=if(events>0,"✓ flowing","✗ MISSING"), last_seen=strftime(last_seen,"%F %T")`;}
  else{q=`index=win_host source="${src}" EventCode=${ev.id}\n| stats count as events, dc(ComputerName) as hosts, max(_time) as last_seen\n| eval status=if(events>0,"✓ flowing","✗ MISSING"), last_seen=strftime(last_seen,"%F %T")`;}
  return `    <panel>
      <title>${xmlEsc(ev.id+' - '+ev.name)}</title>
      <table>
        <search>
          <query>${xmlEsc(q)}</query>
          <earliest>-24h@h</earliest><latest>now</latest>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>`;
 };
 const rows=[];for(let i=0;i<picks.length;i+=3)rows.push(picks.slice(i,i+3));
 return `<dashboard version="1.1" theme="dark">
  <label>${xmlEsc(title)}</label>
  <description>Generated by AEGIS Log Sources - confirms each recommended event ID is arriving. Adjust index=win_host to your index.</description>
${rows.map(r=>`  <row>\n${r.map(panel).join('\n')}\n  </row>`).join('\n')}
</dashboard>`;
}
function lsDownloadDash(){
 const blob=new Blob([lsHealthDashXML()],{type:'application/xml'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='aegis_logsource_health.xml';a.click();
 URL.revokeObjectURL(a.href);toast('Health dashboard XML downloaded');
}
function lsToStudio(){
 // stage techniques for every recommended event that has a linked detection
 let added=0;const seen=new Set();
 lsCurrentPicks().forEach(p=>{if(!p.ev.linked)return;
  eventsForTech; // ensure defined
  // find techniques that this event maps to
  const evObj=ALL().find(e=>e.id===p.ev.linked);
  if(evObj)evObj.mitre.forEach(tid=>{if(MITRE[tid]&&!studio.has(tid)){studio.add(tid);added++;seen.add(tid);}});
 });
 store('aegis-studio',JSON.stringify([...studio]));updateBadges();
 toast(added?`Staged ${added} technique${added===1?'':'s'} from these detections`:'These events have no linked detections to stage');
 if(added)go('studio');
}
