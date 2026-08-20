/* ================= REPORT GENERATOR ================= */
function lkName(e){return e.id.toLowerCase().replace(/[^a-z0-9]/g,'')+'_baseline';}
function tuneSPL(tid,eid){/* legacy shim - not used by new report */
 const lk=lkName(ALL().find(x=>x.id===eid)||{id:eid});
 const e=ALL().find(x=>x.id===eid);
 const meta=ALERT_META[eid]||{};
 const sk=meta.suppressKeys||['ComputerName'];
 const keyFields=sk.join(', ');
 return{lk,keyFields,
  baseline:`${(e&&e.query.split('\n')[0])||'index=*'}\n| stats count by ${keyFields}\n| outputlookup ${lk}`,
  suppress:`${(e&&e.query.trim())||''}\n| search NOT [| inputlookup ${lk} | fields ${keyFields}]`};
}
function evCatalogBlock(e,seenIds){
 if(seenIds.has(e.plat+e.id))return`<div class="rp-ref">↺ <b>${e.id} - ${e.title}</b> is already in the Detection Catalog and serves this technique too. Deploy it once.</div>`;
 seenIds.add(e.plat+e.id);
 const meta=ALERT_META[e.id]||{};
 const suppressible=meta.suppressible!==false;
 const sk=meta.suppressKeys||['ComputerName'];
 const throttle=meta.throttleBy||sk[0];
 const cadence=meta.cadence||'*/15 * * * *';
 const isDefault=cadence==='*/15 * * * *';
 const triage=meta.triage||[];
 const lk=lkName(e);
 const q0=e.query.trim().split('\n')[0];
 return`<div class="rp-card" id="cat-${e.id}">
   <div class="rp-tagrow"><span class="rp-tid">${e.id}</span><span class="rp-evtag">${e.plat.toUpperCase()}</span><span class="rp-stagetag rp-risk-${e.risk==='high'?'high':e.risk==='med'?'med':'low'}">${e.risk.toUpperCase()} RISK</span><strong>${e.title}</strong></div>
   ${e.setup?`<div class="rp-setup"><b>Telemetry:</b> ${esc(e.setup)}</div>`:''}
   <h3>Detection query</h3>
   <pre>${esc(e.query)}</pre>
   ${triage.length?`<div class="rp-triage"><h4>Triage - where to start</h4><ol>${triage.map(t=>`<li>${esc(t)}</li>`).join('')}</ol></div>`:''}
   ${!isDefault?`<div class="rp-cadence-note"><b>Alert cadence deviation:</b> Use cron <code>${cadence}</code> - ${cadence.startsWith('*/5')||cadence.startsWith('* ')?'this event is too high-priority for a 15-minute window; catch it within 5 minutes.':cadence.startsWith('0 ')?'hourly is sufficient; this attack pattern plays out over hours and a tight window just adds noise.':''}</div>`:''}
   <h3>${suppressible?'Suppress known-good':'Do not suppress'}</h3>
   ${suppressible?`<p>Deploy as a scheduled alert (<code>*/15 * * * *</code>, window <code>-20m@m</code> to <code>now</code>). Throttle by <code>${throttle}</code> for <code>4h</code>. Build the baseline daily; subtract it in the alert:</p>
   <pre>${q0}
| stats count by ${sk.join(', ')}
| outputlookup ${lk}

// Append to the alert search:
| search NOT [| inputlookup ${lk} | fields ${sk.join(', ')}]</pre>
   <p style="font-size:10.5px;color:#8b8ba6">Run the baseline builder for one week in non-alerting mode before enabling triggers - let it learn normal behaviour first.</p>`
   :`<div class="rp-no-suppress">Every instance of this event warrants a human review. Do not add a baseline suppression. Forward logs off-host so this event cannot be tampered with before you act on it. ${!isDefault?`Schedule the alert at <code>${cadence}</code> rather than the default.`:''}</div>`}
 </div>`;
}
/* Compact stage-band diagram (kept for the on-screen quick view) */
function chainDiagramReport(){
 const activeStages=new Set([...studio].map(primaryStage));
 const activeIdx=TACTICS.map((_,i)=>i).filter(i=>activeStages.has(i));
 const minA=activeIdx.length?Math.min(...activeIdx):-1,maxA=activeIdx.length?Math.max(...activeIdx):-1;
 let h='<div class="rp-chain">';
 TACTICS.forEach(([tac],i)=>{
  const on=activeStages.has(i);
  const techs=stagedOrdered().filter(id=>primaryStage(id)===i);
  h+=`<div class="rp-cs${on?' on':''}"><div class="nm">${tac}</div><div class="ct">Stage ${i+1}</div>${on?`<div class="tq">${techs.join('<br>')}</div>`:''}</div>`;
  if(i<TACTICS.length-1){const lit=i>=minA&&i<maxA;h+=`<div class="rp-ca${lit?' on':''}">→</div>`;}
 });
 h+='</div>';
 return h;
}
/* SVG diagram: active tactic stages as a top-to-bottom attack-progression flow.
   Each node is a kill-chain stage listing its staged techniques; directed edges
   show progression. Vertical layout avoids crossing arrows and text overflow. */
function attackFlowSVG(){
 const active=TACTICS.map((t,i)=>({name:t[0],idx:i,techs:stagedOrdered().filter(id=>primaryStage(id)===i)}))
                     .filter(s=>s.techs.length);
 if(!active.length)return"";
 const W=560, padX=24, padTop=16;
 const nodeW=W-padX*2;
 const headH=30, rowH=17, nodePadB=12, gapY=30;
 const nodeH=s=>headH+s.techs.length*rowH+nodePadB;
 const pos=[];let y=padTop;
 active.forEach(s=>{pos.push({s,x:padX,y,w:nodeW,h:nodeH(s)});y+=nodeH(s)+gapY;});
 const height=y-gapY+padTop;
 let edges="";
 for(let k=0;k<pos.length-1;k++){
  const a=pos[k],b=pos[k+1];
  const cx=W/2, ay=a.y+a.h, by=b.y;
  edges+=`<line x1="${cx}" y1="${ay}" x2="${cx}" y2="${by-2}" stroke="#8b7bff" stroke-width="1.8" marker-end="url(#af-arrow)"/>`;
  edges+=`<text x="${cx+8}" y="${ay+(gapY/2)+3}" font-family="IBM Plex Mono,monospace" font-size="8" fill="#a9a4c8">then</text>`;
 }
 let nodes="";
 pos.forEach(p=>{
  const s=p.s;
  const techLines=s.techs.map((id,ti)=>{
   const nm=(T(id).name||"");
   const shown=nm.length>34?nm.slice(0,33)+"…":nm;
   const evN=eventsForTech(id).length;
   const dot=evN?"#3a9d78":"#c98aa8";
   return `<g>
     <circle cx="${p.x+14}" cy="${p.y+headH+ti*rowH+6}" r="2.4" fill="${dot}"/>
     <text x="${p.x+24}" y="${p.y+headH+ti*rowH+9}" font-family="IBM Plex Mono,monospace" font-size="9" fill="#5747d6" font-weight="600">${id}</text>
     <text x="${p.x+24+(id.length*6.2)+8}" y="${p.y+headH+ti*rowH+9}" font-family="Sora,sans-serif" font-size="9.5" fill="#3d3d5c">${esc(shown)}</text>
   </g>`;
  }).join("");
  nodes+=`<g>
    <rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="10" fill="#ffffff" stroke="#c9bffa" stroke-width="1.5"/>
    <path d="M ${p.x} ${p.y+12} Q ${p.x} ${p.y} ${p.x+12} ${p.y} L ${p.x+p.w-12} ${p.y} Q ${p.x+p.w} ${p.y} ${p.x+p.w} ${p.y+12} L ${p.x+p.w} ${p.y+headH} L ${p.x} ${p.y+headH} Z" fill="#7a6cf0"/>
    <text x="${p.x+13}" y="${p.y+19}" font-family="IBM Plex Mono,monospace" font-size="9" fill="#fff" font-weight="600">STAGE ${s.idx+1}</text>
    <text x="${p.x+p.w-13}" y="${p.y+19}" text-anchor="end" font-family="Sora,sans-serif" font-size="11.5" fill="#fff" font-weight="700">${esc(s.name)}</text>
    ${techLines}
  </g>`;
 });
 return `<div style="overflow-x:auto;margin:14px 0 4px"><svg viewBox="0 0 ${W} ${height}" width="${W}" height="${height}" style="max-width:100%;height:auto;font-family:Sora,sans-serif">
   <defs><marker id="af-arrow" markerWidth="9" markerHeight="9" refX="6.5" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L6,3 L0,6 Z" fill="#7a6cf0"/></marker></defs>
   ${edges}${nodes}
 </svg>
 <div style="display:flex;gap:16px;margin-top:8px;font-family:IBM Plex Mono,monospace;font-size:9px;color:#77779a">
   <span style="display:flex;align-items:center;gap:5px"><span style="width:7px;height:7px;border-radius:50%;background:#3a9d78;display:inline-block"></span>has detection telemetry</span>
   <span style="display:flex;align-items:center;gap:5px"><span style="width:7px;height:7px;border-radius:50%;background:#c98aa8;display:inline-block"></span>strategy only - no native telemetry</span>
 </div></div>`;
}
function buildMitTable(){
 const freq={};
 [...studio].forEach(id=>{(T(id).mits||[]).forEach(m=>{freq[m]=(freq[m]||0)+1;});});
 if(!Object.keys(freq).length)return'';
 const rows=Object.entries(freq).sort((a,b)=>b[1]-a[1]).map(([m,c])=>
  `<tr><td class="mono">${m}</td><td><b>${MITS[m]?MITS[m].name:'—'}</b></td><td>${MITS[m]?MITS[m].act:'—'}</td><td style="text-align:center;font-family:\'IBM Plex Mono\',monospace;font-weight:600;color:#5747d6">${c}</td></tr>`
 ).join('');
 return`<table><thead><tr><th>ID</th><th>Control</th><th>Action</th><th>Covers</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function buildRecs(){
 const recs=[];
 // telemetry prerequisites - only the ones that aren't default-on
 const nonDefault=collectPanels().filter(e=>{
  const s=e.setup||'';return!s.toLowerCase().includes('on by default')&&!s.toLowerCase().includes('always recorded');
 });
 const setupSeen=new Set();
 const setupItems=nonDefault.filter(e=>{if(setupSeen.has(e.id))return false;setupSeen.add(e.id);return true;})
  .map(e=>`<li><b>${e.id}</b> - ${esc(e.setup)}</li>`);
 if(setupItems.length)recs.push({t:'Enable non-default telemetry first',b:'<p>These detections require audit policy or data event changes before they produce results:</p><ul>'+setupItems.join('')+'</ul>'});
 // strategy-only gaps
 const gaps=[...studio].filter(id=>eventsForTech(id).length===0);
 if(gaps.length)recs.push({t:'Coverage gaps - techniques with no native telemetry',b:'<p>These techniques are in your stage plan but have no mappable Windows or CloudTrail event. Add a log source or use the AI Analyst to build a custom detection:</p><ul>'+gaps.map(id=>`<li><b>${id} · ${T(id).name}</b>${T(id).note?` - ${esc(T(id).note)}`:''}</li>`).join('')+'</ul>'});
 // kill-chain blind spots
 const activeStages=new Set([...studio].map(primaryStage));
 const inactive=TACTICS.map((t,i)=>[t[0],i]).filter(([,i])=>!activeStages.has(i));
 if(inactive.length&&inactive.length<14)recs.push({t:'Kill-chain stages with no coverage',b:`<p>An attacker operating in these stages would not trip any of these rules. Consider staging techniques from at least one detection per blind stage:</p><p style="color:#7a6cf0;font-family:'IBM Plex Mono',monospace;font-size:11px;margin-top:6px">${inactive.map(([n])=>n).join(' · ')}</p>`});
 // ops hardening
 recs.push({t:'Operational checklist',b:`<div class="rp-ops-grid">
  <div class="rp-ops-item"><div class="t">Baseline before alerting</div><div class="d">Run each suppression builder for a week in non-alerting mode to learn normal, then enable triggers. Rushing baselines causes alert fatigue.</div></div>
  <div class="rp-ops-item"><div class="t">Forward logs off-host</div><div class="d">Near-real-time forwarding means 1102 (log clear) or CloudTrail StopLogging cannot destroy the evidence trail before you act on it.</div></div>
  <div class="rp-ops-item"><div class="t">Validate with Atomic Red Team</div><div class="d">Each MITRE technique ID maps directly to atomics. Detonate in your lab to confirm the detection fires before declaring it production-ready.</div></div>
  <div class="rp-ops-item"><div class="t">Add Sysmon for deeper coverage</div><div class="d">Process injection (T1055) and LSASS access (T1003) need Sysmon EID 8/10 - native Security logs can only partially cover these gaps.</div></div>
  <div class="rp-ops-item"><div class="t">Tune throttle per detection</div><div class="d">4h is a starting point. Noisy detections need per-entity suppression. High-fidelity detections (1102, StopLogging) should never be throttled.</div></div>
  <div class="rp-ops-item"><div class="t">Age out baseline lookups</div><div class="d">Add _time to baseline builders and filter to the last 30–60 days so suppression lists don't grow stale and shelter new malicious behaviour.</div></div>
 </div>`});
 return recs;
}
/* Light-theme network topology for the report - renders the finalised hunt map
   with each node's live Windows Event-ID count, or its non-Windows data source. */
function lsTopoReportSVG(){
 if(!lsNodes||!lsNodes.length)return'';
 const W=680,H=500;
 const byType=t=>lsNodes.filter(n=>n.type===t);
 let edges='';
 function link(a,b){if(!a||!b)return;edges+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#c9bffa" stroke-width="1.5"/>`;}
 const fw=byType('fw')[0], dc=byType('dc')[0];
 byType('dmz').forEach(d=>link(fw,d));
 byType('cloud').forEach(c=>link(fw,c));
 lsNodes.filter(n=>['srv','wks'].includes(n.type)).forEach(n=>link(dc,n));
 if(fw&&dc)link(fw,dc);
 const nodes=lsNodes.map(n=>{
  const t=NODE_TYPES[n.type];
  const isLinux=/linux|macos/i.test(n.os);
  const win=t.win&&!isLinux;
  const count=win?lsEventsForNode(n).length:0;
  const badge=win
   ?`<g transform="translate(40,-30)"><circle r="11" fill="#7a6cf0" stroke="#fbfaf7" stroke-width="2"/><text y="3.5" text-anchor="middle" font-size="9" font-weight="700" fill="#fff" font-family="'IBM Plex Mono',monospace">${count}</text></g>`
   :`<g transform="translate(40,-30)"><circle r="11" fill="#2a7fb8" stroke="#fbfaf7" stroke-width="2"/><text y="3.5" text-anchor="middle" font-size="9" font-weight="700" fill="#fff" font-family="'IBM Plex Mono',monospace">⇄</text></g>`;
  return`<g transform="translate(${n.x},${n.y})">
    <rect x="-52" y="-30" width="104" height="60" rx="11" fill="#ffffff" stroke="${win?'#c9bffa':'#bcdcf0'}" stroke-width="1.5"/>
    <text x="0" y="-9" text-anchor="middle" font-size="16">${t.glyph}</text>
    <text x="0" y="9" text-anchor="middle" font-size="9.5" font-weight="600" fill="#23233a" font-family="Sora,sans-serif">${esc(n.label.length>15?n.label.slice(0,14)+'…':n.label)}</text>
    <text x="0" y="21" text-anchor="middle" font-size="7" fill="#8b8ba6" font-family="'IBM Plex Mono',monospace">${esc((n.os||'').length>16?n.os.slice(0,15)+'…':n.os)}</text>
    ${badge}
  </g>`;
 }).join('');
 return`<div style="overflow-x:auto;margin:14px 0"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" style="max-width:100%;height:auto;background:#f6f5fb;border:1px solid #e8e5f8;border-radius:12px">
   ${edges}${nodes}
 </svg>
 <div style="display:flex;gap:18px;margin-top:8px;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#77779a">
   <span style="display:flex;align-items:center;gap:5px"><span style="width:16px;height:16px;border-radius:50%;background:#7a6cf0;color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:8px;font-weight:700">N</span>Windows host - number = collectable Event IDs</span>
   <span style="display:flex;align-items:center;gap:5px"><span style="width:16px;height:16px;border-radius:50%;background:#2a7fb8;color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:8px">⇄</span>Non-Windows - mapped data source</span>
 </div></div>`;
}
function lsTopoReportSummary(){
 if(!lsNodes||!lsNodes.length)return null;
 const counts={};lsNodes.forEach(n=>{counts[n.type]=(counts[n.type]||0)+1;});
 const winNodes=lsNodes.filter(n=>NODE_TYPES[n.type].win&&!/linux|macos/i.test(n.os));
 const evs=new Set();winNodes.forEach(n=>lsEventsForNode(n).forEach(e=>evs.add(e.id)));
 const nonWin=lsNodes.filter(n=>!NODE_TYPES[n.type].win);
 return{counts,winCount:winNodes.length,evCount:evs.size,nonWin};
}
function incidentReportSection(){
 const rows=lsAllObs();
 if(!rows.length)return'';
 const sevColor={info:'#2a7fb8',suspicious:'#b5852f',malicious:'#a83e66'};
 const sevBg={info:'#eaf6ff',suspicious:'#fff8ec',malicious:'#fdeef3'};
 const worst=rows.reduce((a,r)=>Math.max(a,SEV_META[r.obs.sev].rank),0);
 const compromised=lsNodes.filter(n=>lsNodeStatus(n)==='malicious');
 const items=rows.map((r,i)=>{
  const stageName=r.stage<TACTICS.length?`Stage ${r.stage+1} · ${TACTICS[r.stage][0]}`:'Unmapped';
  return`<div class="rp-tl-item">
    <div class="rp-tl-dot" style="background:${sevColor[r.obs.sev]}"></div>
    <div class="rp-tl-body">
      <div class="rp-tl-top"><span class="rp-tl-node">${NODE_TYPES[r.node.type].glyph} ${esc(r.node.label)}</span><span class="rp-tl-sev" style="color:${sevColor[r.obs.sev]};background:${sevBg[r.obs.sev]}">${SEV_META[r.obs.sev].label}</span>${r.obs.evId?`<span class="rp-tl-ev">${r.obs.evId}</span>`:''}<span class="rp-tl-stage">${stageName}</span></div>
      ${r.ev?`<div class="rp-tl-evname">${r.ev.name}</div>`:''}
      ${r.obs.note?`<div class="rp-tl-note">${esc(r.obs.note)}</div>`:''}
    </div>
  </div>`;
 }).join('');
 return`<p>Observations logged across the network during this hunt, ordered along the kill chain. This is the working incident picture - ${rows.length} observation${rows.length===1?'':'s'} across ${new Set(rows.map(r=>r.node.uid)).size} host${new Set(rows.map(r=>r.node.uid)).size===1?'':'s'}${compromised.length?`, ${compromised.length} assessed as compromised`:''}.</p>
 ${worst>=3?`<div class="rp-keyfinding"><div class="rp-kf-label">Active</div><div>This map contains observations rated <strong>malicious</strong>. Treat the affected hosts (${compromised.map(n=>esc(n.label)).join(', ')||'see below'}) as compromised pending containment.</div></div>`:''}
 <div class="rp-timeline">${items}</div>`;
}
function reportHTML(){
 const title=document.getElementById('dash-name')?.value||'ATT&CK Detection Coverage';
 const now=new Date();
 const ordered=stagedOrdered();
 const activeStages=new Set([...studio].map(primaryStage));
 const stagesHit=[...activeStages].filter(i=>i<TACTICS.length).sort((a,b)=>a-b);
 const panels=collectPanels();
 const span=stagesHit.length?`${TACTICS[stagesHit[0]][0]} → ${TACTICS[stagesHit[stagesHit.length-1]][0]}`:'—';
 const totalMits=new Set([...studio].flatMap(id=>T(id).mits||[])).size;

 // §3 Coverage bars
 const barRows=stagesHit.map(i=>{
  const pct=Math.round([...studio].filter(id=>primaryStage(id)===i).length/TACTICS[i][2].length*100);
  return`<div class="rp-bar-row"><div class="rp-bar-label">${TACTICS[i][0]}</div><div class="rp-bar-track"><div class="rp-bar-fill" style="width:${Math.max(pct,8)}%">${pct}%</div></div></div>`;
 }).join('');

 // §4 Mitigation priority table - all mitigations sorted by frequency, built once
 const mitTable=buildMitTable();

 // §3 Tactic → technique relationship table (grouped by tactic, in kill-chain order)
 const tacticRows=stagesHit.map(i=>{
  const stagedHere=ordered.filter(id=>primaryStage(id)===i);
  const techCells=stagedHere.map(id=>{
   const evs=eventsForTech(id);
   const cov=evs.length?`${evs.length} event${evs.length===1?'':'s'}`:'no telemetry';
   return`<div style="margin-bottom:4px"><span class="rp-tid">${id}</span> <span style="font-size:11.5px;color:#3d3d5c">${T(id).name}</span> <span style="font-size:9.5px;color:${evs.length?'#2a7fb8':'#a83e66'};font-family:'IBM Plex Mono',monospace">· ${cov}</span></div>`;
  }).join('');
  return`<tr>
    <td style="white-space:nowrap"><span class="rp-stagetag" style="background:#efecfd;color:#5747d6;border-color:#c9bffa">Stage ${i+1}</span><br><strong style="font-size:12px;color:#23233a">${TACTICS[i][0]}</strong></td>
    <td>${techCells}</td>
  </tr>`;
 }).join('');

 // §6 Kill-chain technique map - grouped under tactic headers so the tactic→technique relationship is explicit
 const techMapByTactic=stagesHit.map(i=>{
  const stagedHere=ordered.filter(id=>primaryStage(id)===i);
  const cards=stagedHere.map(id=>{
   const t=T(id);
   const evs=eventsForTech(id);
   const mitPills=(t.mits||[]).map(m=>`<span class="rp-mit-pill">${m}</span>`).join('');
   const evPills=evs.length
    ?evs.map(e=>`<a class="rp-ev-pill" href="#cat-${e.id}">${e.id}</a>`).join('')
    :`<span style="font-size:10.5px;color:#a83e66">No native telemetry - see §8</span>`;
   return`<div class="rp-tech-compact">
     <div class="rp-tech-meta">
       <span class="rp-tid">${id}</span>
       <strong style="font-size:12.5px">${t.name}</strong>
       ${t.note?`<span class="rp-stagetag" style="background:#fff7e8;color:#8a6a1f;border-color:#f3dfb2">limited coverage</span>`:''}
     </div>
     <div class="rp-tech-summary">${(t.detect&&t.detect.length)?t.detect[0]:(t.summary||t.name)}</div>
     ${t.detect.length>1?`<ul class="rp-tech-signals">${t.detect.slice(1,4).map(d=>`<li>${d}</li>`).join('')}</ul>`:''}
     <div class="rp-controls" style="margin-top:8px;gap:10px;">
       <div><span style="font-family:'IBM Plex Mono',monospace;font-size:8px;color:#8b8ba6;letter-spacing:.12em;text-transform:uppercase;margin-right:5px;">Mitigations</span>${mitPills||'—'}</div>
       <div><span style="font-family:'IBM Plex Mono',monospace;font-size:8px;color:#8b8ba6;letter-spacing:.12em;text-transform:uppercase;margin-right:5px;">Detected by</span>${evPills}</div>
     </div>
   </div>`;
  }).join('');
  return`<div style="margin-bottom:18px">
    <div style="display:flex;align-items:center;gap:9px;margin:16px 0 9px">
      <span class="rp-stagetag" style="background:#7a6cf0;color:#fff;border-color:#7a6cf0">Stage ${i+1}</span>
      <span style="font-size:14px;font-weight:700;color:#17172b">${TACTICS[i][0]}</span>
      <span style="font-size:10.5px;color:#8b8ba6">${stagedHere.length} technique${stagedHere.length===1?'':'s'} staged</span>
    </div>
    ${cards}
  </div>`;
 }).join('');

 // §8 Detection catalog - each event once, curated suppression
 const seenIds=new Set();
 const catalog=ordered.flatMap(id=>eventsForTech(id)).filter((e,i,a)=>
  a.findIndex(x=>x.plat===e.plat&&x.id===e.id)===i
 ).map(e=>evCatalogBlock(e,seenIds)).join('');

 const recs=buildRecs();
 const winCount=panels.filter(p=>p.plat==='windows').length;
 const awsCount=panels.filter(p=>p.plat==='aws').length;
 const gapCount=TACTICS.length-stagesHit.length;
 const strategyOnly=ordered.filter(id=>eventsForTech(id).length===0).length;
 const topo=lsTopoReportSummary();
 const topMit=[...new Set([...studio].flatMap(id=>T(id).mits||[]))]
   .map(m=>[m,[...studio].filter(id=>(T(id).mits||[]).includes(m)).length])
   .sort((a,b)=>b[1]-a[1])[0];

 // key finding sentence
 const earliest=stagesHit.length?TACTICS[stagesHit[0]][0]:'—';
 const latest=stagesHit.length?TACTICS[stagesHit[stagesHit.length-1]][0]:'—';
 const hasInc=lsHasIncident();
 let S=0;const N=()=>++S;

 return`
  <div class="rp-cover">
    <div class="rp-kicker">AEGIS · Detection Engineering Report</div>
    <h1>${esc(title)}</h1>
    <div class="rp-meta">Generated ${now.toLocaleString()} · kill-chain span ${esc(span)}</div>
    <div class="rp-statband">
      <div class="rp-stat"><div class="v">${studio.size}</div><div class="k">Techniques</div></div>
      <div class="rp-stat"><div class="v">${stagesHit.length}<span class="of">/14</span></div><div class="k">Kill-chain stages</div></div>
      <div class="rp-stat"><div class="v">${panels.length}</div><div class="k">Splunk detections</div></div>
      <div class="rp-stat"><div class="v">${totalMits}</div><div class="k">Mitigations</div></div>
      ${topo?`<div class="rp-stat"><div class="v">${topo.winCount+topo.nonWin.length}</div><div class="k">Mapped assets</div></div>`:''}
    </div>
  </div>

  <div class="rp-lead">
    <p>This report operationalises <strong>${studio.size} MITRE ATT&amp;CK technique${studio.size===1?'':'s'}</strong> into <strong>${panels.length} deployable Splunk detection${panels.length===1?'':'s'}</strong>, ordered along the attack kill chain from <strong>${esc(earliest)}</strong> to <strong>${esc(latest)}</strong>. It reads in two parts: the first establishes the threat model and where this coverage sits against it; the second is the deployment reference - the exact queries, triage steps, and suppression logic your team implements.</p>
    ${gapCount>0?`<div class="rp-keyfinding"><div class="rp-kf-label">Key finding</div><div>Coverage spans ${stagesHit.length} of 14 kill-chain stages. ${gapCount} stage${gapCount===1?'':'s'} remain uncovered - an adversary operating there would not trip these rules${topMit?`. The single highest-leverage control is <strong>${topMit[0]} · ${MITS[topMit[0]]?MITS[topMit[0]].name:''}</strong>, which counters ${topMit[1]} of your staged techniques`:''}.</div></div>`:`<div class="rp-keyfinding good"><div class="rp-kf-label">Key finding</div><div>All 14 kill-chain stages carry at least one detection - end-to-end visibility across the intrusion lifecycle.</div></div>`}
  </div>

  <div class="rp-part"><span class="rp-part-n">Part I</span><span class="rp-part-t">Threat model &amp; coverage</span></div>

  <h2><span class="n">${N()}</span>Modelled attack progression</h2>
  <p>How an adversary would move through the tactics this rule set covers. Each stage lists the techniques staged against it; the arrows show progression from first contact toward objective. Detecting earlier in this chain means intervening before the objective is reached.</p>
  ${attackFlowSVG()||'<p style="color:#77779a">Stage at least one technique to generate the progression diagram.</p>'}

  ${topo?`<h2><span class="n">${N()}</span>Monitored network</h2>
  <p>The environment this hunt covers, as mapped in Log Sources. Each Windows host shows how many host-based Event IDs it can contribute; non-Windows assets show that they feed a different source (firewall syslog/NetFlow, cloud audit trail). This is the live picture an analyst updates as an investigation moves across the estate.</p>
  ${lsTopoReportSVG()}
  <div class="rp-topo-legend">${Object.entries(topo.counts).map(([t,c])=>`<span class="rp-topo-pill">${NODE_TYPES[t].glyph} ${c}× ${NODE_TYPES[t].label}</span>`).join('')}</div>
  <p style="font-size:11px;color:#77779a;margin-top:8px">${topo.winCount} Windows host${topo.winCount===1?'':'s'} contribute up to ${topo.evCount} distinct Event IDs${topo.nonWin.length?`; ${topo.nonWin.length} non-Windows asset${topo.nonWin.length===1?'':'s'} (${topo.nonWin.map(n=>NODE_TYPES[n.type].label.split(' ')[0]).join(', ')}) feed syslog/NetFlow or cloud-audit sources instead of Windows events`:''}.</p>
  `:''}

  ${hasInc?`<h2><span class="n">${N()}</span>Incident timeline</h2>
  ${incidentReportSection()}`:''}

  <h2><span class="n">${N()}</span>Tactics &amp; techniques</h2>
  <p>The staged techniques grouped by ATT&amp;CK tactic, in kill-chain order - the relationship between each tactic (the adversary's objective) and the techniques (their methods) addressed here.</p>
  <table><thead><tr><th style="width:180px">Tactic / stage</th><th>Techniques staged</th></tr></thead><tbody>${tacticRows||'<tr><td colspan="2">No techniques staged.</td></tr>'}</tbody></table>

  <h2><span class="n">${N()}</span>Coverage assessment</h2>
  <p>The share of each active tactic's technique set that is staged here. A low bar marks a tactic where the adversary retains many unaddressed alternatives. These figures measure coverage within this report's scope, not the full framework.</p>
  ${barRows||'<p>No active stages.</p>'}

  <h2><span class="n">${N()}</span>Mitigating controls</h2>
  <p>The ATT&amp;CK mitigations countering the staged techniques, ranked by reach. Controls at the top deliver the broadest risk reduction per unit of effort - prioritise them in remediation.</p>
  ${mitTable||'<p>No mitigations mapped.</p>'}

  <div class="rp-part"><span class="rp-part-n">Part II</span><span class="rp-part-t">Deployment reference</span></div>

  <h2><span class="n">${N()}</span>How every detection deploys</h2>
  <p>Each detection in the catalogue follows this six-stage pattern. It is documented once here rather than repeated per rule; entries note only where they deviate - a different cadence, or a rule that must never be suppressed.</p>
  <div class="rp-pipe">
    <div class="rp-ps"><div class="t">1 · Enable</div><div class="d">Turn on the audit policy or data event named in the entry</div></div>
    <div class="rp-ps"><div class="t">2 · Forward</div><div class="d">Universal Forwarder to Splunk, or the AWS Add-on via SQS</div></div>
    <div class="rp-ps"><div class="t">3 · Search</div><div class="d">Validate the SPL over -24h to confirm fields are present</div></div>
    <div class="rp-ps"><div class="t">4 · Alert</div><div class="d">Schedule every ${getSetting('reportCadenceMin')} minutes, window -${getSetting('reportCadenceMin')+5}m@m to now</div></div>
    <div class="rp-ps"><div class="t">5 · Suppress</div><div class="d">Subtract a known-good baseline via inputlookup</div></div>
    <div class="rp-ps"><div class="t">6 · Triage</div><div class="d">Throttle per entity, route to notable index or SOAR</div></div>
  </div>

  <h2><span class="n">${N()}</span>Technique map</h2>
  <p>Each staged technique in detail under its tactic: the primary detection signal, supporting indicators, applicable mitigations, and the event sources that detect it. Event pills link to the full query in the catalogue.</p>
  ${techMapByTactic}

  <h2><span class="n">${N()}</span>Detection catalogue</h2>
  <p>The deployable reference for each event source - query, telemetry prerequisites, triage procedure, and suppression logic. Each source appears once; where techniques share an event, the entry is shared and deployed a single time.</p>
  ${catalog||'<div class="rp-gap">None of the staged techniques have native Windows or CloudTrail telemetry. Add further log sources, or use the AI Analyst to design custom detections.</div>'}

  <h2><span class="n">${N()}</span>Risk-based alerting</h2>
  ${rbaReportSection()}

  <h2><span class="n">${N()}</span>Recommendations</h2>
  ${recs.map(r=>`<div class="rp-rec"><div class="rt">${r.t}</div><div class="rb">${r.b}</div></div>`).join('')}

  <div class="rp-footer"><span>AEGIS Detection Intelligence</span><span>${esc(title)} · ${now.toISOString().slice(0,10)}</span></div>`;
}
function openReport(){
 if(!studio.size){toast('Stage at least one technique first');return;}
 document.getElementById('report').innerHTML=reportHTML();
 document.getElementById('report-veil').classList.add('open');
 document.getElementById('report-veil').scrollTop=0;
}
function closeReport(){document.getElementById('report-veil').classList.remove('open');}
function printReport(){window.print();}
function downloadReport(){
 const title=document.getElementById('dash-name')?.value||'ATT&CK Detection Coverage';
 const inner=document.getElementById('report').innerHTML;
 const RCSS=`body{margin:0;background:#e9e7f2;font-family:'Sora',sans-serif;padding:24px;}
.report{max-width:880px;margin:0 auto;background:#fbfaf7;color:#23233a;border-radius:14px;padding:48px 56px 56px;box-shadow:0 20px 60px rgba(0,0,0,.2);font-size:13px;line-height:1.65;}
.rp-kicker{font-family:'IBM Plex Mono',monospace;font-size:9px;letter-spacing:.3em;text-transform:uppercase;color:#7a6cf0;}
.rp-cover{background:linear-gradient(135deg,#f3f1fc,#fbfaf7);border:1px solid #e8e5f8;border-radius:16px;padding:32px 34px;margin-bottom:8px;}
.rp-statband{display:flex;flex-wrap:wrap;gap:12px;margin-top:22px;}
.rp-stat{flex:1;min-width:92px;background:#fff;border:1px solid #e8e5f8;border-radius:11px;padding:14px 16px;}
.rp-stat .v{font-size:26px;font-weight:700;color:#5747d6;line-height:1;}
.rp-stat .v .of{font-size:14px;color:#b9b2e0;font-weight:600;}
.rp-stat .k{font-size:9.5px;color:#8b8ba6;font-family:'IBM Plex Mono',monospace;letter-spacing:.08em;text-transform:uppercase;margin-top:5px;}
.rp-lead{margin:22px 0 8px;}
.rp-lead p{font-size:13.5px;line-height:1.7;color:#3d3d5c;}
.rp-keyfinding{display:flex;gap:14px;align-items:flex-start;background:#fff8ec;border:1px solid #f3dfb2;border-left:4px solid #d99a2b;border-radius:11px;padding:15px 18px;margin-top:16px;font-size:12.5px;line-height:1.65;color:#5c4a22;break-inside:avoid;}
.rp-keyfinding.good{background:#eef8f4;border-color:#b3e4d0;border-left-color:#2a7a5e;color:#245b47;}
.rp-kf-label{font-family:'IBM Plex Mono',monospace;font-size:8.5px;letter-spacing:.14em;text-transform:uppercase;color:#b5852f;flex-shrink:0;padding-top:2px;font-weight:600;}
.rp-keyfinding.good .rp-kf-label{color:#2a7a5e;}
.rp-part{display:flex;align-items:center;gap:14px;margin:44px 0 8px;padding-bottom:12px;border-bottom:2px solid #17172b;break-after:avoid;}
.rp-part-n{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#7a6cf0;background:#efecfd;border:1px solid #d8d1fa;padding:5px 12px;border-radius:99px;font-weight:600;}
.rp-part-t{font-size:19px;font-weight:700;color:#17172b;}
.rp-topo-legend{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;}
.rp-topo-pill{font-family:'IBM Plex Mono',monospace;font-size:9.5px;background:#f2f1f7;border:1px solid #e3e2ef;color:#55557a;padding:3px 10px;border-radius:99px;}
.rp-timeline{margin:14px 0 6px;border-left:2px solid #e3e2ef;padding-left:4px;}
.rp-tl-item{display:flex;gap:12px;align-items:flex-start;margin-bottom:12px;break-inside:avoid;}
.rp-tl-dot{width:11px;height:11px;border-radius:50%;flex-shrink:0;margin-left:-11px;margin-top:3px;border:2px solid #fbfaf7;}
.rp-tl-body{flex:1;background:#fff;border:1px solid #e8e5f8;border-radius:10px;padding:11px 14px;}
.rp-tl-top{display:flex;flex-wrap:wrap;gap:7px;align-items:center;}
.rp-tl-node{font-size:12px;font-weight:700;color:#23233a;}
.rp-tl-sev{font-family:'IBM Plex Mono',monospace;font-size:8px;letter-spacing:.06em;text-transform:uppercase;padding:2px 8px;border-radius:99px;font-weight:600;}
.rp-tl-ev{font-family:'IBM Plex Mono',monospace;font-size:9px;color:#6a5ae8;background:#efecfd;border:1px solid #d8d1fa;padding:2px 7px;border-radius:99px;}
.rp-tl-stage{font-family:'IBM Plex Mono',monospace;font-size:8px;color:#8b8ba6;margin-left:auto;}
.rp-tl-evname{font-size:11px;color:#55557a;margin-top:4px;}
.rp-tl-note{font-size:11.5px;color:#23233a;margin-top:4px;line-height:1.5;}
h1{font-size:28px;font-weight:700;margin:8px 0 4px;color:#17172b;letter-spacing:-.01em;}
.rp-meta{font-family:'IBM Plex Mono',monospace;font-size:10px;color:#8b8ba6;}
h2{font-size:17px;font-weight:700;margin:36px 0 6px;color:#17172b;display:flex;align-items:center;gap:4px;break-after:avoid;}
h2 .n{color:#fff;background:#7a6cf0;font-family:'IBM Plex Mono',monospace;font-size:11px;width:24px;height:24px;border-radius:7px;display:inline-flex;align-items:center;justify-content:center;margin-right:10px;flex-shrink:0;}
h2+p{color:#6a6a88;font-size:12.5px;margin-top:2px;}
h3{font-size:13px;font-weight:600;margin:18px 0 7px;color:#23233a;}
p{margin-bottom:11px;color:#3d3d5c;line-height:1.68;}
.rp-card{background:#fff;border:1px solid #e8e5f8;border-radius:11px;padding:18px 20px;margin-bottom:14px;break-inside:avoid;}
.rp-tech-compact{border:1px solid #e8e5f8;border-radius:11px;padding:14px 16px;margin-bottom:9px;background:#fff;break-inside:avoid;}
.rp-tech-meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:5px;}
.rp-tech-summary{font-size:12px;color:#3d3d5c;line-height:1.6;margin:4px 0 6px;}
.rp-tech-signals{margin:4px 0 8px;padding-left:16px;}
.rp-tech-signals li{font-size:11.5px;color:#55557a;margin-bottom:2px;}
.rp-controls{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px;}
.rp-tagrow{display:flex;gap:7px;flex-wrap:wrap;align-items:center;margin-bottom:8px;}
.rp-tid{font-family:'IBM Plex Mono',monospace;font-size:10.5px;background:#efecfd;color:#6a5ae8;border:1px solid #d8d1fa;padding:3px 10px;border-radius:99px;font-weight:600;}
.rp-stagetag{font-family:'IBM Plex Mono',monospace;font-size:8.5px;background:#f2f1f7;color:#77779a;border:1px solid #e3e2ef;padding:3px 9px;border-radius:99px;letter-spacing:.08em;text-transform:uppercase;}
.rp-evtag{font-family:'IBM Plex Mono',monospace;font-size:8.5px;background:#eaf6ff;color:#2a7fb8;border:1px solid #cfe9fb;padding:3px 9px;border-radius:99px;}
.rp-mit-pill{font-family:'IBM Plex Mono',monospace;font-size:8.5px;background:#efecfd;color:#6a5ae8;border:1px solid #d8d1fa;padding:2px 9px;border-radius:99px;font-weight:600;}
.rp-ev-pill{font-family:'IBM Plex Mono',monospace;font-size:8.5px;background:#eaf6ff;color:#2a7fb8;border:1px solid #cfe9fb;padding:2px 9px;border-radius:99px;text-decoration:none;}
.rp-risk-high{background:#fdeef3;color:#a83e66;border-color:#f6cede;}
.rp-risk-med{background:#fff7e8;color:#8a6a1f;border-color:#f3dfb2;}
.rp-risk-low{background:#eef8f4;color:#2a7a5e;border-color:#b3e4d0;}
.rp-triage h4{font-size:10px;font-weight:700;color:#5747d6;text-transform:uppercase;letter-spacing:.12em;margin:12px 0 4px;}
.rp-triage ol{margin:4px 0;padding-left:18px;}
.rp-triage li{font-size:11.5px;color:#3d3d5c;margin-bottom:4px;line-height:1.55;}
.rp-setup{background:#fff7e8;border:1px solid #f3dfb2;border-radius:9px;padding:10px 13px;font-size:11.5px;color:#8a6a1f;margin:8px 0 10px;line-height:1.55;}
.rp-cadence-note{background:#eaf6ff;border:1px solid #cfe9fb;border-radius:9px;padding:9px 12px;font-size:11px;color:#2a7fb8;margin:6px 0;}
.rp-no-suppress{background:#fdeef3;border:1px solid #f6cede;border-radius:9px;padding:10px 13px;font-size:11.5px;color:#a83e66;margin:8px 0 4px;line-height:1.55;}
.rp-ref{background:#f2f1fb;border:1px solid #e0dcf6;border-radius:9px;padding:10px 13px;font-size:11.5px;color:#5a5a80;margin:8px 0 10px;}
.rp-gap{background:#fdeef3;border:1px solid #f6cede;border-radius:9px;padding:11px 13px;font-size:11.5px;color:#a83e66;margin:8px 0 10px;line-height:1.55;}
ul,ol{padding-left:18px;margin:6px 0 10px;}li{margin-bottom:4px;color:#3d3d5c;}
pre{background:#17172b;color:#e9e9f5;border-radius:9px;padding:14px 16px;font-family:'IBM Plex Mono',monospace;font-size:10.5px;line-height:1.7;overflow-x:auto;white-space:pre-wrap;margin:8px 0 12px;break-inside:avoid;}
code{font-family:'IBM Plex Mono',monospace;background:#efecfd;color:#6a5ae8;padding:1px 5px;border-radius:4px;font-size:.92em;}
pre code{background:none;color:inherit;padding:0;}
table{width:100%;border-collapse:collapse;margin:8px 0 12px;font-size:11.5px;}
th{text-align:left;font-family:'IBM Plex Mono',monospace;font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#8b8ba6;padding:7px 10px;border-bottom:2px solid #e8e5f8;}
td{padding:8px 10px;border-bottom:1px solid #efedf8;color:#3d3d5c;vertical-align:top;}
td.mono{font-family:'IBM Plex Mono',monospace;font-size:10px;color:#6a5ae8;white-space:nowrap;}
.rp-chain{display:flex;flex-wrap:wrap;gap:0;row-gap:10px;margin:12px 0 6px;align-items:stretch;}
.rp-cs{width:100px;border:1px solid #e3e2ef;background:#f6f5fa;border-radius:9px;padding:7px 8px;text-align:center;}
.rp-cs.on{background:#efecfd;border-color:#c9bffa;}
.rp-cs .nm{font-size:9px;font-weight:600;color:#55557a;line-height:1.25;}.rp-cs.on .nm{color:#5747d6;}
.rp-cs .ct{font-family:'IBM Plex Mono',monospace;font-size:8px;color:#9a9ab5;margin-top:3px;}.rp-cs.on .ct{color:#7a6cf0;font-weight:600;}
.rp-cs .tq{font-family:'IBM Plex Mono',monospace;font-size:7.5px;color:#7a6cf0;margin-top:4px;line-height:1.5;word-break:break-word;}
.rp-ca{display:flex;align-items:center;padding:0 2px;color:#c3c0da;font-size:10px;}.rp-ca.on{color:#7a6cf0;}
.rp-bar-row{display:flex;align-items:center;gap:10px;margin-bottom:6px;}
.rp-bar-label{width:140px;font-size:10.5px;color:#55557a;text-align:right;flex-shrink:0;}
.rp-bar-track{flex:1;background:#efedf8;border-radius:99px;height:13px;overflow:hidden;}
.rp-bar-fill{height:100%;background:linear-gradient(90deg,#8b7bff,#6a5ae8);border-radius:99px;display:flex;align-items:center;justify-content:flex-end;padding-right:6px;font-family:'IBM Plex Mono',monospace;font-size:8px;color:#fff;min-width:20px;}
.rp-pipe{display:flex;gap:0;flex-wrap:wrap;row-gap:8px;margin:12px 0;align-items:stretch;}
.rp-ps{flex:1;min-width:100px;border:1px solid #d8d1fa;background:#efecfd;border-radius:9px;padding:8px 10px;text-align:center;}
.rp-ps .t{font-size:10px;font-weight:600;color:#5747d6;}.rp-ps .d{font-size:8.5px;color:#8b7fd0;margin-top:3px;line-height:1.4;}
.rp-rec{background:#fff;border:1px solid #e8e5f8;border-left:4px solid #7a6cf0;border-radius:9px;padding:13px 16px;margin-bottom:10px;break-inside:avoid;}
.rp-rec .rt{font-weight:600;font-size:12.5px;color:#23233a;margin-bottom:3px;}.rp-rec .rb{font-size:11.5px;color:#55557a;line-height:1.6;}
.rp-ops-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;}
.rp-ops-item{background:#f6f5fa;border:1px solid #e8e5f8;border-radius:9px;padding:10px 13px;break-inside:avoid;}
.rp-ops-item .t{font-size:11.5px;font-weight:600;color:#23233a;margin-bottom:3px;}.rp-ops-item .d{font-size:11px;color:#55557a;line-height:1.55;}
.rp-footer{margin-top:36px;padding-top:14px;border-top:1px solid #e8e5f8;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#9a9ab5;display:flex;justify-content:space-between;}
@media print{body{background:#fff;padding:0;}.report{box-shadow:none;border-radius:0;max-width:none;padding:10mm;}.rp-card,.rp-rec,.rp-tech-compact,.rp-ops-item{break-inside:avoid;}h2{break-before:auto;}}`;
 const doc=`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${esc(title)} - AEGIS Report</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>${RCSS}</style></head><body><div class="report">${inner}</div></body></html>`;
 const blob=new Blob([doc],{type:'text/html'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='aegis_detection_report.html';a.click();
 URL.revokeObjectURL(a.href);toast('Report downloaded');
}
