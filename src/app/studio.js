/* ================= STUDIO ================= */
function togStudio(id){
 const adding=!studio.has(id);
 adding?studio.add(id):studio.delete(id);
 store('aegis-studio',JSON.stringify([...studio]));
 updateBadges();
 if(view==='matrix')renderMatrix();
 if(view==='studio')renderStudio();
 toast(adding?`${id} staged · ${studio.size} total`:`${id} removed · ${studio.size} total`);
}
function stageAllHighRisk(){
 let added=0;
 uniqTechs().forEach(id=>{if(eventsForTech(id).length>=2&&!studio.has(id)){studio.add(id);added++;}});
 store('aegis-studio',JSON.stringify([...studio]));
 updateBadges();renderMatrix();if(view==='studio')renderStudio();
 toast(`Staged ${added} high-coverage technique${added===1?'':'s'} · ${studio.size} total`);
}
const SCENARIOS={
 ransomware:{name:'Ransomware intrusion',techs:['T1566','T1059','T1543.003','T1003','T1021','T1490','T1489','T1486','T1562','T1070']},
 cloud:{name:'Cloud account takeover',techs:['T1078','T1110','T1098','T1548','T1552','T1526','T1530','T1562.008','T1048']},
 insider:{name:'Insider data theft',techs:['T1078','T1087','T1082','T1005','T1039','T1560','T1567','T1048','T1552']}
};
function stageScenario(key){
 const sc=SCENARIOS[key];if(!sc)return;
 let added=0;
 sc.techs.forEach(id=>{if(MITRE[id]&&!studio.has(id)){studio.add(id);added++;}});
 store('aegis-studio',JSON.stringify([...studio]));
 updateBadges();renderMatrix();if(view==='studio')renderStudio();
 toast(`${sc.name}: staged ${added} technique${added===1?'':'s'} · open Studio (3) to compile`);
}
function clearStudio(){studio.clear();store('aegis-studio','[]');updateBadges();renderMatrix();if(view==='studio')renderStudio();toast('Studio cleared');}
/* ---- threat-profile coverage scoring ----
   Score staged coverage against a named adversary's known techniques, not the
   whole framework — a far more meaningful readiness signal. Technique lists are
   scoped to what exists in this app's MITRE set. */
const THREAT_PROFILES={
 apt29:{name:'APT29 (Cozy Bear)',blurb:'Stealthy state-sponsored espionage — identity abuse, living-off-the-land, cloud.',techs:['T1566','T1059','T1078','T1098','T1550','T1552','T1003','T1021','T1070','T1562','T1526','T1530']},
 fin7:{name:'FIN7',blurb:'Financially-motivated — phishing to execution to lateral movement and collection.',techs:['T1566','T1059','T1053','T1543.003','T1003','T1021','T1005','T1560','T1048','T1070']},
 lockbit:{name:'LockBit (RaaS)',blurb:'Ransomware affiliate playbook — access, escalate, disable defenses, encrypt.',techs:['T1078','T1059','T1543.003','T1003','T1021','T1562','T1490','T1489','T1486','T1070']},
 scattered:{name:'Scattered Spider',blurb:'Identity-first intrusion — social engineering, MFA fatigue, cloud + on-prem pivot.',techs:['T1566','T1078','T1098','T1548','T1552','T1621','T1556','T1530','T1021','T1567']}
};
let threatSel=null;
function threatCoverage(key){
 const p=THREAT_PROFILES[key];if(!p)return null;
 // only score against techniques AEGIS actually knows
 const known=p.techs.filter(id=>MITRE[id]);
 const covered=known.filter(id=>studio.has(id));
 const detectable=known.filter(id=>studio.has(id)&&eventsForTech(id).length>0);
 return{profile:p,known,covered,detectable,pct:known.length?Math.round(covered.length/known.length*100):0};
}
function setThreat(key){threatSel=(threatSel===key?null:key);renderStudio();}
function stageThreatGaps(key){
 const c=threatCoverage(key);if(!c)return;
 let added=0;c.known.forEach(id=>{if(!studio.has(id)){studio.add(id);added++;}});
 persistAll();updateBadges();renderMatrix();renderStudio();
 toast(added?`Staged ${added} gap technique${added===1?'':'s'} for ${c.profile.name}`:'Already covering all known techniques');
}
function setStTab(t){stTab=t;renderStudio();}

function collectPanels(){
 const panels=[];
 stagedOrdered().forEach(id=>{eventsForTech(id).forEach(e=>{if(!panels.some(p=>p.plat===e.plat&&p.id===e.id))panels.push({...e,tech:id});});});
 return panels;
}
function expDo(fn){try{fn();}catch(e){}const p=document.getElementById('exp-pop');if(p)p.classList.remove('open');}
/* ---- detection maturity (idea → tested → tuned → production) ---- */
const MATURITY=[['idea','Idea','#8b8ba6'],['tested','Tested','#5cc8ff'],['tuned','Tuned','#ffb547'],['prod','Production','#3ddc97']];
function matOf(id){return maturity[id]||'idea';}
function cycleMaturity(id,e){
 if(e)e.stopPropagation();
 const order=MATURITY.map(m=>m[0]);
 const cur=matOf(id);const next=order[(order.indexOf(cur)+1)%order.length];
 maturity[id]=next;persistAll();renderStudio();
}
function maturityRollup(){
 const staged=[...studio];if(!staged.length)return null;
 const counts={idea:0,tested:0,tuned:0,prod:0};
 staged.forEach(id=>counts[matOf(id)]++);
 return counts;
}

function renderStudio(){
 const basket=document.getElementById('st-basket');
 const main=document.getElementById('st-main');
 if(!studio.size){
  basket.innerHTML=`<div class="bk-empty">Nothing staged yet.</div>`;
  main.innerHTML=`<div class="st-empty">
    <div class="st-empty-glyph"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2 2 7l10 5 10-5-10-5z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/></svg></div>
    <h3>Map your kill chain, compile your dashboard</h3>
    <p>Stage techniques and AEGIS lays them out along the ATT&CK chain, compiles Splunk panels, and writes a full setup report:</p>
    <div class="st-steps">
      <span class="st-step"><b>1</b>Tick techniques in the matrix</span>
      <span class="st-step"><b>2</b>See them mapped on the kill chain</span>
      <span class="st-step"><b>3</b>Generate dashboard XML + report</span>
    </div>
    <button class="btn violet" style="margin-top:12px" onclick="go('matrix')">Open the matrix →</button>
  </div>`;
  return;
 }
 /* basket ordered by stage */
 basket.innerHTML=stagedOrdered().map(id=>{
  const t=T(id),n=eventsForTech(id).length,si=primaryStage(id);
  const stage=si<TACTICS.length?TACTICS[si][0]:'—';
  const mat=MATURITY.find(m=>m[0]===matOf(id));
  return`<div class="bk-item">
    <div class="bk-info">
      <div class="bk-stage">${si<9?'0':''}${si+1} · ${stage}</div>
      <div class="bk-id">${id}</div>
      <div class="bk-name">${t.name}</div>
      <div class="bk-count">${n} mapped detection${n===1?'':'s'}${n===0?' · strategy only':''}</div>
      <button class="bk-mat" style="--mc:${mat[2]}" onclick="cycleMaturity('${id}',event)" data-tip="Detection maturity — click to advance: Idea → Tested → Tuned → Production">● ${mat[1]}</button>
    </div>
    <button class="bk-x" data-tip="Remove" onclick="togStudio('${id}')">×</button>
  </div>`;
 }).join('');

 const panels=collectPanels();
 const stagesHit=[...new Set([...studio].map(primaryStage))].filter(i=>i<TACTICS.length).sort((a,b)=>a-b);
 const span=stagesHit.length?`${TACTICS[stagesHit[0]][0]} → ${TACTICS[stagesHit[stagesHit.length-1]][0]}`:'—';

 main.innerHTML=`
  <div class="st-out-head">
    <h2>Detection Studio</h2>
    <input class="dash-input" id="dash-name" value="ATT&CK Detection Coverage" data-tip="Becomes the dashboard label in Splunk and the report title" data-tip-pos="bottom">
    <button class="btn violet" onclick="openReport()" data-tip="Generate a full, printable setup report with kill-chain diagram, per-detection SPL, deployment steps, and recommendations" data-tip-pos="bottom">⤓ Generate Report</button>
    <div class="exp-menu">
      <button class="btn ghost-violet" onclick="document.getElementById('exp-pop').classList.toggle('open')" data-tip="All export formats" data-tip-pos="bottom">Export ▾</button>
      <div class="exp-pop" id="exp-pop">
        <button onclick="expDo(downloadSavedSearches)">savedsearches.conf <em>deploy to Splunk</em></button>
        <button onclick="expDo(downloadSigma)">Sigma rules (.yml) <em>portable</em></button>
        <button onclick="expDo(copyAllSPL)">Copy all SPL</button>
        <button class="exp-more" onclick="document.getElementById('exp-more').classList.toggle('open');this.classList.toggle('open')">More formats ▾</button>
        <div class="exp-more-wrap" id="exp-more">
          <button onclick="expDo(downloadRBA)">⚡ RBA package (.spl)</button>
          <button onclick="expDo(downloadDashXML)">Dashboard .xml</button>
          <button onclick="expDo(copyDashXML)">Copy dashboard XML</button>
          <button onclick="expDo(navLayer)">ATT&CK Navigator layer</button>
        </div>
      </div>
    </div>
  </div>
  <div class="chain-sum">
    <span class="chain-sum-pill"><b>${studio.size}</b> techniques staged</span>
    <span class="chain-sum-pill"><b>${stagesHit.length}</b>/${TACTICS.length} kill-chain stages</span>
    <span class="chain-sum-pill">Span: <b>${span}</b></span>
    <span class="chain-sum-pill"><b>${panels.length}</b> dashboard panels</span>
    ${(()=>{const r=maturityRollup();return r?`<span class="chain-sum-pill" data-tip="Deployment readiness of your staged detections"><b>${r.prod}</b> production · ${r.tuned+r.tested} in progress · ${r.idea} idea</span>`:'';})()}
  </div>
  <div class="st-tabs">
    <button class="st-tab${stTab==='chain'?' on':''}" onclick="setStTab('chain')">⛓ ATTACK CHAIN</button>
    <button class="st-tab${stTab==='panels'?' on':''}" onclick="setStTab('panels')">▤ DASHBOARD PANELS</button>
    <button class="st-tab${stTab==='threat'?' on':''}" onclick="setStTab('threat')">🎯 THREAT COVERAGE</button>
    <button class="st-tab${stTab==='rba'?' on':''}" onclick="setStTab('rba')">⚡ RISK-BASED ALERTING</button>
  </div>
  ${stTab==='chain'?renderChain():stTab==='rba'?renderRBA():stTab==='threat'?renderThreat():renderPanels(panels)}`;
}
function renderThreat(){
 return`<div class="threat-wrap">
   <div class="threat-intro">Score your staged coverage against a specific adversary's known techniques — a sharper readiness signal than raw framework percentages. Pick a profile to see what you'd catch and what they'd get away with.</div>
   <div class="threat-cards">
     ${Object.entries(THREAT_PROFILES).map(([k,p])=>{const c=threatCoverage(k);const on=threatSel===k;
      return`<div class="threat-card${on?' on':''}" onclick="setThreat('${k}')">
        <div class="threat-card-top"><span class="threat-name">${p.name}</span><span class="threat-pct" style="--pc:${c.pct>=70?'var(--mint)':c.pct>=40?'var(--amber)':'var(--magenta)'}">${c.pct}%</span></div>
        <div class="threat-blurb">${p.blurb}</div>
        <div class="threat-bar"><div class="threat-bar-fill" style="width:${Math.max(c.pct,3)}%;background:${c.pct>=70?'var(--mint)':c.pct>=40?'var(--amber)':'var(--magenta)'}"></div></div>
        <div class="threat-meta">${c.covered.length}/${c.known.length} techniques · ${c.detectable.length} with live telemetry</div>
      </div>`;}).join('')}
   </div>
   ${threatSel?threatDetail(threatSel):'<div class="threat-hint">Select a profile above to break down covered vs uncovered techniques.</div>'}
 </div>`;
}
function threatDetail(key){
 const c=threatCoverage(key);if(!c)return'';
 const row=(id,state)=>{const t=T(id);const evs=eventsForTech(id).length;
  return`<div class="threat-trow ${state}">
    <span class="threat-tid">${id}</span>
    <span class="threat-tname">${t?t.name:id}</span>
    <span class="threat-tstate">${state==='covered'?(evs?'✓ detectable':'✓ staged · no telemetry'):'✗ gap'}</span>
  </div>`;};
 const covered=c.known.filter(id=>studio.has(id));
 const gaps=c.known.filter(id=>!studio.has(id));
 return`<div class="threat-detail">
   <div class="threat-detail-head"><h3>${c.profile.name} — ${c.pct}% covered</h3>${gaps.length?`<button class="btn violet" onclick="stageThreatGaps('${key}')">Stage all ${gaps.length} gap${gaps.length===1?'':'s'} →</button>`:'<span class="threat-clear">Full coverage of known techniques</span>'}</div>
   ${covered.length?`<div class="threat-sec">Covered</div>${covered.map(id=>row(id,'covered')).join('')}`:''}
   ${gaps.length?`<div class="threat-sec">Gaps — ${c.profile.name} could use these unseen</div>${gaps.map(id=>row(id,'gap')).join('')}`:''}
 </div>`;
}

function renderChain(){
 const activeStages=new Set([...studio].map(primaryStage));
 let html='<div class="chain-wrap"><div class="chain">';
 const activeIdx=TACTICS.map((_,i)=>i).filter(i=>activeStages.has(i));
 const minA=activeIdx.length?Math.min(...activeIdx):-1,maxA=activeIdx.length?Math.max(...activeIdx):-1;
 TACTICS.forEach(([tac,slug,techs],i)=>{
  const active=activeStages.has(i);
  const staged=stagedOrdered().filter(id=>primaryStage(id)===i);
  if(active){
   html+=`<div class="cstage active">
     <div class="cstage-head">Stage ${i+1}<b>${tac}</b></div>
     ${staged.map(id=>{
       const t=T(id);let n=eventsForTech(id).length;
       return`<div class="cnode" onclick="openDrawer('${id}')" data-tip="Click for strategy · × to unstage">
         <button class="cnode-x" onclick="event.stopPropagation();togStudio('${id}')" data-tip="Unstage">×</button>
         <div class="cnode-id">${id}</div>
         <div class="cnode-name">${t.name}</div>
         <div class="cnode-evs">${n?n+' detection'+(n===1?'':'s'):'strategy only'}</div>
       </div>`;
     }).join('')}
   </div>`;
  }else{
   html+=`<div class="cstage inactive">
     <div class="cstage-head">Stage ${i+1}<b>${tac}</b></div>
     <div class="cempty-slot">—</div>
   </div>`;
  }
  if(i<TACTICS.length-1){const lit=i>=minA&&i<maxA;html+=`<div class="carrow${lit?' lit':''}">→</div>`;}
 });
 html+='</div></div>';
 html+=`<p style="font-size:11px;color:var(--t2);margin-top:6px;max-width:640px;line-height:1.6">Staged techniques are placed at their primary kill-chain stage. Lit arrows trace the span of the attack you're building coverage for — from the earliest staged stage to the latest. Click any node for its full strategy, or generate the report to get this same sequence with setup steps and SPL.</p>`;
 return html;
}

function renderPanels(panels){
 if(!panels.length)return`<div class="st-empty" style="padding:40px"><p>Your staged techniques are strategy-only (no mapped telemetry yet). They still appear in the kill chain and report with mitigation guidance — but there are no dashboard panels to compile. Stage a technique with mapped events (a colored matrix cell) to get SPL panels.</p></div>`;
 return panels.map(p=>`
   <div class="panel-card">
     <div class="pc-head">
       <span class="eid ${p.plat==='windows'?'w':'a'}">${p.id}</span>
       <h3>${p.title}</h3>
       <span class="mtag" data-tip="Open the ${p.tech} strategy" onclick="openDrawer('${p.tech}')">${p.tech}</span>
       <span class="risk ${p.risk==='high'?'hi':p.risk==='med'?'md':'lo'}">${p.risk.toUpperCase()}</span>
     </div>
     <div class="pc-body">
       ${p.setup?`<div class="setup-note">⚙ <b style="color:var(--amber)">Setup:</b>&nbsp;${esc(p.setup)}</div>`:''}
       <div class="qwrap"><div class="qblock">${hl(p.query)}</div>
       <button class="cpy" onclick="copyText(this,${JSON.stringify(p.query).replace(/"/g,'&quot;')})">COPY</button></div>
       ${splLintHTML(p.query)}
       ${tuneHTML(p.tech)}
     </div>
   </div>`).join('');
}

function renderRBA(){
 const {dets,threshold,minTactics}=buildRBABundle();
 if(!dets.length)return`<div class="st-empty" style="padding:40px"><p>Risk-based alerting needs detections with mapped telemetry. Stage techniques that have colored matrix cells, then this tab builds the risk-scoring searches and the correlation rule.</p></div>`;
 // group by risk object type and show scores
 const rows=dets.map(({e,tid})=>{
  const [roType,roField]=riskObjectFor(e);
  const sc=riskScore(e,tid);
  return`<tr>
    <td><span class="eid ${e.plat==='windows'?'w':'a'}" style="font-size:9px">${e.id}</span></td>
    <td style="font-size:11px">${e.title}</td>
    <td><span class="mtag" onclick="openDrawer('${tid}')" style="cursor:pointer">${tid}</span></td>
    <td style="font-family:var(--mono);font-size:10px;color:var(--t2)">${TACTICS[primaryStage(tid)][0]}</td>
    <td style="font-family:var(--mono);font-size:10px;color:var(--sky)">${roType}:${roField}</td>
    <td style="text-align:center"><span class="rba-score" style="--s:${sc}">${sc}</span></td>
  </tr>`;
 }).join('');
 const corr=rbaCorrelationSPL(threshold,minTactics);
 const sample=dets[0];
 return`
  <div class="rba-intro">
    <div class="rba-intro-icon">⚡</div>
    <div>
      <h3 style="font-size:14px;font-weight:600;margin-bottom:4px">Risk-based alerting turns ${dets.length} noisy detections into one high-fidelity alert</h3>
      <p style="font-size:11.5px;color:var(--t2);line-height:1.6">Instead of paging on every individual detection, each one writes a <b>scored risk event</b> to a dedicated <code style="font-family:var(--mono);font-size:10px;color:var(--violet)">index=risk</code>. A single correlation search sums risk per user or host and fires only when the total crosses <b>${threshold}</b> across <b>${minTactics}+ ATT&amp;CK tactics</b> — surfacing entities that show a genuine attack <i>chain</i>, not isolated events.</p>
    </div>
  </div>
  <div style="display:flex;gap:8px;margin:14px 0">
    <button class="btn mint" onclick="copyRBA()" data-tip="Copy the full RBA package: all risk searches + the correlation rule">Copy full package</button>
    <button class="btn" onclick="downloadRBA()" data-tip="Download as a .spl file">Download .spl</button>
  </div>
  <div class="sec-t" style="margin:18px 0 10px">Risk contribution per detection</div>
  <div style="overflow-x:auto"><table class="rba-table">
    <thead><tr><th>Event</th><th>Detection</th><th>Technique</th><th>Tactic</th><th>Risk object</th><th style="text-align:center">Score</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>
  <div class="sec-t" style="margin:22px 0 10px">The correlation search — your only alerting rule</div>
  <div class="qwrap"><div class="qblock">${hl(corr)}</div>
  <button class="cpy" onclick="copyText(this,${JSON.stringify(corr).replace(/"/g,'&quot;')})">COPY</button></div>
  <div class="sec-t" style="margin:22px 0 10px">Example: one detection, enriched to write risk</div>
  <p style="font-size:11px;color:var(--t2);margin-bottom:8px">Each staged detection is wrapped like this — the original search plus risk metadata, collected into the risk index. All ${dets.length} are in the exported package.</p>
  <div class="qwrap"><div class="qblock">${hl(rbaDetectionSPL(sample.e,sample.tid))}</div>
  <button class="cpy" onclick="copyText(this,${JSON.stringify(rbaDetectionSPL(sample.e,sample.tid)).replace(/"/g,'&quot;')})">COPY</button></div>`;
}

function buildDashXML(){
 const title=document.getElementById('dash-name')?.value||'ATT&CK Detection Coverage';
 const panels=collectPanels();
 const rows=[];for(let i=0;i<panels.length;i+=2)rows.push(panels.slice(i,i+2));
 return`<dashboard version="1.1" theme="dark">
  <label>${xmlEsc(title)}</label>
  <description>Generated by AEGIS Detection Studio · ${studio.size} techniques · kill-chain ordered</description>
${rows.map(row=>`  <row>
${row.map(p=>`    <panel>
      <title>${xmlEsc(p.id+' — '+p.title+' ['+p.tech+' · '+TACTICS[primaryStage(p.tech)][0]+']')}</title>
      <table>
        <search>
          <query>${xmlEsc(p.query)}</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">cell</option>
        <option name="count">20</option>
      </table>
    </panel>`).join('\n')}
  </row>`).join('\n')}
</dashboard>`;
}
function copyDashXML(){navigator.clipboard.writeText(buildDashXML()).then(()=>toast('Dashboard XML copied — paste into Splunk source editor'));}
function downloadDashXML(){
 const blob=new Blob([buildDashXML()],{type:'application/xml'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='attack_coverage_dashboard.xml';a.click();
 URL.revokeObjectURL(a.href);toast('Dashboard XML downloaded');
}
function copyAllSPL(){
 const out=[];collectPanels().forEach(e=>{out.push(`\`\`\` ${e.id} — ${e.title} [${e.tech} · ${TACTICS[primaryStage(e.tech)][0]}] \`\`\`\n${e.query}`);});
 navigator.clipboard.writeText(out.join('\n\n')).then(()=>toast('All SPL queries copied'));
}
function navLayer(){
 const layer={name:document.getElementById('dash-name')?.value||'AEGIS Coverage',versions:{attack:"16",navigator:"5.1.1",layer:"4.5"},domain:"enterprise-attack",description:"Generated by AEGIS Detection Studio",
  techniques:[...studio].map(id=>({techniqueID:id,score:1,color:"#8b7bff",comment:`${eventsForTech(id).length} mapped detection(s)`,enabled:true}))};
 const blob=new Blob([JSON.stringify(layer,null,2)],{type:'application/json'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='aegis_navigator_layer.json';a.click();
 URL.revokeObjectURL(a.href);toast('ATT&CK Navigator layer exported');
}
/* ---- Sigma export (portable detection standard) ---- */
function sigmaLogSource(e){
 if(e.plat==='aws')return {product:'aws',service:'cloudtrail'};
 // windows
 const ch=/^\d+$/.test(e.id)?'security':'security';
 return {product:'windows',service:'security'};
}
function sigmaFor(e,tid){
 const t=T(tid);
 const ls=sigmaLogSource(e);
 const tactic=(TACTICS[primaryStage(tid)]||['',''])[0].toLowerCase().replace(/\s+/g,'_');
 const sev=e.risk==='high'?'high':e.risk==='med'?'medium':'low';
 // build a minimal, valid detection body keyed to the event id
 let sel;
 if(e.plat==='aws'){
  sel=`    eventName: ${e.id}`;
 }else{
  sel=`    EventID: ${/^\d+$/.test(e.id)?e.id:'"'+e.id+'"'}`;
 }
 return `title: ${e.title} (${e.id})
id: aegis-${e.plat}-${String(e.id).toLowerCase().replace(/[^a-z0-9]+/g,'-')}
status: experimental
description: >
  ${t.summary||t.name}. Generated by AEGIS from ${e.id} for ${tid} ${t.name}.
references:
  - https://attack.mitre.org/techniques/${tid.replace('.','/')}/
author: AEGIS Detection Studio
date: ${new Date().toISOString().slice(0,10)}
tags:
  - attack.${tactic}
  - attack.${tid.toLowerCase()}
logsource:
  product: ${ls.product}
  service: ${ls.service}
detection:
  selection:
${sel}
  condition: selection
falsepositives:
  - Legitimate administrative activity — baseline before enabling
level: ${sev}`;
}
function buildSigmaBundle(){
 const panels=collectPanels();
 const out=['# ===================================================================',
  '# AEGIS — Sigma rule pack',
  `# ${panels.length} rules · generated ${new Date().toISOString().slice(0,10)}`,
  '# Convert to your SIEM with sigma-cli, e.g.:  sigma convert -t splunk -p splunk_windows this.yml',
  '# Each rule is separated by the standard YAML document marker (---).',
  '# ===================================================================',''];
 panels.forEach(e=>{out.push(sigmaFor(e,e.tech));out.push('---');});
 return out.join('\n');
}
function downloadSigma(){
 if(!collectPanels().length){toast('Stage detections with telemetry first');return;}
 const blob=new Blob([buildSigmaBundle()],{type:'text/yaml'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='aegis_sigma_rules.yml';a.click();
 URL.revokeObjectURL(a.href);toast('Sigma rule pack exported');
}
/* ---- savedsearches.conf (detection-as-code for Splunk) ---- */
function buildSavedSearches(){
 const panels=collectPanels();
 const app=(document.getElementById('dash-name')?.value||'AEGIS Coverage');
 const out=['# ===================================================================',
  '# AEGIS — savedsearches.conf (Splunk detection-as-code)',
  `# ${panels.length} scheduled detections · generated ${new Date().toISOString().slice(0,10)}`,
  '# Drop into $SPLUNK_HOME/etc/apps/<your_app>/local/savedsearches.conf',
  '# Adjust the cron, index, and email/action.* to your environment.',
  '# ===================================================================',''];
 panels.forEach(e=>{
  const tid=e.tech;const meta=ALERT_META[e.id]||{};
  const cad=meta.cadence||{sched:'15m',window:'-20m@m',throttle:'4h'};
  const cron=cad.sched==='5m'?'*/5 * * * *':cad.sched==='60m'||cad.sched==='1h'?'0 * * * *':'*/15 * * * *';
  const q=(e.query||'').replace(/\n/g,' ');
  out.push(`[AEGIS - ${e.id} - ${e.title}]`);
  out.push(`description = ${T(tid).name} (${tid}) — AEGIS-generated detection from ${e.id}`);
  out.push(`search = ${q}`);
  out.push('dispatch.earliest_time = '+(cad.window||'-20m@m'));
  out.push('dispatch.latest_time = now');
  out.push('cron_schedule = '+cron);
  out.push('enableSched = 1');
  out.push('counttype = number of events');
  out.push('relation = greater than');
  out.push('quantity = 0');
  out.push(`action.notable = 1`);
  out.push(`action.notable.param.rule_title = ${e.title} (${e.id})`);
  out.push(`action.notable.param.security_domain = ${e.plat==='aws'?'network':'endpoint'}`);
  out.push(`action.notable.param.severity = ${e.risk==='high'?'high':e.risk==='med'?'medium':'low'}`);
  if(meta.throttle!==false){out.push('alert.suppress = 1');out.push('alert.suppress.period = '+(cad.throttle||'4h'));
   if(meta.suppressKeys&&meta.suppressKeys.length)out.push('alert.suppress.fields = '+meta.suppressKeys.join(','));}
  out.push(`# ATT&CK: ${tid} · ${(TACTICS[primaryStage(tid)]||['',''])[0]}`);
  out.push('');
 });
 return out.join('\n');
}
function downloadSavedSearches(){
 if(!collectPanels().length){toast('Stage detections with telemetry first');return;}
 const blob=new Blob([buildSavedSearches()],{type:'text/plain'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='savedsearches.conf';a.click();
 URL.revokeObjectURL(a.href);toast('savedsearches.conf exported');
}

/* ================= RISK-BASED ALERTING (RBA) ================= */
/* Per-event risk object (the entity risk accumulates against) + primary field.
   Falls back to a sensible default by platform when not specified. */
const RISK_OBJECT={
 '4624':['user','Target_User_Name'],'4625':['user','Target_User_Name'],'4688':['host','ComputerName'],
 '4657':['host','ComputerName'],'4663':['user','SubjectUserName'],'4672':['user','SubjectUserName'],
 '4698':['host','ComputerName'],'4719':['host','ComputerName'],'4720':['user','Target_User_Name'],
 '4732':['user','MemberName'],'4740':['user','Target_User_Name'],'4769':['user','Account_Name'],
 '5140':['host','ComputerName'],'5145':['user','SubjectUserName'],'5156':['host','ComputerName'],
 '7045':['host','ComputerName'],'1102':['host','ComputerName'],
 'ConsoleLogin':['user','user'],'AssumeRole':['user','caller'],'CreateUser':['user','creator'],
 'CreateAccessKey':['user','creator'],'AttachRolePolicy':['user','role'],'StopLogging':['user','actor'],
 'GetSecretValue':['user','caller'],'ListBuckets':['user','caller'],'GetObject':['user','caller']
};
/* Risk score derived from event severity and how deep in the kill chain it sits.
   Later-stage, higher-severity events carry more risk. Range ~20–100. */
function riskScore(e,tid){
 const base={high:60,med:35,low:20}[e.risk]||30;
 const stage=primaryStage(tid);
 const stageBonus=Math.round((stage/13)*30); // up to +30 for Impact-stage
 const nonSuppressible=(ALERT_META[e.id]&&ALERT_META[e.id].suppressible===false)?10:0;
 return Math.min(100,base+stageBonus+nonSuppressible);
}
function riskObjectFor(e){
 if(RISK_OBJECT[e.id])return RISK_OBJECT[e.id];
 return e.plat==='aws'?['user','userIdentity.arn']:['host','ComputerName'];
}
/* Build the per-detection risk-writing search: the detection, annotated with
   ATT&CK + risk metadata, appended into a risk index. */
function rbaDetectionSPL(e,tid){
 const [roType,roField]=riskObjectFor(e);
 const score=riskScore(e,tid);
 const stage=TACTICS[primaryStage(tid)][0];
 const q=e.query.trim();
 return `${q}
| eval risk_object=${roField}, risk_object_type="${roType}"
| eval risk_score=${score}
| eval mitre_tactic="${stage}", mitre_technique="${tid}", source_event="${e.id}"
| eval search_name="RBA - ${e.id} ${e.title} [${tid}]"
| collect index=risk`;
}
/* The correlation search: aggregate risk per object over a window, fire when the
   score crosses a threshold AND spans multiple kill-chain tactics (reduces FPs). */
function rbaCorrelationSPL(threshold,minTactics){
 return `index=risk earliest=-24h latest=now
| stats sum(risk_score) as total_risk,
        dc(mitre_tactic) as tactic_count,
        dc(mitre_technique) as technique_count,
        values(mitre_tactic) as tactics,
        values(mitre_technique) as techniques,
        values(source_event) as contributing_events,
        count as event_count
    by risk_object, risk_object_type
| where total_risk >= ${threshold} AND tactic_count >= ${minTactics}
| eval risk_summary=risk_object." accumulated ".total_risk." risk across ".tactic_count." ATT&CK tactics"
| sort - total_risk`;
}
function buildRBABundle(){
 const seen=new Set();
 const dets=[];
 stagedOrdered().forEach(id=>{
  eventsForTech(id).forEach(e=>{
   const key=e.plat+e.id;if(seen.has(key))return;seen.add(key);
   dets.push({e,tid:id});
  });
 });
 // suggested threshold: ~60% of the max achievable single-object risk across two busiest tactics,
 // floored to a sensible minimum. minTactics scales with breadth of coverage.
 const stages=new Set(stagedOrdered().map(primaryStage));
 const minTactics=Math.min(3,Math.max(2,stages.size>=4?3:2));
 const threshold=100;
 return {dets,threshold,minTactics};
}
function rbaFullText(){
 const {dets,threshold,minTactics}=buildRBABundle();
 if(!dets.length)return'// Stage at least one technique with mapped telemetry to generate RBA searches.';
 const parts=[];
 parts.push(`===============================================================
 RISK-BASED ALERTING PACKAGE — generated by AEGIS
 ${dets.length} contributing detections · correlation threshold ${threshold} across ${minTactics}+ tactics
===============================================================

HOW THIS WORKS
Each detection below no longer pages an analyst on its own. Instead it writes a
scored risk event (risk_score, risk_object, ATT&CK metadata) into a dedicated
'risk' index. A single correlation search then sums risk per entity (user or
host) over 24h and fires only when the accumulated score crosses ${threshold}
AND the activity spans at least ${minTactics} different ATT&CK tactics. This
surfaces entities showing a *chain* of suspicious behaviour while staying quiet
on isolated, low-value events.

SETUP (once):
  1. Create an index named 'risk' (Settings > Indexes).
  2. Save each CONTRIBUTING DETECTION below as a scheduled search (cron */15).
     They are silent — they only write to the risk index, no alert action.
  3. Save the CORRELATION SEARCH as your alerting rule (cron */15, alert on
     results > 0). This is the only search that notifies an analyst.
  4. Tune the threshold after a week of live risk data.

`);
 parts.push(`--- CONTRIBUTING DETECTIONS (${dets.length}) — each writes to index=risk ---\n`);
 dets.forEach(({e,tid},i)=>{
  parts.push(`# ${i+1}. ${e.id} ${e.title}  [${tid} · ${TACTICS[primaryStage(tid)][0]}]  risk_score=${riskScore(e,tid)}, risk_object=${riskObjectFor(e)[1]} (${riskObjectFor(e)[0]})`);
  parts.push(rbaDetectionSPL(e,tid));
  parts.push('');
 });
 parts.push(`--- CORRELATION SEARCH (the alerting rule) ---\n`);
 parts.push(rbaCorrelationSPL(threshold,minTactics));
 return parts.join('\n');
}
function copyRBA(){
 navigator.clipboard.writeText(rbaFullText()).then(()=>toast('Risk-based alerting package copied'));
}
function downloadRBA(){
 const blob=new Blob([rbaFullText()],{type:'text/plain'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='aegis_rba_package.spl';a.click();
 URL.revokeObjectURL(a.href);toast('RBA package downloaded (.spl)');
}
function rbaReportSection(){
 const {dets,threshold,minTactics}=buildRBABundle();
 if(!dets.length)return'<p>No detections with native telemetry are staged, so a risk-based alerting layer cannot be generated. Add mappable detections to enable this section.</p>';
 const rows=dets.map(({e,tid})=>{
  const [roType,roField]=riskObjectFor(e);
  return`<tr><td class="mono">${e.id}</td><td>${e.title}</td><td class="mono">${tid}</td><td>${TACTICS[primaryStage(tid)][0]}</td><td class="mono">${roType}:${roField}</td><td style="text-align:center;font-weight:600;color:#5747d6">${riskScore(e,tid)}</td></tr>`;
 }).join('');
 const corr=rbaCorrelationSPL(threshold,minTactics);
 return`<p>Rather than alerting on each detection independently, this rule set can be deployed as a <strong>risk-based alerting (RBA)</strong> layer. Each contributing detection writes a scored risk event — carrying its risk value, the entity it concerns, and its ATT&amp;CK metadata — into a dedicated risk index. A single correlation search then aggregates risk per entity and raises one notable only when accumulated risk crosses <strong>${threshold}</strong> across <strong>${minTactics} or more ATT&amp;CK tactics</strong>. This dramatically reduces alert volume while raising fidelity: an analyst is engaged when an entity exhibits a chain of related behaviour, not for isolated low-value events.</p>
 <h3>Risk contribution by detection</h3>
 <p>The score each detection contributes, derived from its severity and how late in the kill chain it occurs. Later-stage, higher-severity, and non-suppressible events carry more weight.</p>
 <table><thead><tr><th>Event</th><th>Detection</th><th>Technique</th><th>Tactic</th><th>Risk object</th><th style="text-align:center">Score</th></tr></thead><tbody>${rows}</tbody></table>
 <h3>Correlation search (the alerting rule)</h3>
 <p>This is the only search that notifies an analyst. The contributing detections above run silently, writing to the risk index; this rule surfaces the entities worth investigating.</p>
 <pre>${esc(corr)}</pre>
 <p style="font-size:11px;color:#77779a">The full package — every contributing detection enriched with risk metadata, plus this correlation search and setup instructions — is available from the <strong>RBA package</strong> export in the Detection Studio.</p>`;
}
