/* ================= AI ================= */
const SYS=`You are an elite detection engineering copilot embedded in AEGIS, a SOC analyst intelligence platform. Expertise: Windows Security Event Logs (all IDs, field semantics, correlation), AWS CloudTrail, MITRE ATT&CK (full framework incl. mitigations), Splunk SPL (advanced — joins, lookups, tstats, ML), false positive suppression.

The analyst is an experienced SOC analyst / detection engineer working with Windows Security events and CloudTrail in Splunk. Their established preferences:
- Broad alerting suppressed via lookup tables (outputlookup baselines, inputlookup suppression) over complex pre-filters
- dc(ComputerName) for frequency scoring
- ut_shannon_lookup for entropy detection (requires tonumber() on the shannon field)
- For 4657: Object_Name = registry key path, New_Value = written data; ImagePath/binary_path do not exist natively

STYLE: Direct, technical, zero fluff. Production-ready SPL with exact field names. For MITRE techniques always give: technique ID, event sources, critical fields, detection query, mitigations, and FP suppression guidance. Use markdown headers and code blocks.

Available Windows events: 4624, 4625, 4657, 4663, 4672, 4688, 4698, 4719, 4720, 4732, 4740, 4769, 5140, 5145, 5156, 7045, 1102. AWS: ConsoleLogin, AssumeRole, CreateUser, CreateAccessKey, AttachRolePolicy, StopLogging, DeleteTrail, GetSecretValue, ListBuckets (enum), GetObject (S3). Note where a detection needs Sysmon, email gateway, proxy, or S3 data events beyond these.

The AEGIS app can export a risk-based alerting (RBA) package: each detection writes a scored risk event (risk_score, risk_object, mitre_tactic, mitre_technique) into index=risk via | collect, and one correlation search sums risk per entity and fires when it crosses a threshold across multiple tactics. When the analyst asks about reducing alert volume or improving fidelity, recommend and build on this RBA pattern using | collect index=risk and the aggregation correlation search.`;

function askAboutTech(id){
 closeDrawer();go('ai');
 const t=T(id);
 quickAsk(`Deep-dive ${id} (${t.name}) for my environment: detection strategy, the exact Windows Event IDs / CloudTrail events to use, key fields, one production-ready SPL query per event source, the relevant ATT&CK mitigations, and a lookup-based FP suppression approach.`);
}
/* Build a compact but rich description of the current staged mapping for the AI */
function mappingContext(){
 if(!studio.size)return null;
 const ordered=stagedOrdered();
 const lines=ordered.map(id=>{
  const t=T(id),si=primaryStage(id);
  const stage=si<TACTICS.length?TACTICS[si][0]:'—';
  const evs=eventsForTech(id).map(e=>`${e.id}(${e.plat})`).join(', ')||'NO NATIVE TELEMETRY';
  const mits=(t.mits||[]).join(',');
  return `- ${id} ${t.name} [stage ${si+1}: ${stage}] — events: ${evs}; mitigations: ${mits}`;
 });
 const activeStages=new Set(ordered.map(primaryStage));
 const gaps=TACTICS.map((t,i)=>[t[0],i]).filter(([,i])=>!activeStages.has(i)).map(([n])=>n);
 const strategyOnly=ordered.filter(id=>eventsForTech(id).length===0);
 return `The analyst has staged these ${studio.size} ATT&CK techniques into their Splunk detection dashboard (kill-chain order):
${lines.join('\n')}

Kill-chain stages with NO coverage: ${gaps.length?gaps.join(', '):'none — all 14 covered'}.
Staged techniques with no native telemetry (strategy only): ${strategyOnly.length?strategyOnly.join(', '):'none'}.`;
}
function analyzeMapping(){
 go('ai');
 const ctx=mappingContext();
 if(!ctx){addMsg('assistant','You haven\'t staged any techniques yet. Go to the **ATT&CK Matrix** and click techniques to stage them — then I can review the mapping and suggest improvements. Try a **Quick stage** scenario button at the top of the matrix for a fast start.');return;}
 const prompt=`${ctx}

Review this detection mapping as a senior detection engineer doing a peer review. Give me a prioritised, side-by-side critique in these sections, using markdown headers:

## Strongest coverage
What's well covered and why (1-2 sentences).

## Highest-priority gaps
The 3 most important weaknesses in this mapping — missing kill-chain stages an attacker would exploit, or staged techniques with weak/no telemetry. For each, name the specific technique or event to add and why it matters.

## Correlation opportunities
Where I have 2+ staged techniques that share a logon session, host, or identity and should be joined into a single higher-fidelity correlation search instead of separate alerts. Give me the actual SPL join for the single best opportunity, using correct Windows field names (Subject_Logon_ID, Target_Logon_ID) or CloudTrail fields.

## Tuning priorities
Which 2-3 of my staged detections will be noisiest in a real environment, and the specific lookup-based suppression or threshold to apply first.

Be specific and reference my actual staged technique IDs. Keep it tight — this is a working review, not a textbook.`;
 addMsg('user','Review my staged coverage and suggest improvements');
 chatLog.push({role:'user',content:prompt});
 runAI();
}
function suggestNextTechniques(){
 go('ai');
 const ctx=mappingContext();
 if(!ctx){addMsg('assistant','Stage some techniques first (click them in the ATT&CK Matrix), then I can recommend what to add next to close your biggest gaps.');return;}
 const prompt=`${ctx}

Based on what I've already staged, recommend the next 4-5 techniques I should add to most improve this dashboard. Prioritise closing kill-chain blind spots and strengthening thin coverage. For each: the technique ID and name, which of my available events detects it (Windows Security or CloudTrail), and one sentence on why it's the right next add given what I already have. Reference my staged techniques so the recommendations connect to my current mapping.`;
 addMsg('user','What should I add next to improve coverage?');
 chatLog.push({role:'user',content:prompt});
 runAI();
}
function buildCorrelations(){
 go('ai');
 const ctx=mappingContext();
 if(!ctx){addMsg('assistant','Stage a few related techniques first — ideally ones that share a logon session or host (e.g. a logon, a process creation, and a service install). Then I can turn them into multi-event correlation searches.');return;}
 const prompt=`${ctx}

Turn my staged single-event detections into higher-fidelity multi-event correlation searches. Identify every pair or chain among my staged techniques that can be linked by a shared key (Subject_Logon_ID/Target_Logon_ID for Windows sessions, ComputerName for host, userIdentity.arn for AWS). For the 2-3 best opportunities, give me production Splunk SPL using join or stats-based correlation with the correct exact field names, plus a one-line note on the fidelity gain versus alerting on each event separately. Follow my convention of broad detection with lookup-based suppression where relevant.`;
 addMsg('user','Build correlation searches from my staged techniques');
 chatLog.push({role:'user',content:prompt});
 runAI();
}
function adviseRBA(){
 go('ai');
 const ctx=mappingContext();
 if(!ctx){addMsg('assistant','Stage some detections first, then I can advise on risk scoring and thresholds. AEGIS can also export a ready-made RBA package from the Detection Studio once you have techniques staged.');return;}
 const prompt=`${ctx}

I'm deploying these as a risk-based alerting (RBA) layer: each detection writes a scored risk event into index=risk with | collect, and one correlation search sums risk per entity (user/host) and fires when it crosses a threshold across multiple ATT&CK tactics. Advise me on: (1) sensible risk_score values for my staged detections given their severity and kill-chain stage; (2) a defensible starting threshold and minimum tactic count for the correlation search given my current coverage; (3) how to tune both after collecting a week of live risk data; (4) any of my staged detections that should bypass RBA and alert directly instead. Be specific to my staged techniques.`;
 addMsg('user','How should I tune my risk-based alerting?');
 chatLog.push({role:'user',content:prompt});
 runAI();
}
function quickAsk(p){go('ai');document.getElementById('comp-in').value=p;ask();}
/* ---- incident (hunt map) AI context ---- */
function incidentContext(){
 if(!lsHasIncident())return null;
 const lines=lsNodes.filter(n=>n.obs&&n.obs.length).map(n=>{
  const t=NODE_TYPES[n.type];
  const obs=n.obs.map(o=>{const ev=LOGSRC.find(e=>e.id===o.evId);return `    · [${o.sev}] ${o.evId?o.evId+(ev?' '+ev.name:''):'(no event id)'}${o.note?' — "'+o.note+'"':''}`;}).join('\n');
  return `- ${n.label} (${t.label}, ${n.os})${lsNodeStatus(n)?' — status '+lsNodeStatus(n).toUpperCase():''}:\n${obs}`;
 });
 return `ACTIVE HUNT — observed events mapped across the network (kill-chain order where known):\n${lines.join('\n')}`;
}
function lsTriageNode(uid){
 const n=lsNodes.find(x=>x.uid===uid);if(!n||!n.obs||!n.obs.length){toast('Log an observation first');return;}
 go('ai');lsCloseNodeEdit();
 const t=NODE_TYPES[n.type];
 const obs=n.obs.map(o=>{const ev=LOGSRC.find(e=>e.id===o.evId);return `- [${o.sev}] ${o.evId?o.evId+(ev?' ('+ev.name+')':''):'no event id'}${o.note?': "'+o.note+'"':''}`;}).join('\n');
 const prompt=`During an active hunt I'm seeing the following on a single host:

Host: ${n.label} — ${t.label}, OS ${n.os}
Observations:
${obs}

As a senior IR analyst, triage THIS host: (1) what is the most likely explanation for these observations together; (2) are they consistent with a known ATT&CK technique or chain; (3) the exact next Splunk queries or Event IDs I should pull on this host to confirm or rule it out; (4) immediate containment steps if this is malicious. Use correct Windows field names. Keep it tight and actionable.`;
 addMsg('user',`Triage ${n.label} — ${n.obs.length} observation${n.obs.length===1?'':'s'}`);
 chatLog.push({role:'user',content:prompt});
 runAI();
}
function analyzeIncident(){
 go('ai');
 const ic=incidentContext();
 if(!ic){addMsg('assistant','No observations are on the hunt map yet. Open **Log Sources → Active hunt**, click a node, and log what you\'re seeing on it (an Event ID, a note, and a severity). Then I can correlate the observations across hosts into a likely attack chain.');return;}
 // give the AI the node list with uids so it can reference them precisely
 const nodeList=lsNodes.map(n=>`  ${n.uid} = ${n.label} (${NODE_TYPES[n.type].label})`).join('\n');
 const prompt=`${ic}

NODES IN THE MAP (use these exact uids in the chain):
${nodeList}

As a senior incident responder, analyse this as one picture. First give a concise narrative: (1) the most likely attack chain in kill-chain order naming ATT&CK techniques; (2) probable patient zero and furthest extent of compromise; (3) the single most urgent action; (4) cross-host Splunk correlation searches (correct field names) to confirm the movement; (5) what to check that isn't yet on the map.

THEN, on the very last line, output a machine-readable chain for the map animation as a single-line JSON object with this exact shape and nothing after it:
ATTACK_CHAIN={"steps":[{"from":"<uid>","to":"<uid>","tech":"T####","detail":"one short clause","conf":"high|medium|low"}]}
Order steps in kill-chain sequence. Use a node's own uid for both from and to when the activity is on-host. Only reference uids from the list above. For "conf", rate how strongly the observed evidence supports each hop — "high" when a logged observation directly shows it, "low" when it's inferred to fill a gap.`;
 addMsg('user','Analyse my hunt map — correlate the observations into an attack chain');
 chatLog.push({role:'user',content:prompt});
 runAI({chain:true});
}
/* parse an ATTACK_CHAIN=... block out of an AI reply; returns steps[] or null */
function parseAttackChain(text){
 if(!text)return null;
 const m=text.match(/ATTACK_CHAIN\s*=\s*(\{[\s\S]*\})/);
 if(!m)return null;
 try{const obj=JSON.parse(m[1]);if(obj&&Array.isArray(obj.steps)&&obj.steps.length)return obj.steps;}catch(e){}
 return null;
}
/* strip the machine block so the user sees only prose */
function stripChainBlock(text){return text.replace(/\n?ATTACK_CHAIN\s*=\s*\{[\s\S]*\}\s*$/,'').trim();}
/* ---- #15 AI proposes a network map from a description ---- */
function aiProposeMap(){
 go('ai');
 const types=Object.entries(NODE_TYPES).map(([k,t])=>`${k} (${t.label})`).join(', ');
 openAiInput('Describe your environment in a sentence or two — roughly how many workstations and servers, whether you have a DC, DMZ, cloud, VPN, OT, etc. I\'ll lay out a starter network map you can then edit and hunt on.',
  'e.g. Small AD shop: 1 DC, 2 file servers, ~15 workstations, a public web server in a DMZ, and an AWS account.',
  (text)=>`Design a starter network topology from this description: "${text}".\n\nAvailable node types (use the short key): ${types}.\n\nOutput ONLY a single-line JSON object, nothing else, with this shape:\nNETWORK_MAP={"nodes":[{"type":"<key>","label":"<short label>"}]}\nRules: use only the listed type keys; keep it to 6–14 nodes (collapse large fleets to 2–3 representative workstations); always include an "internet" node and a perimeter (fw/router/vpn) if anything is internet-facing; give each a short human label. No prose, just the JSON line.`,
  {mapgen:true});
}
function parseNetworkMap(text){
 if(!text)return null;
 const m=text.match(/NETWORK_MAP\s*=\s*(\{[\s\S]*\})/);
 if(!m)return null;
 try{const obj=JSON.parse(m[1]);if(obj&&Array.isArray(obj.nodes)&&obj.nodes.length)return obj.nodes.filter(n=>NODE_TYPES[n.type]);}catch(e){}
 return null;
}
function stripMapBlock(text){return text.replace(/\n?NETWORK_MAP\s*=\s*\{[\s\S]*\}\s*$/,'').trim();}
/* ---- #16 detection-to-node binding: which staged detections fire on which nodes ---- */
/* returns staged techniques whose mapped events this node actually emits */
function lsNodeDetections(n){
 const t=NODE_TYPES[n.type];
 if(!t.win||/linux|macos/i.test(n.os))return {covers:[],events:[]};
 const nodeEventIds=new Set(lsEventsForNode(n).map(e=>e.id));
 const covers=[];const events=new Set();
 [...studio].forEach(tid=>{
  eventsForTech(tid).forEach(e=>{
   if(e.plat==='windows'&&nodeEventIds.has(e.id)){covers.push(tid);events.add(e.id);}
  });
 });
 return {covers:[...new Set(covers)],events:[...events]};
}
function lsDetectionCoverage(){
 // for each staged technique, which mapped nodes could detect it?
 const rows=[];
 [...studio].forEach(tid=>{
  const nodes=lsNodes.filter(n=>lsNodeDetections(n).covers.includes(tid));
  rows.push({tid,name:T(tid).name,nodes});
 });
 return rows;
}
function lsOpenDetCoverage(){
 if(!studio.size){toast('Stage techniques in the Matrix first');return;}
 const rows=lsDetectionCoverage();
 const covered=rows.filter(r=>r.nodes.length).length;
 let v=document.getElementById('ls-det-veil');
 if(!v){v=document.createElement('div');v.id='ls-det-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet">
   <div class="ls-ne-grip" onclick="lsCloseDet()"></div>
   <div class="ls-det-head">Detection coverage on this network</div>
   <div class="ls-det-sub">${covered} of ${rows.length} staged technique${rows.length===1?'':'s'} would fire on a host in your current map. Gaps mean the detection is staged but no mapped node emits its telemetry.</div>
   ${rows.map(r=>`<div class="ls-det-row ${r.nodes.length?'':'gap'}">
     <div class="ls-det-tid">${r.tid}</div>
     <div class="ls-det-tname">${esc(r.name)}</div>
     <div class="ls-det-nodes">${r.nodes.length?r.nodes.map(n=>`${NODE_TYPES[n.type].glyph}`).join(' ')+' '+r.nodes.length+' host'+(r.nodes.length===1?'':'s'):'✗ no host emits this'}</div>
   </div>`).join('')}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseDet();};
}
function lsCloseDet(){const v=document.getElementById('ls-det-veil');if(v)v.classList.remove('open');}
/* ---- #17 incident snapshots: freeze the map mid-hunt, compare later ---- */
let lsSnaps=[];
function lsLoadSnaps(){try{lsSnaps=JSON.parse(read('aegis-snaps','[]'))||[]}catch{lsSnaps=[]}}
function lsSaveSnaps(){try{store('aegis-snaps',JSON.stringify(lsSnaps))}catch{}}
async function lsTakeSnapshot(){
 const name=await uiPrompt('Name this snapshot (e.g. "before containment"):','Snapshot '+(lsSnaps.length+1));
 if(name===null)return;
 lsSnaps.push({id:'s'+Date.now(),name:name||('Snapshot '+(lsSnaps.length+1)),t:Date.now(),
   nodes:JSON.parse(JSON.stringify(lsNodes)),edges:JSON.parse(JSON.stringify(lsEdges)),seq:lsNodeSeq});
 if(lsSnaps.length>12)lsSnaps.shift();
 lsSaveSnaps();toast(`Snapshot "${name}" saved`);renderLogSrc();
}
function lsSnapStats(s){
 const obs=s.nodes.reduce((a,n)=>a+((n.obs||[]).length),0);
 const worst=(n)=>{const o=n.obs||[];if(!o.length)return 0;return Math.max(...o.map(x=>SEV_META[x.sev]?SEV_META[x.sev].rank:1));};
 const mal=s.nodes.filter(n=>worst(n)>=3).length;
 return{nodes:s.nodes.length,obs,mal};
}
async function lsRestoreSnap(id){
 const s=lsSnaps.find(x=>x.id===id);if(!s)return;
 if(!await uiConfirm(`Restore "${s.name}"? The current map will be replaced (take a snapshot first if you want to keep it).`))return;
 lsNodes=JSON.parse(JSON.stringify(s.nodes));lsEdges=JSON.parse(JSON.stringify(s.edges));lsNodeSeq=s.seq||lsNodes.length+1;
 lsScrubT=null;lsAnim=null;
 persistAll();lsSnapshot();lsCloseSnaps();renderLogSrc();toast(`Restored "${s.name}"`);
}
function lsDelSnap(id){lsSnaps=lsSnaps.filter(s=>s.id!==id);lsSaveSnaps();openLsSnaps();}
function lsCompareSnap(id){
 const s=lsSnaps.find(x=>x.id===id);if(!s)return;
 const now={nodes:lsNodes};
 const a=lsSnapStats(s), b=lsSnapStats(now);
 // node-level diff
 const snapIds=new Set(s.nodes.map(n=>n.uid));
 const nowIds=new Set(lsNodes.map(n=>n.uid));
 const added=lsNodes.filter(n=>!snapIds.has(n.uid));
 const removed=s.nodes.filter(n=>!nowIds.has(n.uid));
 const changed=[];
 lsNodes.forEach(n=>{const o=s.nodes.find(x=>x.uid===n.uid);if(!o)return;
  const was=(o.obs||[]).length,is=(n.obs||[]).length;if(was!==is)changed.push({n,was,is});});
 const body=`<div class="ls-snap-diff">
   <div class="ls-snap-diff-h">"${esc(s.name)}" → now</div>
   <div class="ls-snap-diff-row"><span>Hosts</span><b>${a.nodes} → ${b.nodes}</b></div>
   <div class="ls-snap-diff-row"><span>Observations</span><b>${a.obs} → ${b.obs}</b></div>
   <div class="ls-snap-diff-row"><span>Compromised hosts</span><b class="${b.mal>a.mal?'worse':''}">${a.mal} → ${b.mal}</b></div>
   ${added.length?`<div class="ls-snap-diff-sec">Added since</div>${added.map(n=>`<div class="ls-snap-diff-item">+ ${NODE_TYPES[n.type].glyph} ${esc(n.label)}</div>`).join('')}`:''}
   ${removed.length?`<div class="ls-snap-diff-sec">Removed since</div>${removed.map(n=>`<div class="ls-snap-diff-item">− ${NODE_TYPES[n.type].glyph} ${esc(n.label)}</div>`).join('')}`:''}
   ${changed.length?`<div class="ls-snap-diff-sec">New evidence</div>${changed.map(c=>`<div class="ls-snap-diff-item">${NODE_TYPES[c.n.type].glyph} ${esc(c.n.label)}: ${c.was} → ${c.is} observations</div>`).join('')}`:''}
   ${!added.length&&!removed.length&&!changed.length?`<div class="ls-snap-diff-item">No structural change since this snapshot.</div>`:''}
 </div>`;
 const host=document.getElementById('ls-snap-body');if(host)host.innerHTML=body;
}
function openLsSnaps(){
 lsLoadSnaps();
 let v=document.getElementById('ls-snap-veil');
 if(!v){v=document.createElement('div');v.id='ls-snap-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet">
   <div class="ls-ne-grip" onclick="lsCloseSnaps()"></div>
   <div class="ls-det-head">Incident snapshots</div>
   <div class="ls-det-sub">Freeze the map at a point in the hunt, keep investigating, then compare or roll back.</div>
   <button class="btn violet" style="width:100%;justify-content:center;margin-bottom:12px" onclick="lsTakeSnapshot();openLsSnaps()">＋ Take snapshot of current map</button>
   ${lsSnaps.length?lsSnaps.slice().reverse().map(s=>{const st=lsSnapStats(s);return`<div class="ls-snap-row">
     <div class="ls-snap-info"><div class="ls-snap-name">${esc(s.name)}</div><div class="ls-snap-meta">${new Date(s.t).toLocaleString()} · ${st.nodes} hosts · ${st.obs} obs${st.mal?` · ${st.mal} compromised`:''}</div></div>
     <button class="ls-snap-btn" onclick="lsCompareSnap('${s.id}')">diff</button>
     <button class="ls-snap-btn" onclick="lsRestoreSnap('${s.id}')">restore</button>
     <button class="ls-snap-btn del" onclick="lsDelSnap('${s.id}')">×</button>
   </div>`;}).join(''):'<div class="ls-det-sub">No snapshots yet.</div>'}
   <div id="ls-snap-body"></div>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseSnaps();};
}
function lsCloseSnaps(){const v=document.getElementById('ls-snap-veil');if(v)v.classList.remove('open');}
/* lay out proposed nodes by zone tier, then auto-link */
function lsApplyProposedMap(nodes){
 if(!nodes||!nodes.length)return;
 lsNodes=[];lsEdges=[];lsNodeSeq=1;lsScrubT=null;lsPendingChain=null;lsAnim=null;
 // tier by zone: external → edge → dmz/cloud → core → internal
 const tier={external:0,edge:1,dmz:2,cloud:2,core:3,internal:4};
 const rows={};
 nodes.forEach(n=>{const z=NODE_TYPES[n.type].zone;const ti=zoneTier(z);(rows[ti]=rows[ti]||[]).push(n);});
 const W=680;const ys=[60,150,250,360,450];
 Object.keys(rows).sort((a,b)=>a-b).forEach(ti=>{
  const arr=rows[ti];const y=ys[ti]||450;
  arr.forEach((n,i)=>{const x=arr.length===1?W/2:60+(i*(W-120)/(arr.length-1));
   const node=lsAddNode(n.type,x,y,false);if(n.label)node.label=n.label;});
 });
 lsAutoEdges();
 lsHist=[JSON.stringify({nodes:lsNodes,edges:lsEdges,seq:lsNodeSeq})];lsHistIdx=0;
 persistAll();
}
function compKey(e){if((e.metaKey||e.ctrlKey)&&e.key==='Enter'){e.preventDefault();ask();}}
/* ---- AI: detection tuner (paste noisy results → suppression) ---- */
function aiTuner(){
 go('ai');
 openAiInput('Paste a few sample rows from a noisy alert (the fields that make each one benign or interesting), and I\'ll propose the exact suppression: an outputlookup baseline builder + the inputlookup filter to subtract known-good, keeping true positives.',
  'Paste noisy alert results here…',
  (text)=>`I have a noisy Splunk detection firing too often. Here are sample results:\n\n${text}\n\nAs a detection engineer, propose concrete tuning: (1) which fields distinguish benign from suspicious here; (2) an outputlookup baseline-builder search to learn known-good; (3) the inputlookup NOT-based filter to subtract that baseline from the alert while preserving true positives; (4) any per-entity throttle. Use my convention of broad alerting suppressed by lookups. Give runnable SPL.`);
}
/* ---- AI: false-positive explainer (feeds a Notebook note) ---- */
function aiFPExplain(){
 go('ai');
 openAiInput('Paste a single raw event (the fields you have). I\'ll explain whether it\'s likely benign or malicious, why, and what single field or pivot would settle it — then save it as a note on that event in the technique drawer.',
  'Paste one raw event here…',
  (text)=>`Here is a single event that fired an alert:\n\n${text}\n\nExplain like a tier-2 analyst: (1) most likely benign explanation vs malicious explanation; (2) the specific fields in THIS event that point one way or the other; (3) the single most decisive pivot or follow-up query to settle it; (4) a one-line verdict I could paste into my notes. Be concise.`);
}
/* ---- AI: draft a detection for a strategy-only (no telemetry) technique ---- */
function aiGapDetection(){
 const strategyOnly=[...studio].filter(id=>eventsForTech(id).length===0);
 go('ai');
 if(!strategyOnly.length){addMsg('assistant','Good news — every technique you\'ve staged already has at least one native detection mapped. Stage a technique with no telemetry (they show as "strategy only" in the basket) and I\'ll draft a detection approach for it.');return;}
 const list=strategyOnly.map(id=>`${id} ${T(id).name}`).join(', ');
 const prompt=`These staged techniques have no native Windows/CloudTrail detection mapped in my current set — they're strategy-only gaps: ${list}.\n\nFor each, as a detection engineer: (1) the most practical data source to detect it (Sysmon EID, a specific Event ID, EDR, or a derived/behavioural signal); (2) a starter Splunk SPL detection; (3) the key false-positive to expect and how to suppress it. Prioritise the ones with the highest detection value for the least deployment effort.`;
 addMsg('user',`Draft detections for my ${strategyOnly.length} coverage gap${strategyOnly.length===1?'':'s'}`);
 chatLog.push({role:'user',content:prompt});
 runAI();
}
/* small reusable inline-input prompt for the AI (tuner / FP explainer) */
let _aiInputCb=null;
function openAiInput(intro,placeholder,cb,opts){
 _aiInputCb=cb;_aiInputOpts=opts||{};
 addMsg('assistant',intro);
 const c=document.getElementById('chat');
 const box=document.createElement('div');box.className='ai-inline-input';
 box.innerHTML=`<textarea id="ai-inline-ta" placeholder="${esc(placeholder)}"></textarea><button class="btn violet" onclick="submitAiInput()">Send to AI →</button>`;
 c.appendChild(box);c.scrollTop=c.scrollHeight;
 setTimeout(()=>{const ta=document.getElementById('ai-inline-ta');if(ta)ta.focus();},50);
}
let _aiInputOpts={};
function submitAiInput(){
 const ta=document.getElementById('ai-inline-ta');if(!ta||!ta.value.trim()||!_aiInputCb)return;
 const text=ta.value.trim();const prompt=_aiInputCb(text);_aiInputCb=null;
 const box=ta.closest('.ai-inline-input');if(box)box.remove();
 addMsg('user',text.length>200?text.slice(0,200)+'…':text);
 chatLog.push({role:'user',content:prompt});
 runAI(_aiInputOpts);_aiInputOpts={};
}
function growComp(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,130)+'px';}
function addMsg(role,content){
 const hello=document.getElementById('chat-hello');if(hello)hello.style.display='none';
 const c=document.getElementById('chat');const d=document.createElement('div');
 d.className='m '+(role==='user'?'u':'a');
 d.innerHTML=`<div class="m-tag">${role==='user'?'ANALYST':'AEGIS AI'}</div><div class="m-body">${role==='user'?esc(content):mdToHtml(content)}</div>`;
 c.appendChild(d);c.scrollTop=c.scrollHeight;return d;
}
function mdToHtml(t){
 return t
  .replace(/```(\w+)?\n?([\s\S]*?)```/g,(m,l,code)=>`<pre><code>${hl(code.trim())}</code></pre>`)
  .replace(/`([^`]+)`/g,'<code>$1</code>')
  .replace(/^#{1,3} (.+)$/gm,'<h3>$1</h3>')
  .replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>')
  .replace(/^[-*] (.+)$/gm,'<li>$1</li>')
  .replace(/(<li>[\s\S]*?<\/li>)(?!\s*<li>)/g,'<ul>$1</ul>')
  .replace(/\n{2,}/g,'</p><p>').replace(/^/,'<p>').concat('</p>');
}
async function ask(){
 if(busy)return;
 const inp=document.getElementById('comp-in');const msg=inp.value.trim();if(!msg)return;
 inp.value='';growComp(inp);addMsg('user',msg);
 const ctx=mappingContext();const ic=incidentContext();
 const pre=[ctx?`[Staged mapping context]\n${ctx}`:'',ic?`[Active hunt map]\n${ic}`:''].filter(Boolean).join('\n\n');
 chatLog.push({role:'user',content:pre?`${pre}\n\n[My question]\n${msg}`:msg});
 runAI();
}
/* Where the AI Analyst sends its requests.
 *
 * Two modes, in preference order:
 *
 *  1. Through your AEGIS server (`POST /api/ai`). The API key lives on the
 *     server and is never sent to the browser, the request is same-origin so
 *     there is no CORS, and the model and token ceiling are set server-side.
 *     This is the mode to use on a real deployment.
 *  2. Straight to api.anthropic.com. This only authenticates inside the
 *     claude.ai Artifacts sandbox, which injects credentials for you. Opened
 *     from disk or served from GitHub Pages it cannot work — kept as the path
 *     that makes the hosted build's AI tab work when running in claude.ai.
 *
 * A key is never embedded in the client. That is deliberate: ui/index.html is
 * a public artefact and anything in it is published.
 */
function aiVia(){
 return (typeof LIVE!=='undefined'&&LIVE&&LIVE.connected&&LIVE.url&&LIVE.token)?'server':'sandbox';
}
function aiFetch(){
 const body=JSON.stringify({system:SYS,messages:chatLog.slice(-12)});
 if(aiVia()==='server')
  return fetch(LIVE.url.replace(/\/$/,'')+'/api/ai',{method:'POST',headers:liveHeaders(),body});
 return fetch('https://api.anthropic.com/v1/messages',{
  method:'POST',
  headers:{'Content-Type':'application/json'},
  // The sandbox fills in model/max_tokens defaults it accepts; keep this
  // request minimal so it stays valid there.
  body:JSON.stringify({model:'claude-sonnet-4-6',max_tokens:4000,system:SYS,messages:chatLog.slice(-12)})
 });
}
/** What to tell the analyst when the call fails, given how they're running. */
function aiUnreachableMsg(err){
 const detail=err&&err.message?` ${esc(err.message)}`:'';
 if(aiVia()==='server')
  return `**The AI Analyst couldn't reach your AEGIS server.**${detail}\n\n`
   +'Check the connection indicator in the top bar. If the server is up, it may not have '
   +'an API key: set `ANTHROPIC_API_KEY` in its environment (or `ai.apiKey` in '
   +'`server/config.json`) and restart it. Everything else in AEGIS works without this.';
 return `**The AI Analyst has nowhere to send this.**${detail}\n\n`
  +'Connect the console to an AEGIS server that has an API key configured — click the '
  +'connection indicator in the top bar. Without a server, the AI tab only works inside '
  +'claude.ai, which supplies credentials for it.\n\nThe matrix, hunt map, studio, triage, '
  +'ingest, response playbooks and the report all work fully offline.';
}
async function runAI(opts){
 opts=opts||{};
 if(busy)return;
 busy=true;const sendBtn=document.getElementById('comp-send');if(sendBtn)sendBtn.disabled=true;
 const c=document.getElementById('chat');const load=document.createElement('div');
 load.className='m a';load.innerHTML=`<div class="m-tag">AEGIS AI</div><div class="think"><i></i><i></i><i></i></div>`;
 c.appendChild(load);c.scrollTop=c.scrollHeight;
 try{
  const r=await aiFetch();
  const data=await r.json();
  load.remove();
  if(data&&Array.isArray(data.content)&&data.content.length){
   const txt=data.content.filter(b=>b.type==='text').map(b=>b.text).join('').trim()
            || data.content.map(b=>b.text||'').join('').trim();
   if(txt){
    chatLog.push({role:'assistant',content:txt});
    // if we asked for a chain, extract it, show clean prose, and offer to trace on the map
    const chain=opts.chain?parseAttackChain(txt):null;
    const propMap=opts.mapgen?parseNetworkMap(txt):null;
    if(chain){
     addMsg('assistant',stripChainBlock(txt));
     lsPendingChain=chain;
     try{store('aegis-lastchain',JSON.stringify(chain));}catch(e){}
     const el=addMsg('assistant','');
     el.querySelector('.m-body').innerHTML=`<div class="ai-trace-cta"><div><b>${chain.length}-step attack chain reconstructed.</b> Watch it trace across your network map in real time.</div><button class="btn magenta" onclick="lsTracePending()">▶ Trace on map</button></div>`;
    }else if(opts.triage){
     const tr=parseTriage(txt);
     addMsg('assistant',stripTriage(txt));
     if(tr){
      const el=addMsg('assistant','');
      const sv=SEV_META[tr.sev]?tr.sev:'suspicious';
      el.querySelector('.m-body').innerHTML=`<div class="ai-trace-cta"><div><b>Assessed: ${esc(tr.label||'artifact')}</b><br><span class="art-verdict sev-${sv}">${sv}</span>${tr.tech&&MITRE[tr.tech]?` · maps to ${tr.tech} ${esc(MITRE[tr.tech].name)}`:''}</div><button class="btn violet" onclick="artLog('${opts.uid}','${sv}',${JSON.stringify(tr.label||'artifact').replace(/"/g,'&quot;')},'${tr.tech||''}')">✓ Log on host</button></div>`;
     }
    }else if(propMap){
     const clean=stripMapBlock(txt);if(clean)addMsg('assistant',clean);
     _lsProposedMap=propMap;
     const el=addMsg('assistant','');
     const summary=propMap.map(n=>NODE_TYPES[n.type].glyph).join(' ');
     el.querySelector('.m-body').innerHTML=`<div class="ai-trace-cta"><div><b>${propMap.length}-node map proposed.</b> ${summary}<br>Build it on the Network Map (replaces the current one).</div><button class="btn violet" onclick="lsBuildProposedMap()">⧉ Build this map</button></div>`;
    }else{
     addMsg('assistant',txt);
    }
   }
   else addMsg('assistant','The model returned an empty response. Try rephrasing, or ask a more specific detection question.');
  }else if(data&&data.error){
   // The server returns {error:"..."} for its own refusals (no key configured)
   // and passes Anthropic's {error:{message}} straight through.
   const em=typeof data.error==='string'?data.error:(data.error.message||JSON.stringify(data.error));
   addMsg('assistant',`**AI Analyst unavailable.** ${esc(em)}`);
  }else{
   addMsg('assistant','**Unexpected response shape from the API.** Please try again.');
  }
 }catch(err){
  load.remove();
  addMsg('assistant',aiUnreachableMsg(err));
 }
 finally{busy=false;if(sendBtn)sendBtn.disabled=false;}
}
let lsPendingChain=null;
let _lsProposedMap=null;
async function lsBuildProposedMap(){
 if(!_lsProposedMap){toast('No proposed map to build');return;}
 if(lsNodes.length&&!await uiConfirm('Replace the current map with the AI-proposed one? Export the case first if you want to keep the current map.'))return;
 lsApplyProposedMap(_lsProposedMap);
 go('logsrc');
 toast('AI-proposed map built — edit and hunt on it');
}
try{const _lc=read('aegis-lastchain','');if(_lc)lsPendingChain=JSON.parse(_lc);}catch(e){}
function lsTracePending(){
 if(!lsPendingChain)return;
 go('logsrc');
 if(lsStep!=='topology'){lsStep='topology';}
 lsRunAnim(lsPendingChain);
 toast('Tracing the attack chain on your map');
}

/* ================= NOTES ================= */
function fillNoteEvents(){
 if(!document.getElementById('nt-plat'))return;
 const p=document.getElementById('nt-plat').value;const evs=p==='windows'?WIN:AWS;
 document.getElementById('nt-event').innerHTML=evs.map(e=>`<option value="${e.id}">${e.id} — ${e.title}</option>`).join('');
}
function saveNote(){
 const p=document.getElementById('nt-plat').value;const id=document.getElementById('nt-event').value;const txt=document.getElementById('nt-text').value;
 if(!txt.trim())return;
 notes[p+'::'+id]=txt;store('aegis-notes',JSON.stringify(notes));
 document.getElementById('nt-text').value='';renderNotes();updateBadges();renderEvents();toast('Note saved');
}
function saveCardNote(key){
 const [p,id]=key.split('::');const ta=document.getElementById(`na-${p}-${id}`);if(!ta)return;
 notes[key]=ta.value;store('aegis-notes',JSON.stringify(notes));renderNotes();updateBadges();toast('Note saved');
}
function delNote(key){delete notes[key];store('aegis-notes',JSON.stringify(notes));renderNotes();updateBadges();renderEvents();}
function renderNotes(){
 if(!document.getElementById('nt-main'))return;
 const host=document.getElementById('nt-main');
 const entries=Object.entries(notes).filter(([,v])=>v.trim());
 if(!entries.length){host.innerHTML='<div class="nt-empty">No notes yet — knowledge you save here persists across sessions.</div>';return;}
 host.innerHTML=entries.map(([key,txt])=>{
  const [p,id]=key.split('::');const e=(p==='windows'?WIN:AWS).find(x=>x.id===id);
  return`<div class="ncard">
   <div class="nc-top"><span class="eid ${p==='windows'?'w':'a'}">${id}</span><span style="font-size:12px;font-weight:600;flex:1">${e?e.title:id}</span><span style="font-family:var(--mono);font-size:8.5px;color:var(--t3)">${p.toUpperCase()}</span></div>
   <div class="nc-text">${esc(txt)}</div>
   <div class="nc-btns"><button class="nbtn" onclick="jump('${p}','${id}')">Open event</button><button class="nbtn del" onclick="delNote('${key}')">Delete</button></div>
  </div>`;
 }).join('');
}

/* ================= PALETTE ================= */
function openPal(){document.getElementById('pal-veil').classList.add('open');const i=document.getElementById('pal-input');i.value='';i.focus();renderPal();}
function closePal(){document.getElementById('pal-veil').classList.remove('open');}
function renderPal(){
 const q=document.getElementById('pal-input').value.toLowerCase();
 const VIEWS=[['matrix','ATT&CK Matrix'],['logsrc','Network Map'],['studio','Detection Studio'],['ai','AI Analyst']];
 const views=VIEWS.filter(([id,n])=>!q||id.includes(q)||n.toLowerCase().includes(q));
 const evs=ALL().filter(e=>!q||e.id.toLowerCase().includes(q)||e.title.toLowerCase().includes(q)||e.cat.includes(q)).slice(0,7);
 const techs=Object.entries(MITRE).filter(([id,t])=>!q||id.toLowerCase().includes(q)||t.name.toLowerCase().includes(q)).slice(0,6);
 let h='';
 if(views.length)h+=`<div class="pal-sec">Go to</div>`+views.map(([id,n])=>`<div class="pal-item" onclick="closePal();go('${id}')"><span class="pal-eid">↦</span><span class="pal-name">${n}</span><span class="pal-cat">view</span></div>`).join('');
 if(evs.length)h+=`<div class="pal-sec">Events</div>`+evs.map(e=>`<div class="pal-item" onclick="closePal();jump('${e.plat}','${e.id}')"><span class="pal-eid ${e.plat==='aws'?'sky':''}">${e.id}</span><span class="pal-name">${e.title}</span><span class="pal-cat">${e.plat}</span></div>`).join('');
 if(techs.length)h+=`<div class="pal-sec">Techniques</div>`+techs.map(([id,t])=>`<div class="pal-item" onclick="closePal();go('matrix');openDrawer('${id}')"><span class="pal-eid">${id}</span><span class="pal-name">${t.name}</span><span class="pal-cat">mitre</span></div>`).join('');
 document.getElementById('pal-res').innerHTML=h||'<div style="padding:20px;text-align:center;color:var(--t3);font-family:var(--mono);font-size:10px;">No matches</div>';
}
function palKey(e){if(e.key==='Enter'){const f=document.querySelector('.pal-item');if(f)f.click();}if(e.key==='Escape')closePal();}

/* ================= SHORTCUTS ================= */
function openKeys(){document.getElementById('keys-veil').classList.add('open');}
function closeKeys(){document.getElementById('keys-veil').classList.remove('open');}

/* ================= TOUR ================= */
const TOUR=[
 {target:null,title:'Welcome to AEGIS',step:'Getting started',body:'AEGIS turns the MITRE ATT&CK framework into ready-to-deploy Splunk detections. The workflow is three steps: <b>pick techniques</b> on the matrix, <b>review</b> them in the Studio, and <b>generate</b> a dashboard and report. This 60-second tour walks through it.'},
 {target:'#v-matrix .matrix',title:'1 · Pick your techniques',step:'The matrix',body:'All 14 ATT&CK tactics, left to right, with every technique colored by how much telemetry you have for it. <b>Just click a technique to stage it</b> — click again to remove. No pop-ups, no extra windows. Stage as many as you like.',pre:()=>go('matrix')},
 {target:'.mx-bulk',title:'Quick-stage a whole scenario',step:'Shortcut',body:'In a hurry? These buttons stage a complete attack chain in one click — a <b>ransomware intrusion</b>, a <b>cloud takeover</b>, or an <b>insider data theft</b> — or every high-coverage technique at once. A fast way to a full dashboard.'},
 {target:'#v-matrix .tcell','title':'The ⓘ button',step:'Detail',body:'Clicking a cell stages it. The small <b>ⓘ</b> button opens the full strategy instead — detection signals, the exact fields, mapped mitigations, and the events that detect it. Hover any cell for a quick preview.'},
 {target:'#r-logsrc',title:'Your live network map',step:'Network Map',body:'This is the heart of a hunt. <b>Drag in</b> your hosts and infrastructure — DCs, servers, workstations, DMZ, firewalls, routers, switches, cloud, even IoT. <b>Click a node</b> to log what you are seeing on it during an incident. Then <b>Analyse &amp; trace</b> has the AI reconstruct the attack and animate it hopping across your map in real time. You can also draw your own links, trace a path by hand, scrub the incident timeline, and turn the map into a tailored event-ID collection plan.',pre:()=>go('logsrc')},
 {target:'#r-studio',title:'2 · Review the kill chain',step:'The Studio',body:'The Detection Studio lays your staged techniques out <b>along the attack kill chain</b>, so you can see which stages of an intrusion you cover and where the blind spots are. Remove anything with the × on each node.',pre:()=>go('studio')},
 {target:'.st-out-head',title:'3 · Generate outputs',step:'The payoff',body:'From here, export an importable <b>Splunk dashboard</b> (XML), an <b>ATT&CK Navigator layer</b>, a <b>risk-based alerting package</b> (risk-scoring searches plus one correlation rule), or a full <b>engineering report</b> — attack-progression diagram, per-technique SPL, triage steps, suppression logic, and recommendations. Print to PDF or download as HTML.',pre:()=>go('studio')},
 {target:'#r-ai',title:'The AI Analyst reviews your work',step:'Assist',body:'The AI Analyst reads the techniques you\'ve staged and gives <b>side-by-side suggestions to improve your dashboard</b> — coverage gaps, correlation opportunities, and tuning advice. Start with <b>Review my staged coverage</b>. It knows your Splunk conventions.',pre:()=>go('ai')},
 {target:'#plat-seg',title:'Scope, search, shortcuts',step:'Navigate fast',body:'Scope everything to <b>Windows or AWS</b> here. Search filters the current view, <b>⌘K</b> jumps anywhere, <b>1–5</b> switch views, <b>?</b> lists shortcuts. Restart this tour anytime from the bottom-left.',pre:()=>go('matrix')},
 {target:null,title:'You\'re ready',step:'Done',body:'Click a few techniques on the matrix — or try a Quick-stage scenario — then open the Studio and generate your report. The AI Analyst is there whenever you want a second opinion on your coverage.'}
];
let tourStep=-1;
function startTour(){tourStep=0;document.getElementById('tour-veil').classList.add('open');placeTour();document.addEventListener('keydown',tourKeys);}
function tourKeys(e){if(tourStep<0)return;if(e.key==='ArrowRight'){e.preventDefault();tourNext();}if(e.key==='ArrowLeft'){e.preventDefault();tourPrev();}}
function placeTour(){
 const s=TOUR[tourStep];if(!s)return;
 if(s.pre)s.pre();
 const hole=document.getElementById('tour-hole');const card=document.getElementById('tour-card');
 card.innerHTML=`
  <div class="tour-step">${s.step} · ${tourStep+1}/${TOUR.length}</div>
  <div class="tour-title">${s.title}</div>
  <div class="tour-body">${s.body}</div>
  <div class="tour-nav">
    <div class="tour-dots">${TOUR.map((_,i)=>`<span class="tour-dot${i===tourStep?' on':''}"></span>`).join('')}</div>
    ${tourStep>0?'<button class="tour-btn" onclick="tourPrev()">Back</button>':''}
    <button class="tour-btn" onclick="endTour()">Skip</button>
    <button class="tour-btn go" onclick="tourNext()">${tourStep===TOUR.length-1?'Finish':'Next →'}</button>
  </div>`;
 requestAnimationFrame(()=>{
  const el=s.target?document.querySelector(s.target):null;
  if(el){
   const r=el.getBoundingClientRect();
   hole.style.display='block';hole.classList.add('pulse');
   hole.style.left=(r.left-8)+'px';hole.style.top=(r.top-8)+'px';hole.style.width=(r.width+16)+'px';hole.style.height=(r.height+16)+'px';
   card.classList.remove('center');
   const cw=340,ch=card.offsetHeight||200;
   let cx=r.right+18,cy=r.top;
   if(cx+cw>window.innerWidth-12)cx=r.left-cw-18;
   if(cx<12){cx=Math.max(12,Math.min(r.left,window.innerWidth-cw-12));cy=r.bottom+16;}
   if(cy+ch>window.innerHeight-12)cy=Math.max(12,window.innerHeight-ch-12);
   card.style.left=cx+'px';card.style.top=Math.max(12,cy)+'px';card.style.transform='none';
  }else{hole.style.display='none';card.classList.add('center');}
 });
}
function tourNext(){if(tourStep>=TOUR.length-1){endTour();return;}tourStep++;placeTour();}
function tourPrev(){if(tourStep<=0)return;tourStep--;placeTour();}
function endTour(){tourStep=-1;document.getElementById('tour-veil').classList.remove('open');document.removeEventListener('keydown',tourKeys);store('aegis-toured','yes');}
