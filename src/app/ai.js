/* ================= AI ================= */
const SYS=`You are an elite detection engineering copilot embedded in AEGIS, a SOC analyst intelligence platform. Expertise: Windows Security Event Logs (all IDs, field semantics, correlation), AWS CloudTrail, MITRE ATT&CK (full framework incl. mitigations), Splunk SPL (advanced - joins, lookups, tstats, ML), false positive suppression.

The analyst is an experienced SOC analyst / detection engineer working with Windows Security events and CloudTrail in Splunk. Their established preferences:
- Broad alerting suppressed via lookup tables (outputlookup baselines, inputlookup suppression) over complex pre-filters
- dc(ComputerName) for frequency scoring
- ut_shannon_lookup for entropy detection (requires tonumber() on the shannon field)
- For 4657: Object_Name = registry key path, New_Value = written data; ImagePath/binary_path do not exist natively

STYLE: Direct, technical, zero fluff. Production-ready SPL with exact field names. For MITRE techniques always give: technique ID, event sources, critical fields, detection query, mitigations, and FP suppression guidance. Use markdown headers and code blocks.

GROUND TRUTH - THIS IS NON-NEGOTIABLE:
- NEVER present a specific host, IP, account, process, service or event as something that HAS occurred in this environment unless it literally appears in the context you were given (staged mapping, hunt map, or live situation block). Inventing findings - e.g. "compromised Apache Tomcat on 192.168.1.100" when no such data was provided - is a serious failure that wastes the analyst's time. Do not do it.
- If you were given no observations/telemetry, say so ("No telemetry has been provided, so I can't point to anything that happened here") and keep everything clearly hypothetical: "an attacker would typically...", "if you see...", "plan for...".
- Asked to plan for a threat (e.g. "outline an attack vector for APT29") with no live data: produce a clearly-labelled PLAN - techniques to expect stage by stage, the detections to build for each, and how to defend as it escalates - NOT a narrative of a breach that already happened.
- If you cannot do exactly what was asked, say so plainly in one line rather than answering a different question.

DRAWING A NETWORK MAP: When the analyst asks you to draw, lay out, map, "map it out", or build a network / topology / environment, end your reply with ONE line, exactly:
NETWORK_MAP={"nodes":[{"type":"<key>","label":"<short label>"}]}
Use only these type keys: internet, fw, router, switch, vpn, dc, srv, dns, dhcp, ca, mail, db, siem, backup, print, jump, hyper, container, wks, dmz, cloud, nas, iot, proxy. 6-14 nodes; collapse large fleets to 2-3 representative workstations; always include an "internet" node and a perimeter (fw/router/vpn) if anything is internet-facing. The app turns that line into an editable map, so keep any prose above it short. This is a hypothetical planning layout, never a claim that these hosts exist.

CHANGING A TICKET: When the analyst asks you to change, update, comment on, close, prioritise or assign a ticket, end your reply with ONE line, exactly:
TICKET_ACTION={"num":<ticket number>,"patch":{...}}   or   TICKET_ACTION={"num":<n>,"comment":"<text>"}
Allowed patch keys: status ("open"/"review"/"closed"/"discarded"), severity ("low"/"medium"/"high"/"critical"), priority ("low"/"normal"/"high"/"urgent"), assignee (a name), description. The app shows the analyst a confirm button and applies it under THEIR permissions - so propose the action, never assume it succeeded. Say briefly what you're proposing above the line.

Available Windows events: 4624, 4625, 4657, 4663, 4672, 4688, 4698, 4719, 4720, 4732, 4740, 4769, 5140, 5145, 5156, 7045, 1102. AWS: ConsoleLogin, AssumeRole, CreateUser, CreateAccessKey, AttachRolePolicy, StopLogging, DeleteTrail, GetSecretValue, ListBuckets (enum), GetObject (S3). Note where a detection needs Sysmon, email gateway, proxy, or S3 data events beyond these.

The AEGIS app can export a risk-based alerting (RBA) package: each detection writes a scored risk event (risk_score, risk_object, mitre_tactic, mitre_technique) into index=risk via | collect, and one correlation search sums risk per entity and fires when it crosses a threshold across multiple tactics. When the analyst asks about reducing alert volume or improving fidelity, recommend and build on this RBA pattern using | collect index=risk and the aggregation correlation search.

ACCURACY (hard rules - a SOC acts on what you say, so a confident wrong answer is worse than no answer):
- Only state what you actually know or can derive from the analyst's context. Do NOT invent hostnames, usernames, event IDs, field names, IPs, timestamps, or findings that were not given to you. If the context does not contain something, say it is not in the data rather than filling it in.
- If a question is ambiguous, underspecified, or looks like random/garbled input, ask one short clarifying question instead of guessing. Never fabricate a scenario to answer a question you did not understand.
- If you are not confident, say so plainly ("I can't tell from the data here") and state what you'd need. Do not manufacture a plausible-sounding answer.
- Reference real MITRE technique IDs in the form T1234 or T1234.001 so the console can link them; do not invent IDs.`;

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
  return `- ${id} ${t.name} [stage ${si+1}: ${stage}] - events: ${evs}; mitigations: ${mits}`;
 });
 const activeStages=new Set(ordered.map(primaryStage));
 const gaps=TACTICS.map((t,i)=>[t[0],i]).filter(([,i])=>!activeStages.has(i)).map(([n])=>n);
 const strategyOnly=ordered.filter(id=>eventsForTech(id).length===0);
 return `The analyst has staged these ${studio.size} ATT&CK techniques into their Splunk detection dashboard (kill-chain order):
${lines.join('\n')}

Kill-chain stages with NO coverage: ${gaps.length?gaps.join(', '):'none - all 14 covered'}.
Staged techniques with no native telemetry (strategy only): ${strategyOnly.length?strategyOnly.join(', '):'none'}.`;
}
function analyzeMapping(){
 go('ai');
 const ctx=mappingContext();
 if(!ctx){addMsg('assistant','You haven\'t staged any techniques yet. Go to the **ATT&CK Matrix** and click techniques to stage them - then I can review the mapping and suggest improvements. Try a **Quick stage** scenario button at the top of the matrix for a fast start.');return;}
 const prompt=`${ctx}

Review this detection mapping as a senior detection engineer doing a peer review. Give me a prioritised, side-by-side critique in these sections, using markdown headers:

## Strongest coverage
What's well covered and why (1-2 sentences).

## Highest-priority gaps
The 3 most important weaknesses in this mapping - missing kill-chain stages an attacker would exploit, or staged techniques with weak/no telemetry. For each, name the specific technique or event to add and why it matters.

## Correlation opportunities
Where I have 2+ staged techniques that share a logon session, host, or identity and should be joined into a single higher-fidelity correlation search instead of separate alerts. Give me the actual SPL join for the single best opportunity, using correct Windows field names (Subject_Logon_ID, Target_Logon_ID) or CloudTrail fields.

## Tuning priorities
Which 2-3 of my staged detections will be noisiest in a real environment, and the specific lookup-based suppression or threshold to apply first.

Be specific and reference my actual staged technique IDs. Keep it tight - this is a working review, not a textbook.`;
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
 if(!ctx){addMsg('assistant','Stage a few related techniques first - ideally ones that share a logon session or host (e.g. a logon, a process creation, and a service install). Then I can turn them into multi-event correlation searches.');return;}
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
  const obs=n.obs.map(o=>{const ev=LOGSRC.find(e=>e.id===o.evId);return `    · [${o.sev}] ${o.evId?o.evId+(ev?' '+ev.name:''):'(no event id)'}${o.note?' - "'+o.note+'"':''}`;}).join('\n');
  return `- ${n.label} (${t.label}, ${n.os})${lsNodeStatus(n)?' - status '+lsNodeStatus(n).toUpperCase():''}:\n${obs}`;
 });
 return `ACTIVE HUNT - observed events mapped across the network (kill-chain order where known):\n${lines.join('\n')}`;
}
function lsTriageNode(uid){
 const n=lsNodes.find(x=>x.uid===uid);if(!n||!n.obs||!n.obs.length){toast('Log an observation first');return;}
 go('ai');lsCloseNodeEdit();
 const t=NODE_TYPES[n.type];
 const obs=n.obs.map(o=>{const ev=LOGSRC.find(e=>e.id===o.evId);return `- [${o.sev}] ${o.evId?o.evId+(ev?' ('+ev.name+')':''):'no event id'}${o.note?': "'+o.note+'"':''}`;}).join('\n');
 const prompt=`During an active hunt I'm seeing the following on a single host:

Host: ${n.label} - ${t.label}, OS ${n.os}
Observations:
${obs}

As a senior IR analyst, triage THIS host: (1) what is the most likely explanation for these observations together; (2) are they consistent with a known ATT&CK technique or chain; (3) the exact next Splunk queries or Event IDs I should pull on this host to confirm or rule it out; (4) immediate containment steps if this is malicious. Use correct Windows field names. Keep it tight and actionable.`;
 addMsg('user',`Triage ${n.label} - ${n.obs.length} observation${n.obs.length===1?'':'s'}`);
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
Order steps in kill-chain sequence. Use a node's own uid for both from and to when the activity is on-host. Only reference uids from the list above. For "conf", rate how strongly the observed evidence supports each hop - "high" when a logged observation directly shows it, "low" when it's inferred to fill a gap.`;
 addMsg('user','Analyse my hunt map - correlate the observations into an attack chain');
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
 openAiInput('Describe your environment in a sentence or two - roughly how many workstations and servers, whether you have a DC, DMZ, cloud, VPN, OT, etc. I\'ll lay out a starter network map you can then edit and hunt on.',
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
/* A proposed ticket change the AI emitted. Parsed and offered as a confirm
   button - never auto-applied, and always through the normal API, so the
   analyst's own permissions still decide what actually happens. */
function parseTicketAction(text){
 if(!text)return null;
 const m=text.match(/TICKET_ACTION\s*=\s*(\{[\s\S]*?\})\s*$/);
 if(!m)return null;
 try{const o=JSON.parse(m[1]);if(o&&o.num!=null&&(o.patch||o.comment))return o;}catch{}
 return null;
}
function stripTicketBlock(text){return text.replace(/\n?TICKET_ACTION\s*=\s*\{[\s\S]*?\}\s*$/,'').trim();}
let _aiTicketAction=null;
function aiApplyTicketAction(){
 const a=_aiTicketAction;_aiTicketAction=null;
 if(!a)return;
 const t=(LIVE.tickets||[]).find(x=>String(x.num)===String(a.num));
 if(!t){toast('No ticket #'+a.num+' to act on');return;}
 if(a.comment){
  liveApi('/api/tickets/'+t.id+'/comments',{method:'POST',body:JSON.stringify({text:String(a.comment).slice(0,8000)})})
   .then(()=>{toast('Comment added to #'+a.num);if(typeof renderTickets==='function')renderTickets();})
   .catch(e=>toast(e.message));
  return;
 }
 // Only pass fields the ticket API accepts; the server still gates each one.
 const allowed=['status','severity','priority','assignee','description','host','technique'];
 const patch={};Object.keys(a.patch||{}).forEach(k=>{if(allowed.includes(k))patch[k]=a.patch[k];});
 if(!Object.keys(patch).length){toast('Nothing to apply');return;}
 if(typeof tkPatch==='function')tkPatch(t.id,patch);   // enforces permissions, surfaces any 403
}
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
 openAiInput('Paste a single raw event (the fields you have). I\'ll explain whether it\'s likely benign or malicious, why, and what single field or pivot would settle it - then save it as a note on that event in the technique drawer.',
  'Paste one raw event here…',
  (text)=>`Here is a single event that fired an alert:\n\n${text}\n\nExplain like a tier-2 analyst: (1) most likely benign explanation vs malicious explanation; (2) the specific fields in THIS event that point one way or the other; (3) the single most decisive pivot or follow-up query to settle it; (4) a one-line verdict I could paste into my notes. Be concise.`);
}
/* ---- AI: draft a detection for a strategy-only (no telemetry) technique ---- */
function aiGapDetection(){
 const strategyOnly=[...studio].filter(id=>eventsForTech(id).length===0);
 go('ai');
 if(!strategyOnly.length){addMsg('assistant','Good news - every technique you\'ve staged already has at least one native detection mapped. Stage a technique with no telemetry (they show as "strategy only" in the basket) and I\'ll draft a detection approach for it.');return;}
 const list=strategyOnly.map(id=>`${id} ${T(id).name}`).join(', ');
 const prompt=`These staged techniques have no native Windows/CloudTrail detection mapped in my current set - they're strategy-only gaps: ${list}.\n\nFor each, as a detection engineer: (1) the most practical data source to detect it (Sysmon EID, a specific Event ID, EDR, or a derived/behavioural signal); (2) a starter Splunk SPL detection; (3) the key false-positive to expect and how to suppress it. Prioritise the ones with the highest detection value for the least deployment effort.`;
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
 d.innerHTML=`<div class="m-tag">${role==='user'?'ANALYST':'AEGIS AI'}</div><div class="m-body">${role==='user'?esc(content):aiLinkify(mdToHtml(content))}</div>`;
 c.appendChild(d);c.scrollTop=c.scrollHeight;return d;
}
/* Make the technique IDs the AI mentions clickable - one tap jumps to that
   technique's full strategy in the matrix. Only touches real tracked IDs, and
   skips anything inside a code block so SPL is left exactly as written. */
function aiLinkify(html){
 return String(html).split(/(<pre[\s\S]*?<\/pre>)/).map(seg=>{
  if(seg.slice(0,4)==='<pre')return seg;
  return seg.replace(/\bT\d{4}(?:\.\d{3})?\b/g,m=>{
   const known=(typeof MITRE!=='undefined')&&(MITRE[m]||MITRE[m.split('.')[0]]);
   return known?`<a class="ai-tlink" onclick="aiJumpTech('${m}')">${m}</a>`:m;
  });
 }).join('');
}
/* Jump to a technique's strategy page; sub-techniques resolve to their parent. */
function aiJumpTech(id){
 const tid=(MITRE[id]?id:(MITRE[id.split('.')[0]]?id.split('.')[0]:null));
 if(tid){go('matrix');openDrawer(tid);}else toast(id+' - not a tracked technique');
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
 * One place: `POST /api/llm` on your own AEGIS server, which forwards to a
 * model running on that machine.
 *
 * There is no path out to the internet, by design. A SOC console that ships
 * telemetry, hostnames and case detail to a third-party API is a data-egress
 * problem wearing a helpful hat, and it makes the whole tool unusable on the
 * air-gapped networks it is otherwise a good fit for. Nothing here has an API
 * key, because nothing here needs one.
 *
 * This tab and the Companion panel share the one local model. They differ in
 * who starts the conversation: this one answers long-form questions you type,
 * with your staged techniques and hunt map as context; the Companion reads
 * telemetry and speaks first. See LOCAL-AI.md.
 */
function aiFetch(){
 return fetch(LIVE.url.replace(/\/$/,'')+'/api/llm',{
  method:'POST',headers:liveHeaders(),
  body:JSON.stringify({system:SYS,messages:chatLog.slice(-12)}),
 });
}
/** What to tell the analyst when the call fails. */
function aiUnreachableMsg(err){
 const detail=err&&err.message?` ${esc(err.message)}`:'';
 if(!LIVE.connected)
  return `**The AI Analyst needs your AEGIS server.**${detail}\n\n`
   +'Click the connection indicator in the top bar to connect. The model runs on that '
   +'machine - nothing is sent anywhere else.\n\nThe matrix, hunt map, studio, ingest, '
   +'response playbooks and the report all work fully offline without it.';
 return `**No local model answered.**${detail}\n\n`
  +'The AI Analyst runs entirely on your AEGIS host. Set one up with `npm run ai:setup` '
  +'on that machine - it takes about two minutes and needs no API key. See `LOCAL-AI.md`.\n\n'
  +'Everything else in AEGIS works without it.';
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
  if(data&&data.ok&&data.text){
   {
    const txt=String(data.text).trim();
    chatLog.push({role:'assistant',content:txt});
    // if we asked for a chain, extract it, show clean prose, and offer to trace on the map
    const chain=opts.chain?parseAttackChain(txt):null;
    // Apply a map block whenever the model emits one - not only when we asked
    // via aiProposeMap. So "map it out" typed in chat still produces a
    // buildable map, as long as the model output the NETWORK_MAP line.
    const propMap=parseNetworkMap(txt);
    const tkAction=parseTicketAction(txt);
    if(chain){
     addMsg('assistant',stripChainBlock(txt));
     lsPendingChain=chain;
     try{store('aegis-lastchain',JSON.stringify(chain));}catch(e){}
     const el=addMsg('assistant','');
     el.querySelector('.m-body').innerHTML=`<div class="ai-trace-cta"><div><b>${chain.length}-step attack chain reconstructed.</b> Watch it trace across your network map in real time.</div><button class="btn magenta" onclick="lsTracePending()">▶ Trace on map</button></div>`;
    }else if(propMap){
     const clean=stripMapBlock(txt);if(clean)addMsg('assistant',clean);
     _lsProposedMap=propMap;
     const el=addMsg('assistant','');
     const summary=propMap.map(n=>NODE_TYPES[n.type].glyph).join(' ');
     el.querySelector('.m-body').innerHTML=`<div class="ai-trace-cta"><div><b>${propMap.length}-node map proposed.</b> ${summary}<br>Build it on the Network Map (replaces the current one).</div><button class="btn violet" onclick="lsBuildProposedMap()">⧉ Build this map</button></div>`;
    }else if(tkAction){
     const clean=stripTicketBlock(txt);if(clean)addMsg('assistant',clean);
     _aiTicketAction=tkAction;
     const el=addMsg('assistant','');
     const desc=tkAction.comment
       ?`add a comment to ticket #${tkAction.num}`
       :`update ticket #${tkAction.num}: ${Object.entries(tkAction.patch||{}).map(([k,v])=>`${esc(k)} → ${esc(String(v))}`).join(', ')}`;
     el.querySelector('.m-body').innerHTML=`<div class="ai-trace-cta"><div><b>Proposed action:</b> ${desc}. This applies under your own permissions.</div><button class="btn violet" onclick="aiApplyTicketAction()">✓ Apply to #${tkAction.num}</button></div>`;
    }else{
     addMsg('assistant',txt);
    }
   }
  }else{
   // The local proxy answers {ok:false,error} for everything from "no model
   // running" to "it timed out loading 4GB of weights", and each of those is
   // worth telling the analyst verbatim rather than flattening.
   const em=(data&&(data.error||(typeof data.error==='string'?data.error:'')))
     ||'the local model returned nothing';
   addMsg('assistant',`**AI Analyst unavailable.** ${esc(String(em))}\n\n`
    +'It runs on your AEGIS host. `npm run ai:setup` there, or see `LOCAL-AI.md`.');
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
 toast('AI-proposed map built - edit and hunt on it');
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
 document.getElementById('nt-event').innerHTML=evs.map(e=>`<option value="${e.id}">${e.id} - ${e.title}</option>`).join('');
}
function saveNote(){
 const p=document.getElementById('nt-plat').value;const id=document.getElementById('nt-event').value;const txt=document.getElementById('nt-text').value;
 if(!txt.trim())return;
 notes[p+'::'+id]=txt;store('aegis-notes',JSON.stringify(notes));
 document.getElementById('nt-text').value='';renderNotes();updateBadges();refreshCards();toast('Note saved');
}
function saveCardNote(key){
 const [p,id]=key.split('::');const ta=document.getElementById(`na-${p}-${id}`);if(!ta)return;
 notes[key]=ta.value;store('aegis-notes',JSON.stringify(notes));renderNotes();updateBadges();toast('Note saved');
}
function delNote(key){delete notes[key];store('aegis-notes',JSON.stringify(notes));renderNotes();updateBadges();refreshCards();}
function renderNotes(){
 if(!document.getElementById('nt-main'))return;
 const host=document.getElementById('nt-main');
 const entries=Object.entries(notes).filter(([,v])=>v.trim());
 if(!entries.length){host.innerHTML='<div class="nt-empty">No notes yet - knowledge you save here persists across sessions.</div>';return;}
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
/* The in-app guide, for everyone. Deliberately about *using* AEGIS during an
   incident - not about running the server. Anything that needs a shell, a
   config file or an admin lives in docs/RUNBOOK.md instead, because an analyst
   at 3am should not be reading systemd instructions. */
const TOUR=[
 {target:null,title:'Welcome to AEGIS',step:'Getting started',body:'AEGIS is where your team works an incident together: live telemetry from your endpoints, a map of your estate, shared cases, and a signed record of who did what. This 60-second tour shows you round.'},
 {target:'.dash-head',title:'1 · What is happening',step:'Dashboard',body:'Your first screen, and all of it is live. Threat level for the last hour, malicious events as they land, the noisiest hosts, ATT&CK techniques actually <b>observed</b> in your telemetry, and any agent that has gone quiet. <b>⚙ Customise</b> picks your own cards - it is remembered in this browser, so triage and engineering shifts can differ.',pre:()=>go('dash')},
 {target:'#r-logsrc',title:'2 · Your estate',step:'Network Map',body:'Enrolled hosts appear here automatically. <b>Click a node</b> to log what you are seeing on it during a hunt, raise a ticket for it, or open a response playbook. You can draw your own links, trace an attack path by hand, and scrub the incident timeline.',pre:()=>go('logsrc')},
 {target:'#r-siem',title:'3 · Find the evidence',step:'Event Search',body:'Field-aware search across everything your agents have reported. Try <code>severity:malicious</code>, <code>host:DC01</code>, or <code>technique:T1003</code> - the facets under the box are clickable. <b>Live</b> keeps it re-running as new telemetry arrives.',pre:()=>go('siem')},
 {target:'#r-cases',title:'4 · Build the case',step:'Cases',body:'Group tickets and evidence under one incident. Uploaded evidence is stored by its <b>SHA-256</b>, so a file that changes is a file you can prove changed, and the formal report is frozen against a snapshot hash when you finalize it.',pre:()=>go('cases')},
 {target:'#co-ind',title:'The AI runs on your own machine',step:'Local AI',body:'Both AI features run on the AEGIS host - no API key, nothing sent to the internet. The <b>Companion</b> reads telemetry as it lands and comments on anything suspicious <i>without being asked</i>; the <b>AI Analyst</b> tab answers longer questions you type. Greyed out means no model is set up yet.'},
 {target:'#presence-ind',title:'You are not alone in here',step:'The team',body:'The dots show who else is connected right now. <b>◷ Activity</b> is what everyone has been doing, read straight out of the tamper-evident audit chain, and <b>✻ Chat</b> is the room. Every action is recorded against the person who took it.'},
 {target:'#r-matrix',title:'Reference, when you need it',step:'Matrix & Studio',body:'The <b>ATT&CK Matrix</b> is the full technique library - what you <i>could</i> detect, with the telemetry and SPL for each. <b>Detection Studio</b> under Plan lays staged techniques on the kill chain and compiles a coverage report. Both are planning tools, which is why they sit behind the live views.',pre:()=>go('matrix')},
 {target:null,title:'You\'re ready',step:'Done',body:'<b>1–8</b> switch views, <b>⌘K</b> jumps anywhere, <b>?</b> restarts this tour.<br><br>Something broken rather than confusing? That is a job for whoever runs your server - point them at <b>docs/RUNBOOK.md</b>, which has a step-by-step fix for every failure this thing has.'}
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
 // Measure AFTER the step's pre() has navigated and the view has laid out.
 // A single rAF fired too early - the target view often had not reflowed yet,
 // so the spotlight landed on a zero-size or stale rect and looked like it was
 // highlighting nothing. Double-rAF lets layout settle; if the element still
 // has no size (view mid-render) we retry a couple of times, and we scroll it
 // into view first so an off-screen target is actually visible under the hole.
 let tries=0;
 const measure=()=>{
  if(tourStep<0)return;                    // tour was closed while we waited
  let el=s.target?document.querySelector(s.target):null;
  if(el){
   try{el.scrollIntoView({block:'nearest',inline:'nearest'});}catch{}
   let r=el.getBoundingClientRect();
   if(r.width<2&&r.height<2&&tries++<8){setTimeout(measure,70);return;}
   // Still zero-size (e.g. an empty dashboard grid with no live data)? Fall
   // back to the active view so the spotlight always frames something real.
   if(r.width<2&&r.height<2){const fb=document.querySelector('.view.on');if(fb){el=fb;r=fb.getBoundingClientRect();}}
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
 };
 requestAnimationFrame(()=>requestAnimationFrame(measure));
}
function tourNext(){if(tourStep>=TOUR.length-1){endTour();return;}tourStep++;placeTour();}
function tourPrev(){if(tourStep<=0)return;tourStep--;placeTour();}
function endTour(){tourStep=-1;document.getElementById('tour-veil').classList.remove('open');document.removeEventListener('keydown',tourKeys);store('aegis-toured','yes');}
