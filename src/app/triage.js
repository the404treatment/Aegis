/* ================= ARTIFACT TRIAGE WIZARD =================
   Guided, step-by-step triage of something an analyst found on a host.
   Each step offers concrete options; the answers build a structured prompt,
   the AI returns an assessment, and the result is logged onto that node. */
const ART_TYPES={
 file:{label:'A file',glyph:'\ud83d\udcc4',q:[
   {k:'where',label:'Where is it?',opts:['User AppData / Temp','ProgramData','System32 / Windows','Program Files','A network share','User Desktop / Downloads','Somewhere else']},
   {k:'kind',label:'What kind of file?',opts:['Executable (.exe/.dll)','Script (.ps1/.bat/.vbs/.js)','Office document','Archive (.zip/.7z/.rar)','Shortcut (.lnk)','Unknown / no extension']},
   {k:'sig',label:'Is it signed?',opts:['Unsigned','Signed, unknown publisher','Signed, trusted publisher','Not checked yet']}]},
 process:{label:'A running process',glyph:'\u2699',q:[
   {k:'parent',label:'What launched it?',opts:['Office application','Browser','explorer.exe','services.exe / SYSTEM','Another script or shell','Unknown / orphaned']},
   {k:'behave',label:'What is it doing?',opts:['Network connections outbound','Spawning child processes','Reading lots of files','High CPU','Just sitting there','Not sure yet']},
   {k:'ctx',label:'Where does it run from?',opts:['Temp / AppData','System32','Program Files','A share or removable drive','Unknown']}]},
 network:{label:'A network connection',glyph:'\ud83c\udf10',q:[
   {k:'dir',label:'Which direction?',opts:['Outbound to internet','Outbound to another internal host','Inbound from internet','Inbound from internal']},
   {k:'port',label:'What port / protocol?',opts:['443 / HTTPS','80 / HTTP','445 / SMB','3389 / RDP','53 / DNS','An unusual high port']},
   {k:'pat',label:'What does the pattern look like?',opts:['Regular beaconing intervals','One large transfer','Many short connections','Constant long-lived session','Only seen once']}]},
 registry:{label:'A registry change',glyph:'\ud83d\uddc2',q:[
   {k:'key',label:'Which area?',opts:['Run / RunOnce keys','Services','Winlogon / Userinit','Image File Execution Options','Defender / security settings','Somewhere else']},
   {k:'who',label:'Who made the change?',opts:['A user account','SYSTEM','A script or shell','Unknown']}]},
 account:{label:'An account or logon',glyph:'\ud83d\udc64',q:[
   {k:'what',label:'What did you notice?',opts:['New account created','Unexpected privilege grant','Logon at an odd hour','Logon from a new location','Many failed logons','Account added to a group']},
   {k:'type',label:'What kind of account?',opts:['Domain user','Local account','Service account','Admin account','Cloud identity']}]},
 task:{label:'A scheduled task or service',glyph:'\u23f1',q:[
   {k:'what',label:'Which is it?',opts:['New scheduled task','New service','Modified existing task','Modified existing service']},
   {k:'run',label:'What does it run?',opts:['PowerShell or cmd','An executable in Temp/AppData','A signed system binary','Something over the network','Not sure']}]},
 log:{label:'A log entry or alert',glyph:'\ud83d\udcdc',q:[
   {k:'src',label:'Where did it come from?',opts:['Windows Security log','Sysmon','EDR alert','Firewall / proxy','Cloud audit log','SIEM correlation']},
   {k:'nature',label:'What is the nature of it?',opts:['Logs were cleared','Security tooling changed','Suspicious command line','Authentication anomaly','Data transfer','Something else']}]},
 other:{label:'Something else',glyph:'\u2753',q:[
   {k:'what',label:'Roughly what area?',opts:['User reported behaviour','Physical / removable media','Email','Cloud resource','Not sure']}]}
};
let artState=null;
function openArtifactTriage(uid){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 artState={uid,step:0,type:null,answers:{},detail:''};
 renderArtStep();
}
function artClose(){artState=null;const v=document.getElementById('ls-art-veil');if(v)v.classList.remove('open');}
function artPick(k,v){
 if(k==='__type'){artState.type=v;artState.step=1;}
 else{artState.answers[k]=v;artState.step++;}
 renderArtStep();
}
function artBack(){if(artState.step>0){artState.step--;renderArtStep();}}
function renderArtStep(){
 let v=document.getElementById('ls-art-veil');
 if(!v){v=document.createElement('div');v.id='ls-art-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const n=lsNodes.find(x=>x.uid===artState.uid);
 const T=artState.type?ART_TYPES[artState.type]:null;
 const total=T?T.q.length+2:1;
 let body='';
 if(artState.step===0){
  body=`<div class="art-q">What did you find on ${esc(n.label)}?</div>
   <div class="art-opts">${Object.entries(ART_TYPES).map(([k,a])=>`<button class="art-opt" onclick="artPick('__type','${k}')"><span class="art-g">${a.glyph}</span>${a.label}</button>`).join('')}</div>`;
 } else if(T&&artState.step<=T.q.length){
  const q=T.q[artState.step-1];
  body=`<div class="art-q">${esc(q.label)}</div>
   <div class="art-opts">${q.opts.map(o=>`<button class="art-opt" onclick="artPick('${q.k}',${JSON.stringify(o).replace(/"/g,'&quot;')})">${esc(o)}</button>`).join('')}</div>`;
 } else {
  body=`<div class="art-q">Anything else? (paths, names, command lines \u2014 paste what you have)</div>
   <textarea id="art-detail" class="art-ta" placeholder="e.g. C:\\Users\\jsmith\\AppData\\Roaming\\svchost.exe, ran at 02:14, connected to 185.x.x.x">${esc(artState.detail||'')}</textarea>
   <div class="art-sum">${Object.entries(artState.answers).map(([k,val])=>`<span class="art-chip">${esc(val)}</span>`).join('')}</div>
   <button class="btn violet" style="width:100%;justify-content:center;margin-top:10px" onclick="artSubmit()">Analyse with AI \u2192</button>`;
 }
 v.innerHTML=`<div class="art-sheet">
   <div class="ls-ne-grip" onclick="artClose()"></div>
   <div class="art-head"><span>Artifact triage \u00b7 ${esc(n.label)}</span><span class="art-step">${Math.min(artState.step+1,total)} / ${total}</span></div>
   <div class="art-bar"><i style="width:${Math.round((Math.min(artState.step,total-1)/(total-1))*100)}%"></i></div>
   ${body}
   <div class="art-foot">${artState.step>0?`<button class="art-back" onclick="artBack()">\u2039 Back</button>`:''}<button class="art-back" onclick="artClose()">Cancel</button></div>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)artClose();};
}
function artSubmit(){
 const ta=document.getElementById('art-detail');
 artState.detail=ta?ta.value.trim():'';
 const n=lsNodes.find(x=>x.uid===artState.uid);
 const T=ART_TYPES[artState.type];
 const t=NODE_TYPES[n.type];
 const facts=Object.entries(artState.answers).map(([k,v])=>`- ${k}: ${v}`).join('\n');
 const obs=lsNodeObs(n).map(o=>`${o.evId||'note'} (${o.sev})`).join(', ')||'none yet';
 const prompt=`I am triaging an artifact found during a live hunt. Assess it.

HOST: ${n.label} \u2014 ${t.label}, ${n.os}, zone ${zoneLabel(nodeZone(n))}
ALREADY OBSERVED ON THIS HOST: ${obs}

ARTIFACT TYPE: ${T.label}
${facts}
ANALYST DETAIL: ${artState.detail||'(none given)'}

Answer in this order, briefly:
1. WHAT IT LIKELY IS \u2014 the two or three most plausible explanations, benign ones included, most likely first.
2. WHY \u2014 what about the above points each way.
3. ATT&CK \u2014 the technique IDs this would map to if malicious.
4. NEXT CHECK \u2014 the single most useful thing to look at next, and the Windows Event ID or Splunk search to get it. Use SPL with broad alerting plus outputlookup suppression, dc(ComputerName) for host-frequency scoring, and _raw fallback when a field may not exist.
5. VERDICT \u2014 one line, and state your confidence honestly. If this is probably benign, say so plainly.

Then on the very last line output exactly:
TRIAGE={"sev":"info|suspicious|malicious","label":"<six words or fewer>","tech":"T####"}`;
 go('ai');
 addMsg('user',`Triage on ${n.label}: ${T.label} \u2014 ${Object.values(artState.answers).join(', ')}${artState.detail?' \u2014 '+artState.detail.slice(0,120):''}`);
 chatLog.push({role:'user',content:prompt});
 const uid=artState.uid;
 artClose();
 runAI({triage:true,uid});
}
function parseTriage(text){
 const m=text&&text.match(/TRIAGE\s*=\s*(\{[\s\S]*?\})/);
 if(!m)return null;
 try{const o=JSON.parse(m[1]);if(o&&o.sev)return o;}catch(e){}
 return null;
}
function stripTriage(text){return text.replace(/\n?TRIAGE\s*=\s*\{[\s\S]*\}\s*$/,'').trim();}
function artLog(uid,sev,label,tech){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 lsAddObs(uid,tech&&MITRE[tech]?'':'',label,sev);
 if(tech&&MITRE[tech]&&!studio.has(tech)){studio.add(tech);persistAll();renderStudio();}
 toast(`Logged on ${n.label}`);
 go('logsrc');renderLogSrc();
}

/* grouped node picker */
const NODE_GROUPS=[
 ['Endpoints',['wks','iot']],
 ['Servers',['dc','srv','dmz','nas']],
 ['Network',['fw','router','switch','vpn']],
 ['External',['internet','cloud']]
];
function openLsAddMenu(){
 let v=document.getElementById('ls-add-veil');
 if(!v){v=document.createElement('div');v.id='ls-add-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-add-sheet">
   <div class="ls-ne-grip" onclick="lsCloseAddMenu()"></div>
   <div class="ls-add-head">Add a host</div>
   <button class="ls-triage-btn" style="margin:4px 0 10px" onclick="lsCloseAddMenu();openLsImport()">
     <span class="ls-triage-ic">\u2913</span><span><b>Import a host list</b><small>Paste your inventory \u2014 one host per line</small></span></button>
   ${NODE_GROUPS.map(([grp,keys])=>`<div class="ls-addgrp">${grp}</div><div class="ls-addgrid">${keys.filter(k=>NODE_TYPES[k]).map(k=>`<button class="ls-addcard" onclick="lsAddNode('${k}');lsCloseAddMenu()">
     <span class="ls-addg">${NODE_TYPES[k].glyph}</span>
     <span class="ls-addname">${esc(NODE_TYPES[k].label)}</span>
   </button>`).join('')}</div>`).join('')}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseAddMenu();};
}
function lsCloseAddMenu(){const v=document.getElementById('ls-add-veil');if(v)v.classList.remove('open');}
function lsToggleAddMenu(){openLsAddMenu();}
