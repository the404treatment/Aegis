/* ================= ADMIN ================= */
/* Everything a lead needs to run the platform, in one place.
 *
 * Accounts are on by default, which made it absurd that the only way to create
 * the second one was a curl command in a README. This is that, plus the three
 * other things whose absence you only notice during an incident: is the audit
 * chain still intact, who has a live session, and is this deployment still
 * sitting on the published defaults that anyone who read the repo knows.
 *
 * Lead-only, and hidden entirely from analysts rather than shown-and-refused -
 * a nav item you cannot use is just a reminder that you are not trusted. */

let ADMIN = {users:[], sessions:0, chain:null, service:null, deploy:null};
let _adminBusy=false;
let admDeployOS='win';   // which deploy-wizard tab is showing
function admSetDeployOS(os){admDeployOS=os;renderAdmin();}

/* ================= TOOLBOX ================= */
/* A plain-language menu of what an analyst can actually DO in AEGIS. People
   kept missing capabilities that were one click away because nothing listed
   them in one place. Reachable by everyone (rail > Toolbox); the deploy/agent
   entries are lead-gated at the point of action, not hidden. Each tool is
   {icon,name,what,when,go} - `go` is JS run on click, or null for a
   reference-only entry that just explains itself. */
const TOOLBOX=[
 {icon:'▤',name:'Detection Studio',cat:'Build detections',
  what:'Stage ATT&CK techniques and compile Sigma, Splunk savedsearches and a risk-based-alerting (RBA) package from them.',
  when:'When you\'re engineering coverage rather than working a live incident.',go:"go('studio')"},
 {icon:'◷',name:'Baseline builder',cat:'Build detections',
  what:'Turn your network into a prioritised Event-ID plan and run it in non-alerting mode first, so detections learn "normal" before they fire.',
  when:'Before enabling triggers on a new estate - a week of baselining kills most false positives.',go:"go('logsrc');setTimeout(()=>lsBuildFromTopo&&lsBuildFromTopo(),50)"},
 {icon:'◎',name:'Attack trace',cat:'Hunt',
  what:'Map how an intruder would move host-to-host, then animate the path. Or let the AI reconstruct it from your logged observations.',
  when:'Planning a scenario, or explaining a real intrusion to the team.',go:"go('logsrc')"},
 {icon:'⊞',name:'Event search',cat:'Hunt',
  what:'Field-aware search across everything your agents have reported - severity:malicious, host:DC01, technique:T1003.',
  when:'Finding the evidence behind an alert.',go:"go('siem')"},
 {icon:'⇲',name:'Ingest & parse',cat:'Hunt',
  what:'Drop a Chainsaw / Suricata eve.json / Zeek export or a PCAP and get a uniform timeline, IOCs and findings - parsed entirely in your browser.',
  when:'Triaging an export from another tool without standing up a pipeline.',go:"go('logsrc');setTimeout(()=>openLsIngest&&openLsIngest(),50)"},
 {icon:'▤',name:'Response playbooks',cat:'Respond',
  what:'Offline, deterministic containment / eradication / recovery commands per technique or host - OS-aware (Windows, Linux, network gear), no LLM.',
  when:'The moment a host is confirmed compromised and you need exact steps.',go:"openAdvisor&&openAdvisor(null)"},
 {icon:'◆',name:'AI analyst',cat:'Respond',
  what:'A local-model detection-engineering copilot - tune a noisy alert, explain a false positive, correlate a hunt map. Runs on your host, nothing leaves it.',
  when:'Any time - it also floats on every page as the corner button.',go:"go('ai')"},
 {icon:'⎘',name:'Report generator',cat:'Report',
  what:'Compile your staged coverage and the live hunt map into a shareable technical or formal report; a lead can freeze the formal one against a hash.',
  when:'Handover, or a client-facing write-up.',go:"openReport&&openReport()"},
 {icon:'⛨',name:'Endpoint collection agent',cat:'Deploy',
  what:'The read-only PowerShell (Windows) / Python (Linux/macOS) agent that ships a detection-relevant slice of Security, Sysmon and PowerShell events. It accepts no commands and has no remote-exec channel by design.',
  when:'To get real telemetry flowing. A lead deploys it from Admin > Deploy.',go:'__deploy'},
 {icon:'⌖',name:'Network discovery',cat:'Deploy',
  what:'Scan for live hosts (node discover.mjs) and push the agent to what it finds (node deploy-agents.mjs) - run from any machine that can reach them.',
  when:'Rolling agents out to many machines at once.',go:null},
 {icon:'⛓',name:'Audit forensics',cat:'Assurance',
  what:'Every action is written to a hash-chained, tamper-evident log. node verify-audit.mjs proves the chain has not been altered.',
  when:'Proving integrity of the incident record afterwards.',go:null},
];
function openToolbox(){
 let v=document.getElementById('toolbox-veil');
 if(!v){v=document.createElement('div');v.id='toolbox-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const cats=[...new Set(TOOLBOX.map(t=>t.cat))];
 // Resolve the lead-gated deploy action here, at render time - authCan is a
 // const that isn't safe to touch while the modules are still loading.
 const isLead=typeof authCan==='function'&&authCan('user.manage');
 const goOf=t=>t.go==='__deploy'?(isLead?"go('admin')":null):t.go;
 v.innerHTML=`<div class="ls-det-sheet" style="width:min(620px,100vw)">
   <div class="ls-ne-grip" onclick="closeToolbox()"></div>
   <div class="ls-det-head">Analyst toolbox</div>
   <div class="ls-det-sub">Everything AEGIS can do for you, in one place. Click a tool to open it.</div>
   ${cats.map(c=>`<div class="ls-mm-sec">${c}</div>
     ${TOOLBOX.filter(t=>t.cat===c).map(t=>{const g=goOf(t);return`<div class="tbx-tool ${g?'':'ref'}" ${g?`onclick="closeToolbox();${g}"`:''}>
       <span class="tbx-ic">${t.icon}</span>
       <div class="tbx-b"><div class="tbx-name">${esc(t.name)}${g?'':'<span class="tbx-ref">reference</span>'}</div>
         <div class="tbx-what">${t.what}</div>
         <div class="tbx-when">${t.when}</div></div>
       ${g?'<span class="tbx-open">→</span>':''}
     </div>`;}).join('')}`).join('')}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeToolbox();};
}
function closeToolbox(){const v=document.getElementById('toolbox-veil');if(v)v.classList.remove('open');}

const adminIsLead = () => authCan('user.manage');

async function renderAdmin(){
 const host=document.getElementById('admin-body');if(!host)return;
 if(!LIVE.connected){
  host.innerHTML=`<div class="dash-empty">Admin needs a server connection. Click the connection indicator in the top bar.</div>`;return;}
 if(!adminIsLead()){
  host.innerHTML=`<div class="dash-empty">Only a <b>lead</b> can manage accounts and see platform health.
    You are signed in as <b>${esc((ME&&ME.role)||'analyst')}</b>. Ask a lead if you need access.</div>`;return;}

 host.innerHTML=`<div class="dash-empty">Loading…</div>`;
 await adminLoad();

 host.innerHTML=`
  ${adminHealth()}
  <div class="adm-sec">
    <div class="adm-sec-h"><span>Accounts</span>
      <button class="btn violet" onclick="adminNewUser()">+ Add someone</button></div>
    ${adminUsers()}
  </div>
  <div class="adm-sec">
    <div class="adm-sec-h"><span>Analyst toolbox</span>
      <button class="btn ghost-violet" onclick="openToolbox()">Open toolbox</button></div>
    <div class="adm-note">The full menu of what analysts can do here - baselining, response playbooks, ingest, the collection agent and more. It's on everyone's sidebar too.</div>
  </div>
  ${adminDeploy()}
  ${adminService()}`;
}

async function adminLoad(){
 if(_adminBusy)return;_adminBusy=true;
 try{ADMIN.users=await liveApi('/api/users');}catch{ADMIN.users=[];}
 try{const a=await liveApi('/api/activity?limit=1');ADMIN.chain=a.intact!==false;}catch{ADMIN.chain=null;}
 try{ADMIN.deploy=await liveApi('/api/enrollment-info');}catch{ADMIN.deploy=null;}
 _adminBusy=false;
}

/* --------------------------------------------------------- deploy ---- */
/* This was previously only discoverable by reading INSTALL.md and copying a
 * command out of a terminal that printed it once at server startup - the
 * exact information a lead needs to enrol an agent, sitting in a file most
 * analysts never open. The values here come from the server itself
 * (GET /api/enrollment-info, already gated to any signed-in analyst), so this
 * is display only: nothing here lets the browser reach out and install
 * anything on an endpoint. Agents stay push-only and opt-in by design - see
 * the header comment in server/aegis-server.mjs. */
function adminDeploy(){
 const d=ADMIN.deploy;
 if(!d)return`<div class="adm-sec"><div class="adm-sec-h"><span>Deploy an agent</span></div>
   <div class="adm-note">Could not read the enrollment token from the server. It is still printed at server startup, and in server/config.json.</div></div>`;
 // Run from the unzipped repo root, with the path to the agent spelled out
 // (agents\...), so it does not matter which folder the operator is standing
 // in - the single most common install failure was cd'ing into deploy\ and
 // running .\aegis-agent.ps1, which is not there. -ExecutionPolicy Bypass
 // pre-empts the "not digitally signed" wall; the agent self-elevates for the
 // admin rights it needs, so an ordinary PowerShell is a fine place to start.
 // Self-locating: the #1 failure was a relative path that only resolved from
 // the repo root, but people run from Downloads or system32, or download just
 // the one (possibly renamed) script. This finds aegis-agent*.ps1 in the
 // current folder or an .\agents subfolder and runs whichever it finds, so it
 // works wherever the operator actually is.
 const win=`$s='${d.serverUrl}'; $t='${d.enrollmentToken}'\n$a=Get-ChildItem -Recurse -Filter 'aegis-agent*.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1\nif(-not $a){Write-Host 'aegis-agent.ps1 not found here. cd into the unzipped AEGIS folder first.' -ForegroundColor Yellow; return}\npowershell -ExecutionPolicy Bypass -File $a.FullName -Server $s -EnrollmentToken $t -Install`;
 // python3 rather than ./aegis-agent.py: a ZIP download loses the executable
 // bit and the ./ form then fails as "command not found".
 const nix=`sudo python3 agents/aegis-agent.py --server ${d.serverUrl} --token ${d.enrollmentToken} --once`;
 const q=s=>JSON.stringify(s).replace(/"/g,'&quot;');
 const cmd=c=>`<div class="qwrap" style="margin:7px 0 0"><div class="qblock">${esc(c)}</div><button class="cpy" onclick="copyText(this,${q(c)})">COPY</button></div>`;
 const step=(n,title,body)=>`<div class="adm-dstep"><span class="adm-dnum">${n}</span><div class="adm-dstep-b"><b>${title}</b>${body?`<div class="adm-dbody">${body}</div>`:''}</div></div>`;
 const tab=(id,label)=>`<button class="adm-dtab ${admDeployOS===id?'on':''}" onclick="admSetDeployOS('${id}')">${label}</button>`;
 let steps='';
 if(admDeployOS==='win'){
  steps=step(1,'Get the AEGIS files onto the Windows machine you want to watch','Copy the unzipped AEGIS folder there (or to a share it can read). The agent is one file: <code>agents\\aegis-agent.ps1</code>.')
   +step(2,'Open PowerShell, <b>cd</b> into the AEGIS folder, and paste this','It finds the agent script wherever it is (this folder or <code>.\\agents\\</code>), so it does not matter which subfolder you are in:'+cmd(win))
   +step(3,'Approve the Windows admin prompt','It needs elevation to read the Security log. No code-signing or execution-policy fiddling - the command handles both. It installs a scheduled task that reports every 5 minutes and survives reboots. Watch for the green <code>enrolled as &lt;host&gt;</code> line - if enrollment fails it prints the reason in red.')
   +step(4,'Watch it appear','Within a minute the host shows on your Network Map and its telemetry starts lighting the ATT&CK Matrix. Still 0 agents? The endpoint could not reach <code>'+esc(d.serverUrl)+'</code> - check the firewall on the server and that the endpoint can curl that URL.');
 }else if(admDeployOS==='nix'){
  steps=step(1,'Get the AEGIS files onto the Linux / macOS host','Run it through <code>python3</code> (a ZIP download loses the executable bit, so <code>./</code> would fail). Stdlib only - nothing to install.')
   +step(2,'Run it as root:',cmd(nix))
   +step(3,'Schedule it to keep reporting','The <code>--once</code> form is meant for a cron job or systemd timer every 5 minutes - see <code>deploy/aegis-agent.timer</code> for a ready unit.')
   +step(4,'Watch it appear','The host joins your Network Map as it starts reporting.');
 }else{
  steps=step(1,'From any machine that can reach the targets, scan the network',cmd('node discover.mjs --json targets.json'))
   +step(2,'Review what it found','Open <code>targets.json</code> and remove anything you should not touch.')
   +step(3,'Push the agent to everything in the list',cmd('node deploy-agents.mjs --targets targets.json'))
   +step(4,'Watch them appear','Each enrolled host joins the map, and links between enrolled hosts draw themselves.');
 }
 return`<div class="adm-sec">
   <div class="adm-sec-h"><span>Deploy an agent</span></div>
   <div class="adm-note">
     Agents are read-only and push-only - nothing here reaches out to install one for you.
     Pick where you're deploying and follow the steps.
   </div>
   <div class="adm-dtabs">${tab('win','One Windows host')}${tab('nix','One Linux / macOS host')}${tab('many','Many machines at once')}</div>
   <div class="adm-dsteps">${steps}</div>
   <div class="adm-note" style="margin-top:10px">
     Hiding the agent so an intruder can't find it by searching for "AEGIS": add
     <code>-Name svc-telemetry</code> (or <code>--agent-name</code> on the scanning deployer).
     Full walkthrough: <code>docs/RUNBOOK.md</code> section 7.
   </div>
 </div>`;
}

/* ---------------------------------------------------------- health ---- */
function adminHealth(){
 const chainOk=ADMIN.chain;
 const stale=(LIVE.agents||[]).filter(a=>a.stale).length;
 const tiles=[
  {k:'chain', label:'Audit chain',
   v: chainOk===null?'unknown':chainOk?'verified':'BROKEN',
   tone: chainOk===null?'':chainOk?'ok':'bad',
   note: chainOk===false
    ? 'Someone has edited the record on disk. Treat every case file as untrusted until that is explained.'
    : 'Every action is hash-chained. This re-verifies the whole chain.'},
  {k:'people', label:'Accounts', v:String(ADMIN.users.length), tone:ADMIN.users.length?'':'warn',
   note: ADMIN.users.length<2?'A team sharing one login is the same as no accounts at all.':'One per person, so the record means something.'},
  {k:'agents', label:'Agents reporting',
   v:`${(LIVE.agents||[]).length-stale}/${(LIVE.agents||[]).length}`,
   tone: stale?'warn':'ok',
   note: stale?`${stale} gone quiet. Silence is a signal, not calm - see docs/DEFENDING-AEGIS.md.`:'All enrolled agents are reporting.'},
  {k:'here', label:'Online now', v:String(PRESENCE.length||0), tone:'',
   note: PRESENCE.length?PRESENCE.map(p=>p.name).join(', '):'Nobody else is connected.'},
 ];
 return`<div class="adm-tiles">${tiles.map(t=>`
   <div class="adm-tile adm-${esc(t.tone)}">
     <div class="adm-tile-l">${esc(t.label)}</div>
     <div class="adm-tile-v">${esc(t.v)}</div>
     <div class="adm-tile-n">${esc(t.note)}</div>
   </div>`).join('')}</div>`;
}

/* ----------------------------------------------------------- users ---- */
function adminUsers(){
 if(!ADMIN.users.length)return `<div class="dash-empty">No accounts yet.</div>`;
 const meId=ME&&ME.id;
 return`<div class="adm-users">${ADMIN.users.map(u=>{
  const self=u.id===meId;
  return`<div class="adm-user">
    <span class="who-dot sm" style="--who:${whoColor(u.name)}">${esc(initialsOf(u.name))}</span>
    <span class="adm-u-name">${esc(u.name)}${self?' <i>(you)</i>':''}</span>
    <select class="adm-u-role" ${self?'disabled title="You cannot change your own role - that is how people lock themselves out"':''}
      onchange="adminSetRole('${jsq(u.id)}',this.value)">
      ${['analyst','lead'].map(r=>`<option value="${r}" ${u.role===r?'selected':''}>${r}</option>`).join('')}
    </select>
    <button class="adm-u-x" onclick="adminResetPw('${jsq(u.id)}','${jsq(u.name)}')" data-tip="Set a new password">key</button>
    <button class="adm-u-x danger" ${self?'disabled':''}
      onclick="adminDeleteUser('${jsq(u.id)}','${jsq(u.name)}')" data-tip="Remove, and kill their sessions">remove</button>
  </div>`;}).join('')}</div>
  <div class="adm-note">Deleting an account revokes its live sessions immediately - that is the offboarding control.
   Changing a password does the same.</div>`;
}

async function adminNewUser(){
 const name=await uiPrompt('Name - colleagues will see this on everything they do','',{title:'Add someone',ok:'Next'});
 if(!name||!name.trim())return;
 // Default to the standard local password so adding people is one field, not
 // a password-invention exercise. It is pre-filled and editable - clear it to
 // set a real one for a networked deployment.
 const pw=await uiPrompt(`Password for ${name.trim()} (standardised for this box - edit if you want a different one)`,'Password123!',{title:'Add someone',ok:'Create',password:true});
 if(!pw)return;
 const lead=await uiConfirm(`Should ${name.trim()} be a lead?\n\nLeads can manage accounts and freeze formal reports. Analysts can do everything else.`,
   {title:'Role',ok:'Make them a lead',cancel:'Analyst'});
 try{
  await liveApi('/api/users',{method:'POST',body:JSON.stringify({name:name.trim(),password:pw,role:lead?'lead':'analyst'})});
  toast(`${name.trim()} added`);renderAdmin();
 }catch(e){toast('Could not add them: '+e.message);}
}

async function adminSetRole(id,role){
 try{await liveApi('/api/users/'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify({role})});
  toast('Role updated');renderAdmin();
 }catch(e){toast('Could not change the role: '+e.message);renderAdmin();}
}

async function adminResetPw(id,name){
 const pw=await uiPrompt(`New password for ${name} (at least 10 characters)`,'',{title:'Reset password',ok:'Set',password:true});
 if(!pw)return;
 try{await liveApi('/api/users/'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify({password:pw})});
  toast(`Password set - ${name} has been signed out everywhere`);
 }catch(e){toast('Could not set it: '+e.message);}
}

async function adminDeleteUser(id,name){
 if(!await uiConfirm(`Remove ${name}?\n\nTheir sessions die immediately. Everything they did stays in the audit chain and in the case files - this removes the account, not the record.`,
   {title:'Remove account',ok:'Remove',danger:true}))return;
 try{await liveApi('/api/users/'+encodeURIComponent(id),{method:'DELETE'});
  toast(`${name} removed`);renderAdmin();
 }catch(e){toast('Could not remove them: '+e.message);}
}

/* --------------------------------------------------------- service ---- */
function adminService(){
 return`<div class="adm-sec">
   <div class="adm-sec-h"><span>This deployment</span></div>
   <div class="adm-kv">
     <div><span>Server</span><b>${esc(LIVE.url||'—')}</b></div>
     <div><span>Signed in as</span><b>${esc((ME&&ME.name)||'—')} · ${esc((ME&&ME.role)||'')}</b></div>
     <div><span>Local AI</span><b>${CO.available?esc(CO.name+' · '+CO.model):'not configured'}</b></div>
   </div>
   <div class="adm-note">
     AEGIS holds your incident record, which makes it a target. Everything about a stock
     install - service name, port, paths - is public. Change it on the server with
     <code>node harden.mjs --name &lt;something-dull&gt; --port &lt;not-8787&gt; --rotate</code>,
     then read <code>docs/DEFENDING-AEGIS.md</code> for what to alert on. Rotating tokens
     signs out consoles using the shared token; named accounts are unaffected.
   </div>
 </div>`;
}
