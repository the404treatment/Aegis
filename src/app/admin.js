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
 const win=`powershell -ExecutionPolicy Bypass -File agents\\aegis-agent.ps1 -Server ${d.serverUrl} -EnrollmentToken ${d.enrollmentToken} -Install`;
 // python3 rather than ./aegis-agent.py: a ZIP download loses the executable
 // bit and the ./ form then fails as "command not found".
 const nix=`sudo python3 agents/aegis-agent.py --server ${d.serverUrl} --token ${d.enrollmentToken} --once`;
 const scan=`node discover.mjs --json targets.json && node deploy-agents.mjs --targets targets.json`;
 const q=s=>JSON.stringify(s).replace(/"/g,'&quot;');
 return`<div class="adm-sec">
   <div class="adm-sec-h"><span>Deploy an agent</span></div>
   <div class="adm-note">
     Agents are read-only and push-only - there is no channel for the server, or this
     console, to reach out and install one on an endpoint. Run one of these from a
     terminal on the machine you want telemetry from (or, for many machines at once, from
     any machine with network access to them).
   </div>
   <div class="sec-t" style="padding:0 15px;margin-top:10px">Windows - PowerShell in the unzipped folder (it will ask for admin)</div>
   <div class="qwrap" style="margin:6px 15px 0"><div class="qblock">${esc(win)}</div>
     <button class="cpy" onclick="copyText(this,${q(win)})">COPY</button></div>
   <div class="sec-t" style="padding:0 15px;margin-top:10px">Linux / macOS, as root</div>
   <div class="qwrap" style="margin:6px 15px 0"><div class="qblock">${esc(nix)}</div>
     <button class="cpy" onclick="copyText(this,${q(nix)})">COPY</button></div>
   <div class="sec-t" style="padding:0 15px;margin-top:10px">Scan the network first, then push to what it finds</div>
   <div class="qwrap" style="margin:6px 15px 0"><div class="qblock">${esc(scan)}</div>
     <button class="cpy" onclick="copyText(this,${q(scan)})">COPY</button></div>
   <div class="adm-note" style="margin-top:8px">
     Installing under a different name, so an intruder can't spot the agent by searching
     for "AEGIS": add <code>-Name svc-telemetry</code> (or <code>--agent-name</code> on the
     scanning deployer). Step-by-step: <code>docs/RUNBOOK.md</code> section 7.
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
 const pw=await uiPrompt(`Password for ${name.trim()} (at least 10 characters)`,'',{title:'Add someone',ok:'Create',password:true});
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
