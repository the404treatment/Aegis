/* ================= ACCOUNTS ================= */
/* Optional named accounts. The server decides: GET /api/auth/mode says
   whether it wants a login, and until it does the console behaves exactly as
   it always has with a shared analyst token.

   Note this is a two-field form, so it deliberately does NOT use uiPrompt()
   (single input only) and must never use a native prompt() - see Hard Rule
   #1 in CLAUDE.md. It follows the lazy-veil pattern instead. */

let ME = null;   // {id,name,role,shared,caps[]} once authenticated, else null

const authCan = cap => !!(ME && (ME.caps || []).includes(cap));

/** Ask the server whether it wants a login before we try a bare token. */
async function authMode(url) {
 try{
  const r = await fetch(url.replace(/\/$/,'')+'/api/auth/mode');
  if(!r.ok)return{requireLogin:false,accounts:0};
  return await r.json();
 }catch{return{requireLogin:false,accounts:0};}
}

async function authFetchMe(){
 try{ME=await liveApi('/api/auth/me');}catch{ME=null;}
 return ME;
}

/* Whether this server has no accounts yet, so the form offers to create the
   first one instead of asking for a password that cannot exist. */
let _authNeedsSetup=false;
/* Seeded default accounts the server told us about, e.g.
   [{name:'admin',role:'lead'},{name:'user',role:'analyst'}]. Drives the
   one-click role picker on the login screen. */
let _authDefaults=[];
/* When a server requires a login and nobody is signed in, the veil must not be
   dismissable - clicking the backdrop or the grip used to close it and leave
   the console open with no session, which is the reported bypass. Set true by
   the callers that open the veil as a hard gate. */
let _authMandatory=false;
function openLogin(msg,opts){
 opts=opts||{};
 const first=!!_authNeedsSetup;
 const gate=!!_authMandatory && !ME;   // hard gate: no escape hatch to a session-less console
 // The seeded account names, listed as a hint so an analyst knows what to
 // type - but nothing is filled in for them. Both fields start blank.
 const hint=(!first && _authDefaults && _authDefaults.length)?_authDefaults:null;
 let v=document.getElementById('auth-veil');
 if(!v){v=document.createElement('div');v.id='auth-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet" style="width:min(420px,100vw)">
  ${gate?'':'<div class="ls-ne-grip" onclick="closeLogin()"></div>'}
  <div class="ls-det-head">${first?'Create the first account':'Sign in to AEGIS'}</div>
  <div class="ls-det-sub">${first
    ?'This server has no accounts yet. The first one you create is a <b>lead</b>, so it can add everyone else. Work is recorded against the person who did it - that is what makes the case file worth anything later.'
    :'Sign in for live agent data, shared tickets, cases and event search. Everything offline in AEGIS keeps working without an account.'}</div>
  ${msg?`<div class="lint err" style="margin-bottom:10px">${esc(msg)}</div>`:''}
  <label class="ls-ne-label">Server URL</label>
  <input class="ui-dlg-input" id="auth-url" value="${esc(LIVE.url||location.origin)}" placeholder="https://aegis.internal:8787">
  <label class="ls-ne-label">Name</label>
  <input class="ui-dlg-input" id="auth-name" autocomplete="off" value="" placeholder="${first?'your name - colleagues will see it':'e.g. admin1 or user1'}">
  <label class="ls-ne-label">Password</label>
  <input class="ui-dlg-input" id="auth-pw" type="password" autocomplete="off" value="" placeholder="${first?'at least 10 characters':'password'}"
    onkeydown="if(event.key==='Enter')${first?'doBootstrap()':'doLogin()'}">
  <button class="btn violet" style="width:100%;justify-content:center;margin-top:12px" id="auth-go"
    onclick="${first?'doBootstrap()':'doLogin()'}">${first?'Create account &amp; sign in':'Sign in'}</button>
  ${hint?`<div class="auth-hint">Accounts on this box: <b>${hint.map(d=>esc(d.name)).join('</b>, <b>')}</b>. The shared default password is in the install docs (README / INSTALL.md) - change it in Admin.</div>`:''}
  <div class="ls-det-sub" style="margin-top:12px">${first
    ?'Already have an account on another server? <a href="#" onclick="authSwitchServer();return false">Change the server URL</a> above and try again.'
    :(gate?'':'Automating something, or locked out? <a href="#" onclick="closeLogin();openLiveSetup();return false">Use an analyst token</a>.')}</div>
 </div>`;
 v.classList.add('open');
 // Only wire backdrop-dismiss when this is not a hard gate.
 v.onclick=gate?null:(e)=>{if(e.target===v)closeLogin();};
 setTimeout(()=>{const n=document.getElementById('auth-name');if(n&&n.focus)n.focus();},60);
}
/* Closing is only allowed when the veil is not a hard gate. On a login-required
   server with no session, this is a no-op - there is nothing behind it to reach. */
function closeLogin(){
 if(_authMandatory && !ME)return;
 const v=document.getElementById('auth-veil');if(v)v.classList.remove('open');
}

/** Re-check the URL in the box: it may be a server that already has accounts. */
async function authSwitchServer(){
 const url=(document.getElementById('auth-url')||{}).value||'';
 if(!url.trim())return;
 const m=await authMode(url.trim());
 _authNeedsSetup=!!m.needsSetup;
 LIVE.url=url.trim();
 openLogin(_authNeedsSetup?'':'That server already has accounts - sign in with yours.');
}

/** Create the first account on a fresh server, then sign straight in. */
async function doBootstrap(){
 const url=(document.getElementById('auth-url')||{}).value||'';
 const name=(document.getElementById('auth-name')||{}).value||'';
 const pw=(document.getElementById('auth-pw')||{}).value||'';
 if(!url.trim()||!name.trim()||!pw){openLogin('Server URL, name and password are all required.',{name});return;}
 const btn=document.getElementById('auth-go');
 if(btn){btn.disabled=true;btn.textContent='Creating…';}
 try{
  const r=await fetch(url.replace(/\/$/,'')+'/api/auth/bootstrap',{
   method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({name:name.trim(),password:pw}),
  });
  const d=await r.json().catch(()=>({}));
  if(!r.ok){
   // 409 means someone else got there first - fall back to the sign-in form.
   if(r.status===409)_authNeedsSetup=false;
   openLogin(d.error||('Could not create the account (HTTP '+r.status+')'),{name});
   return;
  }
  LIVE.url=url.trim();LIVE.token=d.token;ME=d.user||null;_authNeedsSetup=false;
  closeLogin();liveSave();
  await liveConnect();
  authRenderWho();
  toast(`Welcome, ${(ME&&ME.name)||'analyst'} - you're the lead on this server`);
 }catch(e){
  openLogin('Could not reach that server: '+e.message,{name});
 }finally{
  const b=document.getElementById('auth-go');if(b){b.disabled=false;b.textContent='Create account & sign in';}
 }
}

async function doLogin(){
 const url=(document.getElementById('auth-url')||{}).value||'';
 const name=(document.getElementById('auth-name')||{}).value||'';
 const pw=(document.getElementById('auth-pw')||{}).value||'';
 if(!url.trim()||!name.trim()||!pw){openLogin('Server URL, name and password are all required.');return;}
 const btn=document.getElementById('auth-go');
 if(btn){btn.disabled=true;btn.textContent='Signing in…';}
 try{
  const r=await fetch(url.replace(/\/$/,'')+'/api/auth/login',{
   method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({name:name.trim(),password:pw}),
  });
  const d=await r.json().catch(()=>({}));
  if(!r.ok){openLogin(d.error||('Sign-in failed (HTTP '+r.status+')'));return;}
  // The session token takes the place of the shared analyst token: same
  // transport, but per-user and revocable server-side.
  LIVE.url=url.trim();LIVE.token=d.token;
  ME=d.user||null;
  closeLogin();liveSave();
  await liveConnect();
  authRenderWho();
  toast(`Signed in as ${(ME&&ME.name)||'user'}`);
 }catch(e){
  openLogin('Could not reach that server: '+e.message);
 }finally{
  const b=document.getElementById('auth-go');if(b){b.disabled=false;b.textContent='Sign in';}
 }
}

async function doLogout(){
 if(!await uiConfirm('Sign out of this server? The console keeps working offline.',{title:'Sign out',ok:'Sign out'}))return;
 try{await liveApi('/api/auth/logout',{method:'POST'});}catch{}
 ME=null;LIVE.token='';liveSave();liveDisconnect();
 authRenderWho();
 // A voluntary sign-out is not the hard auto-connect gate: reopen login as a
 // dismissable dialog so signing back in is one click, not a hunt through a
 // greyed-out console. Dismiss it to stay in offline/local mode.
 _authMandatory=false;
 openLogin('Signed out. Sign back in, or close this to keep working offline.');
}

/** Admin is lead-only, and hidden rather than shown-and-refused - a nav item
    you cannot use is just a reminder that you are not trusted. */
function authRenderNav(){
 // Toolbox is for deployment/admin tooling: hide it from a signed-in analyst,
 // but keep it for admins and for the offline/local single-user mode (no ME).
 const tb=document.getElementById('r-toolbox');
 if(tb)tb.style.display=(ME&&!ME.shared&&!authCan('user.manage'))?'none':'';
 const r=document.getElementById('r-admin');if(!r)return;
 const show=LIVE.connected&&authCan('user.manage');
 r.style.display=show?'':'none';
 if(!show&&view==='admin')go('dash');
 const b=document.getElementById('b-admin');
 if(b&&show)b.textContent=ADMIN.users.length||'—';
}

/** Small identity chip in the top bar, next to the live indicator. */
function authRenderWho(){
 authRenderNav();
 const el=document.getElementById('who-ind');if(!el)return;
 if(!ME||!LIVE.connected){
  // Not signed in. If a server is known, show an obvious Sign in chip rather
  // than a blank space, so the way back in is never hidden.
  if(LIVE.url){el.className='who-ind signin';el.innerHTML='<span class="who-name">↪ Sign in</span>';el.title='Sign in to AEGIS';el.onclick=()=>{_authMandatory=false;openLogin();};return;}
  el.className='who-ind';el.innerHTML='';el.onclick=null;return;
 }
 if(ME.shared){
  el.className='who-ind shared';
  el.innerHTML=`<span class="who-name">analyst token</span><span class="who-role">shared</span>`;
  el.title='Authenticated with the shared analyst token, not a named account';
  el.onclick=null;
  return;
 }
 el.className='who-ind on';
 el.innerHTML=`<span class="who-name">${esc(ME.name)}</span><span class="who-role">${esc(ME.role)}</span>`;
 el.title='Signed in - click to sign out';
 el.onclick=doLogout;
}
