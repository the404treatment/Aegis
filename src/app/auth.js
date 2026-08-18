/* ================= ACCOUNTS ================= */
/* Optional named accounts. The server decides: GET /api/auth/mode says
   whether it wants a login, and until it does the console behaves exactly as
   it always has with a shared analyst token.

   Note this is a two-field form, so it deliberately does NOT use uiPrompt()
   (single input only) and must never use a native prompt() — see Hard Rule
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

function openLogin(msg){
 let v=document.getElementById('auth-veil');
 if(!v){v=document.createElement('div');v.id='auth-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet" style="width:min(420px,100vw)">
  <div class="ls-ne-grip" onclick="closeLogin()"></div>
  <div class="ls-det-head">Sign in to AEGIS</div>
  <div class="ls-det-sub">This server requires an account. Everything offline in AEGIS keeps working without one — sign in for live agent data, tickets and event search.</div>
  ${msg?`<div class="lint err" style="margin-bottom:10px">${esc(msg)}</div>`:''}
  <label class="ls-ne-label">Server URL</label>
  <input class="ui-dlg-input" id="auth-url" value="${esc(LIVE.url)}" placeholder="https://aegis.internal:8787">
  <label class="ls-ne-label">Name</label>
  <input class="ui-dlg-input" id="auth-name" autocomplete="username" placeholder="your account name">
  <label class="ls-ne-label">Password</label>
  <input class="ui-dlg-input" id="auth-pw" type="password" autocomplete="current-password" placeholder="password"
    onkeydown="if(event.key==='Enter')doLogin()">
  <button class="btn violet" style="width:100%;justify-content:center;margin-top:12px" id="auth-go" onclick="doLogin()">Sign in</button>
  <div class="ls-det-sub" style="margin-top:12px">Have an analyst token instead? <a href="#" onclick="closeLogin();openLiveSetup();return false">Use a token</a>.</div>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeLogin();};
 setTimeout(()=>{const n=document.getElementById('auth-name');if(n&&n.focus)n.focus();},60);
}
function closeLogin(){const v=document.getElementById('auth-veil');if(v)v.classList.remove('open');}

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
 authRenderWho();toast('Signed out');
}

/** Small identity chip in the top bar, next to the live indicator. */
function authRenderWho(){
 const el=document.getElementById('who-ind');if(!el)return;
 if(!ME||!LIVE.connected){el.className='who-ind';el.innerHTML='';el.onclick=null;return;}
 if(ME.shared){
  el.className='who-ind shared';
  el.innerHTML=`<span class="who-name">analyst token</span><span class="who-role">shared</span>`;
  el.title='Authenticated with the shared analyst token, not a named account';
  el.onclick=null;
  return;
 }
 el.className='who-ind on';
 el.innerHTML=`<span class="who-name">${esc(ME.name)}</span><span class="who-role">${esc(ME.role)}</span>`;
 el.title='Signed in — click to sign out';
 el.onclick=doLogout;
}
