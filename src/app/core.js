/* ================= STATE ================= */
let plat='all',view='dash',cat='all',risks=new Set(),xp=new Set(),tabState={},studio=new Set(),notes={},chatLog=[],busy=false,stTab='chain',maturity={};

const T=id=>MITRE[id]||{name:id,tactic:"—",summary:"",detect:[],pivots:[],mits:[],start:{}};
const ALL=()=>[...WIN.map(e=>({...e,plat:'windows'})),...AWS.map(e=>({...e,plat:'aws'}))];
const eventsForTech=id=>ALL().filter(e=>e.mitre.includes(id));
/* Quotes are escaped as well as angle brackets, because esc() output lands in
   HTML *attributes* in a couple of hundred places, not only in text nodes. In
   a text node the extra entities are decoded by the browser and read
   identically; in an attribute they are the difference between a value and an
   injection. */
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
 .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

/* For untrusted text that lands inside a JS string inside an inline handler -
   onclick="fn('${jsq(x)}')".
 *
 * HTML-escaping alone does NOT make that safe: the browser decodes entities in
 * the attribute value BEFORE the JavaScript is parsed, so a &#39; becomes a
 * real quote and closes the string. The backslash escaping has to happen first,
 * and survive that decode. Server-side input constraints are the primary
 * defence (see `ident` in aegis-server.mjs); this is the second layer. */
const jsq=s=>String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"')
 .replace(/\r/g,'\\r').replace(/\n/g,'\\n').replace(/</g,'\\x3c').replace(/&/g,'\\x26');
const xmlEsc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const uniqTechs=()=>[...new Set(TACTICS.flatMap(t=>t[2]))];

/* primary kill-chain stage for a technique = first tactic it appears in */
function primaryStage(id){
 for(let i=0;i<TACTICS.length;i++)if(TACTICS[i][2].includes(id))return i;
 return 99;
}
function stageIndex(id){return primaryStage(id);}
function stagedOrdered(){return [...studio].sort((a,b)=>primaryStage(a)-primaryStage(b)||a.localeCompare(b));}

function hl(q){
 return esc(q)
  .replace(/\b(index|sourcetype|source|EventCode|eventName|search|eval|stats|where|table|join|fields|sort|by|as|rename|dedup|rex|outputlookup|inputlookup|lookup)\b/g,'<span class="kw">$1</span>')
  .replace(/\b(count|values|dc|sum|avg|max|min|match|cidrmatch|spath|replace|if|isnull|coalesce|tonumber)\b/g,'<span class="fn">$1</span>')
  .replace(/"([^"]*?)"/g,'<span class="str">"$1"</span>')
  .replace(/\b(\d+)\b/g,'<span class="num">$1</span>')
  .replace(/(\||=|!=|&gt;|&lt;)/g,'<span class="op">$1</span>');
}
function toast(msg){
 const t=document.getElementById('toast');
 t.textContent=msg;t.classList.add('show');
 clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('show'),2400);
}
function store(k,v){try{localStorage.setItem(k,v)}catch{}}
function read(k,d){try{return localStorage.getItem(k)??d}catch{return d}}

/* ================= SETTINGS ================= */
/* Global, per-browser preferences - mostly the timing knobs an analyst wants
   to set once (how far back "now" looks, the clock format, the cadence the
   report recommends). Kept in one place so there is a single settings menu to
   change any of them, rather than a constant buried in each view. */
const SETTINGS_DEFAULTS={activityWindowMin:60,clock24:false,reportCadenceMin:15};
let SETTINGS={...SETTINGS_DEFAULTS};
function loadSettings(){try{SETTINGS={...SETTINGS_DEFAULTS,...JSON.parse(read('aegis-settings','{}'))};}catch{SETTINGS={...SETTINGS_DEFAULTS};}}
function saveSettings(){store('aegis-settings',JSON.stringify(SETTINGS));}
function getSetting(k){return SETTINGS[k];}
function setSetting(k,v){SETTINGS[k]=v;saveSettings();}
/* The activity window as a human label, e.g. "the last hour" / "the last 4 hours". */
function activityWindowLabel(){
 const m=getSetting('activityWindowMin');
 if(m<60)return `the last ${m} minutes`;
 const h=m/60;return `the last ${h===1?'hour':h+' hours'}`;
}
/* Locale time/date respecting the 24-hour-clock setting. Use these instead of
   raw toLocaleString so the clock format is consistent across the app. */
function fmtTime(t){try{return new Date(t).toLocaleTimeString([],{hour12:!getSetting('clock24')});}catch{return '';}}
function fmtDateTime(t){try{return new Date(t).toLocaleString([],{hour12:!getSetting('clock24')});}catch{return '';}}

/* ---- settings panel ---- */
function openSettings(){
 let v=document.getElementById('settings-veil');
 if(!v){v=document.createElement('div');v.id='settings-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const winOpts=[15,30,60,240,720,1440];
 const cadOpts=[5,15,30,60];
 v.innerHTML=`<div class="ls-det-sheet" style="width:min(440px,100vw)">
   <div class="ls-ne-grip" onclick="closeSettings()"></div>
   <div class="ls-det-head">Settings</div>
   <div class="ls-det-sub">Per-browser preferences. Timing knobs live here so there's one place to set them.</div>

   <div class="ls-mm-sec">Timing</div>
   <label class="ls-ne-label">"What's happening" window - how far back the dashboard and threat level look</label>
   <select class="ui-dlg-input" onchange="setSetting('activityWindowMin',parseInt(this.value));settingsApply()">
     ${winOpts.map(m=>`<option value="${m}" ${getSetting('activityWindowMin')===m?'selected':''}>${m<60?m+' minutes':(m/60)+' hour'+(m===60?'':'s')}</option>`).join('')}
   </select>
   <label class="ls-ne-label">Report alert cadence - the schedule the generated report recommends</label>
   <select class="ui-dlg-input" onchange="setSetting('reportCadenceMin',parseInt(this.value))">
     ${cadOpts.map(m=>`<option value="${m}" ${getSetting('reportCadenceMin')===m?'selected':''}>every ${m} minutes</option>`).join('')}
   </select>

   <div class="ls-mm-sec">Display</div>
   <label class="ls-ne-label">Clock</label>
   <div class="ls-toolgrp">
     <button class="${!getSetting('clock24')?'on':''}" onclick="setSetting('clock24',false);settingsApply();openSettings()">12-hour</button>
     <button class="${getSetting('clock24')?'on':''}" onclick="setSetting('clock24',true);settingsApply();openSettings()">24-hour</button>
   </div>

   <div class="ls-det-sub" style="margin-top:14px">Timing on the server (how long before an agent is "stale", event-log rotation) is set in <code>server/config.json</code> - see the admin runbook.</div>
   <button class="btn" style="width:100%;justify-content:center;margin-top:10px" onclick="settingsReset()">Reset to defaults</button>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeSettings();};
}
function closeSettings(){const v=document.getElementById('settings-veil');if(v)v.classList.remove('open');}
/* Re-render whatever is affected by a settings change, right now. */
function settingsApply(){
 if(typeof renderDash==='function'&&view==='dash')renderDash();
 if(typeof updateBadges==='function')updateBadges();
 if(typeof renderTickets==='function'&&view==='tickets')renderTickets();
}
function settingsReset(){SETTINGS={...SETTINGS_DEFAULTS};saveSettings();settingsApply();openSettings();toast('Settings reset to defaults');}

/* ================= PERSISTENCE ================= */
/* One place that saves everything that counts as the analyst's work. */
function persistAll(){
 try{
  store('aegis-studio',JSON.stringify([...studio]));
  store('aegis-notes',JSON.stringify(notes));
  store('aegis-nodes',JSON.stringify(lsNodes));
  store('aegis-edges',JSON.stringify(lsEdges));
  store('aegis-nodeseq',String(lsNodeSeq));
  store('aegis-maturity',JSON.stringify(maturity));
  store('aegis-answers',JSON.stringify({sysmon:lsAnswers.sysmon,pwsh:lsAnswers.pwsh,noise:lsAnswers.noise,roles:[...lsAnswers.roles]}));
  flashSaved();
 }catch{}
}
let _savedTimer=null;
function flashSaved(){
 const el=document.getElementById('saved-ind');if(!el)return;
 el.classList.add('show');clearTimeout(_savedTimer);
 _savedTimer=setTimeout(()=>el.classList.remove('show'),1400);
}
/* ---- map undo / redo ----
   History holds successive full snapshots. Every mutation pushes the NEW state
   as the current tip; undo/redo step the index across saved states. */
let lsHist=[], lsHistIdx=-1, _histLock=false;
function lsSnapshot(){
 if(_histLock)return;
 const snap=JSON.stringify({nodes:lsNodes,edges:lsEdges,seq:lsNodeSeq});
 lsHist=lsHist.slice(0,lsHistIdx+1);
 if(lsHist[lsHistIdx]===snap)return; // no change since tip
 lsHist.push(snap);if(lsHist.length>40)lsHist.shift();
 lsHistIdx=lsHist.length-1;
}
function lsUndo(){if(lsHistIdx<=0)return;lsHistIdx--;_applyHist();}
function lsRedo(){if(lsHistIdx>=lsHist.length-1)return;lsHistIdx++;_applyHist();}
function _applyHist(){
 const snap=lsHist[lsHistIdx];if(!snap)return;
 const d=JSON.parse(snap);
 _histLock=true;
 lsNodes=(d.nodes||[]).map(n=>({...n,obs:n.obs||[]}));lsEdges=d.edges||[];lsNodeSeq=d.seq||1;
 persistAll();renderLogSrc();
 _histLock=false;
}
function lsCanUndo(){return lsHistIdx>0;}
function lsCanRedo(){return lsHistIdx<lsHist.length-1;}
function restoreAll(){
 lsLoadZones();liveLoad();
 try{notes=JSON.parse(read('aegis-notes','{}'))}catch{notes={}}
 try{studio=new Set(JSON.parse(read('aegis-studio','[]')))}catch{studio=new Set()}
 try{lsNodes=JSON.parse(read('aegis-nodes','[]'))||[]}catch{lsNodes=[]}
 try{lsEdges=JSON.parse(read('aegis-edges','[]'))||[]}catch{lsEdges=[]}
 try{lsNodeSeq=parseInt(read('aegis-nodeseq','1'))||1}catch{lsNodeSeq=1}
 try{maturity=JSON.parse(read('aegis-maturity','{}'))||{}}catch{maturity={}}
 try{const a=JSON.parse(read('aegis-answers','null'));if(a){lsAnswers.sysmon=a.sysmon;lsAnswers.pwsh=a.pwsh;lsAnswers.noise=a.noise;if(a.roles)lsAnswers.roles=new Set(a.roles);}}catch{}
 // repair any nodes missing the obs array (older saves)
 lsNodes.forEach(n=>{if(!n.obs)n.obs=[];});
 if(lsNodes.length)lsStep='topology';
}
/* Full-case portability - the whole investigation in one file */
function exportCase(){
 const data={
  _aegis:'case',version:3,exported:new Date().toISOString(),
  name:document.getElementById('dash-name')?.value||'AEGIS case',
  studio:[...studio],notes,nodes:lsNodes,edges:lsEdges,nodeSeq:lsNodeSeq,maturity,
  answers:{sysmon:lsAnswers.sysmon,pwsh:lsAnswers.pwsh,noise:lsAnswers.noise,roles:[...lsAnswers.roles]}
 };
 const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);
 a.download=(data.name.replace(/[^a-z0-9]+/gi,'_')||'aegis')+'_case.json';a.click();
 URL.revokeObjectURL(a.href);toast('Case exported - the whole investigation in one file');
}
function importCaseFile(input){
 const f=input.files&&input.files[0];if(!f)return;
 const r=new FileReader();
 r.onload=()=>{
  try{
   const d=JSON.parse(r.result);
   if(d._aegis!=='case')throw new Error('not an AEGIS case file');
   studio=new Set(d.studio||[]);
   notes=d.notes||{};
   lsNodes=(d.nodes||[]).map(n=>({...n,obs:n.obs||[]}));
   lsEdges=d.edges||[];
   lsNodeSeq=d.nodeSeq||(lsNodes.length+1);
   maturity=d.maturity||{};
   if(d.answers){lsAnswers.sysmon=d.answers.sysmon;lsAnswers.pwsh=d.answers.pwsh;lsAnswers.noise=d.answers.noise;if(d.answers.roles)lsAnswers.roles=new Set(d.answers.roles);}
   if(d.name){const dn=document.getElementById('dash-name');if(dn)dn.value=d.name;}
   if(lsNodes.length)lsStep='topology';
   persistAll();
   renderMatrix();renderStudio();renderLogSrc();updateBadges();
   go('studio');
   toast(`Case "${d.name||'restored'}" loaded - ${studio.size} techniques, ${lsNodes.length} nodes`);
  }catch(e){toast('Could not read that case file: '+e.message);}
 };
 r.readAsText(f);input.value='';
}
async function newCase(){
 if(!await uiConfirm('Start a new case? This clears the current staged techniques, hunt map, and observations. Export first if you want to keep them.'))return;
 studio.clear();lsNodes=[];lsEdges=[];lsNodeSeq=1;maturity={};lsStep='topology';lsSelEvent=null;lsResult=null;lsScrubT=null;lsPendingChain=null;
 persistAll();renderMatrix();renderStudio();renderLogSrc();updateBadges();toast('New case started');
}

/* ================= INIT ================= */
document.addEventListener('DOMContentLoaded',()=>{
 loadSettings();
 restoreAll();
 // touch devices: disable hover tooltips (they stick after a tap on mobile)
 if(('ontouchstart' in window)||navigator.maxTouchPoints>0)document.body.classList.add('touch');
 window.addEventListener('touchstart',()=>document.body.classList.add('touch'),{once:true,passive:true});
 if(read('aegis-tips','on')==='off'){document.body.classList.add('no-tips');document.getElementById('tips-toggle').classList.add('off');}
 ['matrix','events','logsrc'].forEach(c=>{if(read('aegis-coach-'+c,'')==='hide')document.getElementById('coach-'+c)?.classList.add('hidden');});
 renderMatrix();renderStudio();renderLogSrc();updateBadges();
 document.addEventListener('keydown',e=>{
  const typing=/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName||'');
  if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();openPal();return;}
  if(e.key==='Escape'){closePal();closeDrawer();closeKeys();endTour();if(document.getElementById('report-veil').classList.contains('open'))closeReport();return;}
  if(typing)return;
  if(e.key==='?'){e.preventDefault();openKeys();return;}
  const vmap={'1':'dash','2':'matrix','3':'logsrc','4':'studio','5':'siem','6':'cases','7':'tickets','8':'ai'};
  if(vmap[e.key])go(vmap[e.key]);
 });
 window.addEventListener('resize',()=>{if(tourStep>=0)placeTour();});
 document.addEventListener('click',e=>{
  if(!e.target.closest('.case-menu')){const p=document.getElementById('case-pop');if(p)p.classList.remove('open');}
  if(!e.target.closest('.exp-menu')){const p=document.getElementById('exp-pop');if(p)p.classList.remove('open');}
 });
 // Open on the view named in the URL, so a link to #logsrc lands there.
 const hv=location.hash.slice(1);
 if(hv&&TITLES[hv])go(hv,true);
 window.addEventListener('hashchange',()=>{
  const h=location.hash.slice(1);
  if(h&&TITLES[h]&&h!==view)go(h,true);
 });
 if(read('aegis-toured','')!=='yes')setTimeout(startTour,600);
 dashLoad();renderDash();dashTick();
 // Reconnect to the server we were last using, if any.
 liveAutoConnect();
});
function updateBadges(){
 document.getElementById('b-matrix').textContent=uniqTechs().length;
 // The dashboard badge counts what needs attention now, not a library size.
 const bd=document.getElementById('b-dash');
 if(bd){const rec=(LIVE.events||[]).filter(e=>e.severity==='malicious'&&(e.ts||0)>Date.now()-getSetting('activityWindowMin')*60000).length;
  bd.textContent=rec||'—';bd.className='rbadge'+(rec?' hot':'');}
 const be=document.getElementById('b-events');if(be)be.textContent=WIN.length+AWS.length;
 // The map badge counts hosts you've placed, not the 48 log-source types in
 // the reference data - that number meant nothing next to "Network Map".
 const bl=document.getElementById('b-logsrc');if(bl)bl.textContent=(typeof lsNodes!=='undefined'&&lsNodes.length)?lsNodes.length:'—';
 document.getElementById('b-studio').textContent=studio.size;
 const bt=document.getElementById('b-tickets');if(bt)bt.textContent=LIVE.tickets.filter(x=>x.status!=='closed').length;
 const bs=document.getElementById('b-siem');if(bs)bs.textContent=LIVE.events.length;
 const bc=document.getElementById('b-cases');if(bc)bc.textContent=LIVE.cases.filter(c=>c.status!=='closed').length;
 const bn=document.getElementById('b-notes');if(bn)bn.textContent=Object.values(notes).filter(v=>v.trim()).length;
 updateStats();
}
function updateStats(){
 const techs=uniqTechs();const total=techs.length;
 let evScope=ALL();if(plat!=='all')evScope=evScope.filter(e=>e.plat===plat);
 const covered=techs.filter(id=>evScope.some(e=>e.mitre.includes(id))).length;
 const st=document.getElementById('ms-tech');if(!st)return;
 // breadth vs depth: the full matrix is present, but only some carry a written strategy
 const withStrategy=techs.filter(id=>!(MITRE[id]||{}).ref).length;
 st.innerHTML=`${total}<em> · all detailed</em>`;
 document.getElementById('ms-cov').innerHTML=`${covered}<em>/${total}</em>`;
 document.getElementById('ms-staged').textContent=studio.size;
}

/* ================= COACH / TIPS ================= */
function dismissCoach(id){document.getElementById('coach-'+id).classList.add('hidden');store('aegis-coach-'+id,'hide');}
function togTips(){
 const off=document.body.classList.toggle('no-tips');
 document.getElementById('tips-toggle').classList.toggle('off',off);
 store('aegis-tips',off?'off':'on');
 toast(off?'Hover guides off':'Hover guides on');
}

/* ================= NAV ================= */
const TITLES={dash:['Dashboard','Live - what is happening right now'],
 admin:['Admin','Accounts · platform health · deployment'],
 matrix:['ATT&CK Coverage Matrix','15 tactics · full ATT&CK surface'],logsrc:['Network Map','Build · hunt · trace attacks live'],studio:['Detection Studio','Kill-chain mapping · dashboards · report'],siem:['Event Search','Field-aware search across live agent telemetry'],cases:['Cases','Incident files · tickets, evidence, write-up'],ai:['AI Analyst','Claude-powered detection research'],tickets:['Tickets','Shared incident queue']};
function go(v,fromHash){
 if(!TITLES[v])return;
 // Admin is lead-only. The server refuses regardless - this just stops an
 // analyst landing on a page that exists only to tell them no, including via
 // a #admin link someone pasted into chat.
 if(v==='admin'&&!(typeof authCan==='function'&&authCan('user.manage'))){
  if(view==='admin')return;toast('Admin is for leads only');return;
 }
 view=v;
 // Keep the address bar in step so a view can be bookmarked or shared, and
 // the browser's back button does what everyone expects it to.
 if(!fromHash){try{if(location.hash.slice(1)!==v)history.replaceState(null,'','#'+v);}catch{}}
 document.querySelectorAll('.view').forEach(x=>x.classList.remove('on'));
 document.querySelectorAll('.rail-nav .ritem').forEach(x=>x.classList.remove('on'));
 document.getElementById('v-'+v).classList.add('on');
 document.getElementById('r-'+v)?.classList.add('on');
 document.getElementById('bar-title').innerHTML=TITLES[v][0];
 document.getElementById('bar-sub').textContent=TITLES[v][1];
 document.getElementById('gq').value='';
 if(v==='dash')renderDash();
 if(v==='matrix')renderMatrix();   // refresh live-hit overlay on entry
 if(v==='admin')renderAdmin();
 if(v==='studio')renderStudio();
 if(v==='logsrc')renderLogSrc();
 if(v==='tickets')renderTickets();
 if(v==='siem')renderSiem();
 if(v==='cases')renderCases();
 const showPlat=(v==='matrix');
 const ps=document.getElementById('plat-seg');if(ps)ps.style.display=showPlat?'':'none';
 const showSearch=(v==='matrix');
 document.getElementById('gsearch-wrap').style.display=showSearch?'':'none';
 hidePeek();
}
function setPlat(p){
 plat=p;
 document.querySelectorAll('#plat-seg button').forEach((b,i)=>b.classList.toggle('on',['all','windows','aws'][i]===p));
 renderMatrix();updateStats();
}
function onSearch(){if(view==='matrix')renderMatrix();}
