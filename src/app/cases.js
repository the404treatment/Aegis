/* ================= CASES ================= */
/* The incident above the artifacts: a case groups tickets, carries the
   write-up, and holds hashed evidence. Server-backed like Tickets, so it
   degrades to a connect CTA offline rather than pretending to have data. */

const CASE_STATUSES=['open','contained','eradicated','recovered','closed'];
const CASE_SEVS=['low','medium','high','critical'];
let csOpenId=null;

const csById=id=>LIVE.cases.find(c=>c.id===id)||null;
const csTickets=id=>LIVE.tickets.filter(t=>t.caseId===id);

/* The server broadcasts over SSE as well as answering the POST, and the
   broadcast can land BEFORE the fetch promise resolves. Pushing the returned
   object would then duplicate it, so every local write goes through an
   idempotent upsert instead - correct whichever arrives first, and still
   correct if the SSE frame is dropped entirely. */
function csUpsert(c){
 if(!c||!c.id)return null;
 const i=LIVE.cases.findIndex(x=>x.id===c.id);
 if(i>=0){LIVE.cases[i]=c;return LIVE.cases[i];}
 LIVE.cases.push(c);return c;
}

function renderCases(){
 const el=document.getElementById('cs-main');if(!el)return;
 if(!LIVE.connected){
  el.innerHTML=`<div class="ls-empty">
    <div class="ls-empty-ic">▤</div>
    <h3>Cases need a server</h3>
    <p>A case groups the tickets, evidence and write-up for one incident, shared across everyone working it. The rest of AEGIS keeps working offline.</p>
    <div class="ls-empty-acts"><button class="btn violet" onclick="openLiveSetup()">Connect to a server</button></div>
  </div>`;
  return;
 }
 const cases=[...LIVE.cases].sort((a,b)=>b.updatedAt-a.updatedAt);
 el.innerHTML=`
  <div class="cs-head">
    <button class="btn violet" onclick="csNew()">＋ New case</button>
    <span class="cs-count">${cases.length} case${cases.length===1?'':'s'}</span>
  </div>
  ${cases.length?`<div class="cs-list">${cases.map(c=>{
   const tks=csTickets(c.id),ev=(c.evidence||[]).length;
   return `<div class="cs-card sev-${esc(c.severity)}" onclick="csOpen('${c.id}')">
     <div class="cs-card-top">
       <span class="cs-num">#${c.num}</span>
       <span class="cs-title">${esc(c.title)}</span>
       <span class="cs-status st-${esc(c.status)}">${esc(c.status)}</span>
     </div>
     <div class="cs-card-meta">
       <span class="cs-sev sev-${esc(c.severity)}">${esc(c.severity)}</span>
       ${c.assignee?`<span>▸ ${esc(c.assignee)}</span>`:''}
       <span>${tks.length} ticket${tks.length===1?'':'s'}</span>
       <span>${ev} evidence item${ev===1?'':'s'}</span>
       <span class="cs-by">opened by ${esc(c.createdBy)}</span>
     </div>
   </div>`;}).join('')}</div>`
  :`<div class="ls-det-sub" style="padding:20px 2px">No cases yet. Open one when an incident starts - then attach tickets and evidence to it as you work.</div>`}`;
}

async function csNew(){
 const title=await uiPrompt('What is this incident?','',{title:'New case',ok:'Open case',placeholder:'e.g. Ransomware on the finance file server'});
 if(title===null||!title.trim())return;
 try{
  const c=await liveApi('/api/cases',{method:'POST',body:JSON.stringify({title:title.trim()})});
  csUpsert(c);renderCases();updateBadges();
  csOpen(c.id);
 }catch(e){toast('Could not open the case: '+e.message);}
}

function csOpen(id){
 csOpenId=id;
 const c=csById(id);if(!c)return;
 let v=document.getElementById('cs-veil');
 if(!v){v=document.createElement('div');v.id='cs-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=csDetailHTML(c);
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)csClose();};
}
function csClose(){const v=document.getElementById('cs-veil');if(v)v.classList.remove('open');csOpenId=null;}
function csRefresh(){if(csOpenId){const c=csById(csOpenId);if(c){const v=document.getElementById('cs-veil');if(v)v.innerHTML=csDetailHTML(c);}}renderCases();}

function csDetailHTML(c){
 const tks=csTickets(c.id),ev=c.evidence||[];
 const field=(k,label,ph)=>`
  <label class="ls-ne-label">${label}</label>
  <textarea class="art-ta" style="min-height:70px" id="cs-${k}" placeholder="${ph}"
    onchange="csPatch('${c.id}',{${k}:this.value})">${esc(c[k]||'')}</textarea>`;
 return `<div class="ls-det-sheet" style="width:min(640px,100vw)">
  <div class="ls-ne-grip" onclick="csClose()"></div>
  <div class="ls-det-head">#${c.num} · ${esc(c.title)}</div>
  <div class="tk-d-row">
   <select onchange="csPatch('${c.id}',{status:this.value})">${CASE_STATUSES.map(s=>`<option ${c.status===s?'selected':''}>${s}</option>`).join('')}</select>
   <select onchange="csPatch('${c.id}',{severity:this.value})">${CASE_SEVS.map(s=>`<option ${c.severity===s?'selected':''}>${s}</option>`).join('')}</select>
   <input placeholder="assignee" value="${esc(c.assignee||'')}" onchange="csPatch('${c.id}',{assignee:this.value})">
  </div>
  <div class="ls-det-sub">Opened by ${esc(c.createdBy)} · ${new Date(c.createdAt).toLocaleString()}</div>

  <div class="ls-mm-sec">Write-up</div>
  ${field('execSummary','Executive summary','What happened, in plain language a manager can act on.')}
  ${field('scope','Scope','Which hosts, accounts and data were involved - and what you ruled out.')}
  ${field('remediation','Remediation','What was done to contain, eradicate and recover.')}

  <div class="ls-mm-sec">Tickets · ${tks.length}</div>
  ${tks.length?tks.map(t=>`<div class="ls-det-row" onclick="csClose();go('tickets');tkOpen('${t.id}')" style="cursor:pointer">
    <span class="ls-det-tid">#${t.num}</span>
    <span style="flex:1;min-width:0">${esc(t.title)}</span>
    <span class="ls-ne-obs-sev inc-${t.severity==='critical'||t.severity==='high'?'malicious':t.severity==='medium'?'suspicious':'info'}">${esc(t.status)}</span>
  </div>`).join(''):'<div class="ls-det-sub">No tickets attached yet. Open a ticket and pick this case from its Case dropdown.</div>'}

  <div class="ls-mm-sec">Evidence · ${ev.length}</div>
  <div class="ls-det-sub">Every file is SHA-256 hashed on upload and the hash is written into the tamper-evident audit chain, so you can prove later that what you hold is what you collected.</div>
  ${ev.length?ev.map(e=>`<div class="cs-ev">
    <div class="cs-ev-top">
      <a href="#" onclick="csViewEvidence('${esc(e.file)}');return false">${esc(e.name||e.file)}</a>
      <span class="cs-ev-size">${(e.bytes/1024).toFixed(0)} KB</span>
    </div>
    ${e.caption?`<div class="cs-ev-cap">${esc(e.caption)}</div>`:''}
    <div class="cs-ev-hash" title="SHA-256">${esc(e.sha256)}</div>
    <div class="cs-ev-by">added by ${esc(e.addedBy)} · ${new Date(e.addedAt).toLocaleString()}</div>
  </div>`).join(''):'<div class="ls-det-sub">Nothing collected yet.</div>'}
  <input type="file" id="cs-ev-file" style="margin-top:8px" accept=".png,.jpg,.jpeg,.gif,.webp,.pdf,.txt" onchange="csUpload('${c.id}',this)">
  <input class="dash-input" id="cs-ev-cap" style="width:100%;margin-top:6px" placeholder="Caption (optional) - set this before choosing the file">

  ${csReportHTML(c,tks)}
 </div>`;
}

/* ---- formal report: curation, preview, freeze ---- */
function csReportHTML(c,tks){
 const frozen=c.formalFrozen;
 const canFinalize=authCan('report.finalize');
 const eligible=tks.filter(t=>t.includeInFormal&&String(t.formalSummary||'').trim());
 return `
  <div class="ls-mm-sec">Formal report</div>
  ${frozen?`<div class="cs-frozen">
     <div class="cs-frozen-h">✓ Frozen · version ${frozen.version}</div>
     <div class="cs-frozen-b">Signed by ${esc(frozen.frozenBy)} · ${new Date(frozen.frozenAt).toLocaleString()}<br>
       <span class="cs-frozen-hash">${esc(frozen.sha256||'')}</span></div>
     <div class="cs-frozen-n">This snapshot no longer tracks the case. Re-freezing publishes a new version.</div>
   </div>`
  :`<div class="ls-det-sub">Not frozen. The formal report is a live preview until a lead signs it.</div>`}

  <div class="ls-det-sub" style="margin-top:8px">A ticket reaches the client-facing report only when it is flagged <b>and</b> has a plain-language summary. Analyst names and raw technical detail are omitted by policy.</div>
  ${tks.length?tks.map(t=>`<div class="cs-fm ${t.includeInFormal?'on':''}">
    <label class="cs-fm-top">
      <input type="checkbox" ${t.includeInFormal?'checked':''} ${canFinalize?'':'disabled'}
        onchange="csSetFormal('${t.id}',{includeInFormal:this.checked})">
      <span>#${t.num} ${esc(t.title)}</span>
    </label>
    ${t.includeInFormal?`<textarea class="art-ta" style="min-height:56px;margin-top:6px" ${canFinalize?'':'disabled'}
      placeholder="Plain-language summary for the client-facing report - this replaces the technical detail."
      onchange="csSetFormal('${t.id}',{formalSummary:this.value})">${esc(t.formalSummary||'')}</textarea>
      ${String(t.formalSummary||'').trim()?'':'<div class="cs-fm-warn">Needs a summary before it can appear.</div>'}`:''}
  </div>`).join(''):'<div class="ls-det-sub">No tickets attached, so there is nothing to report on yet.</div>'}

  <div style="display:flex;gap:8px;margin-top:10px">
    <button class="btn" style="flex:1;justify-content:center" onclick="csPreview('${c.id}','technical')">Technical preview</button>
    <button class="btn" style="flex:1;justify-content:center" onclick="csPreview('${c.id}','formal')">Formal preview</button>
  </div>
  ${canFinalize?`<button class="btn violet" style="width:100%;justify-content:center;margin-top:8px"
     onclick="csFinalize('${c.id}')" ${eligible.length?'':'disabled'}>
     ${frozen?`Re-freeze as version ${frozen.version+1}`:'Freeze &amp; sign the formal report'}
     ${eligible.length?` · ${eligible.length} item${eligible.length===1?'':'s'}`:' · nothing eligible yet'}
   </button>`
  :`<div class="ls-det-sub" style="margin-top:8px">Freezing the formal report needs the lead role.</div>`}`;
}

async function csSetFormal(ticketId,patch){
 try{
  const t=await liveApi('/api/tickets/'+ticketId,{method:'PATCH',body:JSON.stringify(patch)});
  const i=LIVE.tickets.findIndex(x=>x.id===t.id);
  if(i>=0)LIVE.tickets[i]=t;else LIVE.tickets.push(t);
  csRefresh();
 }catch(e){toast('Could not save: '+e.message);}
}

async function csFinalize(id){
 const c=csById(id);if(!c)return;
 const again=!!c.formalFrozen;
 const msg=again
  ? `Re-freeze this report as version ${c.formalFrozen.version+1}? The current signed version will be replaced.`
  : 'Freeze and sign this formal report? It becomes an immutable snapshot that stops tracking the case.';
 if(!await uiConfirm(msg,{title:'Freeze formal report',ok:again?'Re-freeze':'Freeze & sign'}))return;
 try{
  const snap=await liveApi('/api/cases/'+id+'/finalize',{method:'POST'});
  c.formalFrozen=snap;csRefresh();
  toast(`Formal report frozen · version ${snap.version}`);
 }catch(e){toast('Could not freeze: '+e.message);}
}

async function csPreview(id,kind){
 try{
  const r=await liveApi('/api/cases/'+id+'/report?kind='+kind);
  let v=document.getElementById('cs-rep-veil');
  if(!v){v=document.createElement('div');v.id='cs-rep-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
  v.innerHTML=`<div class="ls-det-sheet" style="width:min(720px,100vw)">
   <div class="ls-ne-grip" onclick="csClosePreview()"></div>
   <div id="cs-rep-body">${csReportDocHTML(r)}</div>
   <div style="display:flex;gap:8px;margin-top:12px">
     <button class="btn" style="flex:1;justify-content:center" onclick="csClosePreview()">Close</button>
     <button class="btn violet" style="flex:1;justify-content:center" onclick="csDownloadReport()">Download</button>
   </div>
  </div>`;
  v.classList.add('open');v.onclick=(e)=>{if(e.target===v)csClosePreview();};
 }catch(e){toast('Could not build the report: '+e.message);}
}
function csClosePreview(){const v=document.getElementById('cs-rep-veil');if(v)v.classList.remove('open');}

function csReportDocHTML(r){
 const sec=(t,b)=>b&&b.trim()?`<div class="rp-sec"><h3>${t}</h3><p>${esc(b).replace(/\n/g,'<br>')}</p></div>`:'';
 return `<div class="rp-doc">
  <div class="rp-kind">${r.kind==='formal'?'Formal report':'Technical report'}${r.frozen?` · frozen v${r.version}`:' · live'}</div>
  <h2>#${r.caseNum} ${esc(r.title)}</h2>
  ${r.frozen?`<div class="rp-signed">Signed by ${esc(r.frozenBy)} · ${new Date(r.frozenAt).toLocaleString()}</div>`:''}
  ${r.kind==='formal'?'<div class="rp-notice">Analyst names and raw technical detail are omitted by policy.</div>':''}
  ${sec('Executive summary',r.execSummary)}
  ${sec('Scope',r.scope)}
  ${sec('Remediation',r.remediation)}
  <div class="rp-sec"><h3>Findings · ${r.blocks.length}</h3>
   ${r.blocks.length?r.blocks.map(b=>`<div class="rp-block">
     <div class="rp-block-h"><b>#${b.num} ${esc(b.title)}</b> <span class="rp-sev">${esc(b.severity||'')}</span></div>
     ${b.host||b.technique?`<div class="rp-meta">${b.host?esc(b.host):''}${b.host&&b.technique?' · ':''}${b.technique?esc(b.technique):''}</div>`:''}
     ${b.body?`<div class="rp-body">${esc(b.body).replace(/\n/g,'<br>')}</div>`:''}
     ${b.raisedBy?`<div class="rp-by">raised by ${esc(b.raisedBy)}</div>`:''}
   </div>`).join(''):'<p class="rp-empty">Nothing qualifies yet.</p>'}
  </div>
 </div>`;
}

function csDownloadReport(){
 const body=document.getElementById('cs-rep-body');if(!body)return;
 const html=`<!doctype html><meta charset="utf-8"><title>AEGIS report</title>
<style>body{font:14px/1.6 system-ui,sans-serif;max-width:800px;margin:40px auto;padding:0 20px;color:#111}
h2{margin:0 0 4px}h3{margin:22px 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#555}
.rp-kind{font:11px monospace;color:#666;text-transform:uppercase;letter-spacing:.12em}
.rp-signed{color:#0a7;font-size:12px;margin:6px 0}
.rp-notice{background:#f4f4f6;border-left:3px solid #888;padding:8px 12px;font-size:12px;margin:12px 0}
.rp-block{border:1px solid #ddd;border-radius:6px;padding:10px 12px;margin-bottom:8px}
.rp-sev{font:10px monospace;text-transform:uppercase;color:#a00}
.rp-meta{font:11px monospace;color:#666;margin-top:2px}
.rp-body{margin-top:6px}.rp-by{font-size:11px;color:#777;margin-top:6px}
</style>${body.innerHTML}`;
 const blob=new Blob([html],{type:'text/html'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);
 a.download='aegis-report.html';a.click();
 URL.revokeObjectURL(a.href);
}

async function csPatch(id,patch){
 try{
  csUpsert(await liveApi('/api/cases/'+id,{method:'PATCH',body:JSON.stringify(patch)}));
  renderCases();
 }catch(e){toast('Could not save: '+e.message);}
}

function csUpload(id,input){
 const f=input.files&&input.files[0];if(!f)return;
 const caption=(document.getElementById('cs-ev-cap')||{}).value||'';
 const r=new FileReader();
 r.onload=async()=>{
  try{
   const rec=await liveApi('/api/cases/'+id+'/evidence',{method:'POST',
    body:JSON.stringify({data:r.result,name:f.name,caption})});
   const c=csById(id);
   // Same race as csUpsert: the case broadcast carrying this record may have
   // already arrived, so only add it if it isn't there.
   if(c){
    c.evidence=c.evidence||[];
    if(!c.evidence.some(x=>x.id===rec.id))c.evidence.push(rec);
   }
   csRefresh();
   toast('Evidence stored · SHA-256 '+rec.sha256.slice(0,12)+'…');
  }catch(e){toast('Upload failed: '+e.message);}
 };
 r.onerror=()=>toast('Could not read that file');
 r.readAsDataURL(f);
 input.value='';
}

/* Evidence is fetched with the session credential and shown from a blob URL -
   a plain link would hit the endpoint unauthenticated and 401. */
async function csViewEvidence(file){
 try{
  const r=await fetch(LIVE.url.replace(/\/$/,'')+'/api/evidence/'+encodeURIComponent(file),{headers:liveHeaders()});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const blob=await r.blob();
  const url=URL.createObjectURL(blob);
  window.open(url,'_blank','noopener');
  setTimeout(()=>URL.revokeObjectURL(url),60000);
 }catch(e){toast('Could not open that evidence: '+e.message);}
}

/* Attach/detach a ticket to a case, offered from the ticket detail sheet. */
function csTicketSelectHTML(t){
 if(!LIVE.cases.length)return'';
 return `<label class="ls-ne-label">Case</label>
  <select style="width:100%" onchange="tkPatch('${t.id}',{caseId:this.value})">
    <option value="">— not attached —</option>
    ${LIVE.cases.map(c=>`<option value="${c.id}" ${t.caseId===c.id?'selected':''}>#${c.num} ${esc(c.title)}</option>`).join('')}
  </select>`;
}
