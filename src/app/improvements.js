/* ================= APP IMPROVEMENTS ================= */

/* --- A. Bulk host import: paste a real inventory instead of clicking 12 times --- */
function openLsImport(){
 let v=document.getElementById('ls-imp-veil');
 if(!v){v=document.createElement('div');v.id='ls-imp-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="lsCloseImport()"></div>
  <div class="ls-det-head">Import hosts</div>
  <div class="ls-det-sub">Paste a host list \u2014 one per line. Optionally add a type and zone after commas:<br>
   <code>DC01, dc, core</code> \u00b7 <code>WKS-042, wks</code> \u00b7 <code>web01, dmz, dmz</code><br>
   With no type, AEGIS guesses from the name (dc\u2192domain controller, sql/app/srv\u2192server, wks/lt/pc\u2192workstation, fw/rtr/sw\u2192network).</div>
  <textarea id="ls-imp-ta" class="art-ta" style="min-height:150px" placeholder="DC01, dc, core&#10;FS01, srv&#10;WKS-101&#10;WKS-102&#10;FW-EDGE, fw, edge"></textarea>
  <button class="btn violet" style="width:100%;justify-content:center;margin-top:10px" onclick="lsRunImport()">Add hosts to map</button>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseImport();};
}
function lsCloseImport(){const v=document.getElementById('ls-imp-veil');if(v)v.classList.remove('open');}
function lsGuessType(name){
 const s=(name||'').toLowerCase();
 if(/^dc|domain|\bad\b/.test(s))return'dc';
 if(/fw|firewall|asa|palo/.test(s))return'fw';
 if(/rtr|router|gw|gateway/.test(s))return'router';
 if(/sw\d|switch/.test(s))return'switch';
 if(/vpn/.test(s))return'vpn';
 if(/nas|stor|share|fs\d/.test(s))return'nas';
 if(/web|dmz|www|proxy/.test(s))return'dmz';
 if(/sql|app|srv|server|exch|db/.test(s))return'srv';
 if(/wks|ws\d|lt|lap|pc|desk/.test(s))return'wks';
 return'wks';
}
function lsRunImport(){
 const ta=document.getElementById('ls-imp-ta');if(!ta)return;
 const rows=ta.value.split('\n').map(r=>r.trim()).filter(Boolean);
 if(!rows.length){toast('Nothing to import');return;}
 let added=0;
 rows.forEach((row,i)=>{
  const parts=row.split(',').map(x=>x.trim());
  const name=parts[0];if(!name)return;
  let type=(parts[1]||'').toLowerCase();
  if(!NODE_TYPES[type])type=lsGuessType(name);
  const zone=(parts[2]||'').toLowerCase();
  const n=lsAddNode(type,120+(i%8)*150,120+Math.floor(i/8)*110,false);
  n.label=name;
  if(zone&&ZONES[zone])n.zone=zone;
  added++;
 });
 lsCloseImport();persistAll();lsSnapshot();renderLogSrc();
 toast(`${added} host${added===1?'':'s'} imported`);
}

/* --- B. "What to build next": ranks unbuilt detections by real-world value --- */
function lsNextDetections(){
 const staged=studio;
 const actorCount={};
 Object.values(THREAT_PROFILES).forEach(p=>p.techs.forEach(id=>{actorCount[id]=(actorCount[id]||0)+1;}));
 const mapped=new Set();
 lsNodes.forEach(n=>lsEventsForNode(n).forEach(e=>(e.mitre||[]).forEach(mm=>mapped.add(mm))));
 const rows=uniqTechs().filter(id=>!staged.has(id)).map(id=>{
  const evs=eventsForTech(id);
  const telem=evs.length;                       // can you even see it
  const onMap=mapped.has(id)?1:0;               // does your actual estate emit it
  const actors=actorCount[id]||0;               // do real groups use it
  const score=telem*2+onMap*3+actors*4;
  return {id,name:T(id).name,telem,onMap,actors,score};
 }).filter(r=>r.score>0).sort((a,b)=>b.score-a.score).slice(0,12);
 return rows;
}
function openLsNext(){
 const rows=lsNextDetections();
 let v=document.getElementById('ls-next-veil');
 if(!v){v=document.createElement('div');v.id='ls-next-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="lsCloseNext()"></div>
  <div class="ls-det-head">Build these next</div>
  <div class="ls-det-sub">Unstaged techniques ranked by what actually pays off: whether your mapped hosts emit the telemetry, whether tracked groups use the technique, and how many Event IDs cover it.</div>
  ${rows.length?rows.map(r=>`<div class="ls-next-row">
    <div class="ls-next-id">${r.id}</div>
    <div class="ls-next-name">${esc(r.name)}
      <div class="ls-next-why">${r.onMap?'<span class="ok">visible on your map</span>':'<span class="no">no mapped host emits it</span>'}${r.actors?` \u00b7 <span class="ok">${r.actors} tracked group${r.actors===1?'':'s'}</span>`:''} \u00b7 ${r.telem} event ID${r.telem===1?'':'s'}</div>
    </div>
    <button class="ls-snap-btn" onclick="togStudio('${r.id}');openLsNext()">stage</button>
  </div>`).join(''):'<div class="ls-det-sub">Everything with telemetry is already staged. Nice.</div>'}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseNext();};
}
function lsCloseNext(){const v=document.getElementById('ls-next-veil');if(v)v.classList.remove('open');}

/* --- C. SPL convention linter: catches the mistakes that cost you a night --- */
function splLint(q){
 const out=[];const s=(q||'');
 if(/ut_shannon/.test(s)&&!/tonumber\s*\(/.test(s))
  out.push({sev:'err',msg:'ut_shannon_lookup result is a string \u2014 wrap it in tonumber() before comparing, or the threshold silently never matches.'});
 if(!/^\s*(index=|\||`)/m.test(s)&&!/index\s*=/.test(s))
  out.push({sev:'warn',msg:'No index= specified. Add one or the search fans out across every index you can read.'});
 if(/EventCode\s*=\s*\d+/.test(s)&&!/sourcetype\s*=/.test(s))
  out.push({sev:'warn',msg:'EventCode without sourcetype can collide across sources \u2014 pin the sourcetype.'});
 if(/\|\s*stats/.test(s)&&/dc\(/.test(s)===false&&/ComputerName/.test(s))
  out.push({sev:'info',msg:'Consider dc(ComputerName) for host-frequency scoring \u2014 it separates fleet-wide noise from targeted activity.'});
 if(!/outputlookup|inputlookup/.test(s)&&/\|\s*stats|\|\s*table/.test(s))
  out.push({sev:'info',msg:'No lookup-based suppression. Broad alerting works better with an inputlookup allow-list you can grow.'});
 if(/\bNOT\s+\w+\s*=\s*"[^"]*\*/.test(s))
  out.push({sev:'warn',msg:'Leading-wildcard NOT clauses are slow and often wrong \u2014 prefer an exclusion lookup.'});
 const q1=(s.match(/"/g)||[]).length;
 if(q1%2!==0)out.push({sev:'err',msg:'Unbalanced double quotes \u2014 this will not parse.'});
 const op=(s.match(/\(/g)||[]).length,cp=(s.match(/\)/g)||[]).length;
 if(op!==cp)out.push({sev:'err',msg:`Unbalanced parentheses (${op} open, ${cp} close).`});
 return out;
}
function splLintHTML(q){
 const rs=splLint(q);
 if(!rs.length)return'<div class="lint ok">\u2713 No convention issues found.</div>';
 return rs.map(r=>`<div class="lint ${r.sev}"><b>${r.sev==='err'?'Error':r.sev==='warn'?'Check':'Tip'}</b> ${esc(r.msg)}</div>`).join('');
}

/* --- D. Coverage scorecard: one honest number, with the working shown --- */
function coverageScore(){
 const all=uniqTechs();
 const withTelem=all.filter(id=>eventsForTech(id).length);
 const staged=[...studio];
 const prod=staged.filter(id=>(maturity[id]||'idea')==='prod');
 const tuned=staged.filter(id=>['tuned','prod'].includes(maturity[id]||'idea'));
 const mapped=new Set();
 lsNodes.forEach(n=>lsEventsForNode(n).forEach(e=>(e.mitre||[]).forEach(mm=>mapped.add(mm))));
 const stagedVisible=staged.filter(id=>mapped.has(id));
 const pct=(a,b)=>b?Math.round(a/b*100):0;
 return {
  total:all.length, withTelem:withTelem.length,
  staged:staged.length, tuned:tuned.length, prod:prod.length,
  stagedVisible:stagedVisible.length,
  telemPct:pct(withTelem.length,all.length),
  stagedPct:pct(staged.length,withTelem.length),
  prodPct:pct(prod.length,Math.max(1,staged.length)),
  visiblePct:pct(stagedVisible.length,Math.max(1,staged.length))
 };
}
function openScorecard(){
 const s=coverageScore();
 let v=document.getElementById('sc-veil');
 if(!v){v=document.createElement('div');v.id='sc-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const bar=(label,val,pct,note)=>`<div class="sc-row">
   <div class="sc-top"><span>${label}</span><b>${val}</b></div>
   <div class="sc-bar"><i style="width:${Math.min(100,pct)}%"></i></div>
   <div class="sc-note">${note}</div></div>`;
 v.innerHTML=`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="closeScorecard()"></div>
  <div class="ls-det-head">Coverage scorecard</div>
  <div class="ls-det-sub">An honest read on where detection engineering actually stands \u2014 not a vanity percentage of the whole ATT&CK matrix.</div>
  ${bar('Techniques with usable telemetry',`${s.withTelem} / ${s.total}`,s.telemPct,'The realistic ceiling for your current log sources.')}
  ${bar('Staged for detection',`${s.staged} / ${s.withTelem}`,s.stagedPct,'Of what you could detect, how much you have picked up.')}
  ${bar('Visible on your actual network',`${s.stagedVisible} / ${Math.max(1,s.staged)}`,s.visiblePct,'Staged detections that a host on your map would really fire.')}
  ${bar('Reached production',`${s.prod} / ${Math.max(1,s.staged)}`,s.prodPct,'Idea and tested rules do not catch anything at 3am.')}
  <div class="sc-foot">${s.staged&&s.visiblePct<60?'\u26a0 A large share of staged detections have no emitting host on your map. Either the map is incomplete or the telemetry is not deployed where it matters.':'Coverage and network reality are broadly in step.'}</div>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeScorecard();};
}
function closeScorecard(){const v=document.getElementById('sc-veil');if(v)v.classList.remove('open');}

/* --- E. Tuning log: record the false positives you actually suppressed --- */
let tuneLog={};
function loadTune(){try{tuneLog=JSON.parse(read('aegis-tune','{}'))||{}}catch{tuneLog={}}}
function saveTune(){try{store('aegis-tune',JSON.stringify(tuneLog))}catch{}}
async function addTuneEntry(tid){
 const v=await uiPrompt('What was the false positive, and how did you suppress it?','',{title:`Tuning note \u00b7 ${tid}`,ok:'Save note',placeholder:'e.g. SCCM agent triggers 4688 nightly \u2014 suppressed via inputlookup sccm_hosts'});
 if(v===null||!v.trim())return;
 (tuneLog[tid]=tuneLog[tid]||[]).push({t:Date.now(),note:v.trim()});
 saveTune();renderStudio();toast('Tuning note saved');
}
function tuneHTML(tid){
 const rows=tuneLog[tid]||[];
 return `<div class="tune">
   <div class="tune-h">Tuning log ${rows.length?`<span>${rows.length}</span>`:''}</div>
   ${rows.map(r=>`<div class="tune-row"><span class="tune-d">${new Date(r.t).toLocaleDateString()}</span>${esc(r.note)}</div>`).join('')}
   <button class="ls-snap-btn" onclick="addTuneEntry('${tid}')">\uff0b Record a false positive</button>
 </div>`;
}
