/* ================= AI ATTACK-CHAIN ANIMATION =================
   The AI returns a structured chain of hops; we play it back on the map so the
   analyst watches the intrusion trace node-to-node in real time. */
let lsAnim=null;
function lsAnimNodeActive(uid){
 if(!lsAnim||!lsAnim.active)return false;
 for(let i=0;i<=lsAnim.idx;i++){const s=lsAnim.steps[i];if(s&&(s.fromUid===uid||s.toUid===uid))return true;}
 return false;
}
function lsAnimSVG(){
 if(!lsAnim||!lsAnim.active)return'';
 let out='';
 for(let i=0;i<=lsAnim.idx&&i<lsAnim.steps.length;i++){
  const s=lsAnim.steps[i];
  const a=lsNodes.find(n=>n.uid===s.fromUid), b=lsNodes.find(n=>n.uid===s.toUid);
  if(!a||!b)continue;
  const current=(i===lsAnim.idx);
  const cc=s.conf?('conf-'+s.conf):'';
  if(a.uid===b.uid){
   out+=`<circle cx="${a.x}" cy="${a.y-46}" r="12" class="ls-anim-self ${current?'now':''} ${cc}"/>`;
  }else{
   const mx=(a.x+b.x)/2,my=(a.y+b.y)/2-46;
   out+=`<path d="M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}" class="ls-anim-path ${current?'now':''} ${cc}" marker-end="url(#ls-animarrow)"/>`;
   if(current){out+=`<circle r="5" class="ls-anim-pulse"><animateMotion dur="1.1s" repeatCount="indefinite" path="M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}"/></circle>`;}
  }
 }
 return out;
}
function lsRunAnim(steps){
 lsAnim={steps:steps.map(s=>({...s,fromUid:lsResolveNode(s.from),toUid:lsResolveNode(s.to)})).filter(s=>s.fromUid&&s.toUid),idx:-1,active:true,timer:null,playing:true};
 if(!lsAnim.steps.length){lsAnim=null;toast('Could not map the chain to your nodes');return;}
 lsStep='topology';renderLogSrc();
 lsAnimNext();
}
function lsResolveNode(ref){
 if(!ref)return null;
 let n=lsNodes.find(x=>x.uid===ref);if(n)return n.uid;
 const r=String(ref).toLowerCase();
 n=lsNodes.find(x=>x.label.toLowerCase()===r)||lsNodes.find(x=>x.label.toLowerCase().includes(r))||lsNodes.find(x=>r.includes(x.label.toLowerCase()));
 if(n)return n.uid;
 const typeMap={internet:'internet',firewall:'fw',router:'router',switch:'switch',vpn:'vpn',workstation:'wks',pc:'wks',desktop:'wks',server:'srv',dc:'dc','domain controller':'dc',cloud:'cloud',nas:'nas',file:'nas',dmz:'dmz',iot:'iot'};
 for(const k in typeMap){if(r.includes(k)){const nn=lsNodes.find(x=>x.type===typeMap[k]);if(nn)return nn.uid;}}
 return null;
}
function lsAnimNext(){
 if(!lsAnim)return;
 lsAnim.idx++;
 if(lsAnim.idx>=lsAnim.steps.length){lsAnim.idx=lsAnim.steps.length-1;lsAnim.playing=false;renderLogSrc();lsAnimRenderCaption(true);return;}
 renderLogSrc();lsAnimRenderCaption();
 if(lsAnim.playing){lsAnim.timer=setTimeout(()=>{if(lsAnim&&lsAnim.playing)lsAnimNext();},2600);}
}
function lsAnimPrev(){if(!lsAnim)return;clearTimeout(lsAnim.timer);lsAnim.playing=false;lsAnim.idx=Math.max(0,lsAnim.idx-1);renderLogSrc();lsAnimRenderCaption();}
function lsAnimPlay(){if(!lsAnim)return;lsAnim.playing=!lsAnim.playing;if(lsAnim.playing){if(lsAnim.idx>=lsAnim.steps.length-1)lsAnim.idx=-1;lsAnimNext();}else{clearTimeout(lsAnim.timer);lsAnimRenderCaption();}}
function lsAnimStop(){if(lsAnim){clearTimeout(lsAnim.timer);}lsAnim=null;renderLogSrc();}
function lsAnimRenderCaption(done){
 const cap=document.getElementById('ls-anim-cap');if(!cap||!lsAnim)return;
 const s=lsAnim.steps[lsAnim.idx];if(!s)return;
 const a=lsNodes.find(n=>n.uid===s.fromUid),b=lsNodes.find(n=>n.uid===s.toUid);
 cap.innerHTML=`<div class="ls-anim-cap-inner">
   <div class="ls-anim-step">${done?'Chain complete · ':''}Step ${lsAnim.idx+1} / ${lsAnim.steps.length}${s.tech?` · <span class="ls-anim-tech">${esc(s.tech)}</span>`:''}${s.conf?` · <span class="ls-anim-conf conf-${esc(s.conf)}">${esc(s.conf)} confidence</span>`:''}</div>
   <div class="ls-anim-hop">${a?NODE_TYPES[a.type].glyph+' '+esc(a.label):'?'} ${a&&b&&a.uid!==b.uid?'\u2192':'\u27f2'} ${b&&(!a||a.uid!==b.uid)?NODE_TYPES[b.type].glyph+' '+esc(b.label):''}</div>
   <div class="ls-anim-detail">${esc(s.detail||s.label||'')}</div>
   <div class="ls-anim-ctrls">
     <button onclick="lsAnimPrev()" ${lsAnim.idx<=0?'disabled':''}>\u2039 Prev</button>
     <button onclick="lsAnimPlay()">${lsAnim.playing?'\u23f8 Pause':'\u25b6 Play'}</button>
     <button onclick="lsAnimNext()" ${lsAnim.idx>=lsAnim.steps.length-1?'disabled':''}>Next \u203a</button>
     <button onclick="lsAnimStop()">\u2715 Exit trace</button>
   </div>
 </div>`;
 cap.style.display='block';
}

function lsEventDetailHTML(evId){
 const ev=LOGSRC.find(e=>e.id===evId);if(!ev)return'';
 const litNodes=lsNodesForEvent(evId);
 const nonWin=lsNodes.filter(n=>!NODE_TYPES[n.type].win);
 const flow=LS_FLOW[evId];
 return`<div class="ls-evdetail">
   <button class="ls-evdetail-x" onclick="lsSelEvent=null;renderLogSrc()">×</button>
   <div class="ls-evd-id">${ev.id}</div>
   <div class="ls-evd-name">${ev.name}</div>
   <div class="ls-evd-noise" style="color:${lsNoiseColor(ev.noise)}">${'●'.repeat(ev.noise)}${'○'.repeat(5-ev.noise)} ${lsNoiseLabel(ev.noise)} volume</div>
   <div class="ls-evd-why">${ev.why}</div>
   <div class="ls-evd-sec">Pulls data from</div>
   ${litNodes.length?`<div class="ls-evd-nodes">${litNodes.map(n=>`<span class="ls-evd-node">${NODE_TYPES[n.type].glyph} ${esc(n.label)}</span>`).join('')}</div>`:`<div class="ls-evd-none">No node in your current topology emits this event. Add a ${ev.roles.map(r=>LS_ROLES[r]).join(' or ')} to collect it.</div>`}
   ${flow?`<div class="ls-evd-sec">Attack flow</div><div class="ls-evd-flow">This event reveals <b>${flow.label}</b>${flow.self?' - activity on the host itself':flow.to?` - movement toward your ${(flow.to||[]).map(z=>NODE_TYPES[z]?NODE_TYPES[z].label.split(' ')[0]:z).join('/')}`:''}. Switch to <b>Attack flow</b> view to trace it on the map.</div>`:''}
   <div class="ls-evd-sec">Enable it</div>
   <div class="ls-evd-setup">${esc(ev.setup)}</div>
   ${ev.linked?`<button class="btn ghost-violet" style="margin-top:12px;width:100%;justify-content:center" onclick="jumpById('${ev.linked}')">Open full detection ↗</button>`:''}
 </div>`;
}

function lsSelectEvent(id){lsSelEvent=(lsSelEvent===id?null:id);renderLogSrc();}

/* Build the plan from the topology: derive roles + non-windows sources present */
function lsBuildFromTopo(){
 const roles=new Set();let hasCloud=false,hasFW=false;
 lsNodes.forEach(n=>{const t=NODE_TYPES[n.type];if(t.win&&!/linux|macos/i.test(n.os)&&t.role)roles.add(t.role);if(n.type==='cloud')hasCloud=true;if(n.type==='fw'||n.type==='router'||n.type==='vpn')hasFW=true;});
 if(!roles.size)roles.add('srv');
 lsAnswers.roles=roles;
 lsResult={picks:lsRecommend(),generic:false,fromTopo:true,nonWin:{cloud:hasCloud,fw:hasFW}};
 lsPlanOpen=true;renderLogSrc();openLsPlan();updateBadges();
}
let lsPlanOpen=false;
function openLsPlan(){
 let v=document.getElementById('ls-plan-veil');
 if(!v){v=document.createElement('div');v.id='ls-plan-veil';v.className='ls-plan-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-plan-panel"><button class="ls-plan-x" onclick="closeLsPlan()">✕</button>${lsResultHTML()}</div>`;
 v.classList.add('open');
 v.onclick=(e)=>{if(e.target===v)closeLsPlan();};
}
function closeLsPlan(){lsPlanOpen=false;const v=document.getElementById('ls-plan-veil');if(v)v.classList.remove('open');}

/* Drag handling - bound after each canvas render */
function lsBindCanvas(){
 if(!window._lsKeys){window._lsKeys=true;document.addEventListener('keydown',lsKeys);}
 const svg=document.getElementById('ls-svg');if(!svg)return;
 svg.querySelectorAll('.ls-node').forEach(g=>{
  const uid=g.getAttribute('data-uid');
  const down=(e)=>{
    if(lsTool==='pan'||_spaceHeld){e.preventDefault();lsPanBegin(e,document.getElementById('ls-svg'));return;}
    e.preventDefault();e.stopPropagation();
    const svgEl=document.getElementById('ls-svg');const r=svgEl.getBoundingClientRect();
    const cx=(e.touches?e.touches[0].clientX:e.clientX),cy=(e.touches?e.touches[0].clientY:e.clientY);
    const p={x:((cx-r.left)/r.width*LS_W-lsPanX)/lsZoom,y:((cy-r.top)/r.height*LS_H-lsPanY)/lsZoom};
    const n=lsNodes.find(x=>x.uid===uid);lsDrag={uid,dx:n.x-p.x,dy:n.y-p.y,moved:false};g.style.cursor='grabbing';
    // long-press → quick observation logger (skips full editor)
    clearTimeout(lsDrag._lp);
    if(!lsConnectMode&&!lsChainMode){
     lsDrag._lp=setTimeout(()=>{if(lsDrag&&!lsDrag.moved){const held=lsDrag.uid;lsDrag=null;if(navigator.vibrate)navigator.vibrate(15);lsQuickObs(held);}},520);
    }
  };
  g.addEventListener('mousedown',down);g.addEventListener('touchstart',down,{passive:false});
  g.addEventListener('dblclick',(e)=>{e.preventDefault();e.stopPropagation();lsDrag=null;lsRenameNode(uid);});
  const rs=g.querySelector('.ls-node-rs');
  if(rs){
   const rdown=(e)=>{e.preventDefault();e.stopPropagation();
    const n=lsNodes.find(z=>z.uid===uid);
    const cy=(e.touches?e.touches[0].clientY:e.clientY);
    lsNodeResize={uid,startY:cy,startScale:n.scale||1};};
   rs.addEventListener('mousedown',rdown);rs.addEventListener('touchstart',rdown,{passive:false});
  }
  const x=g.querySelector('.ls-node-x');
  if(x){
   x.addEventListener('mousedown',(e)=>{e.stopPropagation();});
   x.addEventListener('touchstart',(e)=>{e.stopPropagation();},{passive:false});
   x.addEventListener('click',(e)=>{e.preventDefault();e.stopPropagation();lsDrag=null;lsDeleteNode(uid);});
  }
 });
 // ---- zones: drag the header to move, drag the corner grip to resize ----
 const pt=(e)=>{const r=svg.getBoundingClientRect();
   const cx=(e.touches?e.touches[0].clientX:e.clientX),cy=(e.touches?e.touches[0].clientY:e.clientY);
   return {x:((cx-r.left)/r.width*LS_W-lsPanX)/lsZoom,y:((cy-r.top)/r.height*LS_H-lsPanY)/lsZoom};};
 svg.querySelectorAll('.ls-zone-x').forEach(el=>{
  const z=el.getAttribute('data-zone');
  const stop=(e)=>{e.preventDefault();e.stopPropagation();lsZoneDrag=null;lsDeleteZone(z);};
  el.addEventListener('mousedown',(e)=>{e.stopPropagation();});
  el.addEventListener('touchstart',(e)=>{e.stopPropagation();},{passive:false});
  el.addEventListener('click',stop);
 });
 svg.querySelectorAll('.ls-zone-body').forEach(el=>{
  const z=el.getAttribute('data-zone');
  const down=(e)=>{
   if(lsTool==='pan'||_spaceHeld){e.preventDefault();lsPanBegin(e,svg);return;}
   e.preventDefault();e.stopPropagation();
   const p=pt(e),r=lsZoneRect(z);
   lsZoneDrag={z,mode:'move',ox:p.x-r.x,oy:p.y-r.y,lastx:p.x,lasty:p.y};
   lsZoneSel=z;};
  el.addEventListener('mousedown',down);el.addEventListener('touchstart',down,{passive:false});
 });
 svg.querySelectorAll('.ls-zone-grip').forEach(el=>{
  const z=el.getAttribute('data-zone');
  const down=(e)=>{e.preventDefault();e.stopPropagation();
   const p=pt(e),r=lsZoneRect(z);
   lsZoneDrag={z,mode:'resize',ox:p.x-(r.x+r.w),oy:p.y-(r.y+r.h)};
   lsZoneSel=z;};
  el.addEventListener('mousedown',down);el.addEventListener('touchstart',down,{passive:false});
 });
 svg.querySelectorAll('.ls-zone-label').forEach(el=>{
  el.addEventListener('dblclick',(e)=>{e.preventDefault();e.stopPropagation();lsZoneDrag=null;lsRenameZone(el.getAttribute('data-zone'));});
 });
 // double-click a lane label to rename that zone
 svg.querySelectorAll('.ls-lane-label').forEach(el=>{
  el.addEventListener('dblclick',(e)=>{e.preventDefault();e.stopPropagation();lsRenameZone(el.getAttribute('data-zone'));});
 });
 if(!window._lsCanvasBound){
  window._lsCanvasBound=true;
  window.addEventListener('mousemove',lsCanvasMove);window.addEventListener('mouseup',lsCanvasUp);
  window.addEventListener('touchmove',lsCanvasMove,{passive:false});window.addEventListener('touchend',lsCanvasUp);
 }
 lsBindZoom();
}
let _lsPinch=null;
function lsBindZoom(){
 const cv=document.getElementById('ls-canvas');if(!cv||cv._zoomBound)return;cv._zoomBound=true;
 // wheel = zoom on desktop
 cv.addEventListener('wheel',(e)=>{e.preventDefault();lsZoomBy(e.deltaY<0?1.12:0.89);},{passive:false});
 // drag empty canvas (or anywhere with the hand tool) to pan
 cv.addEventListener('mousedown',(e)=>{
  const onNode=e.target.closest&&e.target.closest('.ls-node');
  const onZone=e.target.closest&&e.target.closest('.ls-zone');
  if(lsTool==='pan'||_spaceHeld||(!onNode&&!onZone)){e.preventDefault();lsPanBegin(e,document.getElementById('ls-svg'));}
 });
 window.addEventListener('mousemove',(e)=>{if(lsPan)lsPanMove(e,document.getElementById('ls-svg'));});
 window.addEventListener('mouseup',()=>{lsPan=null;});
 window.addEventListener('keydown',(e)=>{if(e.code==='Space'){const tag=(e.target.tagName||'').toLowerCase();if(tag!=='input'&&tag!=='textarea'){_spaceHeld=true;cv.classList.add('panning');}}});
 window.addEventListener('keyup',(e)=>{if(e.code==='Space'){_spaceHeld=false;lsPan=null;cv.classList.remove('panning');}});
 // two-finger pinch = zoom, one-finger on empty space = pan
 cv.addEventListener('touchstart',(e)=>{
  if(e.touches.length===2){_lsPinch={d:_lsDist(e.touches),z:lsZoom};}
  else if(e.touches.length===1&&(lsTool==='pan'||(e.target.closest&&!e.target.closest('.ls-node')))){_lsPinch={pan:true,x:e.touches[0].clientX-lsPanX,y:e.touches[0].clientY-lsPanY};}
 },{passive:true});
 cv.addEventListener('touchmove',(e)=>{
  if(!_lsPinch)return;
  if(_lsPinch.pan&&e.touches.length===1){lsPanX=e.touches[0].clientX-_lsPinch.x;lsPanY=e.touches[0].clientY-_lsPinch.y;lsApplyZoom();}
  else if(e.touches.length===2){const d=_lsDist(e.touches);lsZoom=Math.max(0.5,Math.min(3,_lsPinch.z*d/_lsPinch.d));lsApplyZoom();}
 },{passive:true});
 cv.addEventListener('touchend',(e)=>{if(e.touches.length===0)_lsPinch=null;},{passive:true});
}
function _lsDist(t){const dx=t[0].clientX-t[1].clientX,dy=t[0].clientY-t[1].clientY;return Math.hypot(dx,dy);}
function lsZoomBy(f){lsZoom=Math.max(0.5,Math.min(3,lsZoom*f));lsApplyZoom();}
function lsZoomReset(){lsZoom=1;lsPanX=0;lsPanY=0;lsApplyZoom();}
function lsApplyZoom(){const z=document.getElementById('ls-zoomer');if(z)z.setAttribute('transform',`translate(${lsPanX},${lsPanY}) scale(${lsZoom})`);const p=document.getElementById('ls-zoompct');if(p)p.textContent=lsZoomPct()+'%';}
function lsCanvasMove(e){
 const svg0=document.getElementById('ls-svg');
 if(lsNodeResize&&svg0){
  e.preventDefault&&e.preventDefault();
  const cy=(e.touches?e.touches[0].clientY:e.clientY);
  const n=lsNodes.find(z=>z.uid===lsNodeResize.uid);
  if(n){
   n.scale=Math.max(0.5,Math.min(3,lsNodeResize.startScale+(cy-lsNodeResize.startY)/140));
   const g=svg0.querySelector(`[data-uid="${n.uid}"]`);
   if(g)g.setAttribute('transform',`translate(${n.x},${n.y}) scale(${(n.scale||1)*lsNodeScale})`);
  }
  return;
 }
 if(lsZoneDrag&&svg0){
  e.preventDefault&&e.preventDefault();
  const r0=svg0.getBoundingClientRect();
  const cx=(e.touches?e.touches[0].clientX:e.clientX),cy=(e.touches?e.touches[0].clientY:e.clientY);
  const p={x:((cx-r0.left)/r0.width*LS_W-lsPanX)/lsZoom,y:((cy-r0.top)/r0.height*LS_H-lsPanY)/lsZoom};
  const Z=ZONES[lsZoneDrag.z];if(!Z)return;
  if(lsZoneDrag.mode==='move'){
   Z.x=p.x-lsZoneDrag.ox;Z.y=p.y-lsZoneDrag.oy;
   lsZoneDrag.moved=true; // the rectangle moves on its own; hosts stay where they are
  }else{
   Z.w=Math.max(160,p.x-lsZoneDrag.ox-Z.x);
   Z.h=Math.max(90,p.y-lsZoneDrag.oy-Z.y);
   lsZoneDrag.moved=true;
  }
  const zl=svg0.querySelector('#ls-zonelayer');
  if(zl)zl.innerHTML=lsZoneRegions();
  else renderLogSrc();
  return;
 }
 if(!lsDrag)return;const svg=svg0;if(!svg)return;
 e.preventDefault&&e.preventDefault();
 const r=svg.getBoundingClientRect();const cx=(e.touches?e.touches[0].clientX:e.clientX),cy=(e.touches?e.touches[0].clientY:e.clientY);
 const p={x:((cx-r.left)/r.width*LS_W-lsPanX)/lsZoom,y:((cy-r.top)/r.height*LS_H-lsPanY)/lsZoom};
 const n=lsNodes.find(x=>x.uid===lsDrag.uid);if(!n)return;
 n.x=p.x+lsDrag.dx;n.y=p.y+lsDrag.dy; // unbounded: pan/fit will find them
 if(!lsDrag.moved&&lsDrag._lp)clearTimeout(lsDrag._lp);
 lsDrag.moved=true;
 const g=svg.querySelector(`[data-uid="${lsDrag.uid}"]`);if(g)g.setAttribute('transform',`translate(${n.x},${n.y}) scale(${(n.scale||1)*lsNodeScale})`);
 // live-highlight the lane the node would land in
 const tz=lsZoneAtPoint(n.x,n.y);
 if(tz!==lsDragZone){
  lsDragZone=tz;
  svg.querySelectorAll('.ls-zone').forEach(el=>el.classList.toggle('zone-hot',el.getAttribute('data-zone')===tz));
 }
}
function lsCanvasUp(e){
 if(lsNodeResize){lsNodeResize=null;persistAll();lsSnapshot();renderLogSrc();return;}
 if(lsZoneDrag){
  const moved=lsZoneDrag.moved;lsZoneDrag=null;
  if(moved){lsSaveZones();persistAll();lsSnapshot();renderLogSrc();}
  return;
 }
 if(!lsDrag)return;const wasMoved=lsDrag.moved,uid=lsDrag.uid;if(lsDrag._lp)clearTimeout(lsDrag._lp);lsDrag=null;
 if(wasMoved){
  const n=lsNodes.find(x=>x.uid===uid);
  const tz=n?lsZoneAtPoint(n.x,n.y):null;
  lsDragZone=null;
  if(n&&tz&&nodeZone(n)!==tz){n.zone=tz;toast(`${n.label} → ${zoneLabel(tz)}`);}
  persistAll();lsSnapshot();renderLogSrc();return;
 }
 lsDragZone=null;
 if(lsConnectMode){lsNodeClickConnect(uid);return;}
 if(lsChainMode){lsChainAddNode(uid);return;}
 if(e&&(e.ctrlKey||e.metaKey||e.shiftKey)){lsToggleSel(uid,true);return;}
 if(lsSel.size){lsSel.clear();renderLogSrc();}
 lsOpenNodeEdit(uid);
}

/* double-click a node to rename it in place */
async function lsDeleteNode(uid){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 const obs=lsNodeObs(n).length;
 const links=lsEdges.filter(e=>e.a===uid||e.b===uid).length;
 const extra=[obs?`${obs} logged observation${obs===1?'':'s'}`:null,links?`${links} link${links===1?'':'s'}`:null].filter(Boolean).join(' and ');
 if(!await uiConfirm(extra?`This also removes ${extra}.`:'This host will be removed from the map.',{title:`Delete ${n.label}?`,ok:'Delete host',danger:true}))return;
 lsNodes=lsNodes.filter(x=>x.uid!==uid);
 lsEdges=lsEdges.filter(e=>e.a!==uid&&e.b!==uid);
 lsSel.delete(uid);lsManualChain=lsManualChain.filter(x=>x!==uid);
 if(lsEditNode===uid)lsEditNode=null;
 persistAll();lsSnapshot();renderLogSrc();toast(`${n.label} deleted`);
}
async function lsRenameNode(uid){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 const v=await uiPrompt('Host name:',n.label);
 if(v===null||!v.trim())return;
 n.label=v.trim();persistAll();lsSnapshot();renderLogSrc();
 if(lsEditNode===uid)renderNodeEditor(n,NODE_TYPES[n.type]);
}
/* clear the whole map */
async function lsClearMap(){
 lsLoadSnaps();
 const obs=lsNodes.reduce((a,n)=>a+lsNodeObs(n).length,0);
 const nZ=Object.keys(ZONES).length, nSnap=(lsSnaps&&lsSnaps.length)||0;
 if(!lsNodes.length&&!lsEdges.length&&!obs&&!nSnap&&!lsPendingChain){toast('The map is already empty');return;}
 const lines=[
  `\u2022 ${lsNodes.length} host${lsNodes.length===1?'':'s'}`,
  `\u2022 ${lsEdges.length} link${lsEdges.length===1?'':'s'}`,
  `\u2022 ${obs} logged observation${obs===1?'':'s'}`,
  `\u2022 ${nZ} zone${nZ===1?'':'s'}`,
  nSnap?`\u2022 ${nSnap} saved snapshot${nSnap===1?'':'s'}`:null,
  lsPendingChain?'\u2022 the saved attack trace':null
 ].filter(Boolean).join('\n');
 if(!await uiConfirm(lines+'\n\nThis cannot be undone. Export the case first if you want to keep it.',{title:'Clear the entire network map?',ok:'Clear everything',danger:true}))return;
 lsNodes=[];lsEdges=[];lsNodeSeq=1;
 lsScrubT=null;lsPendingChain=null;lsAnim=null;lsManualChain=[];lsSelEvent=null;
 lsEditNode=null;lsCollapsed=new Set();lsZoneSel=null;lsZoneDrag=null;lsDrag=null;lsDragZone=null;
 lsConnectMode=false;lsChainMode=false;lsConnectFrom=null;lsQuery='';lsSel=new Set();
 lsHeatOn=false;lsGrid=false;
 ZONES={};                       // blank canvas: no zones at all
 lsSaveZones();
 lsSnaps=[];lsSaveSnaps();
 lsHist=[JSON.stringify({nodes:[],edges:[],seq:1})];lsHistIdx=0;
 // write the empty state straight to storage so a reload cannot resurrect anything
 try{
  store('aegis-nodes','[]');store('aegis-edges','[]');store('aegis-nodeseq','1');
  store('aegis-lastchain','');store('aegis-snaps','[]');store('aegis-zones','{}');
 }catch(e){}
 const f=document.getElementById('ls-find');if(f)f.value='';
 persistAll();renderLogSrc();
 toast('Network map cleared');
}
function lsOpenNodeEdit(uid){
 if(lsConnectMode||lsChainMode)return; // clicks belong to the active mode
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;const t=NODE_TYPES[n.type];
 lsEditNode=uid;renderNodeEditor(n,t);
}
let lsEditNode=null;
