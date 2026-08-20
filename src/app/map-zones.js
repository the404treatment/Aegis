/* ================= LOG SOURCES ADVISOR ================= */
let lsMode='baseline', lsStep='start', lsAnswers={roles:new Set(['dc','srv','wks']),sysmon:'no',pwsh:'yes',noise:'balanced',cloud:'no'}, lsGroups=[], lsResult=null;
let lsNodes=[], lsNodeSeq=1, lsSelEvent=null, lsFlowView='telemetry', lsDrag=null;
let lsEdges=[], lsConnectMode=false, lsConnectFrom=null, lsShowZones=true;
let lsChainMode=false, lsManualChain=[];
let lsScrubT=null; // when set, only show observations at/before this time
let lsZoom=1, lsPanX=0, lsPanY=0; // map pinch-zoom / pan
let lsHeatOn=false; // node risk-heat overlay
let lsCollapsed=new Set(); // #13 collapsed zone groups
let lsDragZone=null; // lane currently hovered while dragging a node
let lsZoneDrag=null, lsZoneSel=null;
let lsNodeResize=null;
let lsTool='select';        // 'select' | 'pan'
let lsPan=null;             // active pan gesture
let lsNodeScale=1;          // global default: 0.8 compact / 1 normal / 1.3 large
let _spaceHeld=false;


function lsNoiseLabel(n){return['','very low','low','moderate','high','very high'][n]||'—';}
function lsNoiseColor(n){return n<=2?'var(--mint)':n===3?'var(--amber)':'var(--magenta)';}

/* Core engine: given mode + answers, score and select event IDs. */
function lsRecommend(){
 const a=lsAnswers, mode=lsMode;
 const roles=a.roles;
 const noiseCap = a.noise==='quiet'?2 : a.noise==='balanced'?3 : 5; // max noise allowed
 const picks=[];
 LOGSRC.forEach(ev=>{
  // role relevance
  if(![...roles].some(r=>ev.roles.includes(r)))return;
  // sysmon gating
  if(ev.sysmon && a.sysmon!=='yes')return;
  // powershell gating
  if(ev.ch.startsWith('PowerShell') && a.pwsh!=='yes')return;
  // phase relevance
  const inPhase = ev.phase==='both' || ev.phase===mode;
  if(!inPhase)return;
  // noise gating: baseline respects the cap; hunt allows noisier but flags it
  let included=true, flagged=false;
  if(mode==='baseline'){
   if(ev.noise>noiseCap)included=false;
  }else{ // hunt
   if(ev.noise>noiseCap)included=false;      // still respect an explicit quiet/balanced cap
   if(ev.noise>=5)flagged=true;               // very-high-volume sources always get a scope flag
  }
  if(!included)return;
  // score for ordering: signal = inverse noise + role breadth + phase fit + low-volume bonus
  let score=0;
  score += (6-ev.noise)*10;               // quieter = higher
  score += ev.roles.filter(r=>roles.has(r)).length*4;
  if(ev.phase===mode)score+=8;            // exact phase match
  if(ev.phase==='both')score+=4;
  if(ev.linked)score+=6;                  // we have a full detection for it
  if(mode==='hunt' && ev.noise>=4)score+=6; // hunts value the noisy-but-rich sources
  picks.push({ev,score,flagged});
 });
 picks.sort((x,y)=>y.score-x.score);
 return picks;
}
/* Generic broad-coverage preset - solid, not-too-noisy, role-agnostic. */
function lsGenericPreset(){
 const ids=['4624','4625','4672','4688','4698','4719','4720','4726','4732','4728','7045','4697','7040','1102','5001','1116','4104','4740','4616'];
 return LOGSRC.filter(e=>ids.includes(e.id)).map(ev=>({ev,score:0,flagged:false}));
}

function renderLogSrc(){
 const host=document.getElementById('ls-main');if(!host)return;

 if(!lsHist.length){lsHist=[JSON.stringify({nodes:lsNodes,edges:lsEdges,seq:lsNodeSeq})];lsHistIdx=0;}
 if(lsStep!=='topology')lsStep='topology';
 host.innerHTML=lsTopologyHTML();lsBindCanvas();
 if(lsAnim&&lsAnim.active)lsAnimRenderCaption();
}
function lsSeedTopology(){
 lsNodes=[];lsNodeSeq=1;
 // a realistic starter topology, edge → core, that the analyst edits
 lsAddNode('internet',620,50,false);
 lsAddNode('fw',620,150,false);
 lsAddNode('router',480,150,false);
 lsAddNode('dmz',620,260,false);
 lsAddNode('switch',330,260,false);
 lsAddNode('dc',150,180,false);
 lsAddNode('srv',330,380,false);
 lsAddNode('wks',150,340,false);
 lsAddNode('wks',150,440,false);
 lsAddNode('cloud',620,380,false);
 // seeded topology is the clean baseline - reset undo history
 lsHist=[JSON.stringify({nodes:lsNodes,edges:lsEdges,seq:lsNodeSeq})];lsHistIdx=0;

}
function lsAddNode(type,x,y,rerender=true){
 const t=NODE_TYPES[type];
 const n={uid:'n'+(lsNodeSeq++),type,x:x??(120+Math.random()*360),y:y??(120+Math.random()*240),
   label:t.label,os:t.os[0],obs:[]};
 lsNodes.push(n);
 persistAll();lsSnapshot();
 if(rerender)renderLogSrc();
 return n;
}
function lsDelNode(uid){lsNodes=lsNodes.filter(n=>n.uid!==uid);lsEdges=lsEdges.filter(e=>e.a!==uid&&e.b!==uid);persistAll();lsSnapshot();renderLogSrc();}
function lsSetNodeOS(uid,os){const n=lsNodes.find(x=>x.uid===uid);if(n)n.os=os;persistAll();renderLogSrc();}
function lsSetNodeLabel(uid,label){const n=lsNodes.find(x=>x.uid===uid);if(n)n.label=label;persistAll();}

/* ---- custom edges + connect mode ---- */
function lsToggleConnect(){lsConnectMode=!lsConnectMode;lsConnectFrom=null;lsChainMode=false;renderLogSrc();}
function lsAddEdge(a,b){
 if(a===b)return;
 if(lsEdges.some(e=>(e.a===a&&e.b===b)||(e.a===b&&e.b===a)))return;
 lsEdges.push({a,b});persistAll();lsSnapshot();
}
function lsDelEdge(a,b){lsEdges=lsEdges.filter(e=>!((e.a===a&&e.b===b)||(e.a===b&&e.b===a)));persistAll();lsSnapshot();renderLogSrc();}
function lsNodeClickConnect(uid){
 if(!lsConnectFrom){lsConnectFrom=uid;renderLogSrc();return;}
 if(lsConnectFrom===uid){lsConnectFrom=null;renderLogSrc();return;}
 lsAddEdge(lsConnectFrom,uid);lsConnectFrom=null;renderLogSrc();
}
function lsAutoEdges(){
 // rebuild inferred backbone as real edges the user can then edit
 lsEdges=[];
 const byType=t=>lsNodes.filter(n=>n.type===t);
 const fw=byType('fw')[0],dc=byType('dc')[0],rtr=byType('router')[0],sw=byType('switch')[0],net=byType('internet')[0];
 const add=(a,b)=>{if(a&&b)lsAddEdge(a.uid,b.uid);};
 byType('vpn').forEach(v=>add(net,v));
 add(net,fw);add(fw,rtr);
 byType('dmz').forEach(d=>add(fw||net,d));
 byType('cloud').forEach(c=>add(fw||net,c));
 add(rtr,sw);add(rtr,dc);
 const fabric=sw||dc||rtr;
 lsNodes.filter(n=>['srv','wks','nas','iot'].includes(n.type)).forEach(n=>add(fabric,n));
 add(sw,dc);
 persistAll();renderLogSrc();toast('Auto-connected by network tier - drag or click to adjust');
}
function lsToggleZones(){lsShowZones=!lsShowZones;renderLogSrc();}
/* zone bounding regions for the overlay */
/* ---- ZONES: user-editable. A node's zone defaults to its type's zone but can be
   overridden per node, so a router can sit internal or a server can live in the DMZ. ---- */
const ZONE_DEFAULTS={
 external:{label:'Internet / Untrusted',color:'#ff4d8f',tier:0},
 edge:{label:'Edge / Perimeter',color:'#5cc8ff',tier:1},
 dmz:{label:'DMZ',color:'#ff8a5c',tier:2},
 cloud:{label:'Cloud',color:'#5cc8ff',tier:2},
 core:{label:'Core / Identity',color:'#ffb547',tier:3},
 internal:{label:'Internal',color:'#8b7bff',tier:4}
};
let ZONES={};
function lsLoadZones(){try{const z=JSON.parse(read('aegis-zones','null'));if(z&&typeof z==='object')ZONES=z;}catch{}}
function lsSaveZones(){try{store('aegis-zones',JSON.stringify(ZONES))}catch{}}
/* the effective zone of a node: explicit override, else its type default */
function nodeZone(n){
 const z=n.zone||NODE_TYPES[n.type].zone;
 if(ZONES[z])return z;
 const d=NODE_TYPES[n.type].zone;
 if(ZONES[d])return d;
 return z; // no zone rectangle exists yet - the host still carries its label
}
function zoneLabel(z){return (ZONES[z]&&ZONES[z].label)||z;}
function zoneColor(z){return (ZONES[z]&&ZONES[z].color)||'#8b7bff';}
function zoneTier(z){return (ZONES[z]&&ZONES[z].tier!=null)?ZONES[z].tier:4;}
function lsSetNodeZone(uid,z){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 n.zone=z;persistAll();lsSnapshot();renderLogSrc();
 const nn=lsNodes.find(x=>x.uid===uid);if(nn)renderNodeEditor(nn,NODE_TYPES[nn.type]);
}
async function lsAddZone(){
 const label=await uiPrompt('Name the new zone (e.g. "OT cell", "Finance VLAN", "Branch office"):','');
 if(!label||!label.trim())return null;
 const id='z'+Date.now().toString(36);
 const palette=['#8b7bff','#5cc8ff','#3ddc97','#ffb547','#ff8a5c','#ff4d8f','#9d7bff','#4ecdc4'];
 ZONES[id]={label:label.trim(),color:palette[Object.keys(ZONES).length%palette.length],tier:4};
 lsSaveZones();return id;
}
async function lsRenameZone(z){
 const label=await uiPrompt('Zone name:',zoneLabel(z));
 if(label===null||!label.trim())return;
 ZONES[z].label=label.trim();lsSaveZones();renderLogSrc();openLsZoneMgr();
}
function lsSetZoneColor(z,c){ZONES[z].color=c;lsSaveZones();renderLogSrc();openLsZoneMgr();}
function lsSetZoneTier(z,t){ZONES[z].tier=parseInt(t);lsSaveZones();renderLogSrc();}
async function lsDelZone(z){
 const members=lsNodes.filter(n=>nodeZone(n)===z);
 if(members.length&&!await uiConfirm(`${members.length} host${members.length===1?' is':'s are'} in "${zoneLabel(z)}". Delete the zone and move them to Internal?`))return;
 members.forEach(n=>{n.zone='internal';});
 delete ZONES[z];lsCollapsed.delete(z);lsSaveZones();persistAll();renderLogSrc();openLsZoneMgr();
}
async function lsResetZones(){
 if(!await uiConfirm('Reset zones to the defaults? Custom zones will be removed and their hosts moved to Internal.'))return;
 const keep=new Set(Object.keys(ZONE_DEFAULTS));
 lsNodes.forEach(n=>{if(n.zone&&!keep.has(n.zone))n.zone='internal';});
 ZONES=JSON.parse(JSON.stringify(ZONE_DEFAULTS));Object.keys(ZONES).forEach(z=>{delete ZONES[z].x;delete ZONES[z].y;delete ZONES[z].w;delete ZONES[z].h;});lsSaveZones();persistAll();renderLogSrc();openLsZoneMgr();
}
/* zone manager sheet */
function openLsZoneMgr(){
 let v=document.getElementById('ls-zone-veil');
 if(!v){v=document.createElement('div');v.id='ls-zone-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const cols=['#ff4d8f','#ff8a5c','#ffb547','#3ddc97','#5cc8ff','#8b7bff'];
 v.innerHTML=`<div class="ls-det-sheet">
   <div class="ls-ne-grip" onclick="lsCloseZoneMgr()"></div>
   <div class="ls-det-head">Zones</div>
   <div class="ls-det-sub">Rename, recolour, and reorder your network segments. Assign a host to any zone from its node editor - a router can sit internal, a server can sit in the DMZ.</div>
   ${Object.keys(ZONES).map(z=>{const members=lsNodes.filter(n=>nodeZone(n)===z).length;
     return`<div class="ls-zn-row">
       <span class="ls-grp-dot" style="background:${zoneColor(z)}"></span>
       <span class="ls-zn-name" onclick="lsRenameZone('${z}')" data-tip="Click to rename">${esc(zoneLabel(z))}</span>
       <span class="ls-zn-count">${members} host${members===1?'':'s'}</span>
       <select class="ls-zn-tier" onchange="lsSetZoneTier('${z}',this.value)" data-tip="Layout tier - lower sits nearer the internet">
         ${[0,1,2,3,4].map(t=>`<option value="${t}" ${zoneTier(z)===t?'selected':''}>tier ${t}</option>`).join('')}
       </select>
       <div class="ls-zn-cols">${cols.map(c=>`<button style="background:${c}" onclick="lsSetZoneColor('${z}','${c}')"></button>`).join('')}</div>
       <button class="ls-snap-btn del" onclick="lsDelZone('${z}')" data-tip="Delete zone">×</button>
     </div>`;}).join('')}
   <div style="display:flex;gap:8px;margin-top:12px">
     <button class="btn violet" style="flex:2;justify-content:center" onclick="const z=lsAddZone();if(z){renderLogSrc();openLsZoneMgr();}">＋ New zone</button>
     <button class="btn" style="flex:1;justify-content:center" onclick="lsResetZones()">Reset</button>
   </div>
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseZoneMgr();};
}
function lsCloseZoneMgr(){const v=document.getElementById('ls-zone-veil');if(v)v.classList.remove('open');}
const ZONE_STYLE=new Proxy({},{get:(t,z)=>[zoneColor(z),zoneLabel(z)]});
/* ---- FREE-FORM ZONES ----
   Each zone is a rectangle with its own position and size. Drag its header to move it
   (members travel with it), drag the corner to resize. Nothing is auto-snapped. ---- */
const LS_W=1400, LS_H=900;
function lsZoneRect(z){
 const Z=ZONES[z];if(!Z)return null;
 if(Z.x==null){ // first sight of this zone: lay it out as a band by tier, then it is yours to move
  const tier=zoneTier(z), lanes=5;
  Z.x=40; Z.w=LS_W-80;
  Z.h=Math.round((LS_H-120)/lanes);
  Z.y=30+tier*(Z.h+14);
 }
 return {x:Z.x,y:Z.y,w:Z.w,h:Z.h};
}
function lsZoneAtPoint(x,y){
 // topmost zone whose rectangle contains the point
 // when rectangles overlap, the smallest containing zone wins - it is the most specific
 let hit=null,best=Infinity;
 Object.keys(ZONES).filter(z=>ZONES[z].shown!==false).forEach(z=>{
  const r=lsZoneRect(z);if(!r)return;
  if(x>=r.x&&x<=r.x+r.w&&y>=r.y&&y<=r.y+r.h){
   const area=r.w*r.h;
   if(area<best){best=area;hit=z;}
  }
 });
 return hit;
}
function lsZoneRegions(){
 if(!lsShowZones)return'';
 return Object.keys(ZONES).filter(z=>ZONES[z].shown!==false).map(z=>{
  const r=lsZoneRect(z);if(!r)return'';
  const col=zoneColor(z),label=zoneLabel(z);
  const n=lsNodes.filter(x=>nodeZone(x)===z).length;
  const hot=lsDragZone===z, sel=lsZoneSel===z;
  return `<g class="ls-zone ${hot?'zone-hot':''} ${sel?'zone-sel':''}" data-zone="${z}">
    <rect class="ls-zone-body" data-zone="${z}" x="${r.x}" y="${r.y}" width="${r.w}" height="${r.h}" rx="14"
      fill="${col}" fill-opacity="${hot?0.14:0.05}" stroke="${col}" stroke-opacity="${hot||sel?0.6:0.24}" stroke-width="${hot||sel?2:1.2}"/>
    <text class="ls-zone-label" data-zone="${z}" x="${r.x+14}" y="${r.y+18}" fill="${col}">${esc(label.toUpperCase())}</text>
    <text class="ls-zone-count" x="${r.x+14}" y="${r.y+32}" fill="${col}" opacity="0.55">${n} host${n===1?'':'s'}</text>
    <g class="ls-zone-x" data-zone="${z}">
      <circle cx="${r.x+r.w-16}" cy="${r.y+16}" r="10" fill="${col}" fill-opacity="0.18" stroke="${col}" stroke-opacity="0.5"/>
      <path d="M ${r.x+r.w-20} ${r.y+12} L ${r.x+r.w-12} ${r.y+20} M ${r.x+r.w-12} ${r.y+12} L ${r.x+r.w-20} ${r.y+20}" stroke="${col}" stroke-width="1.7" stroke-linecap="round" fill="none"/>
    </g>
    <g class="ls-zone-grip" data-zone="${z}">
      <rect x="${r.x+r.w-20}" y="${r.y+r.h-20}" width="20" height="20" fill="transparent"/>
      <path d="M ${r.x+r.w-13} ${r.y+r.h-3} L ${r.x+r.w-3} ${r.y+r.h-13} M ${r.x+r.w-7} ${r.y+r.h-3} L ${r.x+r.w-3} ${r.y+r.h-7}" stroke="${col}" stroke-opacity="0.7" stroke-width="1.6" fill="none" stroke-linecap="round"/>
    </g>
  </g>`;
 }).join('');
}
async function lsDeleteZone(z){
 const members=lsNodes.filter(n=>nodeZone(n)===z).length;
 const msg=members?`Delete the zone "${zoneLabel(z)}"?\n\n${members} host${members===1?' stays on the map and moves':'s stay on the map and move'} to Internal. The hosts themselves are not deleted.`
                  :`Delete the empty zone "${zoneLabel(z)}"?`;
 if(!await uiConfirm(msg,{title:'Delete zone?',ok:'Delete zone',danger:true}))return;
 lsNodes.forEach(n=>{if(nodeZone(n)===z)n.zone='internal';});
 delete ZONES[z];lsCollapsed.delete(z);if(lsZoneSel===z)lsZoneSel=null;
 lsSaveZones();persistAll();lsSnapshot();renderLogSrc();toast('Zone deleted');
}
/* move every node that belongs to a zone by the same delta */
function lsMoveZoneNodes(z,dx,dy){
 lsNodes.forEach(n=>{if(nodeZone(n)===z){n.x+=dx;n.y+=dy;}});
}
function lsPresetZones(){
 const order=['external','edge','dmz','cloud','core','internal'];
 const h=Math.round((LS_H-40)/order.length)-14;
 order.forEach((z,i)=>{
  const d=ZONE_DEFAULTS[z];
  ZONES[z]={label:d.label,color:d.color,tier:d.tier,x:40,y:24+i*(h+14),w:LS_W-80,h:h};
 });
 lsSaveZones();persistAll();renderLogSrc();toast('Standard zones added');
}
async function lsAddZoneAt(){
 // lsAddZone() is async (it prompts for a name); the old code used the returned
 // Promise as an object key, so a zone added from the toolbar never got its
 // rectangle and could not be placed. Await it.
 const id=await lsAddZone();
 if(!id)return;
 // Drop the new zone somewhere visible in the current viewport rather than a
 // fixed corner it might be scrolled away from.
 ZONES[id].x=60;ZONES[id].y=60;ZONES[id].w=420;ZONES[id].h=200;
 if(!lsShowZones)lsShowZones=true;   // make sure zones are visible, or the new one is invisible
 lsSaveZones();renderLogSrc();toast('Zone added \u2014 drag its header to place it, drag hosts into it');
}
/* auto-arrange: lay zones out as bands and spread hosts inside their own zone */
function lsArrange(){
 const zs=Object.keys(ZONES).filter(z=>ZONES[z].shown!==false).sort((a,b)=>zoneTier(a)-zoneTier(b));
 const h=Math.round((LS_H-40)/Math.max(1,zs.length))-14;
 zs.forEach((z,i)=>{const Z=ZONES[z];Z.x=40;Z.w=LS_W-80;Z.h=h;Z.y=24+i*(h+14);});
 zs.forEach(z=>{
  const r=lsZoneRect(z);
  const ns=lsNodes.filter(x=>nodeZone(x)===z);
  ns.forEach((n,i)=>{
   const cols=Math.max(1,Math.floor((r.w-100)/150));
   const col=i%cols, row=Math.floor(i/cols);
   n.x=r.x+80+col*150;
   n.y=r.y+58+row*82;
  });
 });
 lsSaveZones();persistAll();lsSnapshot();renderLogSrc();toast('Zones and hosts arranged');
}
function lsMoveZone(z,dir){
 const order=Object.keys(ZONES).filter(x=>ZONES[x].shown!==false).sort((a,b)=>zoneTier(a)-zoneTier(b));
 const i=order.indexOf(z),j=i+dir;
 if(i<0||j<0||j>=order.length)return;
 const ta=zoneTier(z),tb=zoneTier(order[j]);
 ZONES[z].tier=tb;ZONES[order[j]].tier=ta===tb?tb+dir:ta;
 lsSaveZones();renderLogSrc();
 const v=document.getElementById('ls-zone-veil');if(v&&v.classList.contains('open'))openLsZoneMgr();
}
