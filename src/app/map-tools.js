/* ===== NEW: 1. host search / filter on the map ===== */
let lsQuery='';
function lsSearch(v){lsQuery=(v||'').toLowerCase().trim();lsApplyFilter();}
function lsApplyFilter(){
 const svg=document.getElementById('ls-svg');if(!svg)return;
 svg.querySelectorAll('.ls-node').forEach(g=>{
  const n=lsNodes.find(x=>x.uid===g.getAttribute('data-uid'));if(!n)return;
  const hit=!lsQuery||[n.label,n.os,NODE_TYPES[n.type].label,zoneLabel(nodeZone(n))].join(' ').toLowerCase().includes(lsQuery);
  g.classList.toggle('filtered-out',!hit);
  g.classList.toggle('filter-hit',!!lsQuery&&hit);
 });
 const c=document.getElementById('ls-findcount');
 if(c)c.textContent=lsQuery?`${lsNodes.filter(n=>[n.label,n.os,NODE_TYPES[n.type].label,zoneLabel(nodeZone(n))].join(' ').toLowerCase().includes(lsQuery)).length} match`:'';
}
/* ===== NEW: 2. multi-select + bulk actions ===== */
let lsSel=new Set();
function lsToggleSel(uid,additive){
 if(!additive)lsSel.clear();
 lsSel.has(uid)?lsSel.delete(uid):lsSel.add(uid);
 renderLogSrc();
}
function lsSelClear(){lsSel.clear();renderLogSrc();}
function lsSelAll(){lsSel=new Set(lsNodes.map(n=>n.uid));renderLogSrc();}
function lsBulkZone(z){
 if(!lsSel.size)return;
 lsNodes.forEach(n=>{if(lsSel.has(n.uid))n.zone=z;});
 persistAll();lsSnapshot();renderLogSrc();toast(`${lsSel.size} host${lsSel.size===1?'':'s'} \u2192 ${zoneLabel(z)}`);
}
async function lsBulkDelete(){
 if(!lsSel.size)return;
 if(!await uiConfirm('Their links and any logged observations go with them.',{title:`Delete ${lsSel.size} selected host${lsSel.size===1?'':'s'}?`,ok:'Delete',danger:true}))return;
 lsNodes=lsNodes.filter(n=>!lsSel.has(n.uid));
 lsEdges=lsEdges.filter(e=>!lsSel.has(e.a)&&!lsSel.has(e.b));
 lsSel.clear();persistAll();lsSnapshot();renderLogSrc();
}
/* ===== NEW: 3. duplicate a host ===== */
function lsDuplicate(uid){
 const n=lsNodes.find(x=>x.uid===uid);if(!n)return;
 const c=JSON.parse(JSON.stringify(n));
 c.uid='n'+(lsNodeSeq++);c.x=n.x+70;c.y=n.y+50;
 c.obs=[];c.label=n.label.replace(/-(\d+)$/,'')+'-'+(lsNodes.filter(x=>x.type===n.type).length+1);
 lsNodes.push(c);persistAll();lsSnapshot();renderLogSrc();toast('Host duplicated');
}
/* ===== NEW: 4. keyboard shortcuts on the map ===== */
function lsKeys(e){
 if(document.getElementById('v-logsrc')&&!document.getElementById('v-logsrc').classList.contains('on'))return;
 const tag=(e.target.tagName||'').toLowerCase();
 if(tag==='input'||tag==='textarea'||tag==='select')return;
 if(e.key==='Delete'||e.key==='Backspace'){if(lsSel.size){e.preventDefault();lsBulkDelete();}}
 else if(e.key==='Escape'){lsSel.clear();lsZoneSel=null;lsConnectMode=false;lsChainMode=false;renderLogSrc();}
 else if((e.ctrlKey||e.metaKey)&&e.key==='d'){if(lsSel.size===1){e.preventDefault();lsDuplicate([...lsSel][0]);}}
 else if((e.ctrlKey||e.metaKey)&&e.key==='a'){e.preventDefault();lsSelAll();}
 else if(e.key==='f'&&!e.ctrlKey&&!e.metaKey){const s=document.getElementById('ls-find');if(s){e.preventDefault();s.focus();}}
}
/* ===== add-host menu =====
   Lives here rather than in the triage wizard it used to share a file with -
   it is a map function and always was. */
function openLsAddMenu(){
 let v=document.getElementById('ls-add-veil');
 if(!v){v=document.createElement('div');v.id='ls-add-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-add-sheet">
   <div class="ls-ne-grip" onclick="lsCloseAddMenu()"></div>
   <div class="ls-add-head">Add a host</div>
   ${NODE_GROUPS.map(([grp,keys])=>`<div class="ls-addgrp">${grp}</div><div class="ls-addgrid">${keys.filter(k=>NODE_TYPES[k]).map(k=>`<button class="ls-addcard" onclick="lsAddNode('${k}');lsCloseAddMenu()">
     <span class="ls-addg">${NODE_TYPES[k].glyph}</span>
     <span class="ls-addname">${esc(NODE_TYPES[k].label)}</span>
   </button>`).join('')}</div>`).join('')}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseAddMenu();};
}
function lsCloseAddMenu(){const v=document.getElementById('ls-add-veil');if(v)v.classList.remove('open');}
function lsToggleAddMenu(){openLsAddMenu();}

/** Infer a node type from a hostname. Used by the ingest wizard when it meets
    a host it has not seen before. */
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
 return'srv';
}

/* ===== NEW: 5. zoom to fit everything ===== */
function lsZoomFit(){
 if(!lsNodes.length){lsZoomReset();return;}
 const pad=70;
 const xs=lsNodes.map(n=>n.x),ys=lsNodes.map(n=>n.y);
 Object.keys(ZONES).filter(z=>ZONES[z].shown!==false).forEach(z=>{const r=lsZoneRect(z);if(r){xs.push(r.x,r.x+r.w);ys.push(r.y,r.y+r.h);}});
 const x0=Math.min(...xs)-pad,x1=Math.max(...xs)+pad,y0=Math.min(...ys)-pad,y1=Math.max(...ys)+pad;
 const w=Math.max(1,x1-x0),h=Math.max(1,y1-y0);
 lsZoom=Math.max(0.25,Math.min(2,Math.min(LS_W/w,LS_H/h)));
 lsPanX=-x0*lsZoom+(LS_W-w*lsZoom)/2;
 lsPanY=-y0*lsZoom+(LS_H-h*lsZoom)/2;
 lsApplyZoom();
}
/* ===== NEW: 6. export the map as an SVG image ===== */
function lsExportImage(){
 const svg=document.getElementById('ls-svg');if(!svg){toast('Nothing to export');return;}
 const clone=svg.cloneNode(true);
 clone.setAttribute('xmlns','http://www.w3.org/2000/svg');
 clone.querySelectorAll('.ls-zone-grip').forEach(el=>el.remove());
 const css=`<style>text{font-family:'IBM Plex Mono',monospace}.ls-node-box{fill:#12121c;stroke:#2a2a3d;stroke-width:1.5}
 .ls-node-glyph{font-size:17px}.ls-node-label{fill:#e8e8f0;font-size:11px;font-family:'Sora',sans-serif;font-weight:600}
 .ls-node-os{fill:#7a7a92;font-size:8px}.ls-edge{stroke:#2a2a3d;stroke-width:1.5}
 .ls-badge-c{fill:#1a1a28;stroke:#8b7bff}.ls-badge-t{fill:#8b7bff;font-size:9px}</style>`;
 const out=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${LS_W} ${LS_H}" width="${LS_W}" height="${LS_H}"><rect width="100%" height="100%" fill="#0a0a12"/>${css}${clone.innerHTML}</svg>`;
 const blob=new Blob([out],{type:'image/svg+xml'});
 const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='aegis-network-map.svg';a.click();
 URL.revokeObjectURL(a.href);toast('Map exported as SVG');
}
/* ===== NEW: 7. grid + snap ===== */
let lsGrid=false;
function lsToggleGrid(){lsGrid=!lsGrid;renderLogSrc();}
function lsGridSVG(){
 if(!lsGrid)return'';
 let o='<g class="ls-grid">';
 for(let x=0;x<=LS_W;x+=50)o+=`<line x1="${x}" y1="0" x2="${x}" y2="${LS_H}"/>`;
 for(let y=0;y<=LS_H;y+=50)o+=`<line x1="0" y1="${y}" x2="${LS_W}" y2="${y}"/>`;
 return o+'</g>';
}
/* ===== NEW: 8. edge labels (protocol / port) ===== */
function lsEdgeLabel(e){
 const a=lsNodes.find(x=>x.uid===e.a),b=lsNodes.find(x=>x.uid===e.b);
 if(!a||!b||!e.label)return'';
 return `<text class="ls-edge-lbl" x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-6}" text-anchor="middle">${esc(e.label)}</text>`;
}
async function lsLabelEdge(ai,bi){
 const e=lsEdges.find(x=>(x.a===ai&&x.b===bi)||(x.a===bi&&x.b===ai));if(!e)return;
 const v=await uiPrompt('Label this link (e.g. "SMB 445", "trunk", "VPN tunnel"):',e.label||'');
 if(v===null)return;e.label=v.trim();persistAll();renderLogSrc();
}
/* ===== NEW: 9. empty state ===== */
function lsEmptyStateHTML(){
 return `<div class="ls-empty">
   <div class="ls-empty-ic">\u25f3</div>
   <h3>Your map is empty</h3>
   <p>Build the network you're hunting on. Everything else in AEGIS \u2014 coverage, triage, the attack trace \u2014 works off this picture.</p>
   <div class="ls-empty-acts">
     <button class="btn violet" onclick="openLsTemplates()">\u29c9 Start from a template</button>
     <button class="btn ghost-violet" onclick="aiProposeMap()">\u2726 Describe it to the AI</button>
     <button class="btn ghost-violet" onclick="openLsAddMenu()">\uff0b Add hosts manually</button>
     <button class="btn ghost-violet" onclick="lsPresetZones()">\u25a4 Add the standard zones</button>
     <button class="btn ghost-violet" onclick="lsSeedTopology();persistAll();renderLogSrc();toast('Sample network loaded')">\u25f1 Load a sample network</button>
   </div>
 </div>`;
}
/* ===== NEW: 10. incident summary strip ===== */
function lsIncidentStrip(){
 const mal=lsNodes.filter(n=>lsNodeStatus(n)==='malicious').length;
 const sus=lsNodes.filter(n=>lsNodeStatus(n)==='suspicious').length;
 const obs=lsNodes.reduce((a,n)=>a+lsNodeObs(n).length,0);
 if(!obs)return'';
 const worst=mal?'malicious':sus?'suspicious':'info';
 return `<div class="ls-incstrip sev-${worst}">
   <span class="ls-inc-dot"></span>
   <b>${obs}</b> observation${obs===1?'':'s'} across <b>${lsNodes.filter(n=>lsNodeObs(n).length).length}</b> host${lsNodes.filter(n=>lsNodeObs(n).length).length===1?'':'s'}
   ${mal?`<span class="ls-inc-tag mal">${mal} compromised</span>`:''}
   ${sus?`<span class="ls-inc-tag sus">${sus} suspicious</span>`:''}
   <button class="ls-inc-act" onclick="analyzeIncident()">Analyse \u2192</button>
 </div>`;
}



/* consolidated map menu - keeps the toolbar to what you touch constantly */
function openLsMapMenu(){
 let v=document.getElementById('ls-map-veil');
 if(!v){v=document.createElement('div');v.id='ls-map-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 const row=(icon,label,fn,on,note)=>`<button class="ls-mm-item ${on?'on':''}" onclick="${fn}">
   <span class="ls-mm-ic">${icon}</span><span><b>${label}</b>${note?`<small>${note}</small>`:''}</span>${on?'<span class="ls-mm-on">on</span>':''}</button>`;
 v.innerHTML=`<div class="ls-det-sheet">
   <div class="ls-ne-grip" onclick="lsCloseMapMenu()"></div>
   <div class="ls-det-head">Map options</div>
   <div class="ls-mm-sec">Size &amp; view</div>
   <div class="ls-mm-scale">
     <span>Host size</span>
     <div class="ls-toolgrp">
       <button class="${lsNodeScale===0.8?'on':''}" onclick="lsSetNodeScale(0.8);openLsMapMenu()">Small</button>
       <button class="${lsNodeScale===1?'on':''}" onclick="lsSetNodeScale(1);openLsMapMenu()">Normal</button>
       <button class="${lsNodeScale===1.3?'on':''}" onclick="lsSetNodeScale(1.3);openLsMapMenu()">Large</button>
     </div>
   </div>
   ${row('\u26f6','Zoom to fit','lsZoomFit();lsCloseMapMenu()',false,'Frame everything on screen')}
   ${row('\u25a6','Alignment grid','lsToggleGrid();openLsMapMenu()',lsGrid)}
   ${row('\u25a4','Zone regions','lsToggleZones();openLsMapMenu()',lsShowZones)}
   ${row('\ud83d\udd25','Risk heat','lsToggleHeat();openLsMapMenu()',lsHeatOn,'Exposure vs telemetry coverage')}
   <div class="ls-mm-sec">Zones</div>
   ${row('\uff0b','Add a zone','lsAddZoneAt();lsCloseMapMenu()',false,'Draw your own segment')}
   ${row('\u25a4','Add the standard zones','lsPresetZones();lsCloseMapMenu()',false,'Internet \u2192 Edge \u2192 DMZ \u2192 Cloud \u2192 Core \u2192 Internal')}
   ${row('\u2699','Edit zones','openLsZoneMgr();lsCloseMapMenu()',false,'Rename, recolour, reorder, collapse')}
   ${row('\u2637','Arrange hosts','lsArrange();lsCloseMapMenu()',false,'Tidy every host into its zone')}
   ${row('\u229f','Auto-link by tier','lsAutoEdges();lsCloseMapMenu()')}
   <div class="ls-mm-sec">Detection</div>
   ${row('\u2913','Ingest a tool export','openLsIngest();lsCloseMapMenu()',false,'Chainsaw, Suricata eve.json, Zeek logs, or a PCAP \u2014 parsed offline, right here')}
   ${row('\u26a0','Logging posture','openLoggingGaps();lsCloseMapMenu()',false,'Which hosts are missing Sysmon, 4104, 5145')}
   <div class="ls-mm-sec">Case</div>
   ${row('\u25f7','Snapshots','openLsSnaps();lsCloseMapMenu()',false,'Freeze, compare or roll back')}
   ${row('\u2913','Export as image','lsExportImage();lsCloseMapMenu()')}
   ${row('\u2699','Logging plan','lsBuildFromTopo();lsCloseMapMenu()',false,'Which Event IDs to enable first')}
   ${row('\u25f1','Load a sample network','lsSeedTopology();persistAll();renderLogSrc();lsCloseMapMenu()')}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)lsCloseMapMenu();};
}
function lsCloseMapMenu(){const v=document.getElementById('ls-map-veil');if(v)v.classList.remove('open');}
/* ---- pan tool, zoom + node sizing ---- */
function lsSetTool(x){lsTool=x;renderLogSrc();}
function lsSetNodeScale(v){lsNodeScale=parseFloat(v);persistAll();renderLogSrc();}
function lsZoomPct(){return Math.round(lsZoom*100);}
function lsPanBegin(e,svg){
 const cx=(e.touches?e.touches[0].clientX:e.clientX),cy=(e.touches?e.touches[0].clientY:e.clientY);
 lsPan={sx:cx,sy:cy,px:lsPanX,py:lsPanY};
}
function lsPanMove(e,svg){
 if(!lsPan)return;
 const r=svg.getBoundingClientRect();
 const cx=(e.touches?e.touches[0].clientX:e.clientX),cy=(e.touches?e.touches[0].clientY:e.clientY);
 lsPanX=lsPan.px+(cx-lsPan.sx)/r.width*LS_W;
 lsPanY=lsPan.py+(cy-lsPan.sy)/r.height*LS_H;
 lsApplyZoom();
}
