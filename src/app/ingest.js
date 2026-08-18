/* ================= INGEST ================= */
/* Offline, zero-dependency parsers for external tool exports: a Chainsaw
   (WithSecure) Sigma-hunt CSV/JSON, Suricata eve.json, Zeek TSV/JSON logs,
   and a classic PCAP capture. Runs entirely in the browser — paste or drop a
   file, get back a uniform {timeline, iocs, findings, events} — then commit
   builds/extends the hunt map and logs findings as node observations.
   Ported from Skyhawk's domain/ingest.js; reuses AEGIS's own IOC regexes
   (ioc.js) and host-type guesser (lsGuessType) instead of parallel copies,
   and the PCAP byte-reader uses DataView instead of Node's Buffer so it
   runs unmodified in a browser with no bundler. */

/* ---------- readers (no deps) ---------- */
function ingParseCsv(text){
 const rows=[];let row=[],field='',inQ=false;
 const s=(text||'').replace(/^﻿/,'');
 for(let i=0;i<s.length;i++){
  const c=s[i];
  if(inQ){if(c==='"'){if(s[i+1]==='"'){field+='"';i++;}else inQ=false;}else field+=c;}
  else if(c==='"')inQ=true;
  else if(c===','){row.push(field);field='';}
  else if(c==='\n'||c==='\r'){
   if(c==='\r'&&s[i+1]==='\n')i++;
   row.push(field);field='';
   if(row.length>1||row[0]!=='')rows.push(row);
   row=[];
  }else field+=c;
 }
 if(field.length||row.length){row.push(field);if(row.length>1||row[0]!=='')rows.push(row);}
 if(!rows.length)return{header:[],rows:[]};
 const header=rows[0].map(h=>h.trim());
 const out=rows.slice(1).map(r=>{const o={};header.forEach((h,i)=>{o[h]=r[i]!=null?r[i]:'';});return o;});
 return{header,rows:out};
}
function ingParseJsonish(text){
 const t=(text||'').trim();
 if(!t)return[];
 if(t[0]!=='['&&t.indexOf('\n')>0){
  const lines=t.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
  const objs=[];
  for(const l of lines){try{objs.push(JSON.parse(l));}catch{}}
  if(objs.length)return objs;
 }
 try{const v=JSON.parse(t);return Array.isArray(v)?v:[v];}catch{return[];}
}

/* ---------- shared helpers ---------- */
const ING_ATTACK_RE=/\bT\d{4}(?:\.\d{3})?\b/gi;
const ING_LEVEL_RANK={critical:4,high:3,medium:2,low:1,informational:0,info:0};
const ingNormLevel=l=>{const x=String(l||'').toLowerCase().trim();return['critical','high','medium','low'].includes(x)?x:(x==='informational'||x==='info'?'low':'');};
const ingCi=(obj,...names)=>{
 const keys=Object.keys(obj||{});
 for(const n of names){const k=keys.find(k=>k.toLowerCase()===n.toLowerCase());if(k!=null&&obj[k]!==''&&obj[k]!=null)return obj[k];}
 return'';
};
const ingToIso=v=>{if(!v)return null;const d=new Date(String(v).replace(' ','T'));return isNaN(d)?null:d.toISOString();};
/* reuses ioc.js's extractIocs() + the private-IP filter it already applies to ipv4 */
function ingPushIocs(text,into,seen){
 if(!text)return;
 extractIocs(text).forEach(x=>{const k=x.type+':'+x.value.toLowerCase();if(seen.has(k))return;seen.add(k);into.push(x);});
}
const ingHostAsset=name=>({type:lsGuessType(name),name:String(name).slice(0,80),ip:''});
const ingIpAsset=ip=>({type:IOC_PRIVATE_IP.test(ip)?'srv':'dmz',name:ip,ip});
const ingMkEvent=(source,type,o)=>({ts:o.ts||null,source,type:type||'',host:o.host||o.saddr||'',saddr:o.saddr||'',sport:o.sport!=null?String(o.sport):'',daddr:o.daddr||'',dport:o.dport!=null?String(o.dport):'',proto:(o.proto||'').toString().toLowerCase(),msg:(o.msg||'').toString().slice(0,300),attack:o.attack||[],fields:o.fields||{}});

/* ---------- network map extraction (hosts -> AEGIS map nodes/edges) ---------- */
function ingMapEvents(events){
 const capNodes=48,capEdges=90;
 const byIp={};lsNodes.forEach(n=>{if(n.ip)byIp[n.ip.toLowerCase()]=n;});
 let added=0;
 const ensure=ip=>{
  if(!ip||ip==='-')return null;
  const k=ip.toLowerCase();
  if(byIp[k])return byIp[k];
  if(lsNodes.length>=capNodes)return null;
  const a=ingIpAsset(ip);
  const n=lsAddNode(a.type,120+(added%8)*150,120+Math.floor(added/8)*110,false);
  n.label=ip;n.ip=ip;added++;
  byIp[k]=n;return n;
 };
 const ordered=events.slice().sort((a,b)=>((b.attack&&b.attack.length)?1:0)-((a.attack&&a.attack.length)?1:0));
 let edgesAdded=0;
 for(const ev of ordered){
  if(!ev.saddr||!ev.daddr)continue;
  const a=ensure(ev.saddr),b=ensure(ev.daddr);
  if(!a||!b||a===b)continue;
  if(lsEdges.some(e=>(e.a===a.uid&&e.b===b.uid)||(e.a===b.uid&&e.b===a.uid)))continue;
  if(edgesAdded>=capEdges)break;
  lsAddEdge(a.uid,b.uid);edgesAdded++;
 }
 return{nodesAdded:added,edgesAdded};
}

/* ---------- Chainsaw profile ---------- */
function ingHitsToItems(hits){
 const timeline=[],iocs=[],iocSeen=new Set(),byRule={};
 for(const h of hits){
  const bits=[];
  if(h.eid)bits.push('EID '+h.eid);
  if(h.user)bits.push('user '+h.user);
  if(h.srcip)bits.push('src '+h.srcip);
  if(h.cmd)bits.push(String(h.cmd).slice(0,160));
  const text=h.rule+(h.host?' on '+h.host:'')+(bits.length?' — '+bits.join(' · '):'');
  timeline.push({at:h.at||new Date().toISOString(),text:text.slice(0,500),source:'Chainsaw',level:h.level});
  ingPushIocs([h.srcip,h.cmd,h.blob].join(' '),iocs,iocSeen);
  const key=h.rule;
  const g=byRule[key]||(byRule[key]={rule:key,hosts:new Set(),count:0,level:'',attack:new Set(),first:null,last:null,sampleCmd:''});
  g.count++;
  if(h.host)g.hosts.add(h.host);
  if(ING_LEVEL_RANK[h.level]>(ING_LEVEL_RANK[g.level]||-1))g.level=h.level;
  (h.attack||[]).forEach(t=>g.attack.add(t));
  if(h.at){if(!g.first||h.at<g.first)g.first=h.at;if(!g.last||h.at>g.last)g.last=h.at;}
  if(!g.sampleCmd&&h.cmd)g.sampleCmd=String(h.cmd).slice(0,200);
 }
 const findings=Object.values(byRule).map(g=>{
  const hosts=[...g.hosts];
  const when=g.first?(g.first===g.last?g.first:g.first+' → '+g.last):'';
  return{
   title:g.rule.slice(0,200),severity:g.level||'medium',
   technicalDetail:`Chainsaw flagged ${g.count} matching event${g.count>1?'s':''}`+
    (hosts.length?` on ${hosts.join(', ')}`:'')+(when?` (${when})`:'')+'.'+
    (g.sampleCmd?`\nSample: ${g.sampleCmd}`:''),
   attack:[...g.attack],assets:hosts.map(ingHostAsset),_count:g.count,
  };
 }).sort((a,b)=>(ING_LEVEL_RANK[b.severity]||0)-(ING_LEVEL_RANK[a.severity]||0)||b._count-a._count);
 return{timeline,iocs,findings};
}
const ING_CHAINSAW={
 id:'chainsaw',label:'Chainsaw (Sigma hunt)',
 detect(text,filename,csv,json){
  const f=(filename||'').toLowerCase();
  if(csv&&csv.header.length){
   const h=csv.header.map(x=>x.toLowerCase());
   if(h.includes('detections')&&h.includes('timestamp'))return true;
  }
  if(json&&json.length){const d=json[0];if(d&&(d.detections||d.document||(d.kind&&d.data)))return true;}
  return/chainsaw/.test(f);
 },
 normalize(text,filename,csv,json){
  const hits=[];
  if(csv&&csv.rows.length){
   for(const r of csv.rows){
    const at=ingToIso(ingCi(r,'timestamp','SystemTime','Event Time','time'));
    const rule=ingCi(r,'detections','detection','rule','title')||'Chainsaw detection';
    const host=ingCi(r,'Computer','Computer Name','Hostname','host');
    const user=ingCi(r,'User','User Name','Account','TargetUserName','SubjectUserName');
    const srcip=ingCi(r,'Source IP','SourceIp','IpAddress','Source Address');
    const eid=ingCi(r,'Event ID','EventID','Event Id');
    const cmd=ingCi(r,'Command Line','CommandLine','ProcessCommandLine','Information','Details');
    const level=ingNormLevel(ingCi(r,'level','Level','severity'));
    const tags=ingCi(r,'tags','Tags','attack','mitre');
    const blob=[rule,host,user,srcip,eid,cmd,tags,JSON.stringify(r)].join(' ');
    hits.push({at,rule,host,user,srcip,eid,cmd,level,attack:[...new Set((blob.match(ING_ATTACK_RE)||[]).map(t=>t.toUpperCase()))],blob});
   }
  }
  if(json&&json.length){
   for(const d of json){
    const dataDoc=(d.document&&d.document.data)||d.data||d;
    const ev=dataDoc&&dataDoc.Event?dataDoc.Event:dataDoc;
    const sys=(ev&&ev.System)||{};
    const edata=(ev&&ev.EventData)||{};
    const at=ingToIso(d.timestamp||(sys.TimeCreated&&(sys.TimeCreated['#attributes']?sys.TimeCreated['#attributes'].SystemTime:sys.TimeCreated))||d.SystemTime);
    const detArr=d.detections||d.rules||[];
    const rule=Array.isArray(detArr)?detArr.map(x=>(typeof x==='string'?x:(x.name||x.title))).filter(Boolean).join('; '):String(detArr||'Chainsaw detection');
    const level=ingNormLevel(Array.isArray(detArr)&&detArr[0]&&detArr[0].level);
    const host=sys.Computer||ingCi(edata,'Computer','Hostname')||'';
    const user=ingCi(edata,'TargetUserName','SubjectUserName','User')||'';
    const srcip=ingCi(edata,'IpAddress','SourceIp','SourceAddress')||'';
    const eid=(sys.EventID&&(sys.EventID['#text']||sys.EventID))||'';
    const cmd=ingCi(edata,'CommandLine','ProcessCommandLine','Image')||'';
    const blob=JSON.stringify(d);
    hits.push({at,rule:rule||'Chainsaw detection',host,user,srcip,eid,cmd,level,attack:[...new Set((blob.match(ING_ATTACK_RE)||[]).map(t=>t.toUpperCase()))],blob});
   }
  }
  return ingHitsToItems(hits);
 },
};

/* ---------- Suricata eve.json profile ---------- */
const ING_SURICATA={
 id:'suricata',label:'Suricata IDS (eve.json)',
 detect(text,filename,csv,json){
  if(json&&json.some(d=>d&&d.event_type&&(d.alert||d.flow_id||d.src_ip)))return true;
  return/eve\.json|suricata/i.test(filename||'');
 },
 normalize(text,filename,csv,json){
  const rows=json||[];
  const SEV={1:'high',2:'medium',3:'low',4:'low'};
  const timeline=[],iocs=[],seen=new Set(),g={},events=[];
  for(const e of rows){
   if(!e||typeof e!=='object'||!e.event_type)continue;
   const at=ingToIso(e.timestamp);
   const et=e.event_type;
   let msg=et,attack=[];
   if(et==='alert'&&e.alert){
    const a=e.alert;
    msg=a.signature||'alert';
    attack=[...new Set(((a.metadata&&(a.metadata.mitre_technique_id||a.metadata.mitre_technique_ids))||[]).map(x=>String(x).toUpperCase()).filter(x=>/^T\d{4}(\.\d{3})?$/.test(x)))];
    const sev=SEV[a.severity]||'medium';
    ingPushIocs([e.src_ip,e.dest_ip,e.dns&&e.dns.rrname,e.http&&e.http.hostname,e.tls&&e.tls.sni,
     e.fileinfo&&[e.fileinfo.md5,e.fileinfo.sha1,e.fileinfo.sha256].filter(Boolean).join(' ')].filter(Boolean).join(' '),iocs,seen);
    const flow=`${e.src_ip||'?'}:${e.src_port||''} -> ${e.dest_ip||'?'}:${e.dest_port||''} ${e.proto||''}${e.app_proto?'/'+e.app_proto:''}`.trim();
    timeline.push({at:at||new Date().toISOString(),text:`${msg} — ${flow}`.slice(0,500),source:'suricata'});
    const it=g[msg]||(g[msg]={sig:msg,sev:'',attack:new Set(),hosts:new Set(),count:0,cat:a.category||'',sample:flow,first:null,last:null});
    it.count++;
    if((ING_LEVEL_RANK[sev]||0)>(ING_LEVEL_RANK[it.sev]||-1))it.sev=sev;
    attack.forEach(t=>it.attack.add(t));
    [e.src_ip,e.dest_ip].forEach(ip=>{if(ip)it.hosts.add(ip);});
    if(at){if(!it.first||at<it.first)it.first=at;if(!it.last||at>it.last)it.last=at;}
   }else if(et==='dns'&&e.dns){msg=`DNS ${e.dns.rrtype||''} ${e.dns.rrname||''}`.trim();}
   else if(et==='http'&&e.http){msg=`HTTP ${e.http.http_method||''} ${e.http.hostname||''}${e.http.url||''}`.trim();}
   else if(et==='tls'&&e.tls){msg=`TLS ${e.tls.sni||e.tls.subject||''}`.trim();}
   else if(et==='fileinfo'&&e.fileinfo){msg=`file ${e.fileinfo.filename||''}`.trim();}
   else if(et==='flow'){msg=`flow ${e.proto||''}`.trim();}
   events.push(ingMkEvent('suricata',et,{ts:at,saddr:e.src_ip,sport:e.src_port,daddr:e.dest_ip,dport:e.dest_port,proto:e.proto,msg,attack,
    fields:{app_proto:e.app_proto,sni:e.tls&&e.tls.sni,host:e.http&&e.http.hostname,dns:e.dns&&e.dns.rrname}}));
  }
  const findings=Object.values(g).map(x=>{
   const hosts=[...x.hosts],when=x.first?(x.first===x.last?x.first:x.first+' -> '+x.last):'';
   return{title:x.sig.slice(0,200),severity:x.sev||'medium',attack:[...x.attack],
    assets:hosts.map(ingIpAsset),
    technicalDetail:`Suricata network alert${x.cat?' ('+x.cat+')':''}: ${x.count} hit${x.count>1?'s':''}${when?' ('+when+')':''}.${x.sample?'\nFlow: '+x.sample:''}`,_n:x.count};
  }).sort((a,b)=>(ING_LEVEL_RANK[b.severity]||0)-(ING_LEVEL_RANK[a.severity]||0)||b._n-a._n)
   .map(f=>{delete f._n;return f;});
  return{timeline,iocs,findings,events};
 },
};

/* ---------- Zeek profile ---------- */
const ING_ZEEK={
 id:'zeek',label:'Zeek network logs',
 detect(text,filename,csv,json){
  if(/#fields|#separator|#path\b/.test(text||''))return true;
  if(json&&json.some(d=>d&&(d['id.orig_h']||d._path||(d.id&&d.id.orig_h))))return true;
  return/\bzeek\b|conn\.log|dns\.log|http\.log|ssl\.log|notice\.log/i.test(filename||'');
 },
 normalize(text,filename,csv,json){
  const recs=[];
  let path=(filename||'').replace(/^.*[\\/]/,'').replace(/\.log(\.gz)?$/i,'')||'zeek';
  if(/#fields/.test(text||'')){
   let fields=null;const lines=(text||'').split(/\r?\n/);
   for(const line of lines){
    if(!line)continue;
    if(line[0]==='#'){const m=/^#fields\t(.+)$/.exec(line);if(m)fields=m[1].split('\t');const p=/^#path\t(.+)$/.exec(line);if(p)path=p[1].trim();continue;}
    if(!fields)continue;
    const cols=line.split('\t');const o={};fields.forEach((f,i)=>{o[f]=cols[i];});
    recs.push(o);
   }
  }else if(json&&json.length){
   json.forEach(d=>{if(d&&typeof d==='object'){if(d._path)path=d._path;recs.push(d);}});
  }
  const G=(o,k)=>{const v=o[k]!=null?o[k]:(o.id&&o.id[k.replace('id.','')]);return v==null||v==='-'?'':String(v);};
  const timeline=[],iocs=[],seen=new Set(),events=[],notices={};
  for(const o of recs){
   const at=o.ts?ingToIso(new Date(Number(o.ts)*1000).toISOString()):null;
   const saddr=G(o,'id.orig_h'),daddr=G(o,'id.resp_h'),sport=G(o,'id.orig_p'),dport=G(o,'id.resp_p');
   const proto=G(o,'proto');
   let msg=path;
   if(path==='dns'){msg=`DNS ${G(o,'qtype_name')||''} ${G(o,'query')}`.trim();ingPushIocs(G(o,'query'),iocs,seen);}
   else if(path==='http'){msg=`HTTP ${G(o,'method')} ${G(o,'host')}${G(o,'uri')}`.trim();ingPushIocs(G(o,'host')+' '+G(o,'uri'),iocs,seen);}
   else if(path==='ssl'){msg=`TLS ${G(o,'server_name')}`.trim();ingPushIocs(G(o,'server_name'),iocs,seen);}
   else if(path==='conn'){msg=`conn ${proto} ${saddr}:${sport} -> ${daddr}:${dport} (${G(o,'service')||'?'})`.trim();}
   else if(path==='files'){const h=G(o,'sha256')||G(o,'md5');if(h)ingPushIocs(h,iocs,seen);msg=`file ${G(o,'mime_type')||''}`.trim();}
   else if(path==='notice'){
    const note=G(o,'note')||'Zeek notice',smsg=G(o,'msg');msg=`NOTICE ${note}: ${smsg}`.trim();
    const it=notices[note]||(notices[note]={note,hosts:new Set(),count:0,sample:smsg||'',first:null,last:null});
    it.count++;if(saddr)it.hosts.add(saddr);if(daddr)it.hosts.add(daddr);
    if(at){if(!it.first||at<it.first)it.first=at;if(!it.last||at>it.last)it.last=at;}
    timeline.push({at:at||new Date().toISOString(),text:msg.slice(0,500),source:'zeek'});
   }
   if(daddr)ingPushIocs(daddr,iocs,seen);
   events.push(ingMkEvent('zeek',path,{ts:at,saddr,sport,daddr,dport,proto,msg,
    fields:{uid:o.uid,service:G(o,'service'),query:G(o,'query'),host:G(o,'host'),server_name:G(o,'server_name')}}));
  }
  const findings=Object.values(notices).map(x=>{
   const hosts=[...x.hosts],when=x.first?(x.first===x.last?x.first:x.first+' -> '+x.last):'';
   return{title:('Zeek notice: '+x.note).slice(0,200),severity:'medium',attack:[],
    assets:hosts.map(ingIpAsset),
    technicalDetail:`Zeek raised ${x.count} "${x.note}" notice${x.count>1?'s':''}${when?' ('+when+')':''}.${x.sample?'\n'+x.sample:''}`};
  });
  return{timeline,iocs,findings,events};
 },
};

/* ---------- PCAP profile — classic libpcap -> flow events. Uses DataView
   over an ArrayBuffer (not Node's Buffer) so it runs unmodified in the
   browser; only IPv4 is decoded, capped at 300k packets. ---------- */
function ingParsePcap(arrayBuffer){
 const buf=new Uint8Array(arrayBuffer);
 const dv=new DataView(arrayBuffer);
 if(buf.length<24)return{error:'not a PCAP file',timeline:[],iocs:[],findings:[],events:[]};
 let le,nano;const m=dv.getUint32(0,true);
 if(m===0xa1b2c3d4){le=true;nano=false;}else if(m===0xa1b23c4d){le=true;nano=true;}
 else if(m===0xd4c3b2a1){le=false;nano=false;}else if(m===0x4d3cb2a1){le=false;nano=true;}
 else return{error:"unsupported capture (pcapng isn't parsed yet — export as classic pcap)",timeline:[],iocs:[],findings:[],events:[]};
 const u32=off=>dv.getUint32(off,le);
 const linktype=u32(20);
 const ip4=o=>`${buf[o]}.${buf[o+1]}.${buf[o+2]}.${buf[o+3]}`;
 const flows={};const seen=new Set(),iocs=[];let off=24,n=0;
 while(off+16<=buf.length&&n<300000){
  const tsec=u32(off),tsub=u32(off+4),incl=u32(off+8);off+=16;
  if(incl<=0||off+incl>buf.length)break;
  const ts=new Date(tsec*1000+(nano?tsub/1e6:tsub/1e3)).toISOString();
  let p=off,l3=-1;
  if(linktype===1){const et=(buf[p+12]<<8)|buf[p+13];if(et===0x0800)l3=p+14;else if(et===0x8100&&((buf[p+16]<<8)|buf[p+17])===0x0800)l3=p+18;}
  else if(linktype===101){l3=p;}
  else if(linktype===113){if(((buf[p+14]<<8)|buf[p+15])===0x0800)l3=p+16;}
  off+=incl;n++;
  if(l3<0||l3+20>buf.length||(buf[l3]>>4)!==4)continue;
  const ihl=(buf[l3]&0x0f)*4;const proto=buf[l3+9];
  const saddr=ip4(l3+12),daddr=ip4(l3+16);const l4=l3+ihl;
  let sport='',dport='',pname=proto===6?'tcp':proto===17?'udp':proto===1?'icmp':String(proto);
  if((proto===6||proto===17)&&l4+4<=buf.length){sport=((buf[l4]<<8)|buf[l4+1]);dport=((buf[l4+2]<<8)|buf[l4+3]);}
  const key=`${saddr}|${sport}|${daddr}|${dport}|${pname}`;
  const fl=flows[key]||(flows[key]={saddr,daddr,sport,dport,proto:pname,first:ts,last:ts,pkts:0,bytes:0});
  fl.pkts++;fl.bytes+=incl;fl.last=ts;
 }
 const flist=Object.values(flows);
 flist.forEach(f=>{if(f.daddr)ingPushIocs(f.daddr,iocs,seen);if(f.saddr)ingPushIocs(f.saddr,iocs,seen);});
 const events=flist.map(f=>ingMkEvent('pcap','flow',{ts:f.first,saddr:f.saddr,sport:f.sport,daddr:f.daddr,dport:f.dport,proto:f.proto,
  msg:`${f.proto} ${f.saddr}:${f.sport} -> ${f.daddr}:${f.dport} (${f.pkts} pkts, ${f.bytes} B)`,fields:{packets:f.pkts,bytes:f.bytes,last:f.last}}));
 return{timeline:[],iocs,findings:[],events,stats:{packets:n,flows:flist.length}};
}

/* ---------- registry / public API ---------- */
const ING_PROFILES=[ING_CHAINSAW,ING_SURICATA,ING_ZEEK];
function ingReadAll(text,filename){
 const f=(filename||'').toLowerCase();
 let csv=null,json=null;
 if(f.endsWith('.csv')||f.endsWith('.tsv'))csv=ingParseCsv(text);
 else if(f.endsWith('.json')||f.endsWith('.jsonl')||f.endsWith('.ndjson'))json=ingParseJsonish(text);
 else{
  const t=text.trim();
  if(t[0]==='['||t[0]==='{')json=ingParseJsonish(text);
  else if(t.indexOf(',')>=0&&t.indexOf('\n')>=0)csv=ingParseCsv(text);
  else json=ingParseJsonish(text);
 }
 return{csv,json};
}
function ingDetect(text,filename){
 if(/\.pcap$|\.pcapng$|\.cap$/i.test(filename||''))return'pcap';
 const{csv,json}=ingReadAll(text,filename);
 for(const p of ING_PROFILES){try{if(p.detect(text,filename,csv,json))return p.id;}catch{}}
 return null;
}
/** Parse a text blob with a chosen (or auto-detected) profile -> normalised items. */
function ingParse(text,filename,profileId){
 const{csv,json}=ingReadAll(text,filename);
 let prof=ING_PROFILES.find(p=>p.id===profileId);
 if(!prof)prof=ING_PROFILES.find(p=>{try{return p.detect(text,filename,csv,json);}catch{return false;}});
 if(!prof)return{profile:null,error:'No matching ingest profile. Supported: '+ING_PROFILES.map(p=>p.label).join(', ')+', PCAP capture',timeline:[],iocs:[],findings:[],events:[]};
 const out=prof.normalize(text,filename,csv,json);
 return{profile:prof.id,profileLabel:prof.label,timeline:[],iocs:[],findings:[],events:[],...out,
  stats:{timeline:(out.timeline||[]).length,iocs:(out.iocs||[]).length,findings:(out.findings||[]).length,events:(out.events||[]).length}};
}

/* ================= INGEST WIZARD (UI) ================= */
let ingState=null; // {filename,profile,profileLabel,error,timeline,iocs,findings[+checked],events,stats}
const ING_SEV_MAP={critical:'malicious',high:'malicious',medium:'suspicious',low:'info'};

function openLsIngest(){
 ingState=null;
 let v=document.getElementById('ls-ing-veil');
 if(!v){v=document.createElement('div');v.id='ls-ing-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 renderLsIngest();
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeLsIngest();};
}
function closeLsIngest(){const v=document.getElementById('ls-ing-veil');if(v)v.classList.remove('open');}

function renderLsIngest(){
 const v=document.getElementById('ls-ing-veil');if(!v)return;
 v.innerHTML=ingState?ingPreviewHTML():ingInputHTML();
}
function ingInputHTML(){
 return`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="closeLsIngest()"></div>
  <div class="ls-det-head">Ingest a tool export</div>
  <div class="ls-det-sub">Paste a Chainsaw (Sigma-hunt) CSV/JSON export, Suricata <code>eve.json</code>, or Zeek TSV/JSON logs — parsed entirely offline, right here. For a PCAP capture, use the file picker instead (binary, can't be pasted).</div>
  <label class="ls-ne-label">Filename (optional — helps auto-detect the format)</label>
  <input class="dash-input" id="ing-fname" style="width:100%" placeholder="e.g. eve.json, conn.log, chainsaw.csv">
  <textarea id="ing-ta" class="art-ta" style="min-height:180px;margin-top:8px" placeholder="Paste the export here…"></textarea>
  <button class="btn violet" style="width:100%;justify-content:center;margin-top:10px" onclick="ingParseTextarea()">Parse</button>
  <div class="ls-mm-sec">Or pick a file</div>
  <input type="file" id="ing-file" accept=".csv,.tsv,.json,.jsonl,.ndjson,.log,.pcap,.pcapng,.cap" onchange="ingFileChange(this)">
  ${ingState&&ingState.error?`<div class="lint err" style="margin-top:10px">${esc(ingState.error)}</div>`:''}
 </div>`;
}
function ingParseTextarea(){
 const ta=document.getElementById('ing-ta');
 const fname=(document.getElementById('ing-fname')||{}).value||'';
 const text=ta?ta.value:'';
 if(!text.trim()){toast('Paste something to parse first');return;}
 ingState=ingParse(text,fname);
 renderLsIngest();
}
function ingFileChange(input){
 const f=input.files&&input.files[0];if(!f)return;
 const name=f.name||'';
 if(/\.(pcap|pcapng|cap)$/i.test(name)){
  const r=new FileReader();
  r.onload=()=>{
   const out=ingParsePcap(r.result);
   ingState=out.error?{profile:null,error:out.error,...out}:{profile:'pcap',profileLabel:'PCAP capture (flows)',...out,
    stats:{timeline:0,iocs:out.iocs.length,findings:0,events:out.events.length}};
   renderLsIngest();
  };
  r.readAsArrayBuffer(f);
 }else{
  const r=new FileReader();
  r.onload=()=>{ingState=ingParse(String(r.result||''),name);renderLsIngest();};
  r.readAsText(f);
 }
 input.value='';
}
function ingPreviewHTML(){
 const s=ingState;
 if(s.error||!s.profile){
  return`<div class="ls-det-sheet">
   <div class="ls-ne-grip" onclick="closeLsIngest()"></div>
   <div class="ls-det-head">Couldn't parse that</div>
   <div class="lint err">${esc(s.error||'Unrecognised format.')}</div>
   <button class="btn" style="width:100%;justify-content:center;margin-top:10px" onclick="ingState=null;renderLsIngest()">← Try again</button>
  </div>`;
 }
 const findings=s.findings||[];
 return`<div class="ls-det-sheet">
  <div class="ls-ne-grip" onclick="closeLsIngest()"></div>
  <div class="ls-det-head">${esc(s.profileLabel)}</div>
  <div class="ls-det-sub">${s.stats.findings} finding${s.stats.findings===1?'':'s'} · ${s.stats.events} network event${s.stats.events===1?'':'s'} · ${s.stats.iocs} IOC${s.stats.iocs===1?'':'s'} · ${s.stats.timeline} timeline note${s.stats.timeline===1?'':'s'}. Uncheck anything you don't want logged, then commit.</div>
  ${findings.length?findings.map((f,i)=>`<div class="ls-det-row" style="align-items:flex-start;gap:8px">
    <input type="checkbox" ${f.checked!==false?'checked':''} onchange="ingState.findings[${i}].checked=this.checked" style="margin-top:3px">
    <div style="flex:1;min-width:0">
     <div><b>${esc(f.title)}</b> <span class="ls-ne-obs-sev inc-${ING_SEV_MAP[f.severity]||'info'}" style="margin-left:4px">${esc(f.severity)}</span></div>
     <div style="font-size:10.5px;color:var(--t3);margin-top:2px">${esc((f.technicalDetail||'').slice(0,180))}${(f.assets||[]).length?` · ${f.assets.map(a=>esc(a.name)).join(', ')}`:''}${(f.attack||[]).length?` · ${f.attack.join(', ')}`:''}</div>
    </div>
   </div>`).join(''):'<div class="ls-det-sub">No findings extracted — network events and IOCs (if any) will still be committed.</div>'}
  ${s.iocs&&s.iocs.length?`<div class="ls-mm-sec">Indicators seen (${s.iocs.length})</div><div class="ls-det-sub">${s.iocs.slice(0,24).map(x=>esc(x.value)).join(', ')}${s.iocs.length>24?' …':''}</div>`:''}
  <div style="display:flex;gap:8px;margin-top:12px">
   <button class="btn" style="flex:1;justify-content:center" onclick="ingState=null;renderLsIngest()">← Back</button>
   <button class="btn violet" style="flex:2;justify-content:center" onclick="ingCommit()">Commit to hunt map</button>
  </div>
 </div>`;
}
function ingResolveNode(asset){
 if(asset.ip){
  const existing=lsNodes.find(n=>n.ip&&n.ip.toLowerCase()===asset.ip.toLowerCase());
  if(existing)return existing;
  const n=lsAddNode(asset.type||'srv',120+Math.random()*360,120+Math.random()*240,false);
  n.label=asset.name||asset.ip;n.ip=asset.ip;
  return n;
 }
 const existing=lsNodes.find(n=>n.label&&n.label.toLowerCase()===String(asset.name).toLowerCase());
 if(existing)return existing;
 const n=lsAddNode(asset.type||'wks',120+Math.random()*360,120+Math.random()*240,false);
 n.label=asset.name;
 return n;
}
function ingCommit(){
 const s=ingState;if(!s)return;
 const mapRes=ingMapEvents(s.events||[]);
 const findings=(s.findings||[]).filter(f=>f.checked!==false);
 const stagedTechs=new Set();
 let obsAdded=0;
 findings.forEach(f=>{
  const assets=(f.assets&&f.assets.length)?f.assets:[{type:'wks',name:'Ingested finding',ip:''}];
  const sev=ING_SEV_MAP[f.severity]||'suspicious';
  const note=(f.title+(f.technicalDetail?': '+f.technicalDetail:'')).slice(0,600);
  const tech=(f.attack&&f.attack[0])||'';
  assets.forEach(a=>{
   const n=ingResolveNode(a);
   if(!n.obs)n.obs=[];
   if(n.obs.some(o=>o.note===note))return; // already logged, skip
   n.obs.push({id:'o'+Date.now()+Math.floor(Math.random()*99),evId:'',note,sev,t:Date.now(),tech});
   obsAdded++;
  });
  (f.attack||[]).forEach(t=>{if(MITRE[t])stagedTechs.add(t);});
 });
 stagedTechs.forEach(t=>studio.add(t));
 persistAll();lsSnapshot();renderLogSrc();renderMatrix();renderStudio();updateBadges();
 closeLsIngest();
 toast(`Ingested: ${mapRes.nodesAdded} host${mapRes.nodesAdded===1?'':'s'}, ${mapRes.edgesAdded} link${mapRes.edgesAdded===1?'':'s'}, ${obsAdded} observation${obsAdded===1?'':'s'}, ${stagedTechs.size} technique${stagedTechs.size===1?'':'s'} staged`);
 ingState=null;
}
