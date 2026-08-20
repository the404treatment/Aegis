/* ================= THE TEAM ================= */
/* Two things turn a single-player console into an incident room:
 *
 *   presence - who else is in here right now, live off the SSE stream, and
 *   activity - what everyone has been doing, read out of the audit chain.
 *
 * The audit log already records every action against the person who took it.
 * That log exists to prove what happened and reads like it. This renders the
 * same rows as sentences, so the record doubles as the thing you glance at to
 * see where your colleagues are. One source of truth, two readings.
 *
 * Server-backed, so both simply aren't offered when working offline. */

let PRESENCE=[], activityItems=[], activityOpen=false, _activityBusy=false, _activitySeen=0, activityNew=0;

/* --------------------------------------------------------------- presence */

/** Called for every inbound SSE presence frame. */
function presenceIngest(list){
 PRESENCE=Array.isArray(list)?list:[];
 renderPresence();
}

/** Stable per-person colour, so you learn a teammate's dot by sight. */
function whoColor(name){
 const pal=['#8b7bff','#5cc8ff','#3ddc97','#ffb547','#ff4d8f','#b98bff','#5ce1e6'];
 let h=0;for(let i=0;i<name.length;i++)h=(h*31+name.charCodeAt(i))>>>0;
 return pal[h%pal.length];
}
function initialsOf(name){
 const parts=String(name||'?').trim().split(/[\s._-]+/).filter(Boolean);
 return ((parts[0]||'?')[0]+(parts[1]?parts[1][0]:'')).toUpperCase();
}

function renderPresence(){
 const el=document.getElementById('presence-ind');if(!el)return;
 if(!LIVE.connected||!PRESENCE.length){el.className='presence';el.innerHTML='';return;}
 // You are always in the list; showing yourself as "1 online" reads as lonely,
 // so count colleagues and mark your own dot.
 const mine=ME?ME.id:null;
 const others=PRESENCE.filter(p=>p.id!==mine);
 el.className='presence on';
 el.innerHTML=PRESENCE.slice(0,6).map(p=>{
  const me=p.id===mine;
  return `<span class="who-dot${me?' me':''}" style="--who:${whoColor(p.name)}"
    data-tip="${esc(p.name)}${me?' (you)':''} · ${esc(p.role)}${p.shared?' · shared token':''} · on since ${new Date(p.since).toLocaleTimeString()}"
    >${esc(initialsOf(p.name))}</span>`;
 }).join('')
 +(PRESENCE.length>6?`<span class="who-dot more">+${PRESENCE.length-6}</span>`:'')
 +`<span class="presence-n">${others.length?`${others.length} colleague${others.length===1?'':'s'} online`:'only you online'}</span>`;
}

/* --------------------------------------------------------------- activity */

function activityToggle(){
 if(!LIVE.connected){toast('The activity feed needs a server connection');return;}
 activityOpen=!activityOpen;
 if(activityOpen){activityNew=0;activityLoad();}
 renderActivity();
}

/** Called when anything happens that would have written an audit row. */
function activityPing(){
 if(!LIVE.connected)return;
 if(activityOpen){activityLoad();return;}
 activityNew++;renderActivityButton();
}

async function activityLoad(){
 if(_activityBusy||!LIVE.connected)return;
 _activityBusy=true;
 try{
  const r=await liveApi('/api/activity?limit=60');
  activityItems=r.items||[];
  // The feed is only worth as much as the chain under it. If the audit log
  // no longer verifies, say so here rather than quietly rendering a story
  // that may have been edited.
  activityIntact=r.intact!==false;
 }catch(e){activityItems=[];}
 _activityBusy=false;
 if(activityOpen)renderActivity();
}
let activityIntact=true;

function agoOf(t){
 const s=Math.max(0,Math.round((Date.now()-t)/1000));
 if(s<60)return 'just now';
 if(s<3600)return Math.floor(s/60)+'m ago';
 if(s<86400)return Math.floor(s/3600)+'h ago';
 return Math.floor(s/86400)+'d ago';
}

function renderActivityButton(){
 const b=document.getElementById('activity-ind');if(!b)return;
 b.className='chat-ind'+(LIVE.connected?' on':'')+(activityNew?' unread':'');
 b.innerHTML=LIVE.connected?`◷ Activity${activityNew?`<i>${activityNew>99?'99+':activityNew}</i>`:''}`:'';
 b.onclick=LIVE.connected?activityToggle:null;
}

function renderActivity(){
 renderActivityButton();
 let p=document.getElementById('activity-panel');
 if(!p){p=document.createElement('div');p.id='activity-panel';document.body.appendChild(p);}
 p.className='activity-panel'+(activityOpen&&LIVE.connected?' open':'');
 if(!activityOpen||!LIVE.connected){p.innerHTML='';return;}
 p.innerHTML=`
  <div class="chat-head">
    <span>Team activity</span>
    <button onclick="activityToggle()" data-tip="Close">×</button>
  </div>
  ${!activityIntact?`<div class="lint err" style="margin:10px 12px">The audit chain does not verify. Someone has edited the record on disk - treat this feed, and the case files, as untrusted until that is explained.</div>`:''}
  <div class="act-body">
    ${activityItems.length?activityItems.map(a=>`
      <div class="act-row act-${esc(a.kind)}">
        <span class="who-dot sm" style="--who:${whoColor(a.actor)}">${esc(initialsOf(a.actor))}</span>
        <div class="act-txt">
          <b>${esc(a.actor)}</b> ${esc(a.verb)}${a.noun?' '+esc(a.noun):''}
          ${a.target?`<span class="act-target">${esc(a.target)}</span>`:''}
          ${a.detail?`<span class="act-detail">${esc(a.detail)}</span>`:''}
        </div>
        <span class="act-ago">${agoOf(a.at)}</span>
      </div>`).join('')
     :'<div class="chat-empty">Nothing yet. Raise a ticket or open a case and it shows up here for the whole team.</div>'}
  </div>
  <div class="act-foot">Read from the hash-chained audit log - the same record the formal report is signed against.</div>`;
}
