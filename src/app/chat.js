/* ================= TEAM CHAT ================= */
/* A docked panel for the people working the incident together. Delivery
   rides the SSE stream the console already holds open - the source app polls
   twice a second for this; we don't need to. Server-backed, so it simply
   isn't offered when there's no server. */

let chatOpen=false, chatUnread=0;

function chatToggle(){
 if(!LIVE.connected){toast('Chat needs a server connection');return;}
 chatOpen=!chatOpen;
 if(chatOpen)chatUnread=0;
 renderChat();
 if(chatOpen){
  const i=document.getElementById('chat-in');
  if(i&&i.focus)setTimeout(()=>i.focus(),50);
 }
}

/** Called for every inbound SSE chat frame. */
function chatIngest(m){
 if(!m||!m.id)return;
 if(LIVE.chat.some(x=>x.id===m.id))return;   // same upsert discipline as cases
 LIVE.chat.push(m);
 if(LIVE.chat.length>300)LIVE.chat.splice(0,LIVE.chat.length-300);
 // Don't count your own message, or anything while the panel is open.
 const mine=ME&&(m.fromId===ME.id);
 if(!chatOpen&&!mine)chatUnread++;
 renderChat();
}

function renderChat(){
 const btn=document.getElementById('chat-ind');
 if(btn){
  btn.className='chat-ind'+(LIVE.connected?' on':'')+(chatUnread?' unread':'');
  btn.innerHTML=LIVE.connected?`✻ Chat${chatUnread?`<i>${chatUnread>99?'99+':chatUnread}</i>`:''}`:'';
  btn.onclick=LIVE.connected?chatToggle:null;
 }
 if(typeof renderCompanionButton==='function')renderCompanionButton();  // keep the floating AI button out from under this panel
 let p=document.getElementById('chat-panel');
 if(!p){p=document.createElement('div');p.id='chat-panel';document.body.appendChild(p);}
 p.className='chat-panel'+(chatOpen&&LIVE.connected?' open':'');
 if(!chatOpen||!LIVE.connected){p.innerHTML='';return;}
 const msgs=LIVE.chat.slice(-200);
 p.innerHTML=`
  <div class="chat-head">
    <span>Team chat</span>
    <button onclick="chatToggle()" data-tip="Close">×</button>
  </div>
  <div class="chat-body" id="chat-body">
    ${msgs.length?msgs.map(m=>{
      const mine=ME&&(m.fromId===ME.id);
      const col=typeof userColor==='function'?userColor(m.from):'var(--violet)';
      return `<div class="chat-msg${mine?' mine':''}">
        <div class="chat-meta"><b style="color:${col}"><span class="chat-dot" style="background:${col}"></span>${esc(m.from)}</b><span>${typeof fmtTime==='function'?fmtTime(m.at):new Date(m.at).toLocaleTimeString()}</span></div>
        <div class="chat-text">${highlightIocs(m.text)}</div>
      </div>`;}).join('')
     :'<div class="chat-empty">Nothing yet. Anyone connected to this server sees what you post here.</div>'}
  </div>
  <div class="chat-compose">
    <textarea id="chat-in" class="chat-in" rows="1" placeholder="Message the team…  (Enter sends, Shift+Enter for a new line)" maxlength="2000"
      oninput="chatGrow(this)"
      onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();chatSend();}"></textarea>
    <button class="btn violet" onclick="chatSend()">Send</button>
  </div>`;
 const body=document.getElementById('chat-body');
 if(body)body.scrollTop=body.scrollHeight;
}

/* Grow the compose box with the message, up to a few lines, then scroll. */
function chatGrow(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,120)+'px';}
async function chatSend(){
 const i=document.getElementById('chat-in');if(!i)return;
 const text=i.value.trim();
 if(!text)return;
 i.value='';chatGrow(i);
 try{
  chatIngest(await liveApi('/api/chat',{method:'POST',body:JSON.stringify({text})}));
 }catch(e){
  toast('Could not send: '+e.message);
  i.value=text;chatGrow(i);   // don't silently eat what they typed
 }
}
