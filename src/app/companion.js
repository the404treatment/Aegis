/* ================= LOCAL AI COMPANION ================= */
/* A model running on your own machine, watching the same telemetry you are.
 *
 * The distinction from the AI Analyst tab is not which model - it is who
 * starts the conversation. The Analyst waits to be asked, which is fine when
 * you know the question. This one reads events as they land and offers an
 * opinion first, which is what you actually want at 3am when you do not yet
 * know what you are looking at.
 *
 * Server-backed and entirely local: no key, no internet, nothing leaves the
 * host. Absent a local model the whole feature stays invisible rather than
 * advertising something the analyst cannot use. */

let CO = { available:false, name:'', model:'', watch:false };
let coOpen=false, coItems=[], coUnread=0, coBusy=false;

/** Ask the server what local model, if any, is available. */
async function coStatus(){
 if(!LIVE.connected){CO={available:false,name:'',model:'',watch:false};renderCompanionButton();return CO;}
 try{ CO=await liveApi('/api/llm/status'); }catch{ CO={available:false}; }
 renderCompanionButton();
 return CO;
}

/** An unprompted assessment arrived over the SSE stream. */
function coIngest(item){
 if(!item||!item.text)return;
 coItems.push({...item,kind:'watch'});
 if(coItems.length>60)coItems=coItems.slice(-60);
 if(!coOpen)coUnread++;
 renderCompanion();
 if(view==='dash')renderDash();
 // A malicious verdict is worth interrupting for; a suspicious one is not.
 if(item.worst==='malicious'&&!coOpen)toast('Companion flagged malicious telemetry');
}

function coToggle(){
 if(!CO.available){coExplain();return;}
 coOpen=!coOpen;
 if(coOpen)coUnread=0;
 renderCompanion();
 if(coOpen)setTimeout(()=>{const i=document.getElementById('co-in');if(i)i.focus();},60);
}

/** Explain how to get one, rather than a dead button. */
async function coExplain(){
 await uiConfirm(
  'No local model is running on the AEGIS host.\n\n'
 +'The companion needs an inference server on that machine - Ollama is the '
 +'easiest, and LM Studio, llama.cpp and Jan all work too.\n\n'
 +'Install one, then run:  npm run ai:setup\n\n'
 +'It is entirely optional and everything else in AEGIS works without it. '
 +'See LOCAL-AI.md for the two-minute version.',
  {title:'Local AI companion',ok:'Got it',cancel:null});
}

/** Ask it something directly. */
async function coAsk(text,opts){
 opts=opts||{};
 if(coBusy||!CO.available)return;
 const msg=String(text||'').trim();
 if(!msg)return;
 coItems.push({id:'q_'+Date.now(),at:Date.now(),kind:'you',text:msg});
 coBusy=true;renderCompanion();
 try{
  const r=await liveApi('/api/llm',{method:'POST',body:JSON.stringify({
   messages:[...coHistory(),{role:'user',content:opts.prompt||msg}],
  })});
  coItems.push({id:'a_'+Date.now(),at:Date.now(),kind:'reply',text:r.text,model:r.model});
 }catch(e){
  coItems.push({id:'e_'+Date.now(),at:Date.now(),kind:'error',
   text:/HTTP 503/.test(e.message)?'The local model is no longer reachable. Is it still running?':e.message});
 }
 coBusy=false;renderCompanion();
}

/** Recent turns, so a follow-up question keeps its thread. Small on purpose:
    local models have small context windows and get worse when you fill them. */
function coHistory(){
 const out=[];
 for(const it of coItems.slice(-6)){
  if(it.kind==='you')out.push({role:'user',content:it.text});
  else if(it.kind==='reply'||it.kind==='watch')out.push({role:'assistant',content:it.text});
 }
 return out;
}

function coSend(){
 const i=document.getElementById('co-in');if(!i)return;
 const v=i.value.trim();if(!v)return;
 i.value='';coAsk(v);
}

/** Hand the companion whatever the analyst is looking at right now. */
function coAskAbout(what,context){
 if(!CO.available){coExplain();return;}
 coOpen=true;coUnread=0;renderCompanion();
 coAsk(what,{prompt:`${context}\n\n${what}`});
}

function renderCompanionButton(){
 const b=document.getElementById('co-ind');if(!b)return;
 if(!LIVE.connected){b.className='chat-ind';b.innerHTML='';b.onclick=null;return;}
 b.className='chat-ind on'+(coUnread?' unread':'')+(CO.available?'':' dim');
 b.innerHTML=CO.available
  ?`◈ Companion${coUnread?`<i>${coUnread>9?'9+':coUnread}</i>`:''}`
  :'◈ Local AI';
 b.title=CO.available
  ?`${CO.name} · ${CO.model}${CO.watch?' · watching telemetry':''}`
  :'No local model running - click to find out how';
 b.onclick=coToggle;
}

function renderCompanion(){
 renderCompanionButton();
 let p=document.getElementById('companion-panel');
 if(!p){p=document.createElement('div');p.id='companion-panel';document.body.appendChild(p);}
 p.className='companion-panel'+(coOpen&&CO.available?' open':'');
 if(!coOpen||!CO.available){p.innerHTML='';return;}
 p.innerHTML=`
  <div class="chat-head">
    <span>Companion <span class="co-model">${esc(CO.model||CO.name)}</span></span>
    <button onclick="coToggle()" data-tip="Close">×</button>
  </div>
  <div class="co-body" id="co-body">
    ${coItems.length?coItems.map(it=>coRow(it)).join('')
      :`<div class="chat-empty">Running locally on ${esc(CO.name)}. Nothing leaves this machine.
         ${CO.watch?'<br><br>It will comment on suspicious telemetry on its own. You can also just ask it something.':'<br><br>Ask it something.'}</div>`}
    ${coBusy?'<div class="co-row co-reply"><div class="think"><i></i><i></i><i></i></div></div>':''}
  </div>
  <div class="co-foot">
    <textarea id="co-in" rows="1" placeholder="Ask about what you're looking at…"
      onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();coSend();}"></textarea>
    <button class="btn violet" onclick="coSend()" ${coBusy?'disabled':''}>Ask</button>
  </div>`;
 const b=document.getElementById('co-body');if(b)b.scrollTop=b.scrollHeight;
}

function coRow(it){
 if(it.kind==='you')return`<div class="co-row co-you"><div class="co-txt">${esc(it.text)}</div></div>`;
 if(it.kind==='error')return`<div class="co-row co-err"><div class="co-txt">${esc(it.text)}</div></div>`;
 if(it.kind==='watch')return`<div class="co-row co-watch co-${esc(it.worst||'suspicious')}">
   <div class="co-tag">unprompted · ${it.events} event${it.events===1?'':'s'}${it.hosts&&it.hosts.length?' · '+esc(it.hosts.join(', ')):''}</div>
   <div class="co-txt">${esc(it.text)}</div></div>`;
 return`<div class="co-row co-reply"><div class="co-txt">${esc(it.text)}</div></div>`;
}
