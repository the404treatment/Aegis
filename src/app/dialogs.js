/* ================= IN-APP DIALOGS =================
   Native confirm()/prompt() are unreliable: mobile in-app browsers suppress them,
   and once a user ticks "block further dialogs" they silently return false, which
   makes destructive actions look broken. These are promise-based replacements. */
let _uiDlgResolve=null;
function _uiCloseDlg(val){
 const v=document.getElementById('ui-dlg-veil');
 if(v)v.classList.remove('open');
 const r=_uiDlgResolve;_uiDlgResolve=null;
 if(r)r(val);
}
function _uiDlgVeil(){
 let v=document.getElementById('ui-dlg-veil');
 if(!v){v=document.createElement('div');v.id='ui-dlg-veil';v.className='ui-dlg-veil';document.body.appendChild(v);}
 return v;
}
function uiConfirm(message,opts){
 opts=opts||{};
 return new Promise(res=>{
  _uiDlgResolve=res;
  const v=_uiDlgVeil();
  const body=String(message).split('\n').map(l=>l.trim()?`<p>${esc(l)}</p>`:'<div class="ui-dlg-gap"></div>').join('');
  v.innerHTML=`<div class="ui-dlg ${opts.danger?'danger':''}" role="alertdialog">
    <div class="ui-dlg-title">${esc(opts.title||'Are you sure?')}</div>
    <div class="ui-dlg-body">${body}</div>
    <div class="ui-dlg-acts">
      <button class="ui-dlg-btn" onclick="_uiCloseDlg(false)">${esc(opts.cancel||'Cancel')}</button>
      <button class="ui-dlg-btn go ${opts.danger?'danger':''}" onclick="_uiCloseDlg(true)">${esc(opts.ok||'Confirm')}</button>
    </div>
  </div>`;
  v.classList.add('open');
  v.onclick=(e)=>{if(e.target===v)_uiCloseDlg(false);};
  setTimeout(()=>{const b=v.querySelector('.ui-dlg-btn.go');if(b)b.focus();},40);
 });
}
function uiPrompt(label,def,opts){
 opts=opts||{};
 return new Promise(res=>{
  _uiDlgResolve=res;
  const v=_uiDlgVeil();
  v.innerHTML=`<div class="ui-dlg" role="dialog">
    <div class="ui-dlg-title">${esc(opts.title||label)}</div>
    ${opts.title?`<div class="ui-dlg-body"><p>${esc(label)}</p></div>`:''}
    <input id="ui-dlg-input" class="ui-dlg-input" value="${esc(def||'')}" placeholder="${esc(opts.placeholder||'')}">
    <div class="ui-dlg-acts">
      <button class="ui-dlg-btn" onclick="_uiCloseDlg(null)">Cancel</button>
      <button class="ui-dlg-btn go" onclick="_uiCloseDlg(document.getElementById('ui-dlg-input').value)">${esc(opts.ok||'Save')}</button>
    </div>
  </div>`;
  v.classList.add('open');
  v.onclick=(e)=>{if(e.target===v)_uiCloseDlg(null);};
  setTimeout(()=>{const i=document.getElementById('ui-dlg-input');if(i){try{i.focus();if(i.select)i.select();}catch(e){}
    i.addEventListener('keydown',(e)=>{if(e.key==='Enter')_uiCloseDlg(i.value);if(e.key==='Escape')_uiCloseDlg(null);});}},40);
 });
}
document.addEventListener('keydown',(e)=>{if(_uiDlgResolve&&e.key==='Escape')_uiCloseDlg(false);});
