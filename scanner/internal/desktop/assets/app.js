'use strict';
const $=id=>document.getElementById(id);
let currentReport=null, currentMode='repo', activeScan=null;
const categories=['Code execution','Data exfiltration','Credential theft','Obfuscation','Supply chain','Persistence','Web vulnerabilities','Host control','Embedded payload','File integrity','Document threats','Test signatures'];
// The placeholder allows pasting github.com/... directly. Canonicalize only
// public HTTPS root repository URLs; the Go backend rechecks the same boundary.
function normalizeRepositoryInput(input){
 const raw=String(input??'').trim();
 if(!raw)return '';
 const full=/^(github\.com|www\.github\.com|bitbucket\.org)\//i.test(raw)
   ? 'https://'+raw : raw;
 try{
  const uri=new URL(full);
  const host=uri.hostname.toLowerCase()==='www.github.com'
    ? 'github.com' : uri.hostname.toLowerCase();
  if(uri.protocol!=='https:' || !['github.com','bitbucket.org'].includes(host) ||
     uri.username || uri.password || uri.port || uri.search || uri.hash)return '';
  const parts=uri.pathname.split('/').filter(Boolean);
  if(parts.length!==2 || !parts.every(x=>/^[a-z0-9_.-]{1,100}$/i.test(x) &&
      x!=='.' && x!=='..' && !x.includes('..')))return '';
  const repo=parts[1].replace(/\.git$/i,'');
  if(!repo || !/^[a-z0-9_.-]{1,100}$/i.test(repo))return '';
  return 'https://'+host+'/'+parts[0]+'/'+repo;
 }catch{return ''}
}
const escapeHTML=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const show=(id,yes=true)=>$(id).classList.toggle('hidden',!yes);
const active=(cls,node)=>{document.querySelectorAll('.'+cls).forEach(x=>x.classList.toggle('active',x===node));};
async function api(path,options={}){
 const response=await fetch(path,{credentials:'same-origin',...options});
 if(!response.ok)throw new Error((await response.text()).slice(0,300));
 return response.json();
}
document.querySelectorAll('.navitem').forEach(btn=>btn.addEventListener('click',()=>{active('navitem',btn);document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('active',p.id===btn.dataset.tab));if(btn.dataset.tab==='history')loadHistory();}));
document.querySelectorAll('.scan-mode').forEach(btn=>btn.addEventListener('click',()=>{active('scan-mode',btn);currentMode=btn.dataset.mode;document.querySelectorAll('.mode').forEach(x=>show(x.id,x.id===currentMode+'-mode'));}));
async function scan(mode){
 if(activeScan)return;
 const controller=new AbortController();activeScan=controller;currentReport=null;$('cancelScan').disabled=false;
 show('error',false);show('status');show('empty',false);show('results',false);$('statusText').textContent='Scanning... A large repository may take a minute.';
 document.querySelectorAll('.primary').forEach(x=>x.disabled=true);
 try{
  let report;
  if(mode==='repo'||mode==='folder'){
    const input=mode==='repo' ? $('repoUrl').value.trim() : $('folderPath').value.trim();
    const canonical=mode==='repo' ? normalizeRepositoryInput(input) : input;
    if(!canonical)throw new Error(mode==='repo'
      ? 'Enter a public root GitHub or Bitbucket repository URL (HTTPS only).'
      : 'Please enter a local file or folder path.');
    if(mode==='repo')$('repoUrl').value=canonical;
    const body=mode==='repo'?{url:canonical}:{folder:canonical};
    report=await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:controller.signal});
  }else{
    const files=Array.from((mode==='file'?$('fileUpload'):$('folderUpload')).files);if(!files.length)throw new Error('Choose files or a folder first.');
    const form=new FormData();for(const file of files){form.append('files',file,file.webkitRelativePath||file.name);}
    report=await api('/api/scan-upload',{method:'POST',body:form,signal:controller.signal});
  }
  render(report);
 }catch(err){
  show('error');$('error').textContent=(controller.signal.aborted||err.name==='AbortError')?'Scan cancelled. No completed report was saved.':err.message;
  show('empty',true);
 }finally{
  if(activeScan===controller)activeScan=null;
  show('status',false);document.querySelectorAll('.primary').forEach(x=>x.disabled=false);
 }
}
$('cancelScan').addEventListener('click',()=>{
 if(!activeScan)return;
 $('statusText').textContent='Cancelling scan…';
 $('cancelScan').disabled=true;
 activeScan.abort();
});
$('scanRepo').onclick=()=>scan('repo');$('scanFolder').onclick=()=>scan('folder');$('scanUpload').onclick=()=>scan('upload');$('scanFiles').onclick=()=>scan('file');
function render(report){
 currentReport=report;show('results');show('empty',false);
 $('resultTarget').textContent=report.target;$('resultScore').innerHTML=report.score+'<span>/100</span>';$('resultVerdict').textContent=report.verdict;
 $('resultVerdict').style.color=report.score>=65?'#fd7580':report.score>=26?'#eac276':'#2CFF05';
 $('filesScanned').textContent=report.files_scanned.toLocaleString()+' / '+report.files_seen.toLocaleString();$('filesSkipped').textContent=report.files_skipped+' uninspected · '+report.files_partial+' partial';
 $('findingCount').textContent=report.findings.length;$('coverage').textContent=report.truncated?'Review scan coverage':'Detection matches';$('ruleCount').textContent=report.rules_available;
 // Routine format notes stay inside collapsible diagnostics, not bright warning banners.
 const diagnostics=(report.warnings||[]).filter(Boolean);
 const important=diagnostics.filter(x=>/coverage incomplete|malformed|encrypted|could not|uninspected|budget|truncat|failed|exceeded|unsafe/i.test(x));
 $('scanDiagnostics').innerHTML=diagnostics.length?diagnostics.map(x=>'<li>'+escapeHTML(x)+'</li>').join(''):'<li>All configured checks completed without diagnostic notes.</li>';
 $('scanNotes').classList.toggle('hidden',diagnostics.length===0);
 $('scanNotes').open=false;
 $('scanNotesLabel').textContent=important.length?'Scan details · '+important.length+' items to review':'Scan details';
 $('filesSkipped').textContent=report.files_skipped+' not inspected · '+report.files_partial+' partial';
 let mx=Math.max(1,...Object.values(report.category_scores||{}));
 $('categories').innerHTML=categories.map(cat=>{let value=report.category_scores[cat]||0;return '<div class="cat"><div class="cathead"><span>'+cat+'</span><b>'+value+'</b></div><div class="bar"><div style="width:'+Math.round(value/mx*100)+'%"></div></div></div>';}).join('');
 const filter=$('categoryFilter');filter.innerHTML='<option value="all">All categories</option>'+categories.map(cat=>'<option value="'+cat+'">'+cat+'</option>').join('');filter.onchange=()=>renderFindings(report);
 renderFindings(report);renderCoverage(report);
}
function renderFindings(report){
 let choice=$('categoryFilter').value;let list=report.findings.filter(f=>choice==='all'||f.category===choice);
 $('findings').innerHTML=list.length?list.map(f=>'<div class="finding '+escapeHTML(f.severity)+'"><div class="titleline"><strong>'+escapeHTML(f.title)+'</strong><span class="severity">'+escapeHTML(f.severity)+'</span></div><p>'+escapeHTML(f.detail)+'</p><code>'+escapeHTML(f.file)+':'+f.line+' · '+escapeHTML(f.rule_id)+'</code><pre>'+escapeHTML(f.preview)+'</pre></div>').join(''):'<div class="empty"><p>No detection matches for this filter.</p></div>';
}
function renderCoverage(report){
 const all=Array.isArray(report.coverage)?report.coverage:[];
 $('coverageMetrics').innerHTML='<div><b>'+report.files_seen+'</b><small> repository files inventoried</small></div>'+
 '<div><b>'+report.files_scanned+'</b><small> received baseline inspection</small></div>'+
 '<div><b>'+report.files_partial+'</b><small> partial content scans</small></div>'+
 '<div><b>'+report.embedded_seen+'</b><small> archive members discovered</small></div>'+
 '<div><b>'+report.embedded_uninspected+'</b><small> archive members uninspected</small></div>';
 $('coverageNote').textContent='File identity, hashes, limits and which inspections completed';
 const filter=()=>{
  const q=$('fileSearch').value.trim().toLowerCase(), status=$('fileStatus').value;
  let matching=all.filter(x=>(status==='all'||x.status===status)&&(!q||(x.path+' '+x.type).toLowerCase().includes(q)));
  const visible=matching.slice(0,200);
  $('coverageList').innerHTML=visible.length?visible.map(x=>'<div class="coverage-entry"><div class="coverage-head"><span class="coverage-path">'+escapeHTML(x.path)+'</span><b class="coverage-status '+escapeHTML(x.status)+'">'+escapeHTML(x.status)+'</b></div><div class="coverage-meta">Detected: '+escapeHTML(x.type)+' · Size: '+Number(x.size||0).toLocaleString()+' bytes · Read: '+Number(x.bytes_read||0).toLocaleString()+' bytes'+(x.embedded?' · archive member':'')+'</div><div class="coverage-meta">SHA-256 ('+escapeHTML(x.hash_scope||'not available')+'): <code>'+escapeHTML(x.sha256||'not available')+'</code></div>'+(x.reason?'<div class="coverage-reason">'+escapeHTML(x.reason)+'</div>':'')+'</div>').join(''):'<p class="hint">No entries match this filter.</p>';
  $('coverageCount').textContent='Showing '+visible.length+' of '+matching.length+' matching files. Download JSON for the full coverage manifest.';
 };
 $('fileSearch').oninput=filter;$('fileStatus').onchange=filter;filter();
}
$('export').onclick=()=>{if(currentReport)window.location.href='/api/report/'+encodeURIComponent(currentReport.id)+'?download=1';};
async function loadHistory(){
 try{let items=await api('/api/history');$('historyList').innerHTML=items.length?items.map(it=>'<button class="historyitem" data-id="'+escapeHTML(it.id)+'"><span><strong>'+escapeHTML(it.target)+'</strong><small>'+escapeHTML(new Date(it.date).toLocaleString())+' · '+it.count+' findings</small></span><b>'+it.score+'/100</b></button>').join(''):'<div class="empty">No previous reports yet.</div>';
 document.querySelectorAll('.historyitem').forEach(btn=>btn.onclick=async()=>{try{let r=await api('/api/report/'+btn.dataset.id);document.querySelector('.navitem[data-tab="scan"]').click();render(r);}catch(e){alert(e.message);}});
 }catch(e){$('historyList').textContent=e.message;}
}
const parameters=new URLSearchParams(location.search);if(parameters.get('repo')){$('repoUrl').value=parameters.get('repo');}
api('/api/info').then(info=>{$('ruleCount').textContent=info.rule_count;}).catch(()=>{});

// A short-lived authenticated page heartbeat lets the desktop process shut down
// automatically when the Chrome app window is closed. Brief reloads are tolerated.
const sendHeartbeat=()=>{ if(document.visibilityState !== 'prerender') fetch('/api/window-heartbeat',{method:'POST',credentials:'same-origin',keepalive:true}).catch(()=>{}); };
sendHeartbeat();
setInterval(sendHeartbeat,1000);
