'use strict';
const LOCAL='http://127.0.0.1:48728/';
const repoEl=document.getElementById('repo');
const scanEl=document.getElementById('scan');
let url='';
function normalize(address){
 try {
  const u=new URL(address);
  if(!['github.com','www.github.com','bitbucket.org'].includes(u.hostname)||u.protocol!=='https:')return '';
  const segments=u.pathname.split('/').filter(Boolean);
  if(segments.length<2||!segments.slice(0,2).every(x=>/^[a-z0-9_.-]+$/i.test(x)))return '';
  return 'https://'+(u.hostname==='www.github.com'?'github.com':u.hostname)+'/'+segments[0]+'/'+segments[1].replace(/\.git$/,'');
 }catch{return '';}
}
chrome.tabs.query({active:true,currentWindow:true},tabs=>{
 url=normalize(tabs[0]?.url||'');
 if(url){repoEl.textContent=url;scanEl.disabled=false;}
 else repoEl.textContent='Open a public GitHub or Bitbucket repository page, then try again.';
});
scanEl.addEventListener('click',()=>{if(url)chrome.tabs.create({url:LOCAL+'?repo='+encodeURIComponent(url)});});
document.getElementById('open').addEventListener('click',()=>chrome.tabs.create({url:LOCAL}));
