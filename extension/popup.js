'use strict';
const repoEl = document.getElementById('repo');
const scan = document.getElementById('scan');
let repoURL = '';
function normalize(address){
 try {
  const u = new URL(address);
  if(u.protocol !== 'https:' || !['github.com','www.github.com','bitbucket.org'].includes(u.hostname)) return '';
  if(u.username || u.password || (u.port && u.port !== '443') || u.search || u.hash) return '';
  const parts = u.pathname.split('/').filter(Boolean);
  if(parts.length !== 2 || !parts.every(x => /^[a-z\d._-]{1,100}$/i.test(x) && x!=='.' && x!=='..' && !x.includes('..'))) return '';
  const repo=parts[1].replace(/\.git$/i,'');
  if(!repo || repo==='.' || repo==='..')return '';
  return 'https://' + (u.hostname==='www.github.com'?'github.com':u.hostname) + '/' + parts[0] + '/' + repo;
 } catch { return ''; }
}
chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
 repoURL = normalize(tabs[0]?.url || '');
 repoEl.textContent = repoURL || 'Open a public GitHub or Bitbucket repository.';
 scan.disabled = !repoURL;
});
scan.addEventListener('click', () => {
 if (!repoURL) return;
 chrome.tabs.create({url:'ots-security://scan?url=' + encodeURIComponent(repoURL)});
});
document.getElementById('open').addEventListener('click', () => chrome.tabs.create({url:'ots-security://scan'}));
