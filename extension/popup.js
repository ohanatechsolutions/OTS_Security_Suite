'use strict';
const repoEl = document.getElementById('repo');
const scan = document.getElementById('scan');
let repoURL = '';
function normalize(address){
 try {
  const u = new URL(address);
  if(u.protocol !== 'https:' || !['github.com','www.github.com','bitbucket.org'].includes(u.hostname)) return '';
  const parts = u.pathname.split('/').filter(Boolean);
  if(parts.length < 2 || !parts.slice(0,2).every(x => /^[a-z\d._-]+$/i.test(x))) return '';
  return 'https://' + (u.hostname==='www.github.com'?'github.com':u.hostname) + '/' + parts[0] + '/' + parts[1].replace(/\.git$/,'');
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
