'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'extension', 'popup.js'), 'utf8');
function popupFor(tabUrl) {
  const created=[];
  const node=()=>({textContent:'',disabled:true,handler:null,addEventListener(type,fn){if(type==='click')this.handler=fn;}});
  const elements={repo:node(),scan:node(),open:node()};
  const chrome={tabs:{query(_q,cb){cb([{url:tabUrl}]);},create({url}){created.push(url);}}};
  const document={getElementById(id){assert.ok(elements[id]);return elements[id];}};
  vm.runInNewContext(source,{chrome,document,URL},{timeout:1000});
  return {elements,created};
}
const fixtures=[
 ['https://github.com/owner/repo','https://github.com/owner/repo'],
 ['https://www.github.com/owner/repo.git/','https://github.com/owner/repo'],
 ['https://bitbucket.org/team/project','https://bitbucket.org/team/project'],
 ['http://github.com/owner/repo',''],
 ['https://github.com.evil.test/owner/repo',''],
 ['https://github.com/owner/repo/tree/main',''],
 ['https://github.com/owner/repo?tab=readme',''],
 ['https://github.com/owner/repo#readme',''],
 ['https://user:password@github.com/owner/repo',''],
 ['https://github.com:444/owner/repo',''],
 ['https://github.com/owner/..',''],
 ['https://localhost/owner/repo',''],
 ['https://github.com/owner%2frepo/other','']
];
for(const [url,expected] of fixtures){
 const {elements,created}=popupFor(url);
 assert.equal(elements.scan.disabled,!expected,url);
 if(expected){
  assert.equal(elements.repo.textContent,expected);
  elements.scan.handler();
  assert.equal(created[0],'ots-security://scan?url='+encodeURIComponent(expected));
 } else assert.match(elements.repo.textContent,/public GitHub or Bitbucket/);
 elements.open.handler();
 assert.equal(created.at(-1),'ots-security://scan');
}
console.log('Chrome popup URL and protocol contracts: '+fixtures.length+'/'+fixtures.length+' PASS');
