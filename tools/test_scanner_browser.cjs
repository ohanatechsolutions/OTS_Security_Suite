'use strict';
// No browser/network is used; test the real embedded WebView2 JS in a tiny
// synthetic DOM VM and ensure normalization cannot broaden the Go allowlist.
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','scanner','internal','desktop','assets','app.js'),'utf8');
const nodes=new Map();
function el(id){
 if(!nodes.has(id)) nodes.set(id,{
  value:'',textContent:'',innerHTML:'',style:{},disabled:false,
  classList:{toggle(){}},addEventListener(){},onclick:null
 });
 return nodes.get(id);
}
const doc={getElementById:el,querySelectorAll:()=>[],visibilityState:'visible'};
const context={document:doc,URL,URLSearchParams,AbortController,
 location:{search:''},setInterval(){},
 fetch:async()=>({ok:true,json:async()=>({rule_count:95}),text:async()=>''})};
vm.createContext(context);vm.runInContext(source,context,{timeout:1000});
const cases=[
 ['github.com/owner/repo','https://github.com/owner/repo'],
 ['https://github.com/owner/repo.git','https://github.com/owner/repo'],
 ['https://www.github.com/owner/repo','https://github.com/owner/repo'],
 ['bitbucket.org/team/project','https://bitbucket.org/team/project'],
 ['https://github.com/owner/repo','https://github.com/owner/repo'],
 ['https://github.com/owner/repo/tree/main',''],
 ['http://github.com/owner/repo',''],
 ['https://github.com.evil.tld/owner/repo',''],
 ['https://github.com/owner/repo?token=secret',''],
 ['https://user:password@github.com/owner/repo',''],
 ['https://github.com:444/owner/repo',''],
 ['https://github.com/owner/repo#fragment',''],
 ['https://localhost/owner/repo',''],
 ['file:///etc/passwd',''],
 ['https://github.com/owner/..',''],
 ['https://github.com/owner/a%2Fb',''],
 ['','']
];
for(const [input,expected] of cases){
 const actual=context.normalizeRepositoryInput(input);
 assert.equal(actual,expected,'repo normalization '+input);
}
console.log('Embedded RepoScan browser URL normalization: '+cases.length+'/'+cases.length+' PASS');
