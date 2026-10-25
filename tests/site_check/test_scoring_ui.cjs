const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
function element(){
 return {hidden:false,textContent:'',innerHTML:'',children:[],style:{setProperty(){}},
 classList:{toggle(){},add(){},remove(){}},appendChild(e){this.children.push(e)},
 before(){},scrollIntoView(){},addEventListener(){},querySelector(){return element()}};
}
for (const lang of ['it','ro']){
 const nodes = new Map();
 const get = key => {if(!nodes.has(key))nodes.set(key,element());return nodes.get(key)};
 const form=element(), results=element();
 form.querySelector=get; results.querySelector=get;
 const context={console,clearTimeout,setTimeout,URL,Blob,window:{},
 document:{documentElement:{lang},
 querySelector:s=>s==='[data-site-check-form]'?form:s==='[data-site-check-results]'?results:get(s),
 querySelectorAll:()=>[],createElement:element}};
 vm.createContext(context);
 let source=fs.readFileSync(path.join(__dirname,'../../site-check.js'),'utf8');
 source=source.replace(/\}\)\(\);\s*$/, 'globalThis.testAPI={render,reportLines};})();');
 vm.runInContext(source,context);
 const d={score_model:'technical_v4',overall_score:20,technical_score:20,
 scores:{seo:80,performance:null,security:null,content:null,local:null},pages_checked:1,
 scoring:{mean:40,security_penalty:20,security_assumed_zero:true,
 excluded_sections:['performance','content','local']},issues:[],security_priority:'low'};
 context.testAPI.render(d);
 assert.equal(get('[data-overall]').textContent,20);
 assert.equal(get('[data-overall-ring]').hidden,false);
 assert.match(get('[data-score-grid]').children[2].innerHTML,/N\/D/);
 const note=get('[data-score-method]').textContent;
 assert.match(note,lang==='it'?/conteggiata come 0/:/calculată ca 0/);
 const txt=context.testAPI.reportLines(d).join('\n');
 assert.match(txt,/20\/100/);
 assert.match(txt,lang==='it'?/Protezioni visibili: N\/D/:/Protecții vizibile: N\/D/);
 assert.doesNotMatch(txt,/N\/[DA]\/100/);
 assert.match(txt,lang==='it'?/escluse dalla media/:/excluse din medie/);
 // Zero is a measured value; its report must not masquerade as N/D.
 assert.match(context.testAPI.reportLines({...d,scores:{security:0}}).join('\n'),/0\/100/);
 const legacy=context.testAPI.reportLines({score_model:'basic_checks_v3',scores:{security:null},basic_checks:{security:{status:'not_evaluated'}},issues:[]}).join('\n');
 assert.doesNotMatch(legacy,/N\/D\/100/);
}
console.log('IT/RO: rendering, missing-security explanation and TXT export passed.');
