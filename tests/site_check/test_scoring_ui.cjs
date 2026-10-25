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
 source=source.replace(/\}\)\(\);\s*$/, 'globalThis.testAPI={render,reportLines,withTechnicalScores};})();');
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
 // Deployed v3 API: numeric fields are null, but measured findings are usable.
 const old={score_model:'basic_checks_v3',pages_checked:2,final_url:'https://example.com/',
 scores:{seo:null,performance:null,security:null,content:null,local:null},
 basic_checks:{seo:{status:'findings'},security:{status:'findings'}},issues:[
 {code:'sec_strict-transport-security',area:'Sicurezza',severity:'medium',pages:['https://example.com/','https://example.com/b']},
 {code:'title_missing',area:'SEO tecnica',severity:'high',pages:['https://example.com/']},
 {code:'sitemap',area:'SEO tecnica',severity:'low',pages:['https://example.com/']}]};
 const bridged=context.testAPI.withTechnicalScores(old);
 assert.equal(bridged.scores.security,84);
 assert.equal(bridged.scores.seo,90);
 assert.equal(bridged.scores.local,null);
 assert.equal(bridged.overall_score,90);
 context.testAPI.render(old);
 assert.equal(get('[data-overall-ring]').hidden,false);
 assert.match(context.testAPI.reportLines(old).join('\n'),/90\/100/);
 assert.match(context.testAPI.reportLines(old).join('\n'),/84\/100/);
 assert.equal(old.score_model,'basic_checks_v3'); // do not mutate API evidence
 const invalid={...old,pages_checked:1,issues:[{code:'http_error',area:'SEO tecnica',severity:'high',pages:['https://example.com/']}]};
 const missing=context.testAPI.withTechnicalScores(invalid);
 assert.equal(missing.scores.security,null);
 assert.equal(missing.scoring.security_assumed_zero,true);
 assert.equal(missing.overall_score,0);
 // Zero is a measured value; its report must not masquerade as N/D.
 assert.match(context.testAPI.reportLines({...d,scores:{security:0}}).join('\n'),/0\/100/);
 const legacy=context.testAPI.reportLines({score_model:'basic_checks_v3',scores:{security:null},basic_checks:{security:{status:'not_evaluated'}},issues:[]}).join('\n');
 assert.doesNotMatch(legacy,/N\/D\/100/);
}
console.log('IT/RO: rendering, missing-security explanation and TXT export passed.');
