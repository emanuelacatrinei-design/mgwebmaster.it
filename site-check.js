(()=>{"use strict";
const API="https://audit.mgwebmaster.it/v1/scan";
const form=document.querySelector("[data-site-check-form]");
if(!form)return;
const lang=document.documentElement.lang==="ro"?"ro":"it";
const t=lang==="ro"?{
steps:["Conectare","Pagini","SEO","Securitate","Raport"],
run:"Analiza este în curs. Nu închide pagina.",
err:"Analiza nu a putut fi finalizată.",
offline:"Motorul de analiză nu este încă disponibil. Pagina este pregătită, dar API-ul trebuie publicat.",
na:"N/A",
labels:{seo:"SEO tehnic",performance:"Performanță",security:"Securitate",content:"Conținut",local:"SEO local"},
sev:{high:"ridicată",medium:"medie",low:"redusă"},
issues:"Probleme principale detectate",
pages:"pagini verificate",
seconds:"secunde",
download:"Raport MG Webmaster"
}:{
steps:["Connessione","Pagine","SEO","Sicurezza","Report"],
run:"Analisi in corso. Non chiudere la pagina.",
err:"Non è stato possibile completare l’analisi.",
offline:"Il motore di analisi non è ancora raggiungibile. La pagina è pronta, ma l’API deve essere pubblicata.",
na:"N/D",
labels:{seo:"SEO tecnica",performance:"Prestazioni",security:"Sicurezza",content:"Contenuti",local:"SEO locale"},
sev:{high:"alta",medium:"media",low:"bassa"},
issues:"Problemi principali rilevati",
pages:"pagine controllate",
seconds:"secondi",
download:"Report MG Webmaster"
};
const input=form.querySelector("input[name=url]");
const auth=form.querySelector("input[name=authorized]");
const btn=form.querySelector("button[type=submit]");
const status=document.querySelector("[data-site-check-status]");
const bar=document.querySelector("[data-site-check-bar]");
const msg=document.querySelector("[data-site-check-message]");
const steps=[...document.querySelectorAll("[data-site-check-step]")];
const results=document.querySelector("[data-site-check-results]");
let lastResult=null, timers=[];
function clearTimers(){timers.forEach(clearTimeout);timers=[]}
function setStep(i,pct,text){bar.style.width=pct+"%";steps.forEach((el,n)=>{el.classList.toggle("active",n===i);el.classList.toggle("done",n<i)});if(text)msg.textContent=text}
function fakeProgress(){clearTimers();setStep(0,9,t.run);[[1,24,1000],[2,46,2600],[3,68,4500],[4,84,6500]].forEach(([i,p,ms])=>timers.push(setTimeout(()=>setStep(i,p),ms)))}
function scoreValue(v){return v===null||v===undefined?t.na:String(v)}
function escapeHtml(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m]))}
function render(data){lastResult=data;clearTimers();setStep(4,100);status.hidden=true;results.hidden=false;
const ring=results.querySelector("[data-overall-ring]");ring.style.setProperty("--score",Math.max(0,Math.min(100,data.overall_score||0)));
results.querySelector("[data-overall]").textContent=data.overall_score??t.na;
results.querySelector("[data-url]").textContent=data.final_url||data.requested_url||"";
results.querySelector("[data-meta]").textContent=`${data.pages_checked||0} ${t.pages} · ${((data.duration_ms||0)/1000).toFixed(1)} ${t.seconds}`;
const grid=results.querySelector("[data-score-grid]");grid.innerHTML="";
["seo","performance","security","content","local"].forEach(k=>{const v=data.scores?.[k];const el=document.createElement("div");el.className="site-check-score-card";el.innerHTML=`<strong class="${v==null?"site-check-na":""}">${escapeHtml(scoreValue(v))}</strong><span>${escapeHtml(t.labels[k])}</span>`;grid.appendChild(el)});
const c=data.counts||{};results.querySelector("[data-counts]").innerHTML=`<span class="site-check-chip high">${c.high||0} ${t.sev.high}</span><span class="site-check-chip medium">${c.medium||0} ${t.sev.medium}</span><span class="site-check-chip low">${c.low||0} ${t.sev.low}</span><span class="site-check-chip">${c.total||0} totali</span>`;
const list=results.querySelector("[data-issues]");list.innerHTML="";
(data.issues||[]).forEach(issue=>{const el=document.createElement("article");el.className="site-check-issue "+(issue.severity||"low");el.innerHTML=`<div class="site-check-issue-head"><div><h3>${escapeHtml(issue.title)}</h3><p>${escapeHtml(issue.message)}</p></div><span class="site-check-badge">${escapeHtml(t.sev[issue.severity]||issue.severity)}</span></div>${issue.page?`<small>${escapeHtml(issue.page)}</small>`:""}`;list.appendChild(el)});
results.scrollIntoView({behavior:"smooth",block:"start"});
}
function showError(text){clearTimers();status.hidden=false;bar.style.width="0";steps.forEach(x=>x.classList.remove("active","done"));msg.innerHTML=`<div class="site-check-error">${escapeHtml(text)}</div>`;btn.disabled=false}
form.addEventListener("submit",async e=>{e.preventDefault();if(!auth.checked)return;btn.disabled=true;results.hidden=true;status.hidden=false;fakeProgress();
try{const res=await fetch(API,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:input.value.trim(),authorized:true})});
let body={};try{body=await res.json()}catch{}
if(!res.ok)throw new Error(body.detail||t.err);render(body)
}catch(err){const network=/fetch|network|failed/i.test(String(err));showError(network?t.offline:(err.message||t.err))}
finally{btn.disabled=false}});
const printBtn=document.querySelector("[data-site-check-print]");if(printBtn)printBtn.addEventListener("click",()=>window.print());
const txtBtn=document.querySelector("[data-site-check-download]");if(txtBtn)txtBtn.addEventListener("click",()=>{if(!lastResult)return;const d=lastResult;const lines=[t.download,d.final_url||d.requested_url,"","Punteggio generale: "+(d.overall_score??t.na)+"/100",...Object.entries(d.scores||{}).map(([k,v])=>`${t.labels[k]||k}: ${scoreValue(v)}`),"",t.issues+":",...(d.issues||[]).map(i=>`- [${t.sev[i.severity]||i.severity}] ${i.title}: ${i.message}`),"",d.disclaimer||""];const blob=new Blob([lines.join("\n")],{type:"text/plain;charset=utf-8"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);let host="sito";try{host=new URL(d.final_url||d.requested_url).hostname.replace(/^www\./,"")}catch{}a.download=`mg-webmaster-site-check-${host}.txt`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)});
})();