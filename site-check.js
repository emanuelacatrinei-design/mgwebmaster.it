(()=>{"use strict";
const API_ENDPOINTS=[
"https://sitescanner.mgwebmaster.it/v1/scan",
"https://mg-site-check.onrender.com/v1/scan"
];
const form=document.querySelector("[data-site-check-form]");
if(!form)return;
const lang=document.documentElement.lang==="ro"?"ro":"it";
const t=lang==="ro"?{
steps:["Conectare","Pagini","SEO","Securitate","Raport"],
run:"Analiza este în curs. Nu închide pagina.",
err:"Analiza nu a putut fi finalizată.",
offline:"Motorul de analiză nu este încă disponibil. Pagina este pregătită, dar API-ul trebuie publicat.",
na:"N/D",
labels:{seo:"SEO tehnic",performance:"Performanță tehnică",security:"Protecții vizibile",content:"Structură HTML",local:"Semnale SEO locale"},
sev:{high:"ridicată",medium:"medie",low:"redusă"},
issues:"Semnalări detectate",
technical:"Rezumat tehnic",legacyScore:"Scor general",securityPriority:"Prioritate de securitate",total:"în total",affected:"Pagini afectate",method:"Model tehnic v2: SEO, performanță, conținut și semnale locale. Securitatea este evaluată separat. Scorurile noi nu sunt direct comparabile cu cele ale modelului anterior.",
pages:"pagini verificate",
seconds:"secunde",
download:"Raport MG Webmaster",critical:"Criticitate"
}:{
steps:["Connessione","Pagine","SEO","Sicurezza","Report"],
run:"Analisi in corso. Non chiudere la pagina.",
err:"Non è stato possibile completare l’analisi.",
offline:"Il motore di analisi non è ancora raggiungibile. La pagina è pronta, ma l’API deve essere pubblicata.",
na:"N/D",
labels:{seo:"SEO tecnica",performance:"Prestazioni tecniche",security:"Protezioni visibili",content:"Struttura HTML",local:"Segnali SEO locali"},
sev:{high:"alta",medium:"media",low:"bassa"},
issues:"Segnalazioni rilevate",
technical:"Riepilogo tecnico",legacyScore:"Punteggio generale",securityPriority:"Priorità di sicurezza",total:"totali",affected:"Pagine interessate",method:"Modello tecnico v2: SEO, prestazioni, contenuti e segnali locali. La sicurezza è valutata separatamente. I nuovi punteggi non sono direttamente confrontabili con quelli del modello precedente.",
pages:"pagine controllate",
seconds:"secondi",
download:"Report MG Webmaster",critical:"Criticità"
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
function isBasic(data){return data.score_model==="basic_checks_v3"}
// Bridge the deployed basic-checks API using its complete grouped findings.
// No additional requests and no guessed local/qualitative scores.
function withTechnicalScores(data){
if(data.score_model!=="basic_checks_v3" || !Number.isInteger(data.pages_checked) || data.pages_checked<1 || data.pages_checked>5 || !Array.isArray(data.issues) || !data.basic_checks)return data;
const areas={seo:"SEO tecnica",performance:"Prestazioni",security:"Sicurezza",content:"Contenuti"};
const urls=i=>Array.isArray(i.pages)?i.pages.filter(Boolean):[i.page].filter(Boolean);
const known=new Set([data.final_url||data.requested_url,...data.issues.flatMap(urls)].filter(Boolean));
if(known.size>data.pages_checked)return data;
const broken=new Set(data.issues.filter(i=>i.code==="http_error").flatMap(urls));
const validCount=data.pages_checked-broken.size;
const perPage=[...known].filter(u=>!broken.has(u)).map(url=>({url,issues:data.issues.filter(i=>urls(i).includes(url))}));
while(perPage.length<validCount)perPage.push({url:null,issues:[]});
const globalCodes=new Set(["robots_txt","sitemap","cta"]);
const penalties={high:14,medium:7,low:3};
const overrides={http_error:22,noindex:0,scripts:0,styles:0,server:0,https:20,"sec_strict-transport-security":16,"sec_content-security-policy":16};
const penalty=i=>overrides[i.code]??penalties[i.severity]??0;
const roundEven=n=>{const f=Math.floor(n);return n-f===.5?(f%2?f+1:f):Math.round(n)};
const scores={};
for(const [key,area] of Object.entries(areas)){
if(validCount<=0){scores[key]=null;continue}
const values=perPage.map(p=>Math.max(0,100-p.issues.filter(i=>i.area===area&&!globalCodes.has(i.code)).reduce((n,i)=>n+penalty(i),0)));
const globalPenalty=data.issues.filter(i=>i.area===area&&globalCodes.has(i.code)).reduce((n,i)=>n+penalty(i),0);
scores[key]=Math.max(0,roundEven(values.reduce((a,b)=>a+b,0)/validCount)-globalPenalty);
}
scores.local=null;
const included=Object.entries(scores).filter(([k,v])=>v!==null||k==="security");
const mean=included.reduce((n,[,v])=>n+(v??0),0)/included.length;
const securityPenalty=.2*(100-(scores.security??0));
const overall=Math.round(Math.max(0,Math.min(100,mean-securityPenalty)));
const disclaimer=lang==="ro"?"Verificare preliminară pe cel mult cinci pagini. Scorurile se referă doar la controalele tehnice disponibile; nu evaluează calitatea textelor, Core Web Vitals, competitivitatea locală sau vulnerabilitățile interne și nu certifică securitatea site-ului.":"Controllo preliminare su un massimo di cinque pagine. I punteggi riguardano solo i controlli tecnici disponibili; non valutano qualità dei testi, Core Web Vitals, competitività locale o vulnerabilità interne e non certificano la sicurezza del sito.";
return {...data,scores,score_model:"technical_v4",overall_score:overall,technical_score:overall,disclaimer,
scoring:{mean,security_penalty:securityPenalty,security_assumed_zero:scores.security===null,
excluded_sections:Object.keys(scores).filter(k=>scores[k]===null&&k!=="security"),
unavailable_sections:Object.keys(scores).filter(k=>scores[k]===null),compatibility_source:"basic_checks_v3"}};
}
function basicText(k,a){return (lang==="ro"?{seo:"Elemente SEO de bază",performance:"Semnale de încărcare",security:"Protecții vizibile",content:"Structură HTML a conținutului",local:"Competitivitate locală"}:{seo:"Elementi SEO di base",performance:"Segnali di caricamento",security:"Protezioni visibili",content:"Struttura HTML dei contenuti",local:"Competitività locale"})[k]+": "+(a?.status==="not_evaluated"?(lang==="ro"?"Neevaluată":"Non valutata"):`${a?.findings||0} ${lang==="ro"?"semnalări":"segnalazioni"} · ${a?.affected_pages||0} ${t.pages}`)}
const basicMethod=lang==="ro"?"Verificare preliminară pe cel mult cinci pagini. Numerele reprezintă grupuri de semnalări, nu scoruri de calitate. Calitatea textelor, Core Web Vitals, competitivitatea locală și potențialul de clasare nu sunt evaluate. Absența semnalărilor nu garantează absența problemelor.":"Controllo preliminare su un massimo di cinque pagine. I numeri indicano gruppi di segnalazioni, non voti di qualità. Qualità dei testi, Core Web Vitals, competitività locale e capacità di posizionamento non sono valutati. Nessuna segnalazione non significa assenza di problemi.";
function scoringNotes(data){
if(data.score_model!=="technical_v4")return [];
const r=lang==="ro",s=data.scoring||{};
const notes=[r?"Scor general = media secțiunilor − 20% din punctele lipsă la securitate. Scoruri bazate doar pe verificările tehnice efectuate; nu reprezintă o certificare de securitate.":"Punteggio generale = media delle sezioni − 20% dei punti mancanti nella sicurezza. Voti riferiti solo ai controlli tecnici eseguiti; non sono una certificazione di sicurezza."];
if(s.compatibility_source)notes.push(r?"Scoruri calculate din semnalările API disponibile, prin metoda tehnică v4.":"Punteggi calcolati dalle segnalazioni API disponibili, con il metodo tecnico v4.");
if(Number.isFinite(s.mean)&&Number.isFinite(s.security_penalty))notes.push((r?"Media: ":"Media: ")+s.mean.toFixed(2)+(r?"; penalizare securitate: −":"; penalità sicurezza: −")+s.security_penalty.toFixed(2)+"; "+(r?"rezultat: ":"risultato: ")+scoreValue(data.overall_score)+"/100.");
if(s.security_assumed_zero)notes.push(r?"Securitate N/D: evaluare indisponibilă, calculată ca 0 în medie și în penalizare din precauție. Lipsa datelor nu dovedește o vulnerabilitate.":"Sicurezza N/D: valutazione non disponibile, conteggiata come 0 nella media e nella penalità per criterio prudenziale. La mancanza di dati non dimostra una vulnerabilità.");
if(s.excluded_sections?.length)notes.push((r?"Secțiuni N/D excluse din medie: ":"Sezioni N/D escluse dalla media: ")+s.excluded_sections.map(k=>t.labels[k]||k).join(", ")+".");
return notes;
}
function localLines(data){
const r=lang==="ro",l=data.local_signals;
if(!l||l.method!=="local_signals_v1")return [data.scores?.local!=null?(r?"Dovezile semnalelor locale nu sunt disponibile în această versiune a API-ului.":"Le evidenze dei segnali locali non sono disponibili in questa versione dell’API."):(r?"Semnale SEO locale: N/D. API-ul nu furnizează dovezile necesare pentru această evaluare.":"Segnali SEO locali: N/D. L’API non fornisce le evidenze necessarie per questa valutazione.")];
const labels=r?{phone:"Telefon / WhatsApp",address:"Adresă stradală",locality:"Localitate",maps:"Google Maps",schema:"Date structurate"}:{phone:"Telefono / WhatsApp",address:"Indirizzo stradale",locality:"Località",maps:"Google Maps",schema:"Dati strutturati"};
const states=r?{detected:"Identificat",not_detected:"Căutat, neidentificat",not_evaluated:"Verificare neexecutabilă"}:{detected:"Rilevato",not_detected:"Cercato, non rilevato",not_evaluated:"Controllo non eseguibile"};
const lines=[r?"Scorul descrie doar semnalele din HTML-ul primit, nu poziția în Google Maps. Conținutul adăugat prin JavaScript nu este verificat. Telefon 25, adresă 25, localitate 10, Maps 15, date structurate locale 25; Organization valorează doar 5 puncte și nu echivalează cu LocalBusiness. Prezența unui tip local nu confirmă completitudinea datelor. Verificările neexecutabile sunt excluse proporțional din punctaj.":"Il voto descrive solo i segnali nell’HTML ricevuto, non il posizionamento su Google Maps. I contenuti aggiunti da JavaScript non sono verificati. Telefono 25, indirizzo 25, località 10, Maps 15, dati strutturati locali 25; Organization vale solo 5 punti e non equivale a LocalBusiness. La presenza di un tipo locale non conferma la completezza dei dati. I controlli non eseguibili sono esclusi proporzionalmente dal voto."];
if(l.partial)lines.push(r?"Analiză parțială: unele pagini sau date structurate nu au putut fi verificate.":"Analisi parziale: alcune pagine o dati strutturati non sono stati verificabili.");
Object.keys(labels).forEach(k=>{const c=l.checks?.[k];if(!c)return;lines.push(labels[k]+": "+(states[c.status]||states.not_evaluated)+(c.points==null?"":` (${c.points}/${c.max_points})`));
(c.evidence||[]).forEach(e=>lines.push(`  ${e.value} · ${e.source} · ${e.page}`));
if(c.incomplete)lines.push(r?"  Unele date JSON-LD nu au putut fi interpretate.":"  Alcuni dati JSON-LD non sono stati interpretabili.");
if(c.status!=="detected")(c.checked_pages||[]).forEach(url=>lines.push("  "+url));});
(l.unchecked_pages||[]).forEach(url=>lines.push((r?"Pagină neverificabilă: ":"Pagina non verificabile: ")+url));
return lines;
}
function reportLines(d){
d=withTechnicalScores(d);
const value=d.technical_score??d.overall_score;
return [t.download,d.final_url||d.requested_url,"",
...(isBasic(d)?[basicMethod]:[t.legacyScore+": "+scoreValue(value)+(value==null?"":"/100")]),
...(d.score_model?[(lang==="ro"?"Model: ":"Metodo: ")+d.score_model]:[]),
...scoringNotes(d),
...localLines(d),
...(d.score_model==="technical_v2"?[t.method]:[]),
t.securityPriority+": "+t.sev[d.security_priority||d.criticality||"low"],
...(isBasic(d)?Object.entries(d.basic_checks||{}).map(([k,a])=>basicText(k,a)):Object.entries(d.scores||{}).map(([k,v])=>(t.labels[k]||k)+": "+scoreValue(v)+(v==null?"":"/100"))),
(d.pages_checked||0)+" "+t.pages,"",
...(d.php?[d.php.title,d.php.message,(lang==="ro"?"Reguli verificate la: ":"Regole verificate il: ")+d.php.rules_reviewed_on,""]:[]),
t.issues+":",...(d.issues||[]).flatMap(i=>[`- [${t.sev[i.severity]||i.severity}] ${i.title}: ${i.message}`,...(i.pages||[i.page]).filter(Boolean).map(url=>`  ${url}`)]),"",d.disclaimer||""];
}
function render(data){data=withTechnicalScores(data);lastResult=data;clearTimers();setStep(4,100);status.hidden=true;results.hidden=false;
results.querySelector(".site-check-summary").style.gridTemplateColumns=isBasic(data)?"1fr":"";
const ring=results.querySelector("[data-overall-ring]");ring.hidden=isBasic(data);ring.style.display=isBasic(data)?"none":"";ring.style.setProperty("--score",Math.max(0,Math.min(100,data.overall_score||0)));
results.querySelector("[data-overall]").textContent=data.technical_score??data.overall_score??t.na;
const caption=results.querySelector("[data-score-caption]");if(caption)caption.textContent=isBasic(data)?(lang==="ro"?"Verificări de bază":"Controlli di base"):data.score_model==="technical_v2"?t.technical:t.legacyScore;
const method=results.querySelector("[data-score-method]");if(method){method.hidden=!isBasic(data)&&!["technical_v2","technical_v4"].includes(data.score_model);method.textContent=data.score_model==="technical_v4"?scoringNotes(data).join(" "):isBasic(data)?basicMethod:t.method}
results.querySelector("[data-url]").textContent=data.final_url||data.requested_url||"";
results.querySelector("[data-meta]").textContent=`${data.pages_checked||0} ${t.pages} · ${((data.duration_ms||0)/1000).toFixed(1)} ${t.seconds}`;
const grid=results.querySelector("[data-score-grid]");grid.innerHTML="";
["seo","performance","security","content","local"].forEach(k=>{const v=data.scores?.[k];const el=document.createElement("div");el.className="site-check-score-card";if(isBasic(data)){el.textContent=basicText(k,data.basic_checks?.[k]);grid.appendChild(el);return}el.innerHTML=`<strong class="${v==null?"site-check-na":""}">${escapeHtml(scoreValue(v))}</strong><span>${escapeHtml(t.labels[k])}</span>`;grid.appendChild(el)});
let localBox=results.querySelector("[data-local-signals]");
if(!localBox){localBox=document.createElement("article");localBox.dataset.localSignals="";results.querySelector("[data-issues]").before(localBox)}
localBox.className="site-check-issue";
localBox.innerHTML=`<h3>${escapeHtml(t.labels.local)}</h3>${localLines(data).map(line=>`<p style="overflow-wrap:anywhere">${escapeHtml(line)}</p>`).join("")}`;
const c=data.counts||{};const crit=data.security_priority||data.criticality||"low";results.querySelector("[data-counts]").innerHTML=`<span class="site-check-chip high">${c.high||0} ${t.sev.high}</span><span class="site-check-chip medium">${c.medium||0} ${t.sev.medium}</span><span class="site-check-chip low">${c.low||0} ${t.sev.low}</span><span class="site-check-chip">${c.total||0} ${t.total}</span><span class="site-check-chip ${crit==="high"?"high":crit==="medium"?"medium":"low"}">${(isBasic(data)||["technical_v2","technical_v4"].includes(data.score_model))?t.securityPriority:t.critical}: ${t.sev[crit]||crit}</span>`;
let phpBox=results.querySelector("[data-php-report]");
if(!phpBox){phpBox=document.createElement("article");phpBox.dataset.phpReport="";results.querySelector("[data-issues]").before(phpBox)}
phpBox.hidden=!data.php;
if(data.php){const p=data.php;phpBox.className="site-check-issue "+(["unsupported","potentially_outdated"].includes(p.status)?"high":"medium");phpBox.innerHTML=`<h3>${escapeHtml(p.title)}</h3><p>${escapeHtml(p.message)}</p><small>${lang==="ro"?"Reguli verificate la":"Regole verificate il"} ${escapeHtml(p.rules_reviewed_on)}</small>`;const source=document.createElement("a");source.href="https://www.php.net/archive/2026.php";source.target="_blank";source.rel="noopener noreferrer";source.textContent=lang==="ro"?" Avertizări oficiale PHP":" Avvisi ufficiali PHP";phpBox.appendChild(source)}
const list=results.querySelector("[data-issues]");list.innerHTML="";
(data.issues||[]).forEach(issue=>{const el=document.createElement("article");el.className="site-check-issue "+(issue.severity||"low");el.innerHTML=`<div class="site-check-issue-head"><div><h3>${escapeHtml(issue.title)}</h3><p>${escapeHtml(issue.message)}</p></div><span class="site-check-badge">${escapeHtml(t.sev[issue.severity]||issue.severity)}</span></div>${(issue.pages||[issue.page]).filter(Boolean).map(url=>`<div><small>${escapeHtml(url)}</small></div>`).join("")}`;list.appendChild(el)});
results.scrollIntoView({behavior:"smooth",block:"start"});
}
function showError(text){clearTimers();status.hidden=false;bar.style.width="0";steps.forEach(x=>x.classList.remove("active","done"));msg.innerHTML=`<div class="site-check-error">${escapeHtml(text)}</div>`;btn.disabled=false}
form.addEventListener("submit",async e=>{e.preventDefault();if(!auth.checked)return;
const turnstileToken=(document.querySelector('input[name="cf-turnstile-response"]')?.value||"").trim();
if(!turnstileToken){showError(lang==="ro"?"Completează verificarea anti-bot înainte de analiză.":"Completa la verifica anti-bot prima di avviare l’analisi.");return;}
btn.disabled=true;results.hidden=true;status.hidden=false;fakeProgress();
try{
let lastErr=null,res=null;
for(const endpoint of API_ENDPOINTS){
  try{
    res=await fetch(endpoint,{
      method:"POST",
      headers:{"Content-Type":"text/plain;charset=UTF-8","Accept":"application/json","Accept-Language":lang},
      body:JSON.stringify({url:input.value.trim(),authorized:true,language:lang,turnstile_token:turnstileToken}),
      mode:"cors"
    });
    break;
  }catch(err){lastErr=err}
}
if(!res)throw lastErr||new Error("network");
let body={};try{body=await res.json()}catch{}
if(!res.ok)throw new Error(body.detail||t.err);render(body)
}catch(err){const network=/fetch|network|failed|load/i.test(String(err));showError(network?t.offline:(err.message||t.err))}
finally{btn.disabled=false;if(window.turnstile&&typeof window.turnstile.reset==="function")window.turnstile.reset()}});
const printBtn=document.querySelector("[data-site-check-print]");if(printBtn)printBtn.addEventListener("click",()=>window.print());
const txtBtn=document.querySelector("[data-site-check-download]");if(txtBtn)txtBtn.addEventListener("click",()=>{if(!lastResult)return;const d=lastResult;const lines=reportLines(d);const blob=new Blob([lines.join("\n")],{type:"text/plain;charset=utf-8"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);let host="sito";try{host=new URL(d.final_url||d.requested_url).hostname.replace(/^www\./,"")}catch{}a.download=`mg-webmaster-site-check-${host}.txt`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)});
})();

