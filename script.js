// MG Webmaster: menu principale uniforme su tutte le pagine
const isRomanianPage=(document.documentElement.lang||'').toLowerCase().startsWith('ro')||location.pathname.startsWith('/ro/');
document.querySelectorAll('.nav-links').forEach(nav=>{
  const ro=isRomanianPage;
  const items=ro?[
    ['/ro/','Acasă'],['/ro/servicii/','Servicii'],['/ro/preturi/','Prețuri'],
    ['/ro/proiecte/','Proiecte'],['/ro/template/','Template'],['/ro/blog/','Blog'],
    ['/ro/despre-mine/','Despre mine'],['/ro/analiza-site/','Analizează site-ul'],['/ro/contact/','Contact']
  ]:[
    ['/','Home'],['/servizi/','Servizi'],['/prezzi/','Prezzi'],
    ['/progetti/','Progetti'],['/template/','Template'],['/blog/','Blog'],
    ['/chi-sono/','Chi sono'],['/analisi-sito/','Analizza sito'],['/contatti/','Contatti']
  ];
  const oldLang=nav.querySelector('.language-menu')?.cloneNode(true);
  const oldWa=nav.querySelector('a.button[href*="wa.me"]')?.cloneNode(true);
  const current=(location.pathname.replace(/\/+$/,'')||'/');
  nav.innerHTML='';
  const row1=document.createElement('div'); row1.className='nav-row nav-row-primary';
  const row2=document.createElement('div'); row2.className='nav-row nav-row-secondary';
  const secondLinks=document.createElement('div'); secondLinks.className='nav-secondary-links';
  const actions=document.createElement('div'); actions.className='nav-actions';
  items.forEach(([href,label],index)=>{
    const a=document.createElement('a'); a.href=href; a.textContent=label;
    const normalized=(href.replace(/\/+$/,'')||'/');
    if(current===normalized || (normalized!=='/' && current.startsWith(normalized))) a.setAttribute('aria-current','page');
    if(index<6) row1.appendChild(a); else secondLinks.appendChild(a);
  });
  if(oldLang) actions.appendChild(oldLang);
  if(oldWa) actions.appendChild(oldWa);
  row2.append(secondLinks,actions);
  nav.append(row1,row2);
});

const button=document.querySelector('.menu-button');const menu=document.querySelector('.nav-links');if(button&&menu){button.addEventListener('click',()=>{const open=menu.classList.toggle('open');button.setAttribute('aria-expanded',String(open))})}

document.querySelectorAll('.scrolling-content').forEach(track=>{
  if(track.dataset.marqueeReady)return;
  [...track.children].forEach(item=>{
    const clone=item.cloneNode(true);
    clone.setAttribute('aria-hidden','true');
    track.appendChild(clone);
  });
  track.dataset.marqueeReady='true';
});

const reducedMotion=window.matchMedia('(prefers-reduced-motion: reduce)');
const updateLogoMotion=()=>document.querySelectorAll('.brand-logo-video').forEach(video=>{
  if(reducedMotion.matches){video.pause();video.currentTime=0}else{video.play().catch(()=>{})}
});
updateLogoMotion();
reducedMotion.addEventListener?.('change',updateLogoMotion);

if(!reducedMotion.matches&&'IntersectionObserver' in window){
  const revealItems=[...document.querySelectorAll('main .section .eyebrow, main .section h2, main .section .card, main .section .step, main .section .local-list span, main .section .infographic')];
  document.querySelectorAll('.grid-3, .article-grid, .process, .local-list').forEach(group=>{
    [...group.children].forEach((item,index)=>item.style.setProperty('--reveal-delay',`${Math.min(index*75,375)}ms`));
  });
  revealItems.forEach(item=>item.classList.add('reveal-item'));
  document.body.classList.add('reveal-ready');
  const revealObserver=new IntersectionObserver(entries=>{
    entries.forEach(entry=>{
      if(!entry.isIntersecting)return;
      entry.target.classList.add('is-visible');
      revealObserver.unobserve(entry.target);
    });
  },{threshold:.12,rootMargin:'0px 0px -7%'});
  revealItems.forEach(item=>revealObserver.observe(item));
}

document.querySelectorAll('[data-native-share]').forEach(button=>button.addEventListener('click',async()=>{
  const feedback=button.closest('.share-section')?.querySelector('.share-feedback');
  const data={title:document.title,text:document.querySelector('meta[name="description"]')?.content||'',url:location.href};
  try{
    if(navigator.share){await navigator.share(data);return}
    await navigator.clipboard.writeText(location.href);
    if(feedback)feedback.textContent=isRomanianPage?'Link copiat: îl poți lipi în aplicația dorită.':'Link copiato: ora puoi incollarlo nell’app che preferisci.';
  }catch(error){if(error?.name!=='AbortError'&&feedback)feedback.textContent=isRomanianPage?'Nu s-a putut deschide meniul de distribuire. Copiază linkul din bara de adrese a browserului.':'Non è stato possibile aprire la condivisione. Copia il link dalla barra del browser.'}
}));

const zoomableImages=[...document.querySelectorAll('main img.infographic')];
if(zoomableImages.length){
  const lightbox=document.createElement('div');
  lightbox.className='image-lightbox';
  lightbox.hidden=true;
  lightbox.setAttribute('role','dialog');
  lightbox.setAttribute('aria-modal','true');
  lightbox.innerHTML=`<button type="button" class="image-lightbox-close" aria-label="${isRomanianPage?'Închide imaginea mărită':'Chiudi immagine ingrandita'}">×</button><img alt="">`;
  document.body.appendChild(lightbox);
  const enlarged=lightbox.querySelector('img');
  const closeButton=lightbox.querySelector('button');
  let opener=null;
  const close=()=>{lightbox.hidden=true;document.body.classList.remove('lightbox-open');enlarged.removeAttribute('src');opener?.focus()};
  zoomableImages.forEach(img=>{
    img.classList.add('is-zoomable');img.tabIndex=0;img.setAttribute('role','button');img.setAttribute('aria-label',`${img.alt||(isRomanianPage?'Infografic':'Infografica')}: ${isRomanianPage?'deschide pe tot ecranul':'apri a schermo intero'}`);
    const open=()=>{opener=img;enlarged.src=img.dataset.fullSrc||img.currentSrc||img.src;enlarged.alt=img.alt;lightbox.setAttribute('aria-label',img.alt||(isRomanianPage?'Infografic':'Infografica'));lightbox.hidden=false;document.body.classList.add('lightbox-open');closeButton.focus()};
    img.addEventListener('click',open);img.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();open()}});
  });
  closeButton.addEventListener('click',close);
  lightbox.addEventListener('click',event=>{if(event.target===lightbox)close()});
  document.addEventListener('keydown',event=>{
    if(lightbox.hidden)return;
    if(event.key==='Escape'){event.preventDefault();close()}
    if(event.key==='Tab'){event.preventDefault();closeButton.focus()}
  });
}

/* MG Site Check: collegamento anche nel footer */
(function(){
  function addSiteCheckFooterLink(){
    var ro=document.documentElement.lang&&document.documentElement.lang.toLowerCase().startsWith("ro");
    var href=ro?"/ro/analiza-site/":"/analisi-sito/";
    document.querySelectorAll(".footer-grid").forEach(function(grid){
      if(grid.querySelector('a[href="'+href+'"]')) return;
      var col=grid.querySelector("div");
      if(!col) return;
      var a=document.createElement("a");
      a.href=href;a.textContent=ro?"Analiză gratuită site":"Analisi gratuita sito";
      col.appendChild(a);
    });
  }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded",addSiteCheckFooterLink);
  else addSiteCheckFooterLink();
})();
