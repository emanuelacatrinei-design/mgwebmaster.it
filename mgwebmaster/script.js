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
    if(feedback)feedback.textContent='Link copiato: ora puoi incollarlo nell’app che preferisci.';
  }catch(error){if(error?.name!=='AbortError'&&feedback)feedback.textContent='Non è stato possibile aprire la condivisione. Copia il link dalla barra del browser.'}
}));
