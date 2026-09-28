(() => {
  'use strict';
  const ro = document.documentElement.lang === 'ro';
  const copy = ro ? {
    menu:'Deschide meniul', closeMenu:'Închide meniul', zoom:'Mărește imaginea', close:'Închide',
    sent:'Aceasta este o demonstrație. Nu s-au trimis și nu s-au salvat date.'
  } : {menu:'Apri menu', closeMenu:'Chiudi menu', zoom:'Ingrandisci immagine', close:'Chiudi',
    sent:'Questa è una demo. Nessun dato è stato inviato o salvato.'};
  if (window.self !== window.top) document.body.classList.add('is-embedded');
  const header = document.querySelector('header');
  const toggle = header?.querySelector('button.mobile-toggle,button.menu-btn,button.menu,button.mobile,button.menu-toggle');
  const nav = header?.querySelector('nav');
  if (toggle && nav) {
    nav.id ||= 'demo-navigation';
    toggle.type = 'button';
    toggle.setAttribute('aria-controls',nav.id);
    const setMenu = open => {
      nav.classList.toggle('open',open);
      header.classList.toggle('menu-open',open);
      header.querySelector('.nav')?.classList.toggle('open',open);
      toggle.setAttribute('aria-expanded',String(open));
      toggle.setAttribute('aria-label',open ? copy.closeMenu : copy.menu);
    };
    setMenu(false);
    toggle.addEventListener('click',()=>setMenu(toggle.getAttribute('aria-expanded')!=='true'));
    nav.addEventListener('click',e=>{if(e.target.closest('a'))setMenu(false)});
    document.addEventListener('keydown',e=>{if(e.key==='Escape' && toggle.getAttribute('aria-expanded')==='true'){setMenu(false);toggle.focus()}});
    document.addEventListener('click',e=>{if(!header.contains(e.target))setMenu(false)});
  }
  document.querySelectorAll('form[data-demo-form]').forEach(form => {
    const status = document.createElement('p');
    status.className='mg-demo-form-status';status.setAttribute('role','status');status.setAttribute('aria-live','polite');
    form.append(status);
    form.addEventListener('submit',event=>{event.preventDefault();status.textContent=copy.sent;});
    form.querySelectorAll('button[type="submit"]').forEach(button=>{button.disabled=false;});
  });
  document.querySelectorAll('.acc button,.faq button').forEach((button,index)=>{
    const panel=button.nextElementSibling;if(!panel)return;
    panel.id ||= 'demo-answer-'+index;
    button.type='button';button.setAttribute('aria-controls',panel.id);button.setAttribute('aria-expanded','false');
    panel.hidden=true;
    button.addEventListener('click',()=>{
      const open=button.getAttribute('aria-expanded')!=='true';
      button.setAttribute('aria-expanded',String(open));button.classList.toggle('active',open);
      panel.hidden=!open;panel.style.display=open?'block':'none';
    });
  });
  // Replaces the incomplete gallery handlers in the source packages with one dialog.
  document.querySelectorAll('div.lightbox').forEach(old=>old.remove());
  const photos=[...document.querySelectorAll('[data-lightbox],.gallery img,.gallery-grid img,.studio-gallery img')]
    .filter(node=>!node.parentElement.closest('[data-lightbox]'));
  let lightbox, large, caption, opener;
  const show = (node,event) => {
    event.preventDefault();
    const img=node.matches('img')?node:node.querySelector('img');
    const src=node.getAttribute('data-lightbox') || (node.matches('a')?node.getAttribute('href'):img?.getAttribute('src'));
    if(!src)return;
    if(!lightbox){
      lightbox=document.createElement('dialog');lightbox.className='mg-demo-lightbox';lightbox.setAttribute('aria-label',copy.zoom);
      const close=document.createElement('button');close.type='button';close.textContent=copy.close+' ×';close.addEventListener('click',()=>lightbox.close());
      large=document.createElement('img');caption=document.createElement('p');
      lightbox.append(close,large,caption);document.body.append(lightbox);
      lightbox.addEventListener('click',e=>{if(e.target===lightbox)lightbox.close()});
      lightbox.addEventListener('close',()=>opener?.focus());
    }
    opener=node;large.src=src;large.alt=img?.alt||'';caption.textContent=large.alt;lightbox.showModal();
  };
  photos.forEach(node=>{
    node.classList.add('mg-demo-zoom');
    node.setAttribute('aria-label',copy.zoom+(node.alt?': '+node.alt:''));
    if(!node.matches('a,button')){
      node.tabIndex=0;node.setAttribute('role','button');
      node.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){show(node,e)}});
    }
    node.addEventListener('click',e=>show(node,e));
  });
})();
