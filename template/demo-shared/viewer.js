(() => {
  'use strict';
  const frame=document.querySelector('.demo-frame');
  const stage=document.querySelector('.demo-stage');
  const pages=document.querySelector('#demo-page');
  const direct=document.querySelector('.demo-direct');
  const status=document.querySelector('#demo-status');
  const languageSwitch=document.querySelector('[data-language-switch]');
  const ro=document.documentElement.lang==='ro';
  const allowed=new Map([...pages.options].map(option=>[option.value,option.textContent]));
  const base=new URL('site/',location.href);
  const requested=new URLSearchParams(location.search).get('pagina');
  if(requested && allowed.has(requested)){pages.value=requested;frame.src=new URL(requested,base).href;direct.href=frame.src;}
  pages.addEventListener('change',()=>{
    if(allowed.has(pages.value)){frame.src=new URL(pages.value,base).href;direct.href=frame.src;}
  });
  document.querySelectorAll('[data-device]').forEach(button=>button.addEventListener('click',()=>{
    stage.dataset.size=button.dataset.device;
    document.querySelectorAll('[data-device]').forEach(other=>other.setAttribute('aria-pressed',String(other===button)));
    status.textContent=(ro?'Previzualizare: ':'Anteprima: ')+button.textContent.trim();
  }));
  frame.addEventListener('load',()=>{
    try {
      const url=new URL(frame.contentWindow.location.href);
      const file=url.pathname.split('/').pop()||'index.html';
      if(url.origin===location.origin && url.pathname.startsWith(base.pathname) && allowed.has(file)){
        pages.value=file;direct.href=url.href;
        const peer=pages.selectedOptions[0]?.dataset.peer;
        if(languageSwitch && peer){
          const next=new URL(languageSwitch.href);
          if(peer==='index.html')next.searchParams.delete('pagina');else next.searchParams.set('pagina',peer);
          languageSwitch.href=next.href;
        }
        frame.title=(ro?'Demonstrație navigabilă: ':'Demo navigabile: ')+allowed.get(file);
        const current=new URL(location.href);
        if(file==='index.html')current.searchParams.delete('pagina');else current.searchParams.set('pagina',file);
        history.replaceState(null,'',current);
      }
    } catch (_) { /* The direct link remains available if a browser restricts frame access. */ }
  });
})();
