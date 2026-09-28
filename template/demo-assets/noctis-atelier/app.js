document.addEventListener('DOMContentLoaded',()=>{
  const toggle=document.querySelector('.menu-toggle');
  const nav=document.querySelector('.nav-links');
  if(toggle && nav){toggle.addEventListener('click',()=>nav.classList.toggle('open'));}

  const buttons=[...document.querySelectorAll('[data-filter]')];
  const items=[...document.querySelectorAll('[data-category]')];
  if(buttons.length){
    buttons.forEach(btn=>btn.addEventListener('click',()=>{
      buttons.forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      const value=btn.dataset.filter;
      items.forEach(item=>{
        item.style.display=(value==='all' || item.dataset.category.includes(value)) ? '' : 'none';
      });
    }));
  }

  const observer=new IntersectionObserver(entries=>{
    entries.forEach(entry=>{if(entry.isIntersecting) entry.target.classList.add('visible');});
  },{threshold:.12});
  document.querySelectorAll('.reveal').forEach(el=>observer.observe(el));
});
