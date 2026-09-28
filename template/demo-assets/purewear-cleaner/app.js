
document.documentElement.classList.add('js');
const btn=document.querySelector('.menu-toggle'), menu=document.querySelector('.mobile-nav');
btn?.addEventListener('click',()=>{const o=menu.classList.toggle('open');btn.setAttribute('aria-expanded',o?'true':'false')});
document.querySelectorAll('.mobile-nav a').forEach(a=>a.addEventListener('click',()=>menu?.classList.remove('open')));
if('IntersectionObserver' in window){
 const io=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('visible');io.unobserve(e.target)}}),{threshold:.1});
 document.querySelectorAll('.reveal').forEach(el=>io.observe(el));
}else{document.querySelectorAll('.reveal').forEach(el=>el.classList.add('visible'))}
