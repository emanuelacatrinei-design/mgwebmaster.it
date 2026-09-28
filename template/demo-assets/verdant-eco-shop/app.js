document.documentElement.classList.add('js');
const b=document.querySelector('.menu'),m=document.querySelector('.mobile-nav');
b?.addEventListener('click',()=>m.classList.toggle('open'));
if('IntersectionObserver'in window){const io=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('visible');io.unobserve(e.target)}}),{threshold:.08});document.querySelectorAll('.reveal').forEach(e=>io.observe(e))}else document.querySelectorAll('.reveal').forEach(e=>e.classList.add('visible'));