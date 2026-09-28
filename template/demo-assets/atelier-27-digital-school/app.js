
const menu=document.querySelector('.menu-btn');if(menu){menu.addEventListener('click',()=>document.querySelector('.nav').classList.toggle('open'));}
document.querySelectorAll('.filter').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('.filter').forEach(b=>b.classList.remove('active'));btn.classList.add('active');let cat=btn.dataset.filter;document.querySelectorAll('.catalog-card').forEach(c=>c.classList.toggle('hidden',cat!=='all'&&!c.dataset.cat.includes(cat)));}));
const form=document.querySelector('.demo-form');if(form){form.addEventListener('submit',e=>{e.preventDefault();const out=document.querySelector('.form-status');if(out)out.textContent='Lorem ipsum dolor sit amet: demonstratio tantum, nulla notitia mittitur.';});}
