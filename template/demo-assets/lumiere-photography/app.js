
document.addEventListener('DOMContentLoaded',()=>{
 const b=document.querySelector('.menu-btn'), n=document.querySelector('.links'); if(b&&n)b.addEventListener('click',()=>n.classList.toggle('open'));
 document.querySelectorAll('[data-filter]').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('[data-filter]').forEach(x=>x.classList.remove('active'));btn.classList.add('active');const f=btn.dataset.filter;document.querySelectorAll('.gallery-grid figure').forEach(fig=>fig.classList.toggle('hide',f!=='all'&&fig.dataset.cat!==f));}));
});
