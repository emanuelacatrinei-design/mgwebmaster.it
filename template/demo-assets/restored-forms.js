/* Local demo feedback, including sandboxed frames without allow-forms. */
(() => {
  'use strict';
  const ro = document.documentElement.lang === 'ro';
  const text = ro ? 'Aceasta este o demonstrație. Nu s-au trimis și nu s-au salvat date.' : 'Questa è una demo. Nessun dato è stato inviato o salvato.';
  document.querySelectorAll('form[data-demo-form]').forEach(form => {
    const status = form.querySelector('.mg-demo-form-status');
    if (!status) return;
    status.lang = ro ? 'ro' : 'it';
    const feedback = () => { if (form.reportValidity()) status.textContent = text; };
    form.addEventListener('click', event => {
      if (event.target.closest('button[type="submit"]')) { event.preventDefault(); feedback(); }
    });
    form.addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.target.matches('textarea,button')) { event.preventDefault(); feedback(); }
    });
  });
})();
