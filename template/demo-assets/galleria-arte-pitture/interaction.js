// Demonstration feedback is local; no form data is read, stored or transmitted.
(() => {
  const message = document.documentElement.lang === 'ro'
    ? 'Aceasta este o demonstrație. Nu s-au trimis și nu s-au salvat date.'
    : 'Questa è una demo. Nessun dato è stato inviato o salvato.';
  document.querySelectorAll('form[data-demo-form] button[type="submit"]').forEach(button => {
    button.addEventListener('click', event => {
      event.preventDefault();
      const form = button.closest('form');
      if (!form.reportValidity()) return;
      const status = form.querySelector('.mg-demo-form-status');
      if (status) status.textContent = message;
    });
  });
})();
