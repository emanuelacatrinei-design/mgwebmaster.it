document.querySelectorAll('.menu-header').forEach(header => {
  const button = header.querySelector('.menu-button');
  const menu = header.querySelector('.nav-links');
  if (!button || !menu) return;
  const close = () => {
    menu.classList.remove('open');
    button.setAttribute('aria-expanded', 'false');
  };
  button.addEventListener('click', () => {
    const open = menu.classList.toggle('open');
    button.setAttribute('aria-expanded', String(open));
  });
  header.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    const hadOpenMenu = menu.classList.contains('open');
    close();
    header.querySelectorAll('details[open]').forEach(details => details.removeAttribute('open'));
    if (hadOpenMenu) button.focus();
  });
  document.addEventListener('click', event => {
    if (!header.contains(event.target)) close();
  });
  window.matchMedia('(min-width: 1181px)').addEventListener('change', close);
});
