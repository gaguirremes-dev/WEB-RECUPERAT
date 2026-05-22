/* ─── REKUPERAT · security.js ─── */
'use strict';

/* Block right-click on sensitive elements */
document.querySelectorAll('[data-protected]').forEach(el => {
  el.addEventListener('contextmenu', e => e.preventDefault());
});

/* Disable console in production (soft) */
if (location.hostname !== 'localhost' && !location.hostname.includes('127.0.0.1')) {
  const noop = () => {};
  ['log', 'debug', 'info'].forEach(method => {
    console[method] = noop;
  });
}

/* CSRF-like token for forms */
function generateToken() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

const csrfToken = generateToken();
document.querySelectorAll('form').forEach(form => {
  const hidden = document.createElement('input');
  hidden.type = 'hidden';
  hidden.name = '_token';
  hidden.value = csrfToken;
  form.appendChild(hidden);
});

/* XSS guard: sanitize all inputs on blur */
document.querySelectorAll('input[type="text"], input[type="email"], textarea').forEach(input => {
  input.addEventListener('blur', () => {
    input.value = input.value
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
      .replace(/\//g, '&#x2F;');
  });
});

/* Prevent clickjacking message */
if (window.self !== window.top) {
  document.body.innerHTML = '<p style="padding:2rem;font-family:sans-serif;">Acceso no autorizado.</p>';
}

/* Detect DevTools opening (passive) */
let devToolsOpen = false;
const threshold = 160;
setInterval(() => {
  const widthDiff  = window.outerWidth  - window.innerWidth  > threshold;
  const heightDiff = window.outerHeight - window.innerHeight > threshold;
  if (!devToolsOpen && (widthDiff || heightDiff)) {
    devToolsOpen = true;
  }
}, 3000);

/* Secure external links */
document.querySelectorAll('a[target="_blank"]').forEach(link => {
  link.rel = 'noopener noreferrer';
});
