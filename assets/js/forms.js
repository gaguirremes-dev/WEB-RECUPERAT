/* ─── REKUPERAT · forms.js ─── */
'use strict';

/* Sanitize input to prevent XSS */
function sanitize(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

/* Validate email */
function isEmail(val) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
}

/* Validate phone (Perú) */
function isPhone(val) {
  return /^[\+]?[\d\s\-\(\)]{7,15}$/.test(val);
}

/* Field validation */
function validateField(input) {
  const val = input.value.trim();
  const type = input.dataset.validate;
  let error = '';

  if (input.required && !val) {
    error = 'Este campo es obligatorio.';
  } else if (type === 'email' && val && !isEmail(val)) {
    error = 'Ingresa un correo electrónico válido.';
  } else if (type === 'phone' && val && !isPhone(val)) {
    error = 'Ingresa un número de teléfono válido.';
  } else if (type === 'min' && val.length < parseInt(input.dataset.min || 3)) {
    error = `Mínimo ${input.dataset.min || 3} caracteres.`;
  }

  const errorEl = input.parentElement.querySelector('.form-error-msg');
  if (error) {
    input.classList.add('has-error');
    input.classList.remove('has-success');
    if (errorEl) { errorEl.textContent = error; errorEl.style.display = 'block'; }
    return false;
  } else {
    input.classList.remove('has-error');
    if (val) input.classList.add('has-success');
    if (errorEl) errorEl.style.display = 'none';
    return true;
  }
}

/* Setup form */
function setupForm(formId, onSuccess) {
  const form = document.getElementById(formId);
  if (!form) return;

  const inputs = form.querySelectorAll('.form-input, .form-select, .form-textarea');
  const submitBtn = form.querySelector('[type="submit"]');

  inputs.forEach(input => {
    input.addEventListener('blur', () => validateField(input));
    input.addEventListener('input', () => {
      if (input.classList.contains('has-error')) validateField(input);
    });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    let valid = true;
    inputs.forEach(input => { if (!validateField(input)) valid = false; });
    if (!valid) return;

    /* Checkbox consent */
    const consent = form.querySelector('[name="consent"]');
    if (consent && !consent.checked) {
      showToast('Debes aceptar los términos y condiciones.', 'error');
      return;
    }

    /* Loading state */
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <svg class="spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
      </svg>
      Enviando...`;

    /* Simulate API call */
    await new Promise(r => setTimeout(r, 1800));

    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
    form.reset();
    inputs.forEach(i => { i.classList.remove('has-success', 'has-error'); });

    if (typeof onSuccess === 'function') onSuccess();
    else showToast('¡Mensaje enviado! Nos comunicaremos pronto.', 'success');
  });
}

/* Init all forms */
document.addEventListener('DOMContentLoaded', () => {
  const spinStyle = document.createElement('style');
  spinStyle.textContent = `.spin{animation:spinAnim .8s linear infinite}@keyframes spinAnim{to{transform:rotate(360deg)}}`;
  document.head.appendChild(spinStyle);

  setupForm('contactForm', () => {
    showToast('¡Gracias! Nos comunicaremos contigo en menos de 24 horas.', 'success');
  });

  setupForm('demoForm', () => {
    showToast('¡Solicitud de demo registrada! Te enviamos los detalles por email.', 'success');
  });

  setupForm('debtForm', () => {
    showToast('¡Consulta enviada! Un especialista te contactará pronto.', 'success');
  });
});
