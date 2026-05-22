/* ─── REKUPERAT · animations.js ─── */
'use strict';

/* AOS init */
document.addEventListener('DOMContentLoaded', () => {
  if (typeof AOS !== 'undefined') {
    AOS.init({
      duration: 700,
      easing: 'ease-out-cubic',
      once: true,
      offset: 60,
    });
  }

  initFloatingCards();
  initNumberSpin();
  initGradientShift();
});

/* Floating cards parallax on mouse move */
function initFloatingCards() {
  const hero = document.querySelector('.hero');
  if (!hero) return;

  hero.addEventListener('mousemove', (e) => {
    const { clientX, clientY } = e;
    const { innerWidth, innerHeight } = window;
    const xRatio = (clientX / innerWidth  - 0.5) * 20;
    const yRatio = (clientY / innerHeight - 0.5) * 15;

    document.querySelectorAll('.metric-card').forEach((card, i) => {
      const depth = (i + 1) * 0.35;
      card.style.transform = `translateY(${-yRatio * depth}px) translateX(${xRatio * depth}px)`;
    });
  });

  hero.addEventListener('mouseleave', () => {
    document.querySelectorAll('.metric-card').forEach(card => {
      card.style.transform = '';
    });
  });
}

/* Spin number anim for hero */
function initNumberSpin() {
  const targets = document.querySelectorAll('[data-spin]');
  targets.forEach(el => {
    const chars = '0123456789';
    const finalText = el.textContent;
    let iteration = 0;
    const interval = setInterval(() => {
      el.textContent = finalText.split('').map((letter, idx) => {
        if (idx < iteration) return finalText[idx];
        if (isNaN(letter)) return letter;
        return chars[Math.floor(Math.random() * chars.length)];
      }).join('');
      if (iteration >= finalText.length) clearInterval(interval);
      iteration += 1 / 2;
    }, 40);
  });
}

/* Animated gradient background shift */
function initGradientShift() {
  const hero = document.querySelector('.hero');
  if (!hero) return;

  let angle = 135;
  let dir = 1;
  setInterval(() => {
    angle += dir * 0.3;
    if (angle > 155 || angle < 115) dir *= -1;
    hero.style.backgroundImage =
      `linear-gradient(${angle}deg, #0D1B4B 0%, #1B2D78 38%, #1565C0 68%, #7CB342 100%)`;
  }, 50);
}

/* Stagger reveal for grid items */
function staggerReveal(containerSelector, childSelector, delay = 100) {
  const container = document.querySelector(containerSelector);
  if (!container) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.querySelectorAll(childSelector).forEach((el, i) => {
          setTimeout(() => {
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
          }, i * delay);
        });
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  container.querySelectorAll(childSelector).forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(24px)';
    el.style.transition = 'opacity .6s ease, transform .6s ease';
  });

  observer.observe(container);
}

/* Apply stagger to sections */
document.addEventListener('DOMContentLoaded', () => {
  staggerReveal('#features', '.card');
  staggerReveal('#benefits', '.card');
  staggerReveal('#technology', '.tech-badge');
});
