/* ─── REKUPERAT · app.js ─── */
'use strict';

/* Loader */
window.addEventListener('load', () => {
  setTimeout(() => {
    document.querySelector('.page-loader')?.classList.add('hidden');
  }, 1500);
});

/* Progress bar */
const progressBar = document.querySelector('.progress-bar');
if (progressBar) {
  window.addEventListener('scroll', () => {
    const total = document.documentElement.scrollHeight - window.innerHeight;
    const pct   = (window.scrollY / total) * 100;
    progressBar.style.width = pct + '%';
  });
}

/* Navbar scroll */
const navbar = document.querySelector('.navbar');
if (navbar) {
  window.addEventListener('scroll', () => {
    navbar.classList.toggle('scrolled', window.scrollY > 60);
  });
}

/* Scroll-to-top */
const scrollTopBtn = document.querySelector('.scroll-top');
if (scrollTopBtn) {
  window.addEventListener('scroll', () => {
    scrollTopBtn.classList.toggle('visible', window.scrollY > 400);
  });
  scrollTopBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
}

/* Mobile menu */
const menuBtn     = document.getElementById('menuBtn');
const menuClose   = document.getElementById('menuClose');
const mobileMenu  = document.getElementById('mobileMenu');
const mobileOverlay = document.getElementById('mobileOverlay');

function openMenu() {
  mobileMenu?.classList.add('open');
  mobileOverlay?.classList.add('show');
  document.body.style.overflow = 'hidden';
}
function closeMenu() {
  mobileMenu?.classList.remove('open');
  mobileOverlay?.classList.remove('show');
  document.body.style.overflow = '';
}

menuBtn?.addEventListener('click', openMenu);
menuClose?.addEventListener('click', closeMenu);
mobileOverlay?.addEventListener('click', closeMenu);

/* Animated counters */
function animateCounter(el) {
  const target = parseFloat(el.dataset.target);
  const decimals = el.dataset.decimals ? parseInt(el.dataset.decimals) : 0;
  const suffix = el.dataset.suffix || '';
  const prefix = el.dataset.prefix || '';
  const duration = 2000;
  const step = 16;
  const steps = duration / step;
  const inc = target / steps;
  let current = 0;
  const timer = setInterval(() => {
    current += inc;
    if (current >= target) { current = target; clearInterval(timer); }
    el.textContent = prefix + current.toFixed(decimals) + suffix;
  }, step);
}

const counterObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting && !entry.target.dataset.animated) {
      entry.target.dataset.animated = 'true';
      animateCounter(entry.target);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('[data-counter]').forEach(el => counterObserver.observe(el));

/* FAQ accordion */
document.querySelectorAll('.faq-item').forEach(item => {
  const q = item.querySelector('.faq-q');
  q?.addEventListener('click', () => {
    const isOpen = item.classList.contains('open');
    document.querySelectorAll('.faq-item.open').forEach(i => i.classList.remove('open'));
    if (!isOpen) item.classList.add('open');
  });
});

/* Bar chart animation */
function animateBars(container) {
  const heights = [35,55,40,70,50,85,60,90,75,65,95,80];
  container.querySelectorAll('.bar').forEach((bar, i) => {
    const h = heights[i % heights.length];
    bar.style.height = '0%';
    setTimeout(() => {
      bar.style.transition = `height .7s cubic-bezier(.4,0,.2,1) ${i * 60}ms`;
      bar.style.height = h + '%';
    }, 200);
  });
}

const chartObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting && !entry.target.dataset.animated) {
      entry.target.dataset.animated = 'true';
      animateBars(entry.target);
    }
  });
}, { threshold: 0.3 });

document.querySelectorAll('.bars').forEach(c => chartObserver.observe(c));

/* Toast utility */
function showToast(msg, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast ${type === 'error' ? 'error' : ''}`;
  toast.innerHTML = `
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${type === 'error' ? '#E53E3E' : '#7CB342'}" stroke-width="2.5">
      ${type === 'error'
        ? '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'
        : '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'}
    </svg>
    <span>${msg}</span>`;
  document.body.appendChild(toast);
  requestAnimationFrame(() => { requestAnimationFrame(() => toast.classList.add('show')); });
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 400);
  }, 4500);
}

window.showToast = showToast;

/* Active nav link on scroll */
const sections = document.querySelectorAll('section[id]');
const navLinks  = document.querySelectorAll('.nav-link[data-section]');

const sectionObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const id = entry.target.id;
      navLinks.forEach(link => {
        link.style.color = link.dataset.section === id ? 'var(--blue)' : '';
      });
    }
  });
}, { threshold: 0.3 });

sections.forEach(s => sectionObserver.observe(s));

/* Smooth scroll for anchor links */
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    const target = document.querySelector(a.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      closeMenu();
    }
  });
});

/* Hero particle generator */
function createParticles() {
  const container = document.querySelector('.hero-particles');
  if (!container) return;
  const colors = ['rgba(255,255,255,.12)', 'rgba(124,179,66,.15)', 'rgba(21,101,192,.18)'];
  for (let i = 0; i < 18; i++) {
    const p = document.createElement('div');
    const size = Math.random() * 6 + 3;
    p.style.cssText = `
      position:absolute; border-radius:50%;
      width:${size}px; height:${size}px;
      left:${Math.random() * 100}%;
      background:${colors[Math.floor(Math.random() * colors.length)]};
      animation:floatParticle ${10 + Math.random() * 15}s linear ${Math.random() * -20}s infinite;
    `;
    container.appendChild(p);
  }
}

/* Add keyframe */
const kf = document.createElement('style');
kf.textContent = `@keyframes floatParticle{0%{transform:translateY(100vh);opacity:0}10%{opacity:1}90%{opacity:.6}100%{transform:translateY(-200px);opacity:0}}`;
document.head.appendChild(kf);

createParticles();
