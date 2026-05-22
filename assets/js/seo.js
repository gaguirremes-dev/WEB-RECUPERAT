/* ─── REKUPERAT · seo.js ─── */
'use strict';

/* Breadcrumb JSON-LD for inner pages */
function injectBreadcrumb(items) {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, idx) => ({
      '@type': 'ListItem',
      position: idx + 1,
      name: item.name,
      item: item.url,
    })),
  };
  const script = document.createElement('script');
  script.type = 'application/ld+json';
  script.textContent = JSON.stringify(schema);
  document.head.appendChild(script);
}

/* FAQ Page Schema */
function injectFAQSchema() {
  const faqItems = document.querySelectorAll('.faq-item');
  if (!faqItems.length) return;

  const questions = Array.from(faqItems).map(item => ({
    '@type': 'Question',
    name: item.querySelector('.faq-q')?.textContent?.trim() || '',
    acceptedAnswer: {
      '@type': 'Answer',
      text: item.querySelector('.faq-a-inner')?.textContent?.trim() || '',
    },
  }));

  const schema = { '@context': 'https://schema.org', '@type': 'FAQPage', mainEntity: questions };
  const script = document.createElement('script');
  script.type = 'application/ld+json';
  script.textContent = JSON.stringify(schema);
  document.head.appendChild(script);
}

/* Detect page and inject appropriate breadcrumb */
const path = window.location.pathname.replace(/\/$/, '') || '/';
const breadcrumbs = {
  '/portal-deudor': [
    { name: 'Inicio', url: 'https://rekuperat.com/' },
    { name: 'Portal Deudor', url: 'https://rekuperat.com/portal-deudor' },
  ],
  '/portal-acreedor': [
    { name: 'Inicio', url: 'https://rekuperat.com/' },
    { name: 'Portal Acreedor', url: 'https://rekuperat.com/portal-acreedor' },
  ],
  '/compliance': [
    { name: 'Inicio', url: 'https://rekuperat.com/' },
    { name: 'Compliance', url: 'https://rekuperat.com/compliance' },
  ],
  '/contacto': [
    { name: 'Inicio', url: 'https://rekuperat.com/' },
    { name: 'Contacto', url: 'https://rekuperat.com/contacto' },
  ],
};

const bc = breadcrumbs[path] || breadcrumbs[path.replace('.html', '')];
if (bc) injectBreadcrumb(bc);

document.addEventListener('DOMContentLoaded', injectFAQSchema);
