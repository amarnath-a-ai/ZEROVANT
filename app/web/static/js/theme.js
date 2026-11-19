/**
 * ZEROVANT — Theme Management (Dark / Light Theme)
 * Persists user preference in localStorage and toggles Lucide SVG icons.
 */

import { renderIcon } from './icons.js';

const THEME_KEY = 'zerovant_theme';

export function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
    ? 'light'
    : 'dark';
}

export function applyTheme(theme) {
  if (theme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
  localStorage.setItem(THEME_KEY, theme);

  // Update theme toggle icons across the app with Lucide SVG
  document.querySelectorAll('.theme-toggle-btn').forEach((btn) => {
    const iconContainer = btn.querySelector('.theme-icon-container') || btn;
    iconContainer.innerHTML = theme === 'light' 
      ? renderIcon('moon', { size: 18 }) 
      : renderIcon('sun', { size: 18 });
  });

  // Update Settings page buttons if present
  const btnDark = document.getElementById('btn-theme-dark');
  const btnLight = document.getElementById('btn-theme-light');
  if (btnDark && btnLight) {
    if (theme === 'light') {
      btnDark.classList.remove('active');
      btnLight.classList.add('active');
    } else {
      btnDark.classList.add('active');
      btnLight.classList.remove('active');
    }
  }

  // Notify listeners (e.g. Chart.js color palette refresh)
  window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
}

export function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  applyTheme(next);
}

// Initialize on execution
const initialTheme = getPreferredTheme();
applyTheme(initialTheme);

window.toggleTheme = toggleTheme;
window.applyTheme = applyTheme;
window.getCurrentTheme = () => document.documentElement.getAttribute('data-theme') || 'dark';

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.theme-toggle-btn').forEach((btn) => {
    btn.addEventListener('click', toggleTheme);
  });
});
