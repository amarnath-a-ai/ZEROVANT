/**
 * ZEROVANT — Master Application Controller
 * Obsidian Liquid Glass single-page architecture with Lucide iconography.
 */

import { hydrateIcons } from './icons.js';
import './theme.js';
import './router.js';
import './overview.js';
import './scanner.js';
import './repositories.js';
import './findings.js';
import './graph.js';
import './analytics.js';
import './remediation.js';
import './policies.js';
import './comparison.js';
import './settings.js';

// Global Toast Notification Helper
window.showToast = function (message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease-out';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 3500);
};

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initial Icon Hydration
  hydrateIcons();

  // 2. Register Router Routes
  window.router.register('landing', () => {
    hydrateIcons();
  });

  window.router.register('overview', () => {
    if (window.OverviewModule) window.OverviewModule.init();
    hydrateIcons();
  });

  window.router.register('scanner', () => {
    if (window.ScannerModule) window.ScannerModule.init();
    hydrateIcons();
  });

  window.router.register('repositories', () => {
    if (window.RepositoriesModule) window.RepositoriesModule.init();
    hydrateIcons();
  });

  window.router.register('findings', (params) => {
    if (window.FindingsModule) window.FindingsModule.init(params);
    hydrateIcons();
  });

  window.router.register('attack-graph', (params) => {
    if (window.AttackGraphModule) window.AttackGraphModule.init(params);
    hydrateIcons();
  });

  window.router.register('analytics', () => {
    if (window.AnalyticsModule) window.AnalyticsModule.init();
    hydrateIcons();
  });

  window.router.register('remediation', (params) => {
    if (window.RemediationModule) window.RemediationModule.init(params);
    hydrateIcons();
  });

  window.router.register('policies', () => {
    if (window.PoliciesModule) window.PoliciesModule.init();
    hydrateIcons();
  });

  window.router.register('comparison', (params) => {
    if (window.ComparisonModule) window.ComparisonModule.init(params);
    hydrateIcons();
  });

  window.router.register('settings', () => {
    if (window.SettingsModule) window.SettingsModule.init();
    hydrateIcons();
  });

  // 3. Wire Navigation Links
  document.querySelectorAll('[data-route]').forEach((el) => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      const route = el.getAttribute('data-route');
      if (route) window.router.navigate(route);
    });
  });

  // 4. Mobile Menu Drawer Toggle
  const mobileToggle = document.getElementById('btn-mobile-menu');
  const sidebar = document.querySelector('.app-sidebar');
  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }

  // 5. Global Topbar Search
  const topbarSearch = document.getElementById('global-search-input');
  if (topbarSearch) {
    topbarSearch.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const q = topbarSearch.value.trim();
        if (q) {
          window.router.navigate(`findings?search=${encodeURIComponent(q)}`);
        }
      }
    });
  }

  // 6. Initialize Router
  window.router.init();
});
