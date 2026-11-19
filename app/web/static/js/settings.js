/**
 * ZEROVANT — Screen 10: Settings & Platform Configuration
 */

window.SettingsModule = (function () {
  async function init() {
    const healthRes = await window.api.getHealth();
    const statusEl = document.getElementById('settings-api-status');
    if (statusEl) {
      statusEl.textContent = healthRes.ok ? 'Online & Healthy' : 'Degraded';
      statusEl.className = healthRes.ok ? 'badge badge-low' : 'badge badge-critical';
    }

    const currentThemeEl = document.getElementById('settings-current-theme');
    if (currentThemeEl) {
      currentThemeEl.textContent = window.getCurrentTheme().toUpperCase();
    }
  }

  return {
    init: init,
  };
})();
