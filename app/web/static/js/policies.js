/**
 * ZEROVANT — Screen 08: Security Policies & Rule Catalogue
 * 30 detection rules & 10 attack chains with cyber toggle switches.
 */

import { escapeHTML } from './api.js';
import { renderIcon } from './icons.js';

let allRules = [];
let allChains = [];

async function init() {
  const container = document.getElementById('policies-catalog-list');
  if (container) {
    container.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); padding: 2rem;">
        Loading rule registry and policy catalog...
      </div>
    `;
  }

  const [rulesRes, chainsRes] = await Promise.all([
    window.api.getRules(),
    window.api.getChains(),
  ]);

  if (rulesRes.ok) allRules = rulesRes.data.rules || [];
  if (chainsRes.ok) allChains = chainsRes.data.chains || [];

  renderCatalog();
}

function renderCatalog() {
  const container = document.getElementById('policies-catalog-list');
  if (!container) return;

  if (allRules.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); padding: 2rem;">
        No security policies found in the rule registry.
      </div>
    `;
    return;
  }

  container.innerHTML = allRules.map((rule, idx) => {
    const sev = (rule.severity || 'medium').toLowerCase();
    const isChecked = true; // All 30 rules enabled by default

    let iconName = 'shield-alert';
    if (rule.id.includes('UNPINNED')) iconName = 'git-commit';
    else if (rule.id.includes('SECRET') || rule.id.includes('CREDENTIAL')) iconName = 'key';
    else if (rule.id.includes('PERMISSION')) iconName = 'lock';
    else if (rule.id.includes('SCRIPT_INJECTION')) iconName = 'terminal';
    else if (rule.id.includes('RUNNER')) iconName = 'cpu';

    return `
      <div class="glass-card policy-item-card">
        <div class="policy-item-info">
          <div class="policy-icon-wrap">
            ${renderIcon(iconName, { size: 18 })}
          </div>
          <div class="policy-text-group">
            <div class="flex items-center gap-2 mb-1">
              <span class="mono font-semibold" style="color: var(--accent-primary); font-size: 0.85rem;">${escapeHTML(rule.id)}</span>
              <h4 style="margin: 0;">${escapeHTML(rule.title || rule.name)}</h4>
              <span class="badge badge-${sev}">
                <span class="badge-dot"></span> ${(rule.severity || 'MEDIUM').toUpperCase()}
              </span>
            </div>
            <p>${escapeHTML(rule.description || 'Static analysis detection rule for GitHub Actions CI/CD workflows.')}</p>
          </div>
        </div>

        <label class="toggle-switch">
          <input type="checkbox" ${isChecked ? 'checked' : ''} data-rule-id="${escapeHTML(rule.id)}">
          <span class="toggle-slider"></span>
        </label>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.toggle-switch input').forEach((toggle) => {
    toggle.addEventListener('change', () => {
      const ruleId = toggle.getAttribute('data-rule-id');
      const state = toggle.checked ? 'enabled' : 'disabled';
      window.showToast(`Policy '${ruleId}' ${state}.`, 'info');
    });
  });
}

export const PoliciesModule = {
  init,
};
window.PoliciesModule = PoliciesModule;
