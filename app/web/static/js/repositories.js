/**
 * ZEROVANT — Screen 03: Monitored Repositories
 * Repository inventory, posture scores, and one-click re-audit triggers.
 */

import { escapeHTML } from './api.js';

let allRepos = [];

async function loadRepositories() {
  const tbody = document.getElementById('repositories-tbody');
  if (!tbody) return;

  const res = await window.api.getRepos(100, 0);
  if (!res.ok) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2.5rem;">
          Failed to load monitored repositories.
        </td>
      </tr>
    `;
    return;
  }

  allRepos = res.data.repos || [];
  renderReposTable(allRepos);
}

function renderReposTable(repos) {
  const tbody = document.getElementById('repositories-tbody');
  if (!tbody) return;

  if (repos.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2.5rem;">
          No repositories connected yet. Scan a GitHub repository to add it to your inventory.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = repos.map((r) => {
    const rawScore = r.latest_score !== undefined && r.latest_score !== null ? r.latest_score : 0;
    const scoreVal = Math.max(0, Math.min(100, Math.round(100 - rawScore)));
    const scansCount = r.scan_count || 1;
    const createdAt = r.created_at ? r.created_at.split('T')[0] : 'Recent';

    let badgeClass = 'badge-low';
    if (scoreVal < 50) badgeClass = 'badge-critical';
    else if (scoreVal < 75) badgeClass = 'badge-medium';

    return `
      <tr>
        <td class="font-semibold text-primary">
          <span class="mono" style="color: var(--accent-primary);">${escapeHTML(r.name || 'Unnamed')}</span>
        </td>
        <td>
          <a href="${escapeHTML(r.url || '#')}" target="_blank" rel="noopener" class="truncate" style="max-width: 240px; display: inline-block;">
            ${escapeHTML(r.url || 'Internal target')}
          </a>
        </td>
        <td><span class="mono font-semibold">${scansCount}</span></td>
        <td>
          <span class="badge ${badgeClass}">
            <span class="badge-dot"></span> ${scoreVal} / 100
          </span>
        </td>
        <td style="color: var(--text-muted); font-size: 0.85rem;">${escapeHTML(createdAt)}</td>
        <td>
          <button class="btn btn-outline btn-sm btn-audit-repo" data-url="${escapeHTML(r.url || '')}">
            Audit Now &rarr;
          </button>
        </td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('.btn-audit-repo').forEach((btn) => {
    btn.addEventListener('click', () => {
      const url = btn.getAttribute('data-url');
      if (url) {
        window.router.navigate(`scanner?url=${encodeURIComponent(url)}`);
      }
    });
  });
}

export const RepositoriesModule = {
  init: loadRepositories,
};
window.RepositoriesModule = RepositoriesModule;
