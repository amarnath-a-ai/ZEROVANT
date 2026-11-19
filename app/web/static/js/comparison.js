/**
 * ZEROVANT — Screen 09: Scan Comparison
 * Differential audit analysis comparing baseline (A) and target (B) scans.
 */

import { escapeHTML } from './api.js';

let activeRepoId = null;
let repoScans = [];

async function init(params) {
  const repoId = params ? (params.get('repo_id') || params.get('repoId')) : null;

  const repoSelect = document.getElementById('compare-repo-select');
  if (!repoSelect) return;

  const reposRes = await window.api.getRepos();
  const repos = reposRes.ok ? reposRes.data.repos || [] : [];

  if (repos.length === 0) {
    repoSelect.innerHTML = '<option value="">No repositories available</option>';
    return;
  }

  repoSelect.innerHTML = repos.map((r) => `
    <option value="${escapeHTML(r.id)}">${escapeHTML(r.name || 'Unnamed')} (${r.scan_count || 1} scans)</option>
  `).join('');

  activeRepoId = repoId || repos[0].id;
  repoSelect.value = activeRepoId;

  repoSelect.onchange = () => {
    activeRepoId = repoSelect.value;
    loadHistory(activeRepoId);
  };

  const btnRun = document.getElementById('btn-run-comparison');
  if (btnRun) {
    btnRun.onclick = runComparison;
  }

  await loadHistory(activeRepoId);
}

async function loadHistory(repoId) {
  const selectA = document.getElementById('compare-scan-a-select');
  const selectB = document.getElementById('compare-scan-b-select');
  if (!selectA || !selectB) return;

  const res = await window.api.getRepoHistory(repoId);
  repoScans = res.ok ? res.data.history || [] : [];

  if (repoScans.length < 2) {
    selectA.innerHTML = '<option value="">Need at least 2 scans to compare</option>';
    selectB.innerHTML = '<option value="">Need at least 2 scans to compare</option>';
    return;
  }

  const optionsHTML = repoScans.map((s, idx) => {
    const rawScore = s.repo_score !== undefined ? s.repo_score : 0;
    const scoreVal = Math.max(0, Math.min(100, Math.round(100 - rawScore)));
    const date = s.scanned_at ? s.scanned_at.split('T')[0] : `Scan #${idx + 1}`;
    return `<option value="${escapeHTML(s.scan_id)}">Scan #${idx + 1} (${escapeHTML(date)}) — Posture: ${scoreVal}/100</option>`;
  }).join('');

  selectA.innerHTML = optionsHTML;
  selectB.innerHTML = optionsHTML;

  // Baseline = oldest (0), Target = newest (last)
  selectA.selectedIndex = 0;
  selectB.selectedIndex = repoScans.length - 1;

  runComparison();
}

async function runComparison() {
  const selectA = document.getElementById('compare-scan-a-select');
  const selectB = document.getElementById('compare-scan-b-select');
  const container = document.getElementById('comparison-results-container');

  if (!selectA || !selectB || !container || !activeRepoId) return;

  const scanA = selectA.value;
  const scanB = selectB.value;

  if (!scanA || !scanB) {
    container.innerHTML = `
      <div class="glass-card" style="padding: 2rem; text-align: center; color: var(--text-muted);">
        Please select two valid scans to compare.
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="glass-card" style="padding: 2rem; text-align: center; color: var(--text-muted);">
      Computing differential security posture...
    </div>
  `;

  const res = await window.api.compareScans(activeRepoId, scanA, scanB);
  if (!res.ok) {
    container.innerHTML = `
      <div class="glass-card" style="padding: 2rem; text-align: center; color: var(--severity-critical);">
        Comparison failed: ${escapeHTML(res.message)}
      </div>
    `;
    return;
  }

  const diff = res.data;
  const newFindings = diff.new_findings || [];
  const fixedFindings = diff.fixed_findings || [];
  const persisting = diff.persisting_findings || [];

  container.innerHTML = `
    <div class="overview-metrics-strip mb-6">
      <div class="glass-card metric-strip-card" style="border-top: 2px solid var(--accent-primary);">
        <div class="metric-strip-header">Issues Remediated</div>
        <div class="metric-strip-value" style="color: var(--accent-primary);">&minus;${fixedFindings.length}</div>
        <div class="metric-strip-footer">Resolved in target scan</div>
      </div>
      <div class="glass-card metric-strip-card" style="border-top: 2px solid var(--severity-critical);">
        <div class="metric-strip-header">New Misconfigurations</div>
        <div class="metric-strip-value" style="color: var(--severity-critical);">&plus;${newFindings.length}</div>
        <div class="metric-strip-footer">Introduced vulnerabilities</div>
      </div>
      <div class="glass-card metric-strip-card">
        <div class="metric-strip-header">Persisting Exposure</div>
        <div class="metric-strip-value" style="color: var(--severity-high);">${persisting.length}</div>
        <div class="metric-strip-footer">Unresolved finding debt</div>
      </div>
    </div>

    ${fixedFindings.length > 0 ? `
      <div class="glass-card mb-4" style="padding: 1.5rem;">
        <h4 class="font-bold text-base mb-3" style="color: var(--accent-primary);">&#10003; Successfully Remediated (${fixedFindings.length})</h4>
        <div class="table-responsive">
          <table class="glass-table">
            <thead>
              <tr><th>Rule ID</th><th>Title</th><th>Severity</th><th>File</th></tr>
            </thead>
            <tbody>
              ${fixedFindings.map((f) => `
                <tr>
                  <td><span class="mono" style="color: var(--accent-primary);">${escapeHTML(f.rule_id)}</span></td>
                  <td>${escapeHTML(f.title || f.rule_id)}</td>
                  <td><span class="badge badge-low"><span class="badge-dot"></span> ${(f.severity || 'LOW').toUpperCase()}</span></td>
                  <td><span class="location-tag">${escapeHTML(f.file_path || '')}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    ` : ''}

    ${newFindings.length > 0 ? `
      <div class="glass-card mb-4" style="padding: 1.5rem;">
        <h4 class="font-bold text-base mb-3" style="color: var(--severity-critical);">&times; Newly Introduced Vulnerabilities (${newFindings.length})</h4>
        <div class="table-responsive">
          <table class="glass-table">
            <thead>
              <tr><th>Rule ID</th><th>Title</th><th>Severity</th><th>File</th></tr>
            </thead>
            <tbody>
              ${newFindings.map((f) => `
                <tr>
                  <td><span class="mono" style="color: var(--severity-critical);">${escapeHTML(f.rule_id)}</span></td>
                  <td>${escapeHTML(f.title || f.rule_id)}</td>
                  <td><span class="badge badge-critical"><span class="badge-dot"></span> ${(f.severity || 'CRITICAL').toUpperCase()}</span></td>
                  <td><span class="location-tag">${escapeHTML(f.file_path || '')}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    ` : ''}
  `;
}

export const ComparisonModule = {
  init,
};
window.ComparisonModule = ComparisonModule;
