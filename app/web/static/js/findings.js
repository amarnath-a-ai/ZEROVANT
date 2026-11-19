/**
 * ZEROVANT — Screen 04: Findings Explorer
 * Severity pill filters with counts, search, glass table, interactive detail drawer.
 */

import { escapeHTML } from './api.js';

let currentScan = null;
let allFindings = [];
let activeSeverity = 'all';

async function init(params) {
  const scanId = params ? (params.get('scan_id') || params.get('scanId')) : null;

  if (!scanId) {
    const statsRes = await window.api.getStats();
    if (statsRes.ok && statsRes.data.recent_scans && statsRes.data.recent_scans.length > 0) {
      return loadScanDetails(statsRes.data.recent_scans[0].id);
    }
    showEmptyState('No scan selected or available. Run a scan to explore findings.');
    return;
  }

  await loadScanDetails(scanId);
}

async function loadScanDetails(scanId) {
  const res = await window.api.getScan(scanId);
  if (!res.ok) {
    showEmptyState(`Failed to load scan '${scanId}': ${res.message}`);
    return;
  }

  currentScan = res.data;
  allFindings = currentScan.findings || [];

  // Update Severity Filter Counts
  updateFilterCounts();

  // Wire Filter Tab Buttons
  setupFilters();

  // Render Table
  renderTable(filterFindings());

  // Search input handling
  const searchInput = document.getElementById('findings-search-input');
  if (searchInput) {
    searchInput.oninput = () => renderTable(filterFindings());
  }

  // Drawer Close Button
  const btnCloseDrawer = document.getElementById('btn-close-drawer');
  if (btnCloseDrawer) {
    btnCloseDrawer.onclick = () => {
      const drawer = document.getElementById('finding-detail-drawer');
      if (drawer) drawer.classList.add('hidden');
    };
  }
}

function updateFilterCounts() {
  const counts = { all: allFindings.length, critical: 0, high: 0, medium: 0, low: 0 };
  allFindings.forEach((f) => {
    const sev = (f.severity || '').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  });

  const setCount = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setCount('findings-count-all', counts.all);
  setCount('findings-count-critical', counts.critical);
  setCount('findings-count-high', counts.high);
  setCount('findings-count-medium', counts.medium);
  setCount('findings-count-low', counts.low);
}

function setupFilters() {
  const tabs = document.querySelectorAll('#findings-severity-filters .filter-tab');
  tabs.forEach((tab) => {
    tab.onclick = () => {
      tabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      activeSeverity = tab.getAttribute('data-severity') || 'all';
      renderTable(filterFindings());
    };
  });
}

function filterFindings() {
  let list = allFindings;

  if (activeSeverity !== 'all') {
    list = list.filter((f) => (f.severity || '').toLowerCase() === activeSeverity.toLowerCase());
  }

  const searchInput = document.getElementById('findings-search-input');
  const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
  if (q) {
    list = list.filter((f) =>
      (f.title && f.title.toLowerCase().includes(q)) ||
      (f.rule_id && f.rule_id.toLowerCase().includes(q)) ||
      (f.file_path && f.file_path.toLowerCase().includes(q)) ||
      (f.description && f.description.toLowerCase().includes(q))
    );
  }

  return list;
}

function renderTable(findings) {
  const tbody = document.getElementById('findings-tbody');
  if (!tbody) return;

  if (!findings || findings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 3rem;">
          No findings match the current filter criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = findings.map((f, idx) => {
    const sev = (f.severity || 'low').toLowerCase();
    const badgeClass = `badge-${sev}`;
    const location = `${f.file_path || '.github/workflows/pipeline.yml'}:${f.line_number || 1}`;
    const score = f.base_score !== undefined ? f.base_score : '—';

    return `
      <tr class="finding-row" data-index="${idx}">
        <td><input type="checkbox" class="finding-checkbox"></td>
        <td><span class="mono font-semibold" style="color: var(--accent-primary);">${escapeHTML(f.rule_id || 'RULE')}</span></td>
        <td class="font-medium">${escapeHTML(f.title || f.rule_id)}</td>
        <td>
          <span class="badge ${badgeClass}">
            <span class="badge-dot"></span> ${escapeHTML((f.severity || 'LOW').toUpperCase())}
          </span>
        </td>
        <td><span class="location-tag">${escapeHTML(location)}</span></td>
        <td><span class="mono">${score}</span></td>
        <td>
          <button class="btn btn-outline btn-sm btn-inspect-finding" data-index="${idx}">
            Inspect &rarr;
          </button>
        </td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('.btn-inspect-finding').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.getAttribute('data-index'), 10);
      openDrawer(findings[idx]);
    });
  });

  tbody.querySelectorAll('.finding-row').forEach((row) => {
    row.addEventListener('click', () => {
      const idx = parseInt(row.getAttribute('data-index'), 10);
      openDrawer(findings[idx]);
    });
  });
}

function openDrawer(finding) {
  const drawer = document.getElementById('finding-detail-drawer');
  const idEl = document.getElementById('drawer-finding-id');
  const contentEl = document.getElementById('drawer-finding-content');

  if (!drawer || !contentEl || !finding) return;

  if (idEl) idEl.textContent = `${finding.rule_id} • Line ${finding.line_number || 1}`;

  const sev = (finding.severity || 'low').toLowerCase();
  const expl = finding.explanation || {};

  contentEl.innerHTML = `
    <div class="mb-4">
      <span class="badge badge-${sev} mb-2">
        <span class="badge-dot"></span> ${(finding.severity || 'LOW').toUpperCase()}
      </span>
      <h3 class="text-xl font-bold mb-2">${escapeHTML(finding.title || finding.rule_id)}</h3>
      <p style="color: var(--text-secondary); font-size: 0.9rem;">${escapeHTML(finding.description || '')}</p>
    </div>

    <div class="glass-card mb-4" style="padding: 1.25rem;">
      <div class="font-semibold text-xs text-muted uppercase tracking-wider mb-2">Location</div>
      <div class="location-tag">${escapeHTML(finding.file_path || 'workflow.yml')}:${finding.line_number || 1}</div>
    </div>

    ${finding.raw_yaml ? `
      <div class="mb-4">
        <div class="font-semibold text-xs text-muted uppercase tracking-wider mb-1">Workflow Snippet</div>
        <pre class="diff-code-body" style="border: 1px solid var(--border-solid); border-radius: var(--radius-sm);">${escapeHTML(finding.raw_yaml)}</pre>
      </div>
    ` : ''}

    ${expl.what ? `
      <div class="glass-card mb-4" style="padding: 1.25rem;">
        <div class="font-semibold text-xs text-muted uppercase tracking-wider mb-2">What Was Detected</div>
        <p style="font-size: 0.88rem; color: var(--text-primary); margin: 0;">${escapeHTML(expl.what)}</p>
      </div>
    ` : ''}

    ${expl.why ? `
      <div class="glass-card mb-4" style="padding: 1.25rem;">
        <div class="font-semibold text-xs text-muted uppercase tracking-wider mb-2">Security Risk &amp; Exploitability</div>
        <p style="font-size: 0.88rem; color: var(--text-primary); margin: 0;">${escapeHTML(expl.why)}</p>
      </div>
    ` : ''}

    <div class="mt-6 flex gap-3">
      <button id="btn-remediate-in-center" class="btn btn-primary w-full">
        Open in Remediation Centre &rarr;
      </button>
    </div>
  `;

  const remediateBtn = document.getElementById('btn-remediate-in-center');
  if (remediateBtn) {
    remediateBtn.onclick = () => {
      drawer.classList.add('hidden');
      window.router.navigate(`remediation?rule_id=${encodeURIComponent(finding.rule_id)}`);
    };
  }

  drawer.classList.remove('hidden');
}

function showEmptyState(msg) {
  const tbody = document.getElementById('findings-tbody');
  if (tbody) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 3rem;">
          ${escapeHTML(msg)}
        </td>
      </tr>
    `;
  }
}

export const FindingsModule = {
  init,
};
window.FindingsModule = FindingsModule;
