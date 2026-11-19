/**
 * ZEROVANT — Screen 09: Scan Comparison
 */

window.ComparisonModule = (function () {
  let activeRepoId = null;
  let repoScans = [];

  async function init(params) {
    const repoId = params ? params.get('repoId') : null;

    // Load available repositories into repo select dropdown
    const reposRes = await window.api.getRepos();
    const repoSelect = document.getElementById('comp-repo-select');
    if (!repoSelect) return;

    while (repoSelect.firstChild) repoSelect.removeChild(repoSelect.firstChild);

    const repos = reposRes.ok ? reposRes.data.repos || [] : [];
    if (repos.length === 0) {
      const opt = document.createElement('option');
      opt.textContent = 'No repositories available';
      repoSelect.appendChild(opt);
      return;
    }

    repos.forEach((r) => {
      const opt = document.createElement('option');
      opt.value = r.id;
      opt.textContent = `${r.name} (${r.scan_count || 0} scans)`;
      repoSelect.appendChild(opt);
    });

    activeRepoId = repoId || repos[0].id;
    repoSelect.value = activeRepoId;

    repoSelect.onchange = () => {
      activeRepoId = repoSelect.value;
      loadRepoHistory(activeRepoId);
    };

    const compareBtn = document.getElementById('btn-run-comparison');
    if (compareBtn) {
      compareBtn.onclick = handleCompare;
    }

    await loadRepoHistory(activeRepoId);
  }

  async function loadRepoHistory(repoId) {
    const histRes = await window.api.getRepoHistory(repoId);
    const selectA = document.getElementById('comp-scan-a');
    const selectB = document.getElementById('comp-scan-b');

    if (!selectA || !selectB) return;

    while (selectA.firstChild) selectA.removeChild(selectA.firstChild);
    while (selectB.firstChild) selectB.removeChild(selectB.firstChild);

    repoScans = histRes.ok ? histRes.data.history || [] : [];

    if (repoScans.length < 2) {
      const optA = document.createElement('option');
      optA.textContent = 'Need at least 2 scans to compare';
      selectA.appendChild(optA);
      const optB = document.createElement('option');
      optB.textContent = 'Need at least 2 scans to compare';
      selectB.appendChild(optB);
      return;
    }

    repoScans.forEach((s, idx) => {
      const optA = document.createElement('option');
      optA.value = s.scan_id;
      optA.textContent = `Scan #${idx + 1} (${s.scanned_at}) — Score: ${s.repo_score}`;
      selectA.appendChild(optA);

      const optB = document.createElement('option');
      optB.value = s.scan_id;
      optB.textContent = `Scan #${idx + 1} (${s.scanned_at}) — Score: ${s.repo_score}`;
      selectB.appendChild(optB);
    });

    // Default select oldest as A and newest as B
    selectA.selectedIndex = 0;
    selectB.selectedIndex = repoScans.length - 1;

    // Trigger initial comparison
    handleCompare();
  }

  async function handleCompare() {
    const selectA = document.getElementById('comp-scan-a');
    const selectB = document.getElementById('comp-scan-b');

    if (!selectA || !selectB || !activeRepoId) return;

    const scanA = selectA.value;
    const scanB = selectB.value;

    if (!scanA || !scanB || scanA === scanB) {
      window.showToast('Please select two distinct scans to compare.', 'error');
      return;
    }

    const res = await window.api.compareScans(activeRepoId, scanA, scanB);
    if (!res.ok) {
      window.showToast(res.message || 'Comparison failed', 'error');
      return;
    }

    renderComparisonResults(res.data);
  }

  function renderComparisonResults(diff) {
    const deltaEl = document.getElementById('comp-score-delta');
    const prevScoreEl = document.getElementById('comp-prev-score');
    const currScoreEl = document.getElementById('comp-curr-score');

    const fixedCountEl = document.getElementById('comp-fixed-count');
    const newCountEl = document.getElementById('comp-new-count');
    const persistingCountEl = document.getElementById('comp-persisting-count');

    if (prevScoreEl) prevScoreEl.textContent = `${diff.previous_score} / 100`;
    if (currScoreEl) currScoreEl.textContent = `${diff.current_score} / 100`;

    if (deltaEl) {
      const delta = diff.score_delta;
      deltaEl.textContent = delta > 0 ? `+${delta} pts (Risk Increased)` : `${delta} pts (Security Improved)`;
      deltaEl.className = delta <= 0 ? 'badge badge-low' : 'badge badge-critical';
    }

    if (fixedCountEl) fixedCountEl.textContent = diff.fixed_count || 0;
    if (newCountEl) newCountEl.textContent = diff.new_count || 0;
    if (persistingCountEl) persistingCountEl.textContent = diff.persisting_count || 0;

    // Render Lists of Fixed, New, Persisting Findings
    renderFindingDiffList('comp-fixed-list', diff.fixed || diff.fixed_findings || [], '#2ECC71', 'Fixed');
    renderFindingDiffList('comp-new-list', diff.new || diff.new_findings || [], '#FF5C5C', 'New');
    renderFindingDiffList('comp-persisting-list', diff.persisting || diff.persisting_findings || [], '#FFA94D', 'Persisting');
  }

  function renderFindingDiffList(containerId, findings, color, label) {
    const container = document.getElementById(containerId);
    if (!container) return;

    while (container.firstChild) container.removeChild(container.firstChild);

    if (findings.length === 0) {
      const p = document.createElement('p');
      p.className = 'text-muted';
      p.textContent = `No ${label.toLowerCase()} findings.`;
      container.appendChild(p);
      return;
    }

    findings.forEach((f) => {
      const item = document.createElement('div');
      item.className = 'glass-card';
      item.style.padding = '0.75rem 1rem';
      item.style.marginBottom = '0.5rem';
      item.style.borderLeft = `3px solid ${color}`;

      const titleDiv = document.createElement('div');
      titleDiv.style.fontWeight = '600';
      titleDiv.textContent = f.title || f.rule_id;

      const locDiv = document.createElement('div');
      locDiv.className = 'mono';
      locDiv.style.fontSize = '0.78rem';
      locDiv.style.color = '#9BAAA1';
      locDiv.textContent = `${f.file_path || 'workflow.yml'}:${f.line_number || 1}`;

      item.appendChild(titleDiv);
      item.appendChild(locDiv);
      container.appendChild(item);
    });
  }

  return {
    init: init,
  };
})();
