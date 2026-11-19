/**
 * ZEROVANT — Screen 04: Findings Explorer
 */

window.FindingsModule = (function () {
  let currentScan = null;
  let allFindings = [];
  let activeSeverityFilter = 'all';

  async function loadFindings(params) {
    const scanId = params ? params.get('scanId') : null;

    if (!scanId) {
      // Fetch latest scan from stats
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

    // Update Scan Banner
    const bannerRepo = document.getElementById('findings-banner-repo');
    const bannerScore = document.getElementById('findings-banner-score');
    const bannerCount = document.getElementById('findings-banner-count');
    const bannerGraphLink = document.getElementById('findings-view-graph-btn');

    if (bannerRepo) bannerRepo.textContent = currentScan.repo_name || 'Inline Workflow';
    if (bannerScore) bannerScore.textContent = `${currentScan.repo_score} / 100`;
    if (bannerCount) bannerCount.textContent = allFindings.length;
    if (bannerGraphLink) {
      bannerGraphLink.onclick = () => {
        window.router.navigate(`attack-graph?scanId=${encodeURIComponent(scanId)}`);
      };
    }

    // Initialize Filter Pills
    setupFilterPills();

    // Render Table
    renderFindingsTable(filterFindings());

    // Search input
    const searchInput = document.getElementById('findings-search-input');
    if (searchInput) {
      searchInput.value = '';
      searchInput.oninput = () => {
        renderFindingsTable(filterFindings());
      };
    }
  }

  function setupFilterPills() {
    const pills = document.querySelectorAll('.severity-filter-pill');
    pills.forEach((pill) => {
      pill.onclick = () => {
        pills.forEach((p) => p.classList.remove('active'));
        pill.classList.add('active');
        activeSeverityFilter = pill.getAttribute('data-severity') || 'all';
        renderFindingsTable(filterFindings());
      };
    });
  }

  function filterFindings() {
    let result = allFindings;

    if (activeSeverityFilter !== 'all') {
      result = result.filter(
        (f) => (f.severity || '').toLowerCase() === activeSeverityFilter.toLowerCase()
      );
    }

    const searchInput = document.getElementById('findings-search-input');
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
    if (query) {
      result = result.filter(
        (f) =>
          (f.title && f.title.toLowerCase().includes(query)) ||
          (f.rule_id && f.rule_id.toLowerCase().includes(query)) ||
          (f.file_path && f.file_path.toLowerCase().includes(query))
      );
    }

    return result;
  }

  function renderFindingsTable(findings) {
    const tbody = document.getElementById('findings-table-tbody');
    if (!tbody) return;

    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (findings.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = 'No findings matching criteria.';
      td.className = 'text-muted';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    findings.forEach((f, idx) => {
      const tr = document.createElement('tr');
      tr.className = 'finding-row-expandable';

      const tdId = document.createElement('td');
      tdId.className = 'mono';
      tdId.textContent = f.id || `f-${idx + 1}`;

      const tdRule = document.createElement('td');
      const ruleCode = document.createElement('span');
      ruleCode.className = 'mono';
      ruleCode.textContent = f.rule_id;
      tdRule.appendChild(ruleCode);

      const tdTitle = document.createElement('td');
      tdTitle.textContent = f.title || f.rule_id;

      const tdSev = document.createElement('td');
      const sevBadge = document.createElement('span');
      const s = (f.severity || 'LOW').toUpperCase();
      sevBadge.className = `badge badge-${s.toLowerCase()}`;
      sevBadge.textContent = s;
      tdSev.appendChild(sevBadge);

      const tdLoc = document.createElement('td');
      tdLoc.className = 'mono';
      tdLoc.textContent = `${f.file_path || 'workflow.yml'}:${f.line_number || 1}`;

      const tdAction = document.createElement('td');
      const fixBtn = document.createElement('button');
      fixBtn.className = 'btn btn-outline btn-sm';
      fixBtn.textContent = 'Remediate';
      fixBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        window.router.navigate(
          `remediation?scanId=${encodeURIComponent(currentScan.id)}&findingId=${encodeURIComponent(f.id)}`
        );
      });
      tdAction.appendChild(fixBtn);

      tr.appendChild(tdId);
      tr.appendChild(tdRule);
      tr.appendChild(tdTitle);
      tr.appendChild(tdSev);
      tr.appendChild(tdLoc);
      tr.appendChild(tdAction);

      // Expandable row for Evidence & What/Why
      const trDetail = document.createElement('tr');
      trDetail.className = 'hidden';

      const tdDetail = document.createElement('td');
      tdDetail.colSpan = 6;
      const drawer = document.createElement('div');
      drawer.className = 'finding-detail-drawer';

      if (f.evidence) {
        const evLabel = document.createElement('div');
        evLabel.className = 'input-label';
        evLabel.textContent = 'Detected Evidence:';
        const evCode = document.createElement('div');
        evCode.className = 'finding-evidence-block';
        evCode.textContent = f.evidence;
        drawer.appendChild(evLabel);
        drawer.appendChild(evCode);
      }

      if (f.explanation) {
        const whatDiv = document.createElement('div');
        whatDiv.innerHTML = `<strong>What:</strong> ${window.escapeHTML(f.explanation.what || '')}`;
        const whyDiv = document.createElement('div');
        whyDiv.innerHTML = `<strong>Why it matters:</strong> ${window.escapeHTML(f.explanation.why || '')}`;
        drawer.appendChild(whatDiv);
        drawer.appendChild(whyDiv);
      }

      tdDetail.appendChild(drawer);
      trDetail.appendChild(tdDetail);

      tr.addEventListener('click', () => {
        trDetail.classList.toggle('hidden');
      });

      tbody.appendChild(tr);
      tbody.appendChild(trDetail);
    });
  }

  function showEmptyState(msg) {
    const tbody = document.getElementById('findings-table-tbody');
    if (!tbody) return;
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.textContent = msg;
    td.className = 'text-muted';
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  return {
    init: loadFindings,
  };
})();
