/**
 * ZEROVANT — Screen 07: Remediation Centre (Explainability & YAML Fixes)
 */

window.RemediationModule = (function () {
  let currentFinding = null;

  async function init(params) {
    const scanId = params ? params.get('scanId') : null;
    const findingId = params ? params.get('findingId') : null;

    if (!scanId || !findingId) {
      // Find first finding from stats recent scan
      const statsRes = await window.api.getStats();
      if (statsRes.ok && statsRes.data.recent_scans && statsRes.data.recent_scans.length > 0) {
        const firstScan = await window.api.getScan(statsRes.data.recent_scans[0].id);
        if (firstScan.ok && firstScan.data.findings && firstScan.data.findings.length > 0) {
          return loadRemediation(firstScan.data.findings[0]);
        }
      }
      showEmpty('Select a finding from the Findings Explorer to view explainable remediation guidance.');
      return;
    }

    const scanRes = await window.api.getScan(scanId);
    if (!scanRes.ok) {
      showEmpty(`Failed to load scan '${scanId}'.`);
      return;
    }

    const finding = (scanRes.data.findings || []).find((f) => f.id === findingId);
    if (!finding) {
      showEmpty(`Finding '${findingId}' not found in scan '${scanId}'.`);
      return;
    }

    loadRemediation(finding);
  }

  function loadRemediation(finding) {
    currentFinding = finding;

    const bannerTitle = document.getElementById('rem-banner-title');
    const bannerRule = document.getElementById('rem-banner-rule');
    const bannerSev = document.getElementById('rem-banner-severity');
    const bannerSource = document.getElementById('rem-banner-source');

    if (bannerTitle) bannerTitle.textContent = finding.title || finding.rule_id;
    if (bannerRule) bannerRule.textContent = finding.rule_id;

    if (bannerSev) {
      const s = (finding.severity || 'LOW').toUpperCase();
      bannerSev.className = `badge badge-${s.toLowerCase()}`;
      bannerSev.textContent = s;
    }

    const exp = finding.explanation || {};
    if (bannerSource) {
      bannerSource.textContent = exp.source === 'llm' ? 'AI / LLM' : 'Template Engine';
    }

    // Populate What / Why / How
    const setBox = (id, text) => {
      const el = document.getElementById(id);
      if (el) el.textContent = text || 'Guidance not available.';
    };

    setBox('rem-expl-what', exp.what || 'No description provided.');
    setBox('rem-expl-why', exp.why || 'No architectural impact rationale provided.');
    setBox('rem-expl-how', exp.how || 'Follow secure GitHub Actions pipeline engineering standards.');

    // Populate Split YAML Diff
    renderSplitDiff(exp.fix_diff || '');

    // Setup Copy Fix Button
    const copyBtn = document.getElementById('btn-copy-fix');
    if (copyBtn) {
      copyBtn.onclick = () => {
        const textToCopy = exp.fix_diff || finding.evidence || '';
        navigator.clipboard.writeText(textToCopy).then(() => {
          window.showToast('Unified diff remediation copied to clipboard!', 'success');
        });
      };
    }
  }

  function renderSplitDiff(rawDiff) {
    const beforeContainer = document.getElementById('diff-code-before');
    const afterContainer = document.getElementById('diff-code-after');

    if (!beforeContainer || !afterContainer) return;

    while (beforeContainer.firstChild) beforeContainer.removeChild(beforeContainer.firstChild);
    while (afterContainer.firstChild) afterContainer.removeChild(afterContainer.firstChild);

    if (!rawDiff) {
      const p = document.createElement('div');
      p.textContent = '# No automated diff generated (architectural decision required)';
      afterContainer.appendChild(p);
      return;
    }

    const lines = rawDiff.split('\n');
    lines.forEach((line) => {
      if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('@@')) {
        return;
      }

      if (line.startsWith('-')) {
        const div = document.createElement('div');
        div.style.color = '#FF5C5C';
        div.textContent = line;
        beforeContainer.appendChild(div);
      } else if (line.startsWith('+')) {
        const div = document.createElement('div');
        div.style.color = '#2ECC71';
        div.textContent = line;
        afterContainer.appendChild(div);
      } else {
        const div1 = document.createElement('div');
        div1.style.color = '#9BAAA1';
        div1.textContent = line;
        beforeContainer.appendChild(div1);

        const div2 = document.createElement('div');
        div2.style.color = '#9BAAA1';
        div2.textContent = line;
        afterContainer.appendChild(div2);
      }
    });
  }

  function showEmpty(msg) {
    const bannerTitle = document.getElementById('rem-banner-title');
    if (bannerTitle) bannerTitle.textContent = msg;
  }

  return {
    init: init,
  };
})();
