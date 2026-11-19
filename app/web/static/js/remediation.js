/**
 * ZEROVANT — Screen 07: Remediation Centre (Explainability & YAML Fixes)
 * What/Why/How explanation tabs and side-by-side Before/After diffs with copy fix.
 */

import { escapeHTML } from './api.js';

let currentFinding = null;
let activeTab = 'fix';

async function init(params) {
  const ruleId = params ? (params.get('rule_id') || params.get('ruleId')) : null;
  const scanId = params ? (params.get('scan_id') || params.get('scanId')) : null;

  // Setup tab switcher buttons
  const tabs = document.querySelectorAll('.remediation-tab');
  tabs.forEach((tab) => {
    tab.onclick = () => {
      tabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      activeTab = tab.getAttribute('data-tab') || 'fix';
      renderTabContent();
    };
  });

  if (scanId) {
    const scanRes = await window.api.getScan(scanId);
    if (scanRes.ok && scanRes.data.findings && scanRes.data.findings.length > 0) {
      const match = ruleId 
        ? scanRes.data.findings.find((f) => f.rule_id === ruleId) || scanRes.data.findings[0]
        : scanRes.data.findings[0];
      return loadRemediation(match);
    }
  }

  // Fallback to recent scan finding
  const statsRes = await window.api.getStats();
  if (statsRes.ok && statsRes.data.recent_scans && statsRes.data.recent_scans.length > 0) {
    const firstScan = await window.api.getScan(statsRes.data.recent_scans[0].id);
    if (firstScan.ok && firstScan.data.findings && firstScan.data.findings.length > 0) {
      const match = ruleId 
        ? firstScan.data.findings.find((f) => f.rule_id === ruleId) || firstScan.data.findings[0]
        : firstScan.data.findings[0];
      return loadRemediation(match);
    }
  }

  // Load default educational example
  loadRemediation({
    rule_id: 'CICD-001',
    title: 'Hardcoded secret in workflow',
    severity: 'CRITICAL',
    description: 'Plaintext credentials or cloud keys embedded directly in workflow YAML.',
    explanation: {
      what: 'Workflow defines environment variable with literal credentials instead of referencing repository secrets context.',
      why: 'Anyone with read access to repository or pipeline logs can exfiltrate production secrets and compromise downstream cloud environments.',
      how: 'Migrate the plaintext credential to GitHub Repository Secrets and reference it using ${{ secrets.PROD_API_KEY }}.',
      fix_diff: `--- a/deploy.yml
+++ b/deploy.yml
@@ -10,3 +10,3 @@
 env:
-  API_KEY: "sk_live_abc123"
+  API_KEY: \${{ secrets.PROD_API_KEY }}
 steps:
   - run: echo $API_KEY`,
    },
  });
}

function loadRemediation(finding) {
  currentFinding = finding;

  const badgeEl = document.getElementById('remediation-rule-badge');
  const titleEl = document.getElementById('remediation-finding-title');
  const descEl = document.getElementById('remediation-finding-desc');

  if (badgeEl) {
    const sev = (finding.severity || 'LOW').toLowerCase();
    badgeEl.className = `badge badge-${sev} mb-2`;
    badgeEl.innerHTML = `<span class="badge-dot"></span> ${(finding.severity || 'LOW').toUpperCase()}`;
  }

  if (titleEl) {
    titleEl.textContent = `${finding.rule_id}: ${finding.title || finding.rule_id}`;
  }

  if (descEl) {
    descEl.textContent = finding.description || 'Contextual remediation for detected security vulnerability.';
  }

  // Wire Copy Fix Button
  const btnCopy = document.getElementById('btn-copy-fix');
  if (btnCopy) {
    btnCopy.onclick = () => {
      const exp = finding.explanation || {};
      const textToCopy = exp.fix_diff || finding.raw_yaml || '';
      navigator.clipboard.writeText(textToCopy).then(() => {
        window.showToast('Secure YAML fix copied to clipboard!', 'success');
      });
    };
  }

  // Wire Apply Suggestion Button
  const btnApply = document.getElementById('btn-apply-suggestion');
  if (btnApply) {
    btnApply.onclick = () => {
      window.showToast('Fix marked for implementation in CI/CD pipeline.', 'success');
    };
  }

  renderTabContent();
}

function renderTabContent() {
  const container = document.getElementById('remediation-tab-content');
  if (!container || !currentFinding) return;

  const exp = currentFinding.explanation || {};

  if (activeTab === 'fix') {
    const diff = exp.fix_diff || '';
    const beforeLines = [];
    const afterLines = [];

    diff.split('\n').forEach((line) => {
      if (line.startsWith('-') && !line.startsWith('---')) {
        beforeLines.push(line.slice(1));
      } else if (line.startsWith('+') && !line.startsWith('+++')) {
        afterLines.push(line.slice(1));
      } else if (!line.startsWith('@@') && !line.startsWith('---') && !line.startsWith('+++')) {
        beforeLines.push(line);
        afterLines.push(line);
      }
    });

    const beforeText = beforeLines.join('\n') || '# Vulnerable snippet\nenv:\n  API_KEY: "sk_live_abc123"\nsteps:\n  - run: echo $API_KEY';
    const afterText = afterLines.join('\n') || '# Remediated workflow\nenv:\n  API_KEY: ${{ secrets.PROD_API_KEY }}\nsteps:\n  - run: echo $API_KEY';

    container.innerHTML = `
      <div class="diff-split-container">
        <div class="diff-panel">
          <div class="diff-panel-header diff-before-header">
            &times; Before (Vulnerable)
          </div>
          <pre id="remediation-diff-before" class="diff-code-body">${escapeHTML(beforeText)}</pre>
        </div>

        <div class="diff-panel">
          <div class="diff-panel-header diff-after-header">
            &#10003; After (Recommended Fix)
          </div>
          <pre id="remediation-diff-after" class="diff-code-body">${escapeHTML(afterText)}</pre>
        </div>
      </div>
    `;
  } else if (activeTab === 'overview') {
    container.innerHTML = `
      <div class="flex flex-col gap-4 py-2">
        <div class="glass-card" style="padding: 1.5rem;">
          <h4 class="font-bold text-sm text-muted uppercase tracking-wider mb-2">Finding Overview</h4>
          <p style="font-size: 0.95rem; color: var(--text-primary); line-height: 1.6;">
            ${escapeHTML(exp.what || currentFinding.description || 'Vulnerability detected in workflow configuration.')}
          </p>
        </div>
        <div class="glass-card" style="padding: 1.5rem;">
          <h4 class="font-bold text-sm text-muted uppercase tracking-wider mb-2">Recommended Action</h4>
          <p style="font-size: 0.95rem; color: var(--text-primary); line-height: 1.6;">
            ${escapeHTML(exp.how || 'Replace untrusted syntax with parameterized, hardened equivalents.')}
          </p>
        </div>
      </div>
    `;
  } else if (activeTab === 'why') {
    container.innerHTML = `
      <div class="glass-card py-4" style="padding: 1.5rem;">
        <h4 class="font-bold text-sm text-muted uppercase tracking-wider mb-3">Threat Model &amp; Exploit Vector</h4>
        <p style="font-size: 0.95rem; color: var(--text-primary); line-height: 1.65; margin-bottom: 1rem;">
          ${escapeHTML(exp.why || 'Exploiting this misconfiguration enables an adversary to hijack execution flow or compromise pipeline integrity.')}
        </p>
        <div class="location-tag mt-2">
          Severity Weight: ${(currentFinding.severity || 'CRITICAL').toUpperCase()} &bull; Exploitability: Direct
        </div>
      </div>
    `;
  } else if (activeTab === 'references') {
    container.innerHTML = `
      <div class="glass-card py-4" style="padding: 1.5rem;">
        <h4 class="font-bold text-sm text-muted uppercase tracking-wider mb-3">Security Guidelines &amp; Citations</h4>
        <ul style="list-style: none; display: flex; flex-direction: column; gap: 0.75rem;">
          <li>
            <a href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" target="_blank" rel="noopener" class="flex items-center gap-2">
              GitHub Actions Security Hardening Guidelines &rarr;
            </a>
          </li>
          <li>
            <a href="https://cwe.mitre.org/data/definitions/798.html" target="_blank" rel="noopener" class="flex items-center gap-2">
              CWE-798: Use of Hard-coded Credentials &rarr;
            </a>
          </li>
          <li>
            <a href="https://owasp.org/www-project-top-10-ci-cd-security-risks/" target="_blank" rel="noopener" class="flex items-center gap-2">
              OWASP Top 10 CI/CD Security Risks &rarr;
            </a>
          </li>
        </ul>
      </div>
    `;
  }
}

export const RemediationModule = {
  init,
};
window.RemediationModule = RemediationModule;
