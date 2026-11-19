/**
 * ZEROVANT — Screen 02: Scanner Hub
 * Ingestion from GitHub/Local, YAML line editor, demo workflows, live stage progress.
 */

const VULNERABLE_DEMO_YAML = `name: Build and Deploy Pipeline
on:
  pull_request_target:
    types: [opened, synchronize]

permissions: write-all

jobs:
  pwn_request_demo:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Untrusted PR Code
        uses: actions/checkout@v2
        with:
          ref: \${{ github.event.pull_request.head.sha }}

      - name: Execute Build Script with Injected Context
        run: |
          echo "Building PR from \${{ github.event.pull_request.title }}"
          npm install && npm run build

      - name: Deploy to Production
        env:
          PROD_API_KEY: "sk_live_prod_998877665544"
        run: |
          curl -H "Authorization: Bearer $PROD_API_KEY" https://api.prod.zerovant.internal/deploy
`;

const SAFE_DEMO_YAML = `name: Hardened CI Pipeline
on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  hardened_build:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Checkout Code
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
        with:
          persist-credentials: false

      - name: Run Safe Lint & Test
        env:
          PR_TITLE: \${{ github.event.pull_request.title }}
        run: |
          echo "Auditing PR title securely from environment variable: $PR_TITLE"
          npm test
`;

let activeSource = 'github';

function init() {
  // 1. Provider Tabs Switching
  const tabBtns = document.querySelectorAll('.provider-tab-btn');
  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      activeSource = btn.getAttribute('data-source-type') || 'github';

      const urlInput = document.getElementById('scan-repo-url');
      if (urlInput) {
        if (activeSource === 'github') {
          urlInput.placeholder = 'https://github.com/owner/repository';
          urlInput.value = 'https://github.com/amarnath-e-ai/fnflow';
        } else if (activeSource === 'gitlab') {
          urlInput.placeholder = 'https://gitlab.com/group/project';
          urlInput.value = 'https://gitlab.com/gitlab-org/gitlab';
        } else if (activeSource === 'bitbucket') {
          urlInput.placeholder = 'https://bitbucket.org/workspace/repo';
          urlInput.value = 'https://bitbucket.org/atlassian/sample';
        } else if (activeSource === 'local') {
          urlInput.placeholder = 'C:\\path\\to\\local\\repo or /workspace/repo';
          urlInput.value = 'tests/corpus/chains';
        }
      }
    });
  });

  // 2. Trigger Scan Button
  const btnTrigger = document.getElementById('btn-trigger-scan');
  if (btnTrigger) {
    btnTrigger.onclick = handleTriggerScan;
  }

  // 3. YAML Editor Line Numbers & Audit
  const yamlTextarea = document.getElementById('scan-yaml-textarea');
  const lineNumbersEl = document.getElementById('yaml-line-numbers');
  if (yamlTextarea && lineNumbersEl) {
    const updateLineNumbers = () => {
      const lines = yamlTextarea.value.split('\n').length;
      lineNumbersEl.innerHTML = Array.from({ length: lines }, (_, i) => i + 1).join('<br>');
    };
    yamlTextarea.addEventListener('input', updateLineNumbers);
    yamlTextarea.addEventListener('scroll', () => {
      lineNumbersEl.scrollTop = yamlTextarea.scrollTop;
    });
  }

  // 4. Demo Template Buttons
  const btnVulnDemo = document.getElementById('btn-load-vulnerable-demo');
  if (btnVulnDemo && yamlTextarea) {
    btnVulnDemo.onclick = () => {
      yamlTextarea.value = VULNERABLE_DEMO_YAML;
      yamlTextarea.dispatchEvent(new Event('input'));
      window.showToast('Loaded vulnerable pipeline demo (Pwn-Request attack chain).', 'info');
    };
  }

  const btnSafeDemo = document.getElementById('btn-load-safe-demo');
  if (btnSafeDemo && yamlTextarea) {
    btnSafeDemo.onclick = () => {
      yamlTextarea.value = SAFE_DEMO_YAML;
      yamlTextarea.dispatchEvent(new Event('input'));
      window.showToast('Loaded hardened reference workflow.', 'info');
    };
  }

  // 5. Audit Pasted YAML Button
  const btnScanYaml = document.getElementById('btn-scan-pasted-yaml');
  if (btnScanYaml) {
    btnScanYaml.onclick = handleScanPastedYaml;
  }
}

async function handleTriggerScan() {
  const urlInput = document.getElementById('scan-repo-url');
  const branchSelect = document.getElementById('scan-branch-select');
  const progressBox = document.getElementById('scan-progress-box');
  const btnTrigger = document.getElementById('btn-trigger-scan');

  const rawUrl = urlInput ? urlInput.value.trim() : '';
  const ref = branchSelect ? branchSelect.value.trim() : 'main';

  if (!rawUrl) {
    window.showToast('Please specify a repository URL or path to audit.', 'error');
    return;
  }

  let payload = {};
  if (activeSource === 'local') {
    payload = { local_path: rawUrl, ref: ref };
  } else {
    payload = { repo_url: rawUrl, ref: ref };
  }

  if (progressBox) progressBox.classList.remove('hidden');
  if (btnTrigger) btnTrigger.disabled = true;

  updateProgress(25);

  const res = await window.api.triggerScan(payload);

  if (!res.ok) {
    if (progressBox) progressBox.classList.add('hidden');
    if (btnTrigger) btnTrigger.disabled = false;
    window.showToast(res.message || 'Scan execution failed.', 'error');
    return;
  }

  updateProgress(100);

  setTimeout(() => {
    if (progressBox) progressBox.classList.add('hidden');
    if (btnTrigger) btnTrigger.disabled = false;
    window.showToast('Audit scan completed successfully!', 'success');
    window.router.navigate(`findings?scan_id=${encodeURIComponent(res.data.scan_id)}`);
  }, 500);
}

async function handleScanPastedYaml() {
  const yamlTextarea = document.getElementById('scan-yaml-textarea');
  const progressBox = document.getElementById('scan-progress-box');
  const btnScanYaml = document.getElementById('btn-scan-pasted-yaml');

  const yamlContent = yamlTextarea ? yamlTextarea.value.trim() : '';
  if (!yamlContent) {
    window.showToast('Please paste valid YAML content before scanning.', 'error');
    return;
  }

  if (progressBox) progressBox.classList.remove('hidden');
  if (btnScanYaml) btnScanYaml.disabled = true;

  updateProgress(40);

  const res = await window.api.triggerScan({ yaml: yamlContent });

  if (!res.ok) {
    if (progressBox) progressBox.classList.add('hidden');
    if (btnScanYaml) btnScanYaml.disabled = false;
    window.showToast(res.message || 'YAML evaluation failed.', 'error');
    return;
  }

  updateProgress(100);

  setTimeout(() => {
    if (progressBox) progressBox.classList.add('hidden');
    if (btnScanYaml) btnScanYaml.disabled = false;
    window.showToast('Direct YAML audit complete!', 'success');
    window.router.navigate(`findings?scan_id=${encodeURIComponent(res.data.scan_id)}`);
  }, 450);
}

function updateProgress(pct) {
  const pctEl = document.getElementById('scan-progress-pct');
  if (pctEl) pctEl.textContent = `${pct}%`;
}

export const ScannerModule = {
  init,
};
window.ScannerModule = ScannerModule;
