/**
 * ZEROVANT — Screen 02: Repository Scanner
 */

window.ScannerModule = (function () {
  let activeTab = 'github';

  function init() {
    const tabBtns = document.querySelectorAll('.source-tab-btn');
    tabBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-source');
        switchSourceTab(tab);
      });
    });

    const startBtn = document.getElementById('btn-start-scan');
    if (startBtn) {
      startBtn.addEventListener('click', handleStartScan);
    }
  }

  function switchSourceTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.source-tab-btn').forEach((btn) => {
      if (btn.getAttribute('data-source') === tab) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    const ghSection = document.getElementById('scan-input-github');
    const yamlSection = document.getElementById('scan-input-yaml');

    if (tab === 'github') {
      if (ghSection) ghSection.classList.remove('hidden');
      if (yamlSection) yamlSection.classList.add('hidden');
    } else {
      if (ghSection) ghSection.classList.add('hidden');
      if (yamlSection) yamlSection.classList.remove('hidden');
    }
  }

  async function handleStartScan() {
    const errorBox = document.getElementById('scan-error-msg');
    const progressBox = document.getElementById('scan-progress-box');
    const startBtn = document.getElementById('btn-start-scan');

    if (errorBox) errorBox.classList.add('hidden');

    let payload = {};
    if (activeTab === 'github') {
      const urlInput = document.getElementById('scan-repo-url');
      const refInput = document.getElementById('scan-repo-ref');
      const url = urlInput ? urlInput.value.trim() : '';
      const ref = refInput ? refInput.value.trim() : '';

      if (!url) {
        showError('Please enter a valid GitHub repository URL.');
        return;
      }
      payload = { repo_url: url, ref: ref || 'main' };
    } else {
      const yamlInput = document.getElementById('scan-yaml-textarea');
      const yaml = yamlInput ? yamlInput.value.trim() : '';
      if (!yaml) {
        showError('Please paste GitHub Actions workflow YAML content.');
        return;
      }
      payload = { yaml: yaml };
    }

    // Display animated progress stages
    if (progressBox) progressBox.classList.remove('hidden');
    if (startBtn) startBtn.disabled = true;

    animateStages(1);

    const res = await window.api.triggerScan(payload);

    if (!res.ok) {
      if (progressBox) progressBox.classList.add('hidden');
      if (startBtn) startBtn.disabled = false;
      showError(res.message || 'Scan failed to execute.');
      return;
    }

    animateStages(6);

    setTimeout(() => {
      if (progressBox) progressBox.classList.add('hidden');
      if (startBtn) startBtn.disabled = false;
      window.showToast('Audit scan completed successfully!', 'success');
      window.router.navigate(`findings?scanId=${encodeURIComponent(res.data.scan_id)}`);
    }, 600);
  }

  function animateStages(stageNum) {
    const stages = document.querySelectorAll('.stage-step');
    stages.forEach((el, idx) => {
      const stepIdx = idx + 1;
      if (stepIdx < stageNum) {
        el.className = 'stage-step completed';
      } else if (stepIdx === stageNum) {
        el.className = 'stage-step active';
      } else {
        el.className = 'stage-step';
      }
    });
  }

  function showError(msg) {
    const errorBox = document.getElementById('scan-error-msg');
    if (errorBox) {
      errorBox.textContent = msg;
      errorBox.classList.remove('hidden');
    }
  }

  return {
    init: init,
  };
})();
